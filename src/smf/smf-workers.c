/*
 * Copyright (C) 2026 by Ahmad Raeiji <ahmad.rayeji@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "context.h"
#include "event.h"
#include "smf-workers.h"
#include "smf-sm.h"
#include "radius-path.h"

static ogs_worker_t *smf_workers[OGS_MAX_WORKERS];
static int smf_worker_count = 0;
static int smf_worker_configured = 0;

static OGS_THREAD_LOCAL ogs_fsm_t worker_fsm;

int smf_workers_parse_config(void)
{
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    smf_worker_configured = 0;

    document = ogs_app()->document;
    ogs_assert(document);

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (strcmp(root_key, "smf"))
            continue;

        ogs_yaml_iter_t smf_iter;
        ogs_yaml_iter_recurse(&root_iter, &smf_iter);
        while (ogs_yaml_iter_next(&smf_iter)) {
            const char *smf_key = ogs_yaml_iter_key(&smf_iter);
            ogs_assert(smf_key);
            if (!strcmp(smf_key, "workers")) {
                const char *v = ogs_yaml_iter_value(&smf_iter);
                int n = v ? atoi(v) : 0;
                /* shard 0 is the main thread, so at most MAX-1 workers */
                if (n < 0 || n > OGS_MAX_WORKERS - 1) {
                    ogs_error("smf.workers must be 0..%d (got %d)",
                            OGS_MAX_WORKERS - 1, n);
                    return OGS_ERROR;
                }
                smf_worker_configured = n;
            }
        }
    }

    return OGS_OK;
}

int smf_workers_configured(void)
{
    return smf_worker_configured;
}

int smf_workers_count(void)
{
    return smf_worker_count;
}

bool smf_workers_active(void)
{
    return smf_worker_count > 0;
}

int smf_workers_queue_depth(int wid)
{
    if (wid < 0 || wid >= smf_worker_count || !smf_workers[wid])
        return -1;
    return (int)ogs_queue_size(smf_workers[wid]->queue);
}

/*
 * Shard ids carry ogs_worker_self_id() of the owner: 0 = main thread,
 * 1..N = worker. Decoding never yields more than 15, but a stale or
 * peer-mangled value may point past the live worker count.
 */
int smf_shard_from_teid(uint32_t teid)
{
    return smf_shard_decode_teid(teid);
}

int smf_shard_from_seid(uint64_t seid)
{
    return smf_shard_decode_seid(seid);
}

int smf_shard_from_xid(uint32_t xid)
{
    return smf_shard_decode_xid(xid);
}

int smf_shard_clamp(int shard, uint32_t fallback_key)
{
    return smf_shard_clamp_n(shard, fallback_key, smf_worker_count);
}

int smf_shard_for_new_imsi(const char *imsi_bcd)
{
    return smf_shard_imsi_hash_n(imsi_bcd, smf_worker_count);
}

int smf_event_post_shard(int shard, smf_event_t *e)
{
    ogs_worker_t *worker;
    int rv;

    ogs_assert(e);

    if (shard == 0) {
        rv = ogs_queue_trypush(ogs_app()->queue, e);
        if (rv == OGS_OK)
            ogs_pollset_notify(ogs_app()->pollset);
        return rv;
    }

    if (shard < 1 || shard > smf_worker_count) {
        ogs_error("smf_event_post_shard: bad shard %d (workers=%d)",
                shard, smf_worker_count);
        return OGS_ERROR;
    }

    worker = smf_workers[shard - 1];
    ogs_assert(worker);

    return ogs_worker_post(worker, e);
}

/*
 * freeDiameter / helper threads (never main, never a shard): deliver to
 * the session's owner. Main keeps the historical blocking push, which
 * back-pressures the Diameter thread instead of dropping an answer the
 * session waits for. Never frees; caller keeps ownership on failure.
 */
int smf_event_post_to_sess_owner(const smf_sess_t *sess, smf_event_t *e)
{
    int rv, shard = 0;

    ogs_assert(sess);
    ogs_assert(e);

    if (smf_worker_count > 0)
        shard = smf_sess_owner_shard(sess);

    if (shard == 0) {
        rv = ogs_queue_push(ogs_app()->queue, e);
        if (rv == OGS_OK)
            ogs_pollset_notify(ogs_app()->pollset);
        return rv;
    }

    return smf_event_post_shard(shard, e);
}

int smf_event_push_shard(int shard, smf_event_t *e)
{
    int rv;

    ogs_assert(e);

    rv = smf_event_post_shard(shard, e);
    if (rv != OGS_OK) {
        ogs_error("smf_event_push_shard(%d, %s) failed [%d]",
                shard, smf_event_get_name(e), rv);
        smf_event_free(e);
    }
    return rv;
}

static smf_event_t *fanout_copy(const smf_event_t *tmpl)
{
    smf_event_t *e = smf_event_new(tmpl->h.id);

    e->h.timer_id = tmpl->h.timer_id;
    e->gnode = tmpl->gnode;
    e->pfcp_node = tmpl->pfcp_node;
    e->admin_force = tmpl->admin_force;
    e->cutoff = tmpl->cutoff;
    return e;
}

static int fanout(const smf_event_t *tmpl, bool include_self)
{
    int shard, fails = 0;

    ogs_assert(tmpl);

    if (smf_worker_count <= 0)
        return include_self ?
            smf_event_push_local(fanout_copy(tmpl)) : OGS_OK;

    for (shard = 0; shard <= smf_worker_count; shard++) {
        if (!include_self && shard == ogs_worker_self_id())
            continue;
        if (smf_event_push_shard(shard, fanout_copy(tmpl)) != OGS_OK)
            fails++;
    }

    return fails ? OGS_ERROR : OGS_OK;
}

int smf_event_fanout(const smf_event_t *tmpl)
{
    return fanout(tmpl, true);
}

int smf_event_fanout_others(const smf_event_t *tmpl)
{
    return fanout(tmpl, false);
}

/*
 * Re-post a GTP RX event to the shard that owns the UE/session. The
 * socket-level router works from raw headers only and can misroute
 * (IMSI peek failed, peer echoed a truncated TEID, stale shard bits),
 * and a foreign thread must not create the per-shard GTP xact or touch
 * the UE, so this runs after parse and BEFORE ogs_gtp_xact_receive().
 * Returns true when the event was bounced (pkbuf ownership moved).
 */
static bool rehome_to_owner(smf_event_t *e, int owner)
{
    smf_event_t *ne = NULL;

    if (owner < 0 || owner == ogs_worker_self_id())
        return false;

    ne = smf_event_new(e->h.id);
    ne->gnode = e->gnode;
    ne->pkbuf = e->pkbuf;
    ne->xshard_done = e->xshard_done;
    e->pkbuf = NULL;

    ogs_debug("GTP event %s rehomed: shard %d -> owner %d",
            smf_event_get_name(e), ogs_worker_self_id(), owner);

    smf_event_push_shard(owner, ne);
    return true;
}

/*
 * Cross-shard static-IP collision handshake. The new CSR's IMSI lives on
 * this shard's peer UE owner, but the requested static IPv4 is still held
 * by a session on another shard. Ask that shard to release it; it bounces
 * the CSR back to `reply_shard` (xshard_done set) once the IP is free.
 */
static bool xshard_collision_begin(smf_event_t *e, int ip_owner, int reply)
{
    smf_event_t *ne = NULL;

    ne = smf_event_new(SMF_EVT_XSHARD_COLLISION);
    ne->gnode = e->gnode;
    ne->pkbuf = e->pkbuf;
    ne->reply_shard = reply;
    e->pkbuf = NULL;

    ogs_info("GTP CSR static-IP collision on shard %d: release request "
            "sent, new session will be created on shard %d",
            ip_owner, reply);

    smf_event_push_shard(ip_owner, ne);
    return true;
}

static bool csr_static_ipv4(ogs_gtp2_message_t *message, uint32_t *addr)
{
    ogs_gtp2_create_session_request_t *req =
        &message->create_session_request;
    ogs_ip_t ip;

    if (!req->pdn_address_allocation.presence ||
            !req->pdn_address_allocation.data)
        return false;
    if (ogs_paa_to_ip(req->pdn_address_allocation.data, &ip) != OGS_OK)
        return false;
    if (!ip.ipv4 || !ip.addr)
        return false;

    *addr = ip.addr;
    return true;
}

static int owner_for_new_ue(const void *imsi, int imsi_len)
{
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN + 1];

    ogs_buffer_to_bcd((uint8_t *)imsi, imsi_len, imsi_bcd);
    return smf_shard_for_new_imsi(imsi_bcd);
}

static bool rehome_create_session(smf_event_t *e, ogs_gtp2_message_t *message)
{
    ogs_gtp2_create_session_request_t *req =
        &message->create_session_request;
    int ue_owner = -1, ip_owner = -1;
    uint32_t addr = 0;
    ogs_pool_id_t ip_ue_id = OGS_INVALID_POOL_ID;

    if (!req->imsi.presence || !req->imsi.data || req->imsi.len <= 0)
        return false;
    if (req->imsi.len > OGS_MAX_IMSI_LEN)
        return false;

    ue_owner = smf_ue_owner_shard_by_imsi(req->imsi.data, req->imsi.len);

    if (csr_static_ipv4(message, &addr))
        ip_owner = smf_sess_owner_shard_by_ipv4(addr, &ip_ue_id);

    if (ue_owner < 0) {
        /*
         * Brand-new UE: when its static IP is held elsewhere, create it
         * next to the holder so the single-threaded collision replace
         * (graceful, waits for the UPF) runs unchanged.
         */
        return rehome_to_owner(e, ip_owner >= 0 ?
                ip_owner : owner_for_new_ue(req->imsi.data, req->imsi.len));
    }

    if (ip_owner >= 0 && ip_owner != ue_owner && !e->xshard_done)
        return xshard_collision_begin(e, ip_owner, ue_owner);

    return rehome_to_owner(e, ue_owner);
}

bool smf_worker_rehome_gtp2(smf_event_t *e, ogs_gtp2_message_t *message)
{
    int owner = -1;

    ogs_assert(e);
    ogs_assert(message);

    if (!smf_workers_active())
        return false;

    /* node-level: main owns the peer state */
    if (message->h.type == OGS_GTP2_ECHO_REQUEST_TYPE ||
            message->h.type == OGS_GTP2_ECHO_RESPONSE_TYPE)
        return rehome_to_owner(e, 0);

    /* Replies to OUR requests follow the xact (routed by xid shard). */
    if (e->pkbuf &&
            ogs_gtp2_rx_reply_shard(e->pkbuf->data, e->pkbuf->len) >= 0)
        return false;

    if (message->h.type == OGS_GTP2_CREATE_SESSION_REQUEST_TYPE) {
        /*
         * TEID=0 (S5) or an S11 CSR carrying a sibling PDN's TEID: the
         * IMSI decides. A sibling TEID is owned by the same UE anyway.
         */
        if (!message->h.teid_presence || !message->h.teid ||
                smf_sess_owner_shard_by_seid(message->h.teid) < 0)
            return rehome_create_session(e, message);
    }

    if (message->h.teid_presence && message->h.teid)
        owner = smf_sess_owner_shard_by_seid(message->h.teid);

    return rehome_to_owner(e, owner);
}

bool smf_worker_rehome_gtp1(smf_event_t *e, ogs_gtp1_message_t *message)
{
    int owner = -1;

    ogs_assert(e);
    ogs_assert(message);

    if (!smf_workers_active())
        return false;

    if (message->h.type == OGS_GTP1_ECHO_REQUEST_TYPE ||
            message->h.type == OGS_GTP1_ECHO_RESPONSE_TYPE)
        return rehome_to_owner(e, 0);

    if (e->pkbuf &&
            ogs_gtp1_rx_reply_shard(e->pkbuf->data, e->pkbuf->len) >= 0)
        return false;

    if (message->h.teid)
        owner = smf_sess_owner_shard_by_seid(message->h.teid);

    if (owner < 0 &&
            message->h.type == OGS_GTP1_CREATE_PDP_CONTEXT_REQUEST_TYPE) {
        ogs_gtp1_create_pdp_context_request_t *req =
            &message->create_pdp_context_request;

        if (!req->imsi.presence || !req->imsi.data || req->imsi.len <= 0 ||
                req->imsi.len > OGS_MAX_IMSI_LEN)
            return false;

        owner = smf_ue_owner_shard_by_imsi(req->imsi.data, req->imsi.len);
        if (owner < 0)
            owner = owner_for_new_ue(req->imsi.data, req->imsi.len);
    }

    return rehome_to_owner(e, owner);
}

static void smf_worker_thread_init(ogs_worker_t *worker)
{
    int rv;

    ogs_assert(worker);

    /*
     * The SMF context (config, pools, hashes, UE list) is PROCESS-GLOBAL,
     * initialized once by smf_initialize(). Workers only bring up their
     * per-thread state: the GTP/PFCP transaction pools (each xact is
     * owned by the thread that created it) and this shard's FSM.
     */
    rv = ogs_gtp_xact_init();
    ogs_assert(rv == OGS_OK);
    rv = ogs_pfcp_xact_init();
    ogs_assert(rv == OGS_OK);

    ogs_fsm_init(&worker_fsm, smf_state_initial, smf_state_final, 0);

    ogs_info("SMF shard worker %d ready", worker->id);
}

/*
 * Main's smf_gtp_node_free()/ogs_pfcp_node_remove() only reach slot 0 of
 * each peer's xact lists; a shard must drain its own slot (and the timers
 * those xacts hold) before its thread-local pools go away.
 */
static void smf_worker_xact_sweep(void)
{
    ogs_gtp_node_t *gnode = NULL;
    ogs_pfcp_node_t *node = NULL;

    smf_peers_lock();
    ogs_list_for_each(&smf_self()->sgw_s5c_list, gnode)
        ogs_gtp_xact_delete_all(gnode);
    smf_peers_unlock();

    ogs_pfcp_peer_lock();
    ogs_list_for_each(&ogs_pfcp_self()->pfcp_peer_list, node)
        ogs_pfcp_xact_delete_all(node);
    ogs_pfcp_peer_unlock();
}

static void smf_worker_thread_fini(ogs_worker_t *worker)
{
    ogs_assert(worker);

    ogs_fsm_fini(&worker_fsm, 0);

    smf_worker_xact_sweep();
    ogs_pfcp_xact_final();
    ogs_gtp_xact_final();
    smf_radius_thread_final();
    ogs_tlv_thread_final();

    ogs_info("SMF shard worker %d stopped", worker->id);
}

static void smf_worker_dispatch(ogs_worker_t *worker, void *data)
{
    smf_event_t *e = data;
    int id;

    ogs_assert(worker);
    ogs_assert(e);

    ogs_trace_clear();
    smf_event_lag_observe(e);
    smf_event_trace_rx_restore(e);
    /* FSM transitions overwrite e->h.id with ENTRY/EXIT signals */
    id = e->h.id;
    ogs_fsm_dispatch(&worker_fsm, e);
    ogs_trace_clear();
    /* main's copy of a relayed request; the server owns the original */
    if (e->sbi_relayed && id == OGS_EVENT_SBI_SERVER && e->h.sbi.request)
        ogs_sbi_request_free(e->h.sbi.request);
    /* handlers take ownership of pkbuf / pfcp_message they consume */
    ogs_event_free(e);
}

int smf_workers_start(void)
{
    int i;

    if (smf_worker_configured <= 0)
        return OGS_OK;

    ogs_assert(smf_worker_count == 0);
    ogs_assert(!ogs_worker_active());

    /* Composed SEIDs keep the raw pool index below the shard bits. */
    if (ogs_app()->pool.sess >= (1ull << (32 - OGS_WORKER_ID_BITS))) {
        ogs_error("smf.workers needs max sessions < %u (got %llu)",
                1u << (32 - OGS_WORKER_ID_BITS),
                (unsigned long long)ogs_app()->pool.sess);
        return OGS_ERROR;
    }

    /* Opt-in protocol id sharding BEFORE any worker exists. */
    ogs_worker_shards_enable();

    for (i = 0; i < smf_worker_configured; i++) {
        char tname[16];

        smf_workers[i] = ogs_worker_create(i,
                ogs_app()->pool.event,
                ogs_app()->pool.timer,
                64,
                smf_worker_dispatch, NULL);
        ogs_assert(smf_workers[i]);
        ogs_worker_hooks(smf_workers[i],
                smf_worker_thread_init, smf_worker_thread_fini);
        ogs_snprintf(tname, sizeof(tname), "smf-w%d", i);
        ogs_worker_set_name(smf_workers[i], tname);
        ogs_worker_start(smf_workers[i]);
    }

    smf_worker_count = smf_worker_configured;

    ogs_info("SMF SMP workers: %d shard(s), shared UE/session pools "
            "(max.ue=%llu sess=%llu)",
            smf_worker_count,
            (unsigned long long)ogs_global_conf()->max.ue,
            (unsigned long long)ogs_app()->pool.sess);

    return OGS_OK;
}

void smf_workers_stop(void)
{
    int i;

    /* Join threads only: session timers may live on worker timer
     * managers and are deleted by smf_context_final() on the main
     * thread. smf_workers_final() frees the managers afterwards. */
    for (i = 0; i < smf_worker_count; i++)
        ogs_worker_join(smf_workers[i]);
}

void smf_workers_final(void)
{
    int i;

    for (i = 0; i < smf_worker_count; i++) {
        ogs_worker_destroy(smf_workers[i]);
        smf_workers[i] = NULL;
    }
    smf_worker_count = 0;
}
