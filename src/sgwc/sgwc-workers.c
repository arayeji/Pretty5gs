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
#include "sgwc-workers.h"
#include "sgwc-sm.h"

static ogs_worker_t *sgwc_workers[OGS_MAX_WORKERS];
static int sgwc_worker_count = 0;
static int sgwc_worker_configured = 0;

static OGS_THREAD_LOCAL ogs_fsm_t worker_fsm;

int sgwc_workers_parse_config(void)
{
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    sgwc_worker_configured = 0;

    document = ogs_app()->document;
    ogs_assert(document);

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (strcmp(root_key, "sgwc"))
            continue;

        ogs_yaml_iter_t sgwc_iter;
        ogs_yaml_iter_recurse(&root_iter, &sgwc_iter);
        while (ogs_yaml_iter_next(&sgwc_iter)) {
            const char *sgwc_key = ogs_yaml_iter_key(&sgwc_iter);
            ogs_assert(sgwc_key);
            if (!strcmp(sgwc_key, "workers")) {
                const char *v = ogs_yaml_iter_value(&sgwc_iter);
                int n = v ? atoi(v) : 0;
                /* shard 0 is the main thread, so at most MAX-1 workers */
                if (n < 0 || n > OGS_MAX_WORKERS - 1) {
                    ogs_error("sgwc.workers must be 0..%d (got %d)",
                            OGS_MAX_WORKERS - 1, n);
                    return OGS_ERROR;
                }
                sgwc_worker_configured = n;
            }
        }
    }

    return OGS_OK;
}

int sgwc_workers_configured(void)
{
    return sgwc_worker_configured;
}

int sgwc_workers_count(void)
{
    return sgwc_worker_count;
}

bool sgwc_workers_active(void)
{
    return sgwc_worker_count > 0;
}

ogs_worker_t *sgwc_worker_by_id(int wid)
{
    if (wid < 0 || wid >= sgwc_worker_count)
        return NULL;
    return sgwc_workers[wid];
}

/*
 * Shard bits carry ogs_worker_self_id() of the owner: 0 = main thread,
 * 1..N = worker. These helpers return the WORKER INDEX (shard - 1);
 * -1 means main-owned, and callers already route wid < 0 to the main
 * queue.
 */
int sgwc_shard_from_teid(uint32_t teid)
{
    int shard = (int)((teid >> (32 - OGS_WORKER_ID_BITS)) &
            ((1u << OGS_WORKER_ID_BITS) - 1));
    return shard - 1;
}

int sgwc_shard_from_seid(uint64_t seid)
{
    /* Local SEIDs are composed in the low 32 bits (same as S5C TEID). */
    return sgwc_shard_from_teid((uint32_t)seid);
}

int sgwc_shard_from_xid(uint32_t xid)
{
    /* GTPv2/PFCP: shard bits directly below CMD bit 23 (was a
     * hardcoded ">> 20 & 7"; must track OGS_WORKER_ID_BITS). */
    return (int)((xid >> (23 - OGS_WORKER_ID_BITS)) &
            ((1u << OGS_WORKER_ID_BITS) - 1)) - 1;
}

int sgwc_shard_from_imsi_bcd(const char *imsi_bcd)
{
    unsigned h = 5381;
    const char *p;

    ogs_assert(imsi_bcd);
    ogs_assert(sgwc_worker_count > 0);

    for (p = imsi_bcd; *p; p++)
        h = ((h << 5) + h) + (unsigned char)*p;

    return (int)(h % (unsigned)sgwc_worker_count);
}

int sgwc_gtpv2_peek_imsi_bcd(ogs_pkbuf_t *pkbuf, char *bcd, size_t bcd_size)
{
    ogs_gtp2_header_t *h;
    uint8_t *p, *end;
    int hdr_len;

    ogs_assert(pkbuf);
    ogs_assert(bcd);
    ogs_assert(bcd_size > 0);

    bcd[0] = '\0';

    if (pkbuf->len < 8)
        return OGS_ERROR;

    h = (ogs_gtp2_header_t *)pkbuf->data;
    hdr_len = h->teid_presence ? OGS_GTPV2C_HEADER_LEN : 8;
    if (pkbuf->len < (size_t)hdr_len)
        return OGS_ERROR;

    p = (uint8_t *)pkbuf->data + hdr_len;
    end = (uint8_t *)pkbuf->data + pkbuf->len;

    while (p + 4 <= end) {
        uint8_t type = p[0];
        uint16_t len = ((uint16_t)p[1] << 8) | p[2];
        uint8_t instance = p[3] & 0x0f;
        uint8_t *val = p + 4;

        if (val + len > end)
            break;

        if (type == OGS_GTP2_IMSI_TYPE && instance == 0 && len > 0) {
            if (len > OGS_MAX_IMSI_LEN)
                len = OGS_MAX_IMSI_LEN;
            ogs_buffer_to_bcd(val, len, bcd);
            return OGS_OK;
        }

        p = val + len;
    }

    return OGS_ERROR;
}

/*
 * Re-post a GTP RX event to the shard that owns the UE/session.
 *
 * The socket-level router (sgwc_gtp_deliver) can misroute:
 *  - Create Session TEID=0 when the IMSI peek fails (falls back to the
 *    MME's SQN/xid bits, often landing on main),
 *  - S5 messages whose PGW echoes a truncated TEID (shard bits 0 ->
 *    main; sgwc_sess_find_by_teid() still recovers the session via the
 *    inbound-roam offset variants),
 *  - stale shard bits remapped with % N.
 * A foreign thread must not create the per-shard GTP xact or mutate the
 * UE, so this check runs after parse and BEFORE ogs_gtp_xact_receive().
 * Returns true when the event was bounced (pkbuf ownership moved).
 */
static bool rehome_to_owner(sgwc_event_t *e, int owner)
{
    int self;
    int rv;
    sgwc_event_t *ne = NULL;

    self = ogs_worker_self_id() - 1;    /* -1 = main thread */
    if (owner == self)
        return false;

    ne = sgwc_event_new(e->id);
    if (!ne) {
        ogs_error("rehome_to_owner: sgwc_event_new() failed");
        return false;
    }
    ne->gnode = e->gnode;
    ne->pkbuf = e->pkbuf;
    e->pkbuf = NULL;

    ogs_debug("GTP event %d rehomed: shard %d -> owner %d",
            e->id, self, owner);

    if (owner < 0) {
        rv = ogs_queue_push(ogs_app()->queue, ne);
        if (rv != OGS_OK) {
            ogs_error("rehome_to_owner: main queue push failed [%d]", rv);
            ogs_pkbuf_free(ne->pkbuf);
            ne->pkbuf = NULL;
            sgwc_event_free(ne);
        } else {
            ogs_pollset_notify(ogs_app()->pollset);
        }
    } else {
        /* frees ne (and pkbuf) on failure */
        sgwc_event_push_to_worker(owner, ne);
    }
    return true;
}

bool sgwc_worker_rehome_gtp2(sgwc_event_t *e, ogs_gtp2_message_t *message)
{
    int owner;
    sgwc_ue_t *sgwc_ue = NULL;
    sgwc_sess_t *sess = NULL;

    ogs_assert(e);
    ogs_assert(message);

    if (!sgwc_workers_active())
        return false;

    /* node-level, main owns the peer FSMs; router already sent these
     * to main */
    if (message->h.type == OGS_GTP2_ECHO_REQUEST_TYPE ||
            message->h.type == OGS_GTP2_ECHO_RESPONSE_TYPE)
        return false;

    /* Replies to OUR requests follow the xact (routed by xid shard);
     * bouncing them to the UE/sess owner would strand the xact. */
    if (e->pkbuf &&
            ogs_gtp2_rx_reply_shard(e->pkbuf->data, e->pkbuf->len) >= 0)
        return false;

    if (e->id == SGWC_EVT_S11_MESSAGE) {
        if (message->h.teid_presence && message->h.teid)
            sgwc_ue = sgwc_ue_find_by_teid(message->h.teid);
        if (!sgwc_ue &&
                message->h.type == OGS_GTP2_CREATE_SESSION_REQUEST_TYPE &&
                message->create_session_request.imsi.presence &&
                message->create_session_request.imsi.data &&
                message->create_session_request.imsi.len > 0) {
            sgwc_ue = sgwc_ue_find_by_imsi(
                    message->create_session_request.imsi.data,
                    message->create_session_request.imsi.len);
            if (!sgwc_ue) {
                /* Brand-new UE: create it on the sticky IMSI shard so
                 * the composed TEIDs get worker bits, never main's. */
                char imsi_bcd[OGS_MAX_IMSI_BCD_LEN + 1];
                ogs_buffer_to_bcd(
                        (uint8_t *)message->create_session_request.imsi.data,
                        message->create_session_request.imsi.len, imsi_bcd);
                return rehome_to_owner(
                        e, sgwc_shard_from_imsi_bcd(imsi_bcd));
            }
        }
        if (!sgwc_ue)
            return false;
        owner = sgwc_shard_from_teid(sgwc_ue->sgw_s11_teid);
    } else if (e->id == SGWC_EVT_S5C_MESSAGE) {
        if (message->h.teid_presence && message->h.teid)
            sess = sgwc_sess_find_by_teid(message->h.teid);
        if (!sess)
            return false;
        owner = sgwc_shard_from_teid(sess->sgw_s5c_teid);
    } else {
        return false;
    }

    return rehome_to_owner(e, owner);
}

bool sgwc_worker_rehome_gtp1(sgwc_event_t *e, ogs_gtp1_message_t *message)
{
    sgwc_ue_t *sgwc_ue = NULL;
    sgwc_sess_t *sess = NULL;

    ogs_assert(e);
    ogs_assert(message);

    if (!sgwc_workers_active())
        return false;

    /* Only rehome peer-initiated requests; GTPv1 replies must stay on
     * the thread holding the local xact. */
    if (message->h.type != OGS_GTP1_CREATE_PDP_CONTEXT_REQUEST_TYPE &&
            message->h.type != OGS_GTP1_UPDATE_PDP_CONTEXT_REQUEST_TYPE &&
            message->h.type != OGS_GTP1_DELETE_PDP_CONTEXT_REQUEST_TYPE)
        return false;

    if (message->h.teid) {
        sess = sgwc_sess_find_by_teid(message->h.teid);
        if (sess)
            return rehome_to_owner(
                    e, sgwc_shard_from_teid(sess->sgw_s5c_teid));
        return false;
    }

    if (message->h.type == OGS_GTP1_CREATE_PDP_CONTEXT_REQUEST_TYPE &&
            message->create_pdp_context_request.imsi.presence &&
            message->create_pdp_context_request.imsi.data &&
            message->create_pdp_context_request.imsi.len > 0) {
        sgwc_ue = sgwc_ue_find_by_imsi(
                message->create_pdp_context_request.imsi.data,
                message->create_pdp_context_request.imsi.len);
        if (sgwc_ue)
            return rehome_to_owner(
                    e, sgwc_shard_from_teid(sgwc_ue->sgw_s11_teid));
        {
            /* New Gn UE: stick to the same IMSI shard S11 would pick */
            char imsi_bcd[OGS_MAX_IMSI_BCD_LEN + 1];
            ogs_buffer_to_bcd(
                    (uint8_t *)message->create_pdp_context_request.imsi.data,
                    message->create_pdp_context_request.imsi.len, imsi_bcd);
            return rehome_to_owner(e, sgwc_shard_from_imsi_bcd(imsi_bcd));
        }
    }

    return false;
}

int sgwc_event_push_to_worker(int wid, sgwc_event_t *e)
{
    ogs_worker_t *worker;
    int rv;

    ogs_assert(e);

    worker = sgwc_worker_by_id(wid);
    if (!worker) {
        ogs_error("sgwc_event_push_to_worker: bad wid %d", wid);
        sgwc_event_free(e);
        return OGS_ERROR;
    }

    rv = ogs_worker_post(worker, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_worker_post(wid=%d) failed [%d]", wid, rv);
        if (e->pkbuf)
            ogs_pkbuf_free(e->pkbuf);
        if (e->pfcp_message)
            ogs_pfcp_message_free(e->pfcp_message);
        e->pkbuf = NULL;
        e->pfcp_message = NULL;
        sgwc_event_free(e);
    }
    return rv;
}

int sgwc_event_fanout_workers(sgwc_event_e id, int admin_force)
{
    int i, rv, fails = 0;

    for (i = 0; i < sgwc_worker_count; i++) {
        sgwc_event_t *e = sgwc_event_new(id);
        ogs_assert(e);
        e->admin_force = admin_force;
        rv = sgwc_event_push_to_worker(i, e);
        if (rv != OGS_OK)
            fails++;
    }

    return fails ? OGS_ERROR : OGS_OK;
}

/*
 * Deliver one event copy to EVERY shard: each worker queue plus the main
 * app queue (main owns shard 0). Used for cross-owner sweeps — peer
 * restart purge, PFCP restoration — where every thread must act on the
 * UEs it owns. The detecting thread also gets its copy through its own
 * queue, so it processes the purge in arrival order with its traffic.
 */
static int sgwc_event_fanout_all_shards(const sgwc_event_t *tmpl)
{
    int i, rv, fails = 0;
    sgwc_event_t *e = NULL;

    for (i = 0; i < sgwc_worker_count; i++) {
        e = sgwc_event_new(tmpl->id);
        ogs_assert(e);
        e->timer_id = tmpl->timer_id;
        e->gnode = tmpl->gnode;
        e->pfcp_node = tmpl->pfcp_node;
        rv = sgwc_event_push_to_worker(i, e);
        if (rv != OGS_OK)
            fails++;
    }

    /* Main thread's copy (shard 0). */
    e = sgwc_event_new(tmpl->id);
    ogs_assert(e);
    e->timer_id = tmpl->timer_id;
    e->gnode = tmpl->gnode;
    e->pfcp_node = tmpl->pfcp_node;
    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("fanout to main queue failed [%d]", rv);
        sgwc_event_free(e);
        fails++;
    } else {
        ogs_pollset_notify(ogs_app()->pollset);
    }

    return fails ? OGS_ERROR : OGS_OK;
}

int sgwc_event_fanout_restart_purge(ogs_gtp_node_t *gnode, int kind)
{
    sgwc_event_t tmpl;

    memset(&tmpl, 0, sizeof(tmpl));
    tmpl.id = SGWC_EVT_PEER_RESTART_PURGE;
    tmpl.timer_id = kind;
    tmpl.gnode = gnode;

    return sgwc_event_fanout_all_shards(&tmpl);
}

int sgwc_event_fanout_sxa_restore(ogs_pfcp_node_t *pfcp_node)
{
    sgwc_event_t tmpl;

    memset(&tmpl, 0, sizeof(tmpl));
    tmpl.id = SGWC_EVT_SXA_RESTORE;
    tmpl.pfcp_node = pfcp_node;

    return sgwc_event_fanout_all_shards(&tmpl);
}

static void sgwc_worker_thread_init(ogs_worker_t *worker)
{
    int rv;

    ogs_assert(worker);

    /*
     * The SGW-C context (config, pools, hashes, UE list) is
     * PROCESS-GLOBAL — initialized exactly once by sgwc_initialize().
     * Workers only bring up their per-thread state: the GTP/PFCP
     * transaction pools (each xact is owned by the thread that created
     * it) and this shard's FSM.
     */
    rv = ogs_gtp_xact_init();
    ogs_assert(rv == OGS_OK);
    rv = ogs_pfcp_xact_init();
    ogs_assert(rv == OGS_OK);

    ogs_fsm_init(&worker_fsm, sgwc_state_initial, sgwc_state_final, 0);

    ogs_info("SGWC shard worker %d ready", worker->id);
}

static void sgwc_worker_thread_fini(ogs_worker_t *worker)
{
    ogs_assert(worker);

    ogs_fsm_fini(&worker_fsm, 0);

    ogs_pfcp_xact_final();
    ogs_gtp_xact_final();
    ogs_tlv_thread_final();

    ogs_info("SGWC shard worker %d stopped", worker->id);
}

static void sgwc_worker_dispatch(ogs_worker_t *worker, void *data)
{
    sgwc_event_t *e = data;

    ogs_assert(worker);
    ogs_assert(e);

    ogs_fsm_dispatch(&worker_fsm, e);
    sgwc_event_free(e);
}

int sgwc_workers_start(void)
{
    int i;

    if (sgwc_worker_configured <= 0)
        return OGS_OK;

    ogs_assert(sgwc_worker_count == 0);
    ogs_assert(!ogs_worker_active());

    /* Opt-in protocol id sharding BEFORE any worker exists. */
    ogs_worker_shards_enable();

    /*
     * The UE/session pools are process-global and already sized from
     * config by sgwc_context_init(); workers allocate from them under
     * sgwc_ctx_lock(). Nothing to split here.
     */
    for (i = 0; i < sgwc_worker_configured; i++) {
        sgwc_workers[i] = ogs_worker_create(i,
                ogs_app()->pool.event,
                ogs_app()->pool.timer,
                64,
                sgwc_worker_dispatch, NULL);
        ogs_assert(sgwc_workers[i]);
        ogs_worker_hooks(sgwc_workers[i],
                sgwc_worker_thread_init, sgwc_worker_thread_fini);
        {
            char tname[16];
            ogs_snprintf(tname, sizeof(tname), "sgwc-w%d", i);
            ogs_worker_set_name(sgwc_workers[i], tname);
        }
        ogs_worker_start(sgwc_workers[i]);
    }

    sgwc_worker_count = sgwc_worker_configured;

    ogs_info("SGWC SMP workers: %d shard(s), shared UE/session pools "
            "(max.ue=%llu sess=%llu)",
            sgwc_worker_count,
            (unsigned long long)ogs_global_conf()->max.ue,
            (unsigned long long)ogs_app()->pool.sess);

    return OGS_OK;
}

void sgwc_workers_stop(void)
{
    int i;

    /* Join threads only: session timers may live on worker timer
     * managers and are deleted by sgwc_context_final() on the main
     * thread. sgwc_workers_final() frees the managers afterwards. */
    for (i = 0; i < sgwc_worker_count; i++)
        ogs_worker_join(sgwc_workers[i]);
}

void sgwc_workers_final(void)
{
    int i;

    for (i = 0; i < sgwc_worker_count; i++) {
        ogs_worker_destroy(sgwc_workers[i]);
        sgwc_workers[i] = NULL;
    }
    sgwc_worker_count = 0;
}
