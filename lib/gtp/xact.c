/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 * Copyright (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * This file is part of Open5GS.
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

#include "ogs-gtp.h"
#include "ogs-app.h"

typedef enum {
    GTP_XACT_UNKNOWN_STAGE,
    GTP_XACT_INITIAL_STAGE,
    GTP_XACT_INTERMEDIATE_STAGE,
    GTP_XACT_FINAL_STAGE,
} ogs_gtp_xact_stage_t;

/*
 * Transaction layer storage:
 *   - Main / IO thread (ogs_worker_self() == NULL): process-global pool.
 *     NF initialize() and nf_main() share it — Open5GS runs those on
 *     different threads, so a TLS-only pool left nf_main with a NULL
 *     id_hash and crashed on the first GTP timer (MME/SMF/SGWC).
 *   - SMP shard workers: per-thread TLS pool. Cross-thread access to a
 *     worker xact is still a bug by construction.
 */
static int global_xact_initialized = 0;
static uint32_t global_xact_id = 0;
/* one named type so xact_pool()'s ternary yields a real pointer type
 * (OGS_POOL declares an anonymous struct per instance otherwise) */
typedef OGS_POOL(xact_pool_t, ogs_gtp_xact_t);

static xact_pool_t global_pool;

static OGS_THREAD_LOCAL int tls_xact_initialized = 0;
static OGS_THREAD_LOCAL uint32_t tls_xact_id = 0;
static OGS_THREAD_LOCAL xact_pool_t tls_pool;

#define xact_pool() (ogs_worker_self() ? &tls_pool : &global_pool)
#define xact_id_var() (ogs_worker_self() ? &tls_xact_id : &global_xact_id)
#define xact_initialized_var() \
    (ogs_worker_self() ? &tls_xact_initialized : &global_xact_initialized)

/* Shard xact lists on the shared gnode: index = owning shard id
 * (0 = main thread, workers = worker->id + 1; single-threaded NFs
 * therefore behave as before, and worker 0 never aliases main). */
#define xact_local_list(gnode)  (&(gnode)->local_list[ogs_worker_self_id()])
#define xact_remote_list(gnode) (&(gnode)->remote_list[ogs_worker_self_id()])

/*
 * Allocate the next xid. When SMP workers are active the space is
 * partitioned: the top OGS_WORKER_ID_BITS of each version's xid range
 * carry the owner's worker id, so the RX router can steer a response
 * to the worker holding the transaction with a shift, and concurrent
 * workers can never allocate colliding sequence numbers.
 */
static uint32_t xact_next_xid(uint32_t min, uint32_t max)
{
    uint32_t *xid = xact_id_var();

    if (ogs_worker_shards_active()) {
        /* max-min+1 is a power of two for both GTPv1 (0..0xffff) and
         * GTPv2 (1..0x800000 => span below is exact) id spaces. */
        uint32_t span = ((max - min + 1) >> OGS_WORKER_ID_BITS);
        uint32_t base = (uint32_t)ogs_worker_self_id() * span;

        *xid = (*xid + 1) % span;
        if (base + *xid < min)
            *xid = min - base;   /* only shard 0 can go below min */

        return base + *xid;
    }

    return OGS_NEXT_ID(*xid, min, max);
}

static ogs_gtp_xact_t *ogs_gtp_xact_remote_create(ogs_gtp_node_t *gnode, uint8_t gtp_version, uint32_t sqn);
static ogs_gtp_xact_stage_t ogs_gtp2_xact_get_stage(uint8_t type, uint32_t xid);
static ogs_gtp_xact_stage_t ogs_gtp1_xact_get_stage(uint8_t type, uint32_t xid);
static int ogs_gtp_xact_delete(ogs_gtp_xact_t *xact);
static int ogs_gtp_xact_update_rx(ogs_gtp_xact_t *xact, uint8_t type);

/*
 * O(1) transaction index on the gnode (perf: the linear list scans in
 * the receive paths were the top CPU consumers on both MME and SGW-C).
 *
 * Key = (org, version, xid). The index keeps the FIRST transaction per
 * key so a hit is what the legacy list scan would have found; duplicate
 * keys (remote xids colliding after SQN>>8, wrap reuse) are left to the
 * fallback scan, and removal only clears the slot if it points at the
 * transaction being deleted — a duplicate then reappears via the scan.
 * Counters give O(1) list lengths (mme_ue_xact_count was 10% of the
 * MME core walking these lists).
 */
static uint64_t xact_index_key(uint8_t org, uint8_t version, uint32_t xid)
{
    return ((uint64_t)org << 40) | ((uint64_t)version << 32) | xid;
}

#define xact_index_hash(gnode) ((gnode)->xact_hash[ogs_worker_self_id()])

static void xact_index_add(ogs_gtp_xact_t *xact)
{
    ogs_hash_t *h = xact_index_hash(xact->gnode);
    int wid = ogs_worker_self_id();

    xact->hash_key =
        xact_index_key(xact->org, xact->gtp_version, xact->xid);
    if (!ogs_hash_get(h, &xact->hash_key, sizeof(xact->hash_key)))
        ogs_hash_set(h, &xact->hash_key, sizeof(xact->hash_key), xact);

    if (xact->org == OGS_GTP_LOCAL_ORIGINATOR)
        xact->gnode->xact_local_count[wid]++;
    else
        xact->gnode->xact_remote_count[wid]++;
}

static void xact_index_del(ogs_gtp_xact_t *xact)
{
    ogs_hash_t *h = xact_index_hash(xact->gnode);
    int wid = ogs_worker_self_id();

    if (ogs_hash_get(h, &xact->hash_key, sizeof(xact->hash_key)) == xact)
        ogs_hash_set(h, &xact->hash_key, sizeof(xact->hash_key), NULL);

    if (xact->org == OGS_GTP_LOCAL_ORIGINATOR)
        xact->gnode->xact_local_count[wid]--;
    else
        xact->gnode->xact_remote_count[wid]--;
}

static ogs_gtp_xact_t *xact_index_get(
        ogs_gtp_node_t *gnode, uint8_t org, uint8_t version, uint32_t xid)
{
    uint64_t key = xact_index_key(org, version, xid);
    return ogs_hash_get(xact_index_hash(gnode), &key, sizeof(key));
}

int ogs_gtp_xact_count(ogs_gtp_node_t *gnode, uint8_t org)
{
    int wid = ogs_worker_self_id();

    ogs_assert(gnode);
    return org == OGS_GTP_LOCAL_ORIGINATOR ?
        gnode->xact_local_count[wid] : gnode->xact_remote_count[wid];
}

static bool ogs_gtp_xact_on_list(ogs_gtp_xact_t *xact)
{
    ogs_gtp_xact_t *iter = NULL;
    ogs_list_t *list = NULL;

    if (!xact || !xact->gnode)
        return false;

    list = xact->org == OGS_GTP_LOCAL_ORIGINATOR ?
        xact_local_list(xact->gnode) : xact_remote_list(xact->gnode);

    ogs_list_for_each(list, iter) {
        if (iter == xact)
            return true;
    }

    return false;
}

static ogs_gtp_xact_t *ogs_gtp_xact_find_by_id_for_timer(ogs_pool_id_t id)
{
    ogs_gtp_xact_t *xact = NULL;

    if (id < OGS_MIN_POOL_ID || id > OGS_MAX_POOL_ID)
        return NULL;

    xact = ogs_gtp_xact_find_by_id(id);
    if (!xact)
        return NULL;

    if (xact->id != id) {
        ogs_warn("Stale GTP Transaction [%d] (pool id mismatch)", (int)id);
        return NULL;
    }

    if (!ogs_gtp_xact_on_list(xact)) {
        ogs_warn("Stale GTP Transaction [%d] (not on peer list)", (int)id);
        return NULL;
    }

    return xact;
}

static void response_timeout(void *data);
static void holding_timeout(void *data);
static void peer_timeout(void *data);

static uint32_t ogs_gtp2_sqn_key(uint32_t sqn)
{
    return be32toh(sqn) & 0xffffff;
}

/*
 * Match an incoming GTPv2 message to a LOCAL outstanding transaction.
 * Use the full 24-bit sequence number, not xid alone: under heavy S5 load
 * many in-flight Create Session transactions can share the same xid window
 * while the low sequence octet differs. Also skip completed transactions
 * (step != expect_step) so a late response does not attach to the wrong sess.
 */
static bool ogs_gtp2_xact_local_match(
        ogs_gtp_xact_t *xact, uint32_t xid, uint32_t rx_key, int expect_step)
{
    if (!xact)
        return false;
    if (xact->gtp_version != 2 || xact->xid != xid)
        return false;
    if (xact->org != OGS_GTP_LOCAL_ORIGINATOR)
        return false;
    if (!xact->sqn || ogs_gtp2_sqn_key(xact->sqn) != rx_key)
        return false;
    if (expect_step >= 0 && xact->step != expect_step)
        return false;
    return true;
}

static ogs_gtp_xact_t *ogs_gtp2_xact_find_local(
        ogs_list_t *list, uint32_t xid, uint32_t sqn, int expect_step)
{
    ogs_gtp_xact_t *xact = NULL;
    uint32_t rx_key = ogs_gtp2_sqn_key(sqn);

    ogs_list_for_each(list, xact) {
        if (xact->gtp_version != 2 || xact->xid != xid)
            continue;
        if (xact->org != OGS_GTP_LOCAL_ORIGINATOR)
            continue;
        if (!xact->sqn || ogs_gtp2_sqn_key(xact->sqn) != rx_key)
            continue;
        if (expect_step >= 0 && xact->step != expect_step)
            continue;
        return xact;
    }

    return NULL;
}

static bool ogs_gtp2_xact_is_local_reply(
        ogs_gtp_xact_stage_t stage, uint32_t xid)
{
    if (stage == GTP_XACT_INTERMEDIATE_STAGE)
        return true;

    if (stage == GTP_XACT_FINAL_STAGE && !(xid & OGS_GTP_CMD_XACT_ID))
        return true;

    return false;
}

int ogs_gtp2_rx_reply_shard(const void *data, size_t len)
{
    const ogs_gtp2_header_t *h = data;
    uint32_t sqn, xid;
    ogs_gtp_xact_stage_t stage;

    if (!ogs_worker_shards_active())
        return -1;
    if (!data || len < 8)
        return -1;
    if (h->version != 2)
        return -1;

    sqn = h->teid_presence ? h->sqn : h->sqn_only;
    xid = OGS_GTP2_SQN_TO_XID(sqn);
    stage = ogs_gtp2_xact_get_stage(h->type, xid);

    if (!ogs_gtp2_xact_is_local_reply(stage, xid))
        return -1;

    /* xact_next_xid(): GTPv2 xid space 1..0x800000 split into
     * 2^OGS_WORKER_ID_BITS per-shard windows => shard = xid >> 20 */
    return (int)((xid >> (23 - OGS_WORKER_ID_BITS)) &
            ((1u << OGS_WORKER_ID_BITS) - 1));
}

static void ogs_gtp_xact_log_state(
        const ogs_gtp_xact_t *xact, uint8_t type, const char *why)
{
    char buf[OGS_ADDRSTRLEN];

    if (!xact) {
        ogs_error("%s (no transaction) type=%u", why, type);
        return;
    }

    if (why && (strstr(why, "invalid step") || strstr(why, "orphan"))) {
        ogs_warn("%s: gtpv=%u xid=%u step=%d org=%u type=%u peer=[%s]:%d "
                "local_teid=0x%x enb_ue_id=%d",
                why, xact->gtp_version, xact->xid, xact->step, xact->org, type,
                xact->gnode ? OGS_ADDR(&xact->gnode->addr, buf) : "?",
                xact->gnode ? OGS_PORT(&xact->gnode->addr) : 0,
                xact->local_teid, xact->enb_ue_id);
        return;
    }

    if (xact->gnode) {
        ogs_error("%s: gtpv=%u xid=%u step=%d org=%u type=%u peer=[%s]:%d "
                "local_teid=0x%x enb_ue_id=%d",
                why, xact->gtp_version, xact->xid, xact->step, xact->org, type,
                OGS_ADDR(&xact->gnode->addr, buf), OGS_PORT(&xact->gnode->addr),
                xact->local_teid, xact->enb_ue_id);
    } else {
        ogs_error("%s: gtpv=%u xid=%u step=%d org=%u type=%u local_teid=0x%x "
                "enb_ue_id=%d",
                why, xact->gtp_version, xact->xid, xact->step, xact->org, type,
                xact->local_teid, xact->enb_ue_id);
    }
}

int ogs_gtp_xact_init(void)
{
    int *ready = xact_initialized_var();
    uint32_t *xid = xact_id_var();

    ogs_assert(*ready == 0);

    ogs_pool_init(xact_pool(), ogs_app()->pool.xact);

    /*
     * Start the sequence number space at a random point instead of 0 so a
     * restarted daemon does not immediately reuse the sequence numbers its
     * previous incarnation still has in flight; late/retransmitted responses
     * from peers would otherwise be matched to new, unrelated transactions.
     * Bounded by the GTPv1 range (the counter is shared with GTPv2 and wraps
     * within each version's own range on allocation).
     */
    *xid = ogs_random32() % (OGS_GTP1_MAX_XACT_ID + 1);

    *ready = 1;

    return OGS_OK;
}

void ogs_gtp_xact_final(void)
{
    int *ready = xact_initialized_var();

    ogs_assert(*ready == 1);

    ogs_pool_final(xact_pool());

    *ready = 0;
}

ogs_gtp_xact_t *ogs_gtp1_xact_local_create(ogs_gtp_node_t *gnode,
        ogs_gtp1_header_t *hdesc, ogs_pkbuf_t *pkbuf,
        void (*cb)(ogs_gtp_xact_t *xact, void *data), void *data)
{
    int rv;
    char buf[OGS_ADDRSTRLEN];
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(gnode);
    ogs_assert(hdesc);

    ogs_pool_id_calloc(xact_pool(), &xact);
    if (!xact) {
        ogs_error("Maximum number of xact[%lld] reached",
                    (long long)ogs_app()->pool.xact);
        return NULL;
    }
    xact->index = ogs_pool_index(xact_pool(), xact);

    xact->gtp_version = 1;
    xact->org = OGS_GTP_LOCAL_ORIGINATOR;
    xact->xid = xact_next_xid(
            OGS_GTP1_MIN_XACT_ID, OGS_GTP1_MAX_XACT_ID);
    xact->gnode = gnode;
    xact->cb = cb;
    xact->data = data;

    /* 7.6 "The T3-RESPONSE timer shall be started when a signalling request
     * message (for which a response has been defined) is sent." */
    if (hdesc->type != OGS_GTP1_RAN_INFORMATION_RELAY_TYPE) {
        xact->tm_response = ogs_timer_add(
                ogs_worker_timer_mgr(ogs_app()->timer_mgr), response_timeout,
                OGS_UINT_TO_POINTER(xact->id));
        if (!xact->tm_response) {
            ogs_error("Maximum number of xact->tm_response[%lld] reached",
                        (long long)ogs_app()->pool.timer);
            ogs_gtp_xact_delete(xact);
            return NULL;
        }
        xact->response_rcount =
            ogs_local_conf()->time.message.gtp.n3_response_rcount;
    }

    xact->tm_holding = ogs_timer_add(
            ogs_worker_timer_mgr(ogs_app()->timer_mgr), holding_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_holding) {
        ogs_error("Maximum number of xact->tm_holding[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_gtp_xact_delete(xact);
        return NULL;
    }
    xact->holding_rcount = ogs_local_conf()->time.message.gtp.n3_holding_rcount;

    ogs_list_add(xact_local_list(xact->gnode), xact);
    xact_index_add(xact);

    rv = ogs_gtp1_xact_update_tx(xact, hdesc, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_update_tx(rv=%d) failed", (int)rv);
        ogs_gtp_xact_delete(xact);
        return NULL;
    }

    ogs_debug("[%d] LOCAL Create  peer [%s]:%d",
            xact->xid,
            OGS_ADDR(&gnode->addr, buf),
            OGS_PORT(&gnode->addr));

    return xact;
}

ogs_gtp_xact_t *ogs_gtp_xact_local_create(ogs_gtp_node_t *gnode,
        ogs_gtp2_header_t *hdesc, ogs_pkbuf_t *pkbuf,
        void (*cb)(ogs_gtp_xact_t *xact, void *data), void *data)
{
    int rv;
    char buf[OGS_ADDRSTRLEN];
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(gnode);
    ogs_assert(hdesc);

    ogs_pool_id_calloc(xact_pool(), &xact);
    if (!xact) {
        ogs_error("Maximum number of xact[%lld] reached",
                    (long long)ogs_app()->pool.xact);
        return NULL;
    }
    xact->index = ogs_pool_index(xact_pool(), xact);

    xact->gtp_version = 2;
    xact->org = OGS_GTP_LOCAL_ORIGINATOR;
    xact->xid = xact_next_xid(
            OGS_GTP_MIN_XACT_ID, OGS_GTP_CMD_XACT_ID);
    if (hdesc->type == OGS_GTP2_MODIFY_BEARER_COMMAND_TYPE ||
        hdesc->type == OGS_GTP2_DELETE_BEARER_COMMAND_TYPE ||
        hdesc->type == OGS_GTP2_BEARER_RESOURCE_COMMAND_TYPE) {
        xact->xid |= OGS_GTP_CMD_XACT_ID;
    }
    xact->gnode = gnode;
    xact->cb = cb;
    xact->data = data;

    xact->tm_response = ogs_timer_add(
            ogs_worker_timer_mgr(ogs_app()->timer_mgr), response_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_response) {
        ogs_error("Maximum number of xact->tm_response[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_gtp_xact_delete(xact);
        return NULL;
    }
    xact->response_rcount =
        ogs_local_conf()->time.message.gtp.n3_response_rcount,

    xact->tm_holding = ogs_timer_add(
            ogs_worker_timer_mgr(ogs_app()->timer_mgr), holding_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_holding) {
        ogs_error("Maximum number of xact->tm_holding[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_gtp_xact_delete(xact);
        return NULL;
    }
    xact->holding_rcount = ogs_local_conf()->time.message.gtp.n3_holding_rcount,

    xact->tm_peer = ogs_timer_add(ogs_worker_timer_mgr(ogs_app()->timer_mgr), peer_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_peer) {
        ogs_error("Maximum number of xact->tm_peer[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_gtp_xact_delete(xact);
        return NULL;
    }

    ogs_list_add(xact_local_list(xact->gnode), xact);
    xact_index_add(xact);

    rv = ogs_gtp_xact_update_tx(xact, hdesc, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_update_tx(rv=%d) failed", (int)rv);
        ogs_gtp_xact_delete(xact);
        return NULL;
    }

    ogs_debug("[%d] LOCAL Create  peer [%s]:%d",
            xact->xid,
            OGS_ADDR(&gnode->addr, buf),
            OGS_PORT(&gnode->addr));

    return xact;
}

static ogs_gtp_xact_t *ogs_gtp_xact_remote_create(ogs_gtp_node_t *gnode, uint8_t gtp_version, uint32_t sqn)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(gnode);

    ogs_pool_id_calloc(xact_pool(), &xact);
    if (!xact) {
        ogs_error("Maximum number of xact[%lld] reached",
                    (long long)ogs_app()->pool.xact);
        return NULL;
    }
    xact->index = ogs_pool_index(xact_pool(), xact);

    xact->gtp_version = gtp_version;
    xact->org = OGS_GTP_REMOTE_ORIGINATOR;
    xact->xid = (gtp_version == 1) ?
            OGS_GTP1_SQN_TO_XID(sqn) : OGS_GTP2_SQN_TO_XID(sqn);
    xact->gnode = gnode;

    xact->tm_response = ogs_timer_add(
            ogs_worker_timer_mgr(ogs_app()->timer_mgr), response_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_response) {
        ogs_error("Maximum number of xact->tm_response[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_gtp_xact_delete(xact);
        return NULL;
    }
    xact->response_rcount =
        ogs_local_conf()->time.message.gtp.n3_response_rcount,

    xact->tm_holding = ogs_timer_add(
            ogs_worker_timer_mgr(ogs_app()->timer_mgr), holding_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_holding) {
        ogs_error("Maximum number of xact->tm_holding[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_gtp_xact_delete(xact);
        return NULL;
    }
    xact->holding_rcount = ogs_local_conf()->time.message.gtp.n3_holding_rcount,

    xact->tm_peer = ogs_timer_add(ogs_worker_timer_mgr(ogs_app()->timer_mgr), peer_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_peer) {
        ogs_error("Maximum number of xact->tm_peer[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_gtp_xact_delete(xact);
        return NULL;
    }

    ogs_list_add(xact_remote_list(xact->gnode), xact);
    xact_index_add(xact);

    ogs_debug("[%d] REMOTE Create  peer [%s]:%d",
            xact->xid,
            OGS_ADDR(&gnode->addr, buf),
            OGS_PORT(&gnode->addr));

    return xact;
}

ogs_gtp_xact_t *ogs_gtp_xact_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(xact_pool(), id);
}

void ogs_gtp_xact_delete_all(ogs_gtp_node_t *gnode)
{
    ogs_gtp_xact_t *xact = NULL, *next_xact = NULL;

    ogs_list_for_each_safe(xact_local_list(gnode), next_xact, xact)
        ogs_gtp_xact_delete(xact);
    ogs_list_for_each_safe(xact_remote_list(gnode), next_xact, xact)
        ogs_gtp_xact_delete(xact);
}

int ogs_gtp1_xact_update_tx(ogs_gtp_xact_t *xact,
        ogs_gtp1_header_t *hdesc, ogs_pkbuf_t *pkbuf)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_gtp_xact_stage_t stage;
    ogs_gtp1_header_t *h = NULL;
    int gtp_hlen = 0;

    ogs_assert(xact);
    ogs_assert(xact->gnode);
    ogs_assert(hdesc);
    ogs_assert(pkbuf);

    ogs_debug("[%d] %s UPD TX-%d  peer [%s]:%d",
            xact->xid,
            xact->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            hdesc->type,
            OGS_ADDR(&xact->gnode->addr, buf),
            OGS_PORT(&xact->gnode->addr));

    stage = ogs_gtp1_xact_get_stage(hdesc->type, xact->xid);
    if (xact->org == OGS_GTP_LOCAL_ORIGINATOR) {
        switch (stage) {
        case GTP_XACT_INITIAL_STAGE:
            if (xact->step != 0) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_pkbuf_free(pkbuf);
                return OGS_ERROR;
            }
            break;

        case GTP_XACT_INTERMEDIATE_STAGE:
            ogs_expect(0);
            ogs_pkbuf_free(pkbuf);
            return OGS_ERROR;

        case GTP_XACT_FINAL_STAGE:
            if (xact->step != 2 && xact->step != 3) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_pkbuf_free(pkbuf);
                return OGS_ERROR;
            }
            break;

        default:
            ogs_assert_if_reached();
            break;
        }
    } else if (xact->org == OGS_GTP_REMOTE_ORIGINATOR) {
        switch (stage) {
        case GTP_XACT_INITIAL_STAGE:
            ogs_expect(0);
            ogs_pkbuf_free(pkbuf);
            return OGS_ERROR;

        case GTP_XACT_INTERMEDIATE_STAGE:
        case GTP_XACT_FINAL_STAGE:
            if (xact->step != 1) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_pkbuf_free(pkbuf);
                return OGS_ERROR;
            }
            break;

        default:
            ogs_error("invalid stage[%d]", stage);
            ogs_pkbuf_free(pkbuf);
            return OGS_ERROR;
        }
    } else {
        ogs_error("invalid org[%d]", xact->org);
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    gtp_hlen = OGS_GTPV1C_HEADER_LEN;


    ogs_pkbuf_push(pkbuf, gtp_hlen);
    h = (ogs_gtp1_header_t *)pkbuf->data;
    memset(h, 0, gtp_hlen);

    h->version = 1;
    h->type = hdesc->type;
    h->pt = 1; /* GTP */
    h->teid = htobe32(hdesc->teid);

    h->s = 1;
    h->sqn = OGS_GTP1_XID_TO_SQN(xact->xid);
    h->length = htobe16(pkbuf->len - 8);

    /* Save Message type and packet of this step */
    xact->seq[xact->step].type = h->type;
    xact->seq[xact->step].pkbuf = pkbuf;

    /* Step */
    xact->step++;

    return OGS_OK;
}

int ogs_gtp_xact_update_tx(ogs_gtp_xact_t *xact,
        ogs_gtp2_header_t *hdesc, ogs_pkbuf_t *pkbuf)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_gtp_xact_stage_t stage;
    ogs_gtp2_header_t *h = NULL;
    int gtp_hlen = 0;

    ogs_assert(xact);
    ogs_assert(xact->gnode);
    ogs_assert(hdesc);
    ogs_assert(pkbuf);

    ogs_debug("[%d] %s UPD TX-%d  peer [%s]:%d",
            xact->xid,
            xact->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            hdesc->type,
            OGS_ADDR(&xact->gnode->addr, buf),
            OGS_PORT(&xact->gnode->addr));

    stage = ogs_gtp2_xact_get_stage(hdesc->type, xact->xid);
    if (xact->org == OGS_GTP_LOCAL_ORIGINATOR) {
        switch (stage) {
        case GTP_XACT_INITIAL_STAGE:
            if (xact->step != 0) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_pkbuf_free(pkbuf);
                return OGS_ERROR;
            }
            break;

        case GTP_XACT_INTERMEDIATE_STAGE:
            ogs_expect(0);
            ogs_pkbuf_free(pkbuf);
            return OGS_ERROR;

        case GTP_XACT_FINAL_STAGE:
            if (xact->step != 2) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_pkbuf_free(pkbuf);
                return OGS_ERROR;
            }
            break;

        default:
            ogs_assert_if_reached();
            break;
        }
    } else if (xact->org == OGS_GTP_REMOTE_ORIGINATOR) {
        switch (stage) {
        case GTP_XACT_INITIAL_STAGE:
            ogs_expect(0);
            ogs_pkbuf_free(pkbuf);
            return OGS_ERROR;

        case GTP_XACT_INTERMEDIATE_STAGE:
        case GTP_XACT_FINAL_STAGE:
            if (xact->step != 1) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_pkbuf_free(pkbuf);
                return OGS_ERROR;
            }
            break;

        default:
            ogs_error("invalid stage[%d]", stage);
            ogs_pkbuf_free(pkbuf);
            return OGS_ERROR;
        }
    } else {
        ogs_error("invalid org[%d]", xact->org);
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    if (hdesc->type > OGS_GTP2_VERSION_NOT_SUPPORTED_INDICATION_TYPE) {
        gtp_hlen = OGS_GTPV2C_HEADER_LEN;
    } else {
        gtp_hlen = OGS_GTPV2C_HEADER_LEN - OGS_GTP2_TEID_LEN;
    }

    ogs_pkbuf_push(pkbuf, gtp_hlen);
    h = (ogs_gtp2_header_t *)pkbuf->data;
    memset(h, 0, gtp_hlen);

    h->version = 2;
    h->type = hdesc->type;

    if (hdesc->type > OGS_GTP2_VERSION_NOT_SUPPORTED_INDICATION_TYPE) {
        h->teid_presence = 1;
        h->teid = htobe32(hdesc->teid);
        h->sqn = OGS_GTP2_XID_TO_SQN(xact->xid);
        xact->sqn = h->sqn;
    } else {
        h->teid_presence = 0;
        h->sqn_only = OGS_GTP2_XID_TO_SQN(xact->xid);
        xact->sqn = h->sqn_only;
    }
    h->length = htobe16(pkbuf->len - 4);

    /* Save Message type and packet of this step */
    xact->seq[xact->step].type = h->type;
    xact->seq[xact->step].pkbuf = pkbuf;

    /* Step */
    xact->step++;

    return OGS_OK;
}

static int ogs_gtp_xact_update_rx(ogs_gtp_xact_t *xact, uint8_t type)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_gtp_xact_stage_t stage;

    ogs_debug("[%d] %s UPD RX-%d  peer [%s]:%d",
            xact->xid,
            xact->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            type,
            OGS_ADDR(&xact->gnode->addr, buf),
            OGS_PORT(&xact->gnode->addr));

    if (xact->gtp_version == 1)
        stage = ogs_gtp1_xact_get_stage(type, xact->xid);
    else
        stage = ogs_gtp2_xact_get_stage(type, xact->xid);

    if (xact->org == OGS_GTP_LOCAL_ORIGINATOR) {
        switch (stage) {
        case GTP_XACT_INITIAL_STAGE:
            ogs_expect(0);
            return OGS_ERROR;

        case GTP_XACT_INTERMEDIATE_STAGE:
            if (xact->seq[1].type == type) {
                ogs_pkbuf_t *pkbuf = NULL;

                if (xact->step != 2 && xact->step != 3) {
                    ogs_gtp_xact_log_state(xact, type, "invalid step");
                    /* pkbuf is still NULL here (assigned from
                     * xact->seq[2].pkbuf below); nothing to free. */
                    return OGS_ERROR;
                }

                pkbuf = xact->seq[2].pkbuf;
                if (pkbuf) {
                    if (xact->tm_holding)
                        ogs_timer_start(xact->tm_holding,
                                ogs_local_conf()->time.message.
                                    gtp.t3_holding_duration);

                    ogs_warn("[%d] %s Request Duplicated. Retransmit!"
                            " for step %d type %d peer [%s]:%d",
                            xact->xid,
                            xact->org == OGS_GTP_LOCAL_ORIGINATOR ?
                                "LOCAL " : "REMOTE",
                            xact->step, type,
                            OGS_ADDR(&xact->gnode->addr,
                                buf),
                            OGS_PORT(&xact->gnode->addr));
                    ogs_expect(OGS_OK == ogs_gtp_sendto(xact->gnode, pkbuf));
                } else {
                    ogs_warn("[%d] %s Request Duplicated. Discard!"
                            " for step %d type %d peer [%s]:%d",
                            xact->xid,
                            xact->org == OGS_GTP_LOCAL_ORIGINATOR ?
                                "LOCAL " : "REMOTE",
                            xact->step, type,
                            OGS_ADDR(&xact->gnode->addr,
                                buf),
                            OGS_PORT(&xact->gnode->addr));
                }

                return OGS_RETRY;
            }

            if (xact->step != 1) {
                ogs_warn("invalid step[%d]", xact->step);
                return OGS_ERROR;
            }

            if (xact->tm_holding)
                ogs_timer_start(xact->tm_holding,
                        ogs_local_conf()->time.message.gtp.t3_holding_duration);

            break;

        case GTP_XACT_FINAL_STAGE:
            if (xact->step != 1) {
                ogs_gtp_xact_log_state(xact, type, "invalid step");
                return OGS_ERROR;
            }
            break;

        default:
            ogs_error("invalid stage[%d]", stage);
            return OGS_ERROR;
        }
    } else if (xact->org == OGS_GTP_REMOTE_ORIGINATOR) {
        switch (stage) {
        case GTP_XACT_INITIAL_STAGE:
            if (xact->seq[0].type == type) {
                ogs_pkbuf_t *pkbuf = NULL;

                if (xact->step != 1 && xact->step != 2) {
                    ogs_gtp_xact_log_state(xact, type, "invalid step");
                    return OGS_ERROR;
                }

                pkbuf = xact->seq[1].pkbuf;
                if (pkbuf) {
                    if (xact->tm_holding)
                        ogs_timer_start(xact->tm_holding,
                                ogs_local_conf()->time.message.
                                    gtp.t3_holding_duration);

                    ogs_warn("[%d] %s Request Duplicated. Retransmit!"
                            " for step %d type %d peer [%s]:%d",
                            xact->xid,
                            xact->org == OGS_GTP_LOCAL_ORIGINATOR ?
                                "LOCAL " : "REMOTE",
                            xact->step, type,
                            OGS_ADDR(&xact->gnode->addr,
                                buf),
                            OGS_PORT(&xact->gnode->addr));
                    ogs_expect(OGS_OK == ogs_gtp_sendto(xact->gnode, pkbuf));
                } else {
                    ogs_warn("[%d] %s Request Duplicated. Discard!"
                            " for step %d type %d peer [%s]:%d",
                            xact->xid,
                            xact->org == OGS_GTP_LOCAL_ORIGINATOR ?
                                "LOCAL " : "REMOTE",
                            xact->step, type,
                            OGS_ADDR(&xact->gnode->addr,
                                buf),
                            OGS_PORT(&xact->gnode->addr));
                }

                return OGS_RETRY;
            }

            if (xact->step != 0) {
                ogs_gtp_xact_log_state(xact, type, "invalid step");
                return OGS_ERROR;
            }
            if (xact->tm_holding)
                ogs_timer_start(xact->tm_holding,
                        ogs_local_conf()->time.message.gtp.t3_holding_duration);

            break;

        case GTP_XACT_INTERMEDIATE_STAGE:
            ogs_gtp_xact_log_state(xact, type,
                    "orphan intermediate response for remote-origin xact");
            return OGS_ERROR;

        case GTP_XACT_FINAL_STAGE:
            if (xact->step != 2) {
                ogs_gtp_xact_log_state(xact, type, "invalid step");
                return OGS_ERROR;
            }

            /* continue */
            break;

        default:
            ogs_error("invalid stage[%d]", stage);
            return OGS_ERROR;
        }
    } else {
        ogs_error("invalid org[%d]", xact->org);
        return OGS_ERROR;
    }

    if (xact->tm_response)
        ogs_timer_stop(xact->tm_response);

    /* Save Message type of this step */
    xact->seq[xact->step].type = type;

    /* Step */
    xact->step++;

    return OGS_OK;
}


int ogs_gtp_xact_commit(ogs_gtp_xact_t *xact)
{
    char buf[OGS_ADDRSTRLEN];

    uint8_t type;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_stage_t stage;

    ogs_assert(xact);
    ogs_assert(xact->gnode);

    ogs_debug("[%d] %s Commit  peer [%s]:%d",
            xact->xid,
            xact->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            OGS_ADDR(&xact->gnode->addr, buf),
            OGS_PORT(&xact->gnode->addr));

    type = xact->seq[xact->step-1].type;
    if (xact->gtp_version == 1)
        stage = ogs_gtp1_xact_get_stage(type, xact->xid);
    else
        stage = ogs_gtp2_xact_get_stage(type, xact->xid);

    if (xact->org == OGS_GTP_LOCAL_ORIGINATOR) {
        switch (stage) {
        case GTP_XACT_INITIAL_STAGE:
            if (xact->step != 1) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_gtp_xact_delete(xact);
                return OGS_ERROR;
            }

            if (xact->tm_response)
                ogs_timer_start(xact->tm_response,
                        ogs_local_conf()->time.message.gtp.
                        t3_response_duration);

            break;

        case GTP_XACT_INTERMEDIATE_STAGE:
            if (xact->step != 2) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_gtp_xact_delete(xact);
                return OGS_ERROR;
            }
            return OGS_OK;

        case GTP_XACT_FINAL_STAGE:
            if (xact->step != 2 && xact->step != 3) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_gtp_xact_delete(xact);
                return OGS_ERROR;
            }
            if (xact->step == 2) {
                ogs_gtp_xact_delete(xact);
                return OGS_OK;
            }

            break;

        default:
            ogs_error("invalid stage[%d]", stage);
            ogs_gtp_xact_delete(xact);
            return OGS_ERROR;
        }
    } else if (xact->org == OGS_GTP_REMOTE_ORIGINATOR) {
        switch (stage) {
        case GTP_XACT_INITIAL_STAGE:
            ogs_expect(0);
            ogs_gtp_xact_delete(xact);
            return OGS_ERROR;

        case GTP_XACT_INTERMEDIATE_STAGE:
            if (xact->step != 2) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_gtp_xact_delete(xact);
                return OGS_ERROR;
            }
            if (xact->tm_response)
                ogs_timer_start(xact->tm_response,
                        ogs_local_conf()->time.message.gtp.
                        t3_response_duration);

            break;

        case GTP_XACT_FINAL_STAGE:
            if (xact->step != 2 && xact->step != 3) {
                ogs_warn("invalid step[%d]", xact->step);
                ogs_gtp_xact_delete(xact);
                return OGS_ERROR;
            }
            if (xact->step == 3) {
                ogs_gtp_xact_delete(xact);
                return OGS_OK;
            }

            break;

        default:
            ogs_error("invalid stage[%d]", stage);
            ogs_gtp_xact_delete(xact);
            return OGS_ERROR;
        }
    } else {
        ogs_error("invalid org[%d]", xact->org);
        ogs_gtp_xact_delete(xact);
        return OGS_ERROR;
    }

    pkbuf = xact->seq[xact->step-1].pkbuf;
    ogs_assert(pkbuf);

    if (ogs_gtp_sendto(xact->gnode, pkbuf) != OGS_OK) {
        ogs_error("[%d] ogs_gtp_sendto() failed peer [%s]:%d",
                xact->xid,
                OGS_ADDR(&xact->gnode->addr, buf),
                OGS_PORT(&xact->gnode->addr));
        ogs_gtp_xact_delete(xact);
        return OGS_ERROR;
    }

    return OGS_OK;
}

static void response_timeout(void *data)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_pool_id_t xact_id = OGS_INVALID_POOL_ID;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(data);
    xact_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(xact_id >= OGS_MIN_POOL_ID && xact_id <= OGS_MAX_POOL_ID);

    xact = ogs_gtp_xact_find_by_id_for_timer(xact_id);
    if (!xact) {
        ogs_warn("GTP Transaction has already been removed [%d]", xact_id);
        return;
    }
    ogs_assert(xact->gnode);

    ogs_debug("[%d] %s Response Timeout "
            "for step %d type %d peer [%s]:%d",
            xact->xid,
            xact->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            xact->step, xact->seq[xact->step-1].type,
            OGS_ADDR(&xact->gnode->addr, buf),
            OGS_PORT(&xact->gnode->addr));

    if (--xact->response_rcount > 0) {
        ogs_pkbuf_t *pkbuf = NULL;

        if (xact->tm_response)
            ogs_timer_start(xact->tm_response,
                    ogs_local_conf()->time.message.gtp.t3_response_duration);

        pkbuf = xact->seq[xact->step-1].pkbuf;
        ogs_assert(pkbuf);

        ogs_expect(OGS_OK == ogs_gtp_sendto(xact->gnode, pkbuf));
    } else {
        ogs_debug("[%d] %s No Reponse. Give up! "
                "for step %d type %d peer [%s]:%d",
                xact->xid,
                xact->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
                xact->step, xact->seq[xact->step-1].type,
                OGS_ADDR(&xact->gnode->addr, buf),
                OGS_PORT(&xact->gnode->addr));

        if (xact->cb)
            xact->cb(xact, xact->data);

        ogs_gtp_xact_delete(xact);
    }
}

static void holding_timeout(void *data)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_pool_id_t xact_id = OGS_INVALID_POOL_ID;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(data);
    xact_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(xact_id >= OGS_MIN_POOL_ID && xact_id <= OGS_MAX_POOL_ID);

    xact = ogs_gtp_xact_find_by_id_for_timer(xact_id);
    if (!xact) {
        ogs_warn("GTP Transaction has already been removed [%d]", xact_id);
        return;
    }
    ogs_assert(xact->gnode);

    ogs_debug("[%d] %s Holding Timeout "
            "for step %d type %d peer [%s]:%d",
            xact->xid,
            xact->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            xact->step, xact->seq[xact->step-1].type,
            OGS_ADDR(&xact->gnode->addr, buf),
            OGS_PORT(&xact->gnode->addr));

    if (--xact->holding_rcount > 0) {
        if (xact->tm_holding)
            ogs_timer_start(xact->tm_holding,
                    ogs_local_conf()->time.message.gtp.t3_holding_duration);
    } else {
        ogs_debug("[%d] %s Delete Transaction "
                "for step %d type %d peer [%s]:%d",
                xact->xid,
                xact->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
                xact->step, xact->seq[xact->step-1].type,
                OGS_ADDR(&xact->gnode->addr, buf),
                OGS_PORT(&xact->gnode->addr));
        ogs_gtp_xact_delete(xact);
    }
}

static void peer_timeout(void *data)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_pool_id_t xact_id = OGS_INVALID_POOL_ID;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(data);
    xact_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(xact_id >= OGS_MIN_POOL_ID && xact_id <= OGS_MAX_POOL_ID);

    xact = ogs_gtp_xact_find_by_id_for_timer(xact_id);
    if (!xact) {
        ogs_warn("GTP Transaction has already been removed [%d]", xact_id);
        return;
    }
    ogs_assert(xact->gnode);

    ogs_error("[%d] %s Peer Timeout "
            "for step %d type %d peer [%s]:%d",
            xact->xid,
            xact->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            xact->step, xact->seq[xact->step-1].type,
            OGS_ADDR(&xact->gnode->addr, buf),
            OGS_PORT(&xact->gnode->addr));

    if (xact->peer_cb)
        xact->peer_cb(xact, xact->peer_data);
}

int ogs_gtp1_xact_receive(
        ogs_gtp_node_t *gnode, ogs_gtp1_header_t *h, ogs_gtp_xact_t **xact)
{
    int rv;
    char buf[OGS_ADDRSTRLEN];

    uint8_t type;
    uint32_t sqn, xid;
    ogs_gtp_xact_stage_t stage;
    ogs_list_t *list = NULL;
    ogs_gtp_xact_t *new = NULL;

    ogs_assert(gnode);
    ogs_assert(h);

    type = h->type;

    if (!h->s) {
        ogs_error("ogs_gtp_xact_update_rx() failed, pkt has no SQN");
        return OGS_ERROR;
    }
    sqn = h->sqn;

    xid = OGS_GTP1_SQN_TO_XID(sqn);
    stage = ogs_gtp1_xact_get_stage(type, xid);

    switch (stage) {
    case GTP_XACT_INITIAL_STAGE:
        list = xact_remote_list(gnode);
        break;
    case GTP_XACT_INTERMEDIATE_STAGE:
        list = xact_local_list(gnode);
        break;
    case GTP_XACT_FINAL_STAGE:
        /* For types which are replies to replies, the xact is never locally
         * created during transmit, but actually during rx of the initial req, hence
         * it is never placed in the local_list, but in the remote_list. */
        if (type == OGS_GTP1_SGSN_CONTEXT_ACKNOWLEDGE_TYPE)
            list = xact_remote_list(gnode);
        else
            list = xact_local_list(gnode);
        break;
    default:
        ogs_error("[%d] Unexpected type %u from GTPv1 peer [%s]:%d",
                xid, type, OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));
        return OGS_ERROR;
    }

    ogs_assert(list);

    new = xact_index_get(gnode,
            list == xact_local_list(gnode) ?
                OGS_GTP_LOCAL_ORIGINATOR : OGS_GTP_REMOTE_ORIGINATOR,
            1, xid);
    if (new && (new->gtp_version != 1 || new->xid != xid))
        new = NULL;

    if (!new)
    ogs_list_for_each(list, new) {
        if (new->gtp_version == 1 && new->xid == xid) {
            ogs_debug("[%d] %s Find GTPv%u peer [%s]:%d",
                    new->xid,
                    new->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
                    new->gtp_version,
                    OGS_ADDR(&gnode->addr, buf),
                    OGS_PORT(&gnode->addr));
            break;
        }
    }

    if (!new) {
        /*
         * SGSN Context Response (INTERMEDIATE_STAGE) must match a LOCAL xact
         * created when we sent SGSN Context Request. When the original xact
         * already timed out or was committed, a late/duplicate response must
         * not spawn a REMOTE xact: ogs_gtp_xact_update_rx() rejects
         * REMOTE+INTERMEDIATE and used to log spurious ERROR noise.
         */
        if (stage == GTP_XACT_INTERMEDIATE_STAGE) {
            ogs_debug("[%d] Late or duplicate GTPv1 response (type %u) from "
                    "peer [%s]:%d - no matching local xact, discarded",
                    xid, type, OGS_ADDR(&gnode->addr, buf),
                    OGS_PORT(&gnode->addr));
            return OGS_ERROR;
        }

        ogs_debug("[%d] Cannot find xact type %u from GTPv1 peer [%s]:%d",
                  xid, type, OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));
        new = ogs_gtp_xact_remote_create(gnode, 1, sqn);
    }
    ogs_assert(new);

    ogs_debug("[%d] %s Receive peer [%s]:%d",
            new->xid,
            new->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            OGS_ADDR(&gnode->addr, buf),
            OGS_PORT(&gnode->addr));

    rv = ogs_gtp_xact_update_rx(new, type);
    if (rv == OGS_ERROR) {
        ogs_gtp_xact_log_state(new, type, "ogs_gtp_xact_update_rx() failed");
        ogs_gtp_xact_delete(new);
        return rv;
    } else if (rv == OGS_RETRY) {
        return rv;
    }

    *xact = new;
    return rv;
}

int ogs_gtp_xact_receive(
        ogs_gtp_node_t *gnode, ogs_gtp2_header_t *h, ogs_gtp_xact_t **xact)
{
    int rv;
    char buf[OGS_ADDRSTRLEN];

    uint8_t type;
    uint32_t sqn, xid;
    ogs_gtp_xact_stage_t stage;
    ogs_list_t *list = NULL;
    ogs_gtp_xact_t *new = NULL;

    ogs_assert(gnode);
    ogs_assert(h);

    type = h->type;

    if (h->teid_presence) sqn = h->sqn;
    else sqn = h->sqn_only;

    xid = OGS_GTP2_SQN_TO_XID(sqn);
    stage = ogs_gtp2_xact_get_stage(type, xid);

    switch (stage) {
    case GTP_XACT_INITIAL_STAGE:
        list = xact_remote_list(gnode);
        break;
    case GTP_XACT_INTERMEDIATE_STAGE:
        list = xact_local_list(gnode);
        break;
    case GTP_XACT_FINAL_STAGE:
        if (xid & OGS_GTP_CMD_XACT_ID) {
            if (type == OGS_GTP2_MODIFY_BEARER_FAILURE_INDICATION_TYPE ||
                type == OGS_GTP2_DELETE_BEARER_FAILURE_INDICATION_TYPE ||
                type == OGS_GTP2_BEARER_RESOURCE_FAILURE_INDICATION_TYPE) {
                list = xact_local_list(gnode);
            } else {
                list = xact_remote_list(gnode);
            }
        } else {
            list = xact_local_list(gnode);
        }
        break;
    default:
        ogs_error("[%d] Unexpected type %u from GTPv2 peer [%s]:%d",
                xid, type, OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));
        return OGS_ERROR;
    }

    ogs_assert(list);

    if (list == xact_local_list(gnode) && ogs_gtp2_xact_is_local_reply(stage, xid)) {
        /*
         * Reply to a request we sent (Create Session Response on S5, etc.).
         * Must match the exact sequence number and an outstanding step-1
         * local transaction. Do not fall back to remote_create: that always
         * fails update_rx() and drops the response under load.
         */
        new = xact_index_get(gnode, OGS_GTP_LOCAL_ORIGINATOR, 2, xid);
        if (!ogs_gtp2_xact_local_match(new, xid, ogs_gtp2_sqn_key(sqn), 1))
            new = ogs_gtp2_xact_find_local(list, xid, sqn, 1);
        if (!new) {
            ogs_warn("[sqn:0x%x] No local GTPv2 xact for type %u "
                    "from peer [%s]:%d (late or orphan response?)",
                    ogs_gtp2_sqn_key(sqn), type,
                    OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));
            return OGS_ERROR;
        }
    } else {
        ogs_gtp_xact_t *iter = NULL;

        new = xact_index_get(gnode,
                list == xact_local_list(gnode) ?
                    OGS_GTP_LOCAL_ORIGINATOR : OGS_GTP_REMOTE_ORIGINATOR,
                2, xid);
        if (new && (new->gtp_version != 2 || new->xid != xid))
            new = NULL;

        if (!new)
        ogs_list_for_each(list, iter) {
            if (iter->gtp_version == 2 && iter->xid == xid) {
                new = iter;
                ogs_debug("[%d] %s Find GTPv%u peer [%s]:%d",
                        new->xid,
                        new->org == OGS_GTP_LOCAL_ORIGINATOR ?
                            "LOCAL " : "REMOTE",
                        new->gtp_version,
                        OGS_ADDR(&gnode->addr, buf),
                        OGS_PORT(&gnode->addr));
                break;
            }
        }

        if (!new) {
            ogs_debug("[%d] Cannot find xact type %u from GTPv2 peer [%s]:%d",
                    xid, type, OGS_ADDR(&gnode->addr, buf),
                    OGS_PORT(&gnode->addr));
            new = ogs_gtp_xact_remote_create(gnode, 2, sqn);
        }
        ogs_assert(new);
    }

    ogs_debug("[%d] %s Receive peer [%s]:%d",
            new->xid,
            new->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            OGS_ADDR(&gnode->addr, buf),
            OGS_PORT(&gnode->addr));

    rv = ogs_gtp_xact_update_rx(new, type);
    if (rv == OGS_ERROR) {
        ogs_gtp_xact_log_state(new, type, "ogs_gtp_xact_update_rx() failed");
        ogs_gtp_xact_delete(new);
        return rv;
    } else if (rv == OGS_RETRY) {
        return rv;
    }

    *xact = new;
    return rv;
}

static ogs_gtp_xact_stage_t ogs_gtp1_xact_get_stage(uint8_t type, uint32_t xid)
{
    ogs_gtp_xact_stage_t stage = GTP_XACT_UNKNOWN_STAGE;

    switch (type) {
    case OGS_GTP1_ECHO_REQUEST_TYPE:
    case OGS_GTP1_NODE_ALIVE_REQUEST_TYPE:
    case OGS_GTP1_REDIRECTION_REQUEST_TYPE:
    case OGS_GTP1_CREATE_PDP_CONTEXT_REQUEST_TYPE:
    case OGS_GTP1_UPDATE_PDP_CONTEXT_REQUEST_TYPE:
    case OGS_GTP1_DELETE_PDP_CONTEXT_REQUEST_TYPE:
    case OGS_GTP1_INITIATE_PDP_CONTEXT_ACTIVATION_REQUEST_TYPE:
    case OGS_GTP1_PDU_NOTIFICATION_REQUEST_TYPE:
    case OGS_GTP1_PDU_NOTIFICATION_REJECT_REQUEST_TYPE:
    case OGS_GTP1_SEND_ROUTEING_INFORMATION_FOR_GPRS_REQUEST_TYPE:
    case OGS_GTP1_FAILURE_REPORT_REQUEST_TYPE:
    case OGS_GTP1_NOTE_MS_GPRS_PRESENT_REQUEST_TYPE:
    case OGS_GTP1_IDENTIFICATION_REQUEST_TYPE:
    case OGS_GTP1_SGSN_CONTEXT_REQUEST_TYPE:
    case OGS_GTP1_FORWARD_RELOCATION_REQUEST_TYPE:
    case OGS_GTP1_RELOCATION_CANCEL_REQUEST_TYPE:
    case OGS_GTP1_UE_REGISTRATION_QUERY_REQUEST_TYPE:
    case OGS_GTP1_RAN_INFORMATION_RELAY_TYPE:
        stage = GTP_XACT_INITIAL_STAGE;
        break;
    case OGS_GTP1_SGSN_CONTEXT_RESPONSE_TYPE:
        stage = GTP_XACT_INTERMEDIATE_STAGE;
        break;
    case OGS_GTP1_ECHO_RESPONSE_TYPE:
    case OGS_GTP1_NODE_ALIVE_RESPONSE_TYPE:
    case OGS_GTP1_REDIRECTION_RESPONSE_TYPE:
    case OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE:
    case OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE:
    case OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE:
    case OGS_GTP1_INITIATE_PDP_CONTEXT_ACTIVATION_RESPONSE_TYPE:
    case OGS_GTP1_PDU_NOTIFICATION_RESPONSE_TYPE:
    case OGS_GTP1_PDU_NOTIFICATION_REJECT_RESPONSE_TYPE:
    case OGS_GTP1_SEND_ROUTEING_INFORMATION_FOR_GPRS_RESPONSE_TYPE:
    case OGS_GTP1_FAILURE_REPORT_RESPONSE_TYPE:
    case OGS_GTP1_NOTE_MS_GPRS_PRESENT_RESPONSE_TYPE:
    case OGS_GTP1_IDENTIFICATION_RESPONSE_TYPE:
    case OGS_GTP1_SGSN_CONTEXT_ACKNOWLEDGE_TYPE:
    case OGS_GTP1_FORWARD_RELOCATION_RESPONSE_TYPE:
    case OGS_GTP1_RELOCATION_CANCEL_RESPONSE_TYPE:
    case OGS_GTP1_UE_REGISTRATION_QUERY_RESPONSE_TYPE:
        stage = GTP_XACT_FINAL_STAGE;
        break;

    default:
        ogs_error("Not implemented GTPv1 Message Type(%d)", type);
        break;
    }

    return stage;
}

/* TS 29.274 Table 6.1-1 */
static ogs_gtp_xact_stage_t ogs_gtp2_xact_get_stage(uint8_t type, uint32_t xid)
{
    ogs_gtp_xact_stage_t stage = GTP_XACT_UNKNOWN_STAGE;

    switch (type) {
    case OGS_GTP2_ECHO_REQUEST_TYPE:
    case OGS_GTP2_CREATE_SESSION_REQUEST_TYPE:
    case OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE:
    case OGS_GTP2_DELETE_SESSION_REQUEST_TYPE:
    case OGS_GTP2_CHANGE_NOTIFICATION_REQUEST_TYPE:
    case OGS_GTP2_REMOTE_UE_REPORT_NOTIFICATION_TYPE:
    case OGS_GTP2_MODIFY_BEARER_COMMAND_TYPE:
    case OGS_GTP2_DELETE_BEARER_COMMAND_TYPE:
    case OGS_GTP2_BEARER_RESOURCE_COMMAND_TYPE:
    case OGS_GTP2_TRACE_SESSION_ACTIVATION_TYPE:
    case OGS_GTP2_TRACE_SESSION_DEACTIVATION_TYPE:
    case OGS_GTP2_STOP_PAGING_INDICATION_TYPE:
    case OGS_GTP2_DELETE_PDN_CONNECTION_SET_REQUEST_TYPE:
    case OGS_GTP2_PGW_DOWNLINK_TRIGGERING_NOTIFICATION_TYPE:
    case OGS_GTP2_CREATE_FORWARDING_TUNNEL_REQUEST_TYPE:
    case OGS_GTP2_SUSPEND_NOTIFICATION_TYPE:
    case OGS_GTP2_RESUME_NOTIFICATION_TYPE:
    case OGS_GTP2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
    case OGS_GTP2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
    case OGS_GTP2_RELEASE_ACCESS_BEARERS_REQUEST_TYPE:
    case OGS_GTP2_DOWNLINK_DATA_NOTIFICATION_TYPE:
    case OGS_GTP2_PGW_RESTART_NOTIFICATION_TYPE:
    case OGS_GTP2_UPDATE_PDN_CONNECTION_SET_REQUEST_TYPE:
    case OGS_GTP2_MODIFY_ACCESS_BEARERS_REQUEST_TYPE:
        stage = GTP_XACT_INITIAL_STAGE;
        break;
    case OGS_GTP2_CREATE_BEARER_REQUEST_TYPE:
    case OGS_GTP2_UPDATE_BEARER_REQUEST_TYPE:
    case OGS_GTP2_DELETE_BEARER_REQUEST_TYPE:
        if (xid & OGS_GTP_CMD_XACT_ID)
            stage = GTP_XACT_INTERMEDIATE_STAGE;
        else
            stage = GTP_XACT_INITIAL_STAGE;
        break;
    case OGS_GTP2_ECHO_RESPONSE_TYPE:
    case OGS_GTP2_VERSION_NOT_SUPPORTED_INDICATION_TYPE:
    case OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE:
    case OGS_GTP2_MODIFY_BEARER_RESPONSE_TYPE:
    case OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE:
    case OGS_GTP2_CHANGE_NOTIFICATION_RESPONSE_TYPE:
    case OGS_GTP2_REMOTE_UE_REPORT_ACKNOWLEDGE_TYPE:
    case OGS_GTP2_MODIFY_BEARER_FAILURE_INDICATION_TYPE:
    case OGS_GTP2_DELETE_BEARER_FAILURE_INDICATION_TYPE:
    case OGS_GTP2_BEARER_RESOURCE_FAILURE_INDICATION_TYPE:
    case OGS_GTP2_DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION_TYPE:
    case OGS_GTP2_CREATE_BEARER_RESPONSE_TYPE:
    case OGS_GTP2_UPDATE_BEARER_RESPONSE_TYPE:
    case OGS_GTP2_DELETE_BEARER_RESPONSE_TYPE:
    case OGS_GTP2_DELETE_PDN_CONNECTION_SET_RESPONSE_TYPE:
    case OGS_GTP2_PGW_DOWNLINK_TRIGGERING_ACKNOWLEDGE_TYPE:
    case OGS_GTP2_CREATE_FORWARDING_TUNNEL_RESPONSE_TYPE:
    case OGS_GTP2_SUSPEND_ACKNOWLEDGE_TYPE:
    case OGS_GTP2_RESUME_ACKNOWLEDGE_TYPE:
    case OGS_GTP2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE_TYPE:
    case OGS_GTP2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE_TYPE:
    case OGS_GTP2_RELEASE_ACCESS_BEARERS_RESPONSE_TYPE:
    case OGS_GTP2_DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE_TYPE:
    case OGS_GTP2_PGW_RESTART_NOTIFICATION_ACKNOWLEDGE_TYPE:
    case OGS_GTP2_UPDATE_PDN_CONNECTION_SET_RESPONSE_TYPE:
    case OGS_GTP2_MODIFY_ACCESS_BEARERS_RESPONSE_TYPE:
        stage = GTP_XACT_FINAL_STAGE;
        break;

    default:
        ogs_error("Not implemented GTPv2 Message Type(%d)", type);
        break;
    }

    return stage;
}

void ogs_gtp_xact_associate(ogs_gtp_xact_t *xact1, ogs_gtp_xact_t *xact2)
{
    ogs_assert(xact1);
    ogs_assert(xact2);

    ogs_assert(xact1->assoc_xact_id == OGS_INVALID_POOL_ID);
    ogs_assert(xact2->assoc_xact_id == OGS_INVALID_POOL_ID);

    xact1->assoc_xact_id = xact2->id;
    xact2->assoc_xact_id = xact1->id;
}

void ogs_gtp_xact_deassociate(ogs_gtp_xact_t *xact1, ogs_gtp_xact_t *xact2)
{
    ogs_assert(xact1);
    ogs_assert(xact2);

    ogs_assert(xact1->assoc_xact_id != OGS_INVALID_POOL_ID);
    ogs_assert(xact2->assoc_xact_id != OGS_INVALID_POOL_ID);

    xact1->assoc_xact_id = OGS_INVALID_POOL_ID;
    xact2->assoc_xact_id = OGS_INVALID_POOL_ID;
}

static int ogs_gtp_xact_delete(ogs_gtp_xact_t *xact)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_gtp_xact_t *assoc_xact = NULL;

    ogs_assert(xact);
    ogs_assert(xact->gnode);

    ogs_debug("[%d] %s Delete  peer [%s]:%d",
            xact->xid,
            xact->org == OGS_GTP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            OGS_ADDR(&xact->gnode->addr, buf),
            OGS_PORT(&xact->gnode->addr));

    /*
     * Stop/delete timers before freeing the xact so holding_timeout and
     * friends never hash-lookup a freed transaction.
     */
    if (xact->tm_response) {
        ogs_timer_stop(xact->tm_response);
        ogs_timer_delete(xact->tm_response);
        xact->tm_response = NULL;
    }
    if (xact->tm_peer) {
        ogs_timer_stop(xact->tm_peer);
        ogs_timer_delete(xact->tm_peer);
        xact->tm_peer = NULL;
    }
    if (xact->tm_holding) {
        ogs_timer_stop(xact->tm_holding);
        ogs_timer_delete(xact->tm_holding);
        xact->tm_holding = NULL;
    }

    if (xact->seq[0].pkbuf)
        ogs_pkbuf_free(xact->seq[0].pkbuf);
    if (xact->seq[1].pkbuf)
        ogs_pkbuf_free(xact->seq[1].pkbuf);
    if (xact->seq[2].pkbuf)
        ogs_pkbuf_free(xact->seq[2].pkbuf);

    assoc_xact = ogs_gtp_xact_find_by_id(xact->assoc_xact_id);
    if (assoc_xact)
        ogs_gtp_xact_deassociate(xact, assoc_xact);

    xact_index_del(xact);
    ogs_list_remove(xact->org == OGS_GTP_LOCAL_ORIGINATOR ?
            xact_local_list(xact->gnode) : xact_remote_list(xact->gnode), xact);
    ogs_pool_id_free(xact_pool(), xact);

    return OGS_OK;
}
