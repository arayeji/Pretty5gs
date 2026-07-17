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
                /*
                 * SMP is not production-stable yet: workers:4 wedged main
                 * (PFCP Recv-Q stuck, peers_active=0). Refuse to start
                 * shards unless explicitly opted in via the environment.
                 */
                if (n > 0 && !ogs_env_get("SGWC_SMP")) {
                    ogs_error("sgwc.workers=%d ignored — SMP disabled "
                            "(export SGWC_SMP=1 to override)", n);
                    n = 0;
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
    /* GTPv2/PFCP: shard bits at 22..20, below CMD bit 23. */
    return (int)((xid >> 20) & 7) - 1;
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

static void sgwc_worker_thread_init(ogs_worker_t *worker)
{
    int rv;

    ogs_assert(worker);

    sgwc_context_init();

    /*
     * sgwc_context_init() re-installs the "sgwc" log domain at the core
     * default level (INFO), clobbering the configured level that main
     * applied via ogs_log_config_domain(). Re-apply it here or every
     * worker's re-init drops the whole process back to INFO, ignoring
     * logger.level in sgwc.yaml.
     */
    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    ogs_assert(rv == OGS_OK);

    rv = ogs_gtp_xact_init();
    ogs_assert(rv == OGS_OK);
    rv = ogs_pfcp_xact_init();
    ogs_assert(rv == OGS_OK);

    rv = sgwc_context_parse_config();
    ogs_assert(rv == OGS_OK);

    ogs_fsm_init(&worker_fsm, sgwc_state_initial, sgwc_state_final, 0);

    ogs_info("SGWC shard worker %d ready", worker->id);
}

static void sgwc_worker_thread_fini(ogs_worker_t *worker)
{
    ogs_assert(worker);

    ogs_fsm_fini(&worker_fsm, 0);

    sgwc_context_final();

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
    int max_ue, max_sess;
    int per_ue, per_sess;

    if (sgwc_worker_configured <= 0)
        return OGS_OK;

    ogs_assert(sgwc_worker_count == 0);
    ogs_assert(!ogs_worker_active());

    /* Opt-in protocol id sharding BEFORE any worker exists. */
    ogs_worker_shards_enable();

    max_ue = ogs_global_conf()->max.ue;
    max_sess = ogs_app()->pool.sess;
    if (max_ue < sgwc_worker_configured)
        max_ue = sgwc_worker_configured;
    if (max_sess < sgwc_worker_configured)
        max_sess = sgwc_worker_configured;

    per_ue = max_ue / sgwc_worker_configured;
    per_sess = max_sess / sgwc_worker_configured;
    if (per_ue < 1) per_ue = 1;
    if (per_sess < 1) per_sess = 1;

    /*
     * Shrink the global pools so each worker's context_init takes a fair
     * share. Main already initialized with tiny pools (see init.c).
     */
    ogs_global_conf()->max.ue = per_ue;
    ogs_app()->pool.sess = per_sess;
    ogs_app()->pool.bearer = ogs_max(ogs_app()->pool.bearer /
            sgwc_worker_configured, 4);
    ogs_app()->pool.tunnel = ogs_max(ogs_app()->pool.tunnel /
            sgwc_worker_configured, 4);

    for (i = 0; i < sgwc_worker_configured; i++) {
        sgwc_workers[i] = ogs_worker_create(i,
                ogs_app()->pool.event,
                ogs_app()->pool.timer,
                64,
                sgwc_worker_dispatch, NULL);
        ogs_assert(sgwc_workers[i]);
        ogs_worker_hooks(sgwc_workers[i],
                sgwc_worker_thread_init, sgwc_worker_thread_fini);
        ogs_worker_start(sgwc_workers[i]);
    }

    sgwc_worker_count = sgwc_worker_configured;

    ogs_info("SGWC SMP workers: %d shard(s), per-shard max.ue=%d sess=%d",
            sgwc_worker_count, per_ue, per_sess);

    return OGS_OK;
}

void sgwc_workers_stop(void)
{
    int i;

    for (i = 0; i < sgwc_worker_count; i++) {
        ogs_worker_destroy(sgwc_workers[i]);
        sgwc_workers[i] = NULL;
    }
    sgwc_worker_count = 0;
}
