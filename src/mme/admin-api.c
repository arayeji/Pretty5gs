/*
 * Copyright (C) 2026 by Open5GS contributors
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/*
 * Admin endpoints for the MME Prometheus HTTP server. These bounce
 * the actual mutation onto the MME main thread via the MME event
 * queue (see MME_EVENT_ADMIN_DETACH_* in mme-event.h and the
 * matching cases in mme-sm.c). Access control is NOT enforced
 * inside the daemon - the operator firewalls the metrics port at
 * the host/network level. The HTTP layer logs every admin call
 * with the caller address for auditability.
 */

#include "ogs-core.h"
#include "ogs-app.h"

#include "mme-context.h"
#include "mme-event.h"
#include "mme-workers.h"
#include "mme-sm.h"      /* emm_state_ue_context_will_remove (FSM check) */
#include "mme-path.h"    /* orphan-sweep heartbeat accessors */

#include "admin-api.h"   /* pulls in ogs-metrics.h */
#include "s1ap-tx.h"     /* TX offload queue depths (/admin/queues) */
#include "s1ap-io.h"     /* IO command queue depth (/admin/queues) */
#include "mme-gtp-path.h" /* GTP-C RX thread state (/admin/queues) */
#include "mme-li.h"
#include "mme-pgw-host.h"
#include "mme-pgw-dns.h"
#include "runtime-config.h"
#include "mme-trace-sync.h"

#include <stdarg.h>
#include <string.h>

/*
 * HTTP status codes. We don't pull in microhttpd.h here just to
 * avoid coupling the MME to the metrics' transport; these are
 * standard RFC 7231 codes.
 */
#define ADMIN_HTTP_ACCEPTED            202
#define ADMIN_HTTP_BAD_REQUEST         400
#define ADMIN_HTTP_NOT_FOUND           404
#define ADMIN_HTTP_INTERNAL_ERROR      500
#define ADMIN_HTTP_SERVICE_UNAVAIL     503

static size_t fmt_json_status(char *body, size_t cap, int status,
                              const char *fmt, ...)
{
    if (!body || cap == 0) return 0;
    int written;
    va_list ap;
    char detail[512];

    va_start(ap, fmt);
    written = vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    if (written < 0) detail[0] = '\0';

    written = snprintf(body, cap,
            "{\"status\":%d,\"detail\":\"%s\"}\n", status, detail);
    if (written < 0) return 0;
    return (size_t)((size_t)written < cap ? (size_t)written : cap - 1);
}

int mme_admin_enb_detach(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    if (!q) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_BAD_REQUEST, "missing query");
        return ADMIN_HTTP_BAD_REQUEST;
    }

    /*
     * Resolve the eNB to an internal pool id while holding the
     * metrics dump lock - that serialises us against the MME
     * main thread's mme_enb_add / mme_enb_remove and keeps the
     * pointer valid until we read enb->id.
     */
    ogs_pool_id_t enb_pool_id = OGS_INVALID_POOL_ID;
    uint32_t resolved_enb_id = 0;

    ogs_metrics_dump_lock();
    mme_enb_t *enb = NULL;
    if (q->has_enb_id) {
        enb = mme_enb_find_by_enb_id(q->enb_id);
    } else if (q->ip && *q->ip) {
        /* Linear walk: small list (thousands at worst). */
        mme_enb_t *it = NULL;
        ogs_list_for_each(&mme_self()->enb_list, it) {
            if (!it->sctp.addr) continue;
            const char *peer = ogs_sockaddr_to_string_static(it->sctp.addr);
            if (!peer) continue;
            /* peer is "[ipv6]:port" or "ipv4:port" - strip the bracketed
             * v6 form first, otherwise lop off the trailing ":port". */
            char host[OGS_ADDRSTRLEN] = "";
            if (peer[0] == '[') {
                const char *end = strchr(peer + 1, ']');
                if (end) {
                    size_t n = (size_t)(end - (peer + 1));
                    if (n < sizeof(host)) {
                        memcpy(host, peer + 1, n); host[n] = '\0';
                    }
                }
            } else {
                const char *colon = strrchr(peer, ':');
                size_t n = colon ? (size_t)(colon - peer) : strlen(peer);
                if (n < sizeof(host)) {
                    memcpy(host, peer, n); host[n] = '\0';
                }
            }
            if (strcmp(host, q->ip) == 0) { enb = it; break; }
        }
    }
    if (enb) {
        enb_pool_id = enb->id;
        resolved_enb_id = enb->enb_id;
    }
    ogs_metrics_dump_unlock();

    if (enb_pool_id == OGS_INVALID_POOL_ID) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_NOT_FOUND, "eNB not found");
        return ADMIN_HTTP_NOT_FOUND;
    }

    /* Queue the actual detach onto the MME main thread. */
    mme_event_t *e = mme_event_new(MME_EVENT_ADMIN_DETACH_ENB);
    if (!e) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->enb_id = enb_pool_id;
    e->admin_force = q->force ? 1 : 0;

    int rv = mme_queue_push_main(e);
    if (rv != OGS_OK) {
        mme_event_free(e);
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_SERVICE_UNAVAIL, "event queue full");
        return ADMIN_HTTP_SERVICE_UNAVAIL;
    }

    *body_len = fmt_json_status(body, body_cap,
            ADMIN_HTTP_ACCEPTED,
            "detach queued for enb_id=0x%x mode=%s",
            (unsigned)resolved_enb_id,
            e->admin_force ? "force" : "graceful");
    return ADMIN_HTTP_ACCEPTED;
}

int mme_admin_ue_detach(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    if (!q || !q->imsi || !*q->imsi) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_BAD_REQUEST, "missing ?imsi=...");
        return ADMIN_HTTP_BAD_REQUEST;
    }

    ogs_pool_id_t mme_ue_pool_id = OGS_INVALID_POOL_ID;

    int owner_wid = -1;

    ogs_metrics_dump_lock();
    mme_ue_t *mme_ue = mme_ue_find_by_imsi_bcd(q->imsi);
    if (mme_ue) {
        mme_ue_pool_id = mme_ue->id;
        owner_wid = mme_shard_from_teid(mme_ue->mme_s11_teid);
    }
    ogs_metrics_dump_unlock();

    if (mme_ue_pool_id == OGS_INVALID_POOL_ID) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_NOT_FOUND, "UE not found");
        return ADMIN_HTTP_NOT_FOUND;
    }

    mme_event_t *e = mme_event_new(MME_EVENT_ADMIN_DETACH_UE);
    if (!e) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->mme_ue_id = mme_ue_pool_id;
    e->owner_wid = owner_wid;
    e->admin_force = q->force ? 1 : 0;

    int rv = mme_event_push_to_ue_owner(e);
    if (rv != OGS_OK) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_SERVICE_UNAVAIL, "event queue full");
        return ADMIN_HTTP_SERVICE_UNAVAIL;
    }

    *body_len = fmt_json_status(body, body_cap,
            ADMIN_HTTP_ACCEPTED,
            "detach queued for imsi=%s mode=%s",
            q->imsi, e->admin_force ? "force" : "graceful");
    return ADMIN_HTTP_ACCEPTED;
}

int mme_admin_ue_page(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    if (!q || !q->imsi || !*q->imsi) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_BAD_REQUEST, "missing ?imsi=...");
        return ADMIN_HTTP_BAD_REQUEST;
    }

    ogs_pool_id_t mme_ue_pool_id = OGS_INVALID_POOL_ID;
    bool connected = false;
    int owner_wid = -1;

    ogs_metrics_dump_lock();
    mme_ue_t *mme_ue = mme_ue_find_by_imsi_bcd(q->imsi);
    if (mme_ue) {
        mme_ue_pool_id = mme_ue->id;
        connected = ECM_CONNECTED(mme_ue);
        owner_wid = mme_shard_from_teid(mme_ue->mme_s11_teid);
    }
    ogs_metrics_dump_unlock();

    if (mme_ue_pool_id == OGS_INVALID_POOL_ID) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_NOT_FOUND, "UE not found");
        return ADMIN_HTTP_NOT_FOUND;
    }

    /*
     * Advisory shortcut: if the UE is already connected there is nothing
     * to page. The MME main thread re-checks authoritatively before it
     * actually sends the S1AP Paging.
     */
    if (connected) {
        *body_len = fmt_json_status(body, body_cap, 200,
                "UE already ECM-CONNECTED for imsi=%s", q->imsi);
        return 200;
    }

    mme_event_t *e = mme_event_new(MME_EVENT_ADMIN_PAGE_UE);
    if (!e) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->mme_ue_id = mme_ue_pool_id;
    e->owner_wid = owner_wid;
    /* force=1 -> re-page even if a paging procedure is already in flight. */
    e->admin_force = q->force ? 1 : 0;

    int rv = mme_event_push_to_ue_owner(e);
    if (rv != OGS_OK) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_SERVICE_UNAVAIL, "event queue full");
        return ADMIN_HTTP_SERVICE_UNAVAIL;
    }

    *body_len = fmt_json_status(body, body_cap,
            ADMIN_HTTP_ACCEPTED,
            "paging queued for imsi=%s domain=ps mode=%s",
            q->imsi, e->admin_force ? "force-repage" : "normal");
    return ADMIN_HTTP_ACCEPTED;
}

int mme_admin_trace_imsi(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    int status = ogs_metrics_admin_trace_imsi(q, body, body_cap, body_len);

    if (q && q->sync && q->sync[0] && status == 200)
        *body_len = mme_trace_sync_append(q, body, body_cap, *body_len);

    return status;
}

static void mme_admin_set_maintenance(bool maintenance)
{
    ogs_metrics_dump_lock();
    mme_self()->maintenance_mode = maintenance;
    ogs_metrics_dump_unlock();
}

static int mme_admin_maintenance_queue(mme_event_e id, int force,
        char *body, size_t body_cap, size_t *body_len)
{
    mme_event_t *e = NULL;
    int rv;

    e = mme_event_new(id);
    if (!e) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->admin_force = force;

    rv = mme_queue_push_main(e);
    if (rv != OGS_OK) {
        mme_event_free(e);
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_SERVICE_UNAVAIL, "event queue full");
        return ADMIN_HTTP_SERVICE_UNAVAIL;
    }

    ogs_pollset_notify(ogs_app()->pollset);

    *body_len = fmt_json_status(body, body_cap, ADMIN_HTTP_ACCEPTED,
            "maintenance event queued");
    return ADMIN_HTTP_ACCEPTED;
}

/*
 * Counting these means walking every mme_ue under mme_ctx_lock(), which is
 * the one global mutex every mme_ue_find_by_id() on every worker also needs.
 * At a few hundred thousand contexts that walk starves the whole MME - a
 * capture during a production stall showed this function holding the mutex
 * with 17 of 75 threads blocked on it and the S11 receive queue overflowing.
 * Nothing here is worth stalling call processing for, so the counts are
 * computed at most once per TTL and served from cache in between. Callers
 * see how stale they are via counts_age_s.
 */
#define MME_MAINT_COUNTS_TTL ogs_time_from_sec(10)

static ogs_time_t maint_counts_time;
static int maint_ue_count, maint_sessionless, maint_idle;
static int maint_will_remove, maint_orphan_candidates;

size_t mme_dump_maintenance_status(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    int ue_count, sessionless, idle, will_remove, orphan_candidates;
    bool maintenance = false;
    bool drain_active = false;
    unsigned drain_processed = 0;
    int written;
    mme_ue_t *mme_ue = NULL;
    ogs_time_t now;
    long long counts_age_s;

    ogs_time_t sweep_last_run = 0;
    int sweep_last_purged = 0, sweep_last_remaining = 0;
    uint64_t sweep_total_purged = 0;
    long long sweep_age_s = -1;

    (void)page;
    (void)page_size;
    (void)q;

    if (!buf || buflen == 0)
        return 0;

    now = ogs_time_now();

    ogs_metrics_dump_lock();
    maintenance = mme_self()->maintenance_mode;
    drain_active = mme_self()->drain_active;
    drain_processed = mme_self()->drain_processed;

    if (!maint_counts_time || now - maint_counts_time >= MME_MAINT_COUNTS_TTL) {
        int n_ue = 0, n_sessionless = 0, n_idle = 0;
        int n_will_remove = 0, n_orphan = 0;

        ogs_list_for_each(&mme_self()->mme_ue_list, mme_ue) {
            bool no_sess = ogs_list_empty(&mme_ue->sess_list);
            bool is_idle = !ECM_CONNECTED(mme_ue);

            n_ue++;
            if (no_sess) n_sessionless++;
            if (is_idle) n_idle++;
            if (mme_ue->ue_context_will_remove) n_will_remove++;
            /*
             * What the orphan sweep is meant to reclaim: a session-less
             * context that is not actively mid-removal. Tracks the leak
             * directly.
             */
            if (no_sess && !OGS_FSM_CHECK(&mme_ue->sm,
                        emm_state_ue_context_will_remove))
                n_orphan++;
        }

        maint_ue_count = n_ue;
        maint_sessionless = n_sessionless;
        maint_idle = n_idle;
        maint_will_remove = n_will_remove;
        maint_orphan_candidates = n_orphan;
        maint_counts_time = now;
    }

    ue_count = maint_ue_count;
    sessionless = maint_sessionless;
    idle = maint_idle;
    will_remove = maint_will_remove;
    orphan_candidates = maint_orphan_candidates;
    counts_age_s = (long long)ogs_time_to_sec(now - maint_counts_time);
    ogs_metrics_dump_unlock();

    mme_orphan_sweep_get_stats(&sweep_last_run, &sweep_last_purged,
            &sweep_last_remaining, &sweep_total_purged);
    if (sweep_last_run)
        sweep_age_s = (long long)ogs_time_to_sec(
                ogs_time_now() - sweep_last_run);

    written = snprintf(buf, buflen,
            "{\"maintenance\":%s,\"ue_count\":%d,"
            "\"sessionless\":%d,\"idle\":%d,\"will_remove\":%d,"
            "\"orphan_candidates\":%d,\"counts_age_s\":%lld,"
            "\"drain\":{\"active\":%s,\"processed\":%u},"
            "\"sweep\":{\"age_s\":%lld,\"last_purged\":%d,"
            "\"last_remaining\":%d,\"total_purged\":%llu}}\n",
            maintenance ? "true" : "false", ue_count,
            sessionless, idle, will_remove, orphan_candidates, counts_age_s,
            drain_active ? "true" : "false", drain_processed,
            sweep_age_s, sweep_last_purged, sweep_last_remaining,
            (unsigned long long)sweep_total_purged);
    if (written < 0)
        return 0;
    return (size_t)((size_t)written < buflen ? (size_t)written : buflen - 1);
}

int mme_admin_maintenance_enable(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    (void)q;
    mme_admin_set_maintenance(true);
    (void)mme_admin_maintenance_queue(
            MME_EVENT_ADMIN_MAINTENANCE_ENABLE, 0,
            body, body_cap, body_len);
    return mme_admin_maintenance_status(q, body, body_cap, body_len);
}

int mme_admin_maintenance_disable(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    (void)q;
    mme_admin_set_maintenance(false);
    (void)mme_admin_maintenance_queue(
            MME_EVENT_ADMIN_MAINTENANCE_DISABLE, 0,
            body, body_cap, body_len);
    return mme_admin_maintenance_status(q, body, body_cap, body_len);
}

int mme_admin_maintenance_drain(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    mme_admin_set_maintenance(true);
    return mme_admin_maintenance_queue(
            MME_EVENT_ADMIN_MAINTENANCE_DRAIN, q && q->force,
            body, body_cap, body_len);
}

int mme_admin_maintenance_status(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    size_t n;

    (void)q;

    n = mme_dump_maintenance_status(body, body_cap, 0, 0, NULL);
    if (n == 0) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "status encode failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    *body_len = n;
    return 200;
}

int mme_admin_pgw_host_cache(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    int removed = 0;
    int written;

    if (!body || body_cap == 0 || !body_len)
        return ADMIN_HTTP_BAD_REQUEST;

    if (!q || (!q->clear && (!q->fqdn || !*q->fqdn))) {
        *body_len = snprintf(body, body_cap,
                "{\"ok\":false,\"detail\":\"use clear=1 or fqdn=<host.realm>\"}\n");
        return ADMIN_HTTP_BAD_REQUEST;
    }

    if (q->clear) {
        removed = mme_pgw_host_cache_clear_all();
        removed += mme_pgw_dns_cache_clear_all();
        written = snprintf(body, body_cap,
                "{\"ok\":true,\"detail\":\"pgw-host/apn-dns cache cleared\","
                "\"removed\":%d}\n", removed);
    } else {
        if (mme_pgw_host_cache_remove_fqdn(q->fqdn) != OGS_OK) {
            *body_len = snprintf(body, body_cap,
                    "{\"ok\":false,\"detail\":\"fqdn not in cache\","
                    "\"fqdn\":\"%s\"}\n", q->fqdn);
            return ADMIN_HTTP_NOT_FOUND;
        }
        written = snprintf(body, body_cap,
                "{\"ok\":true,\"detail\":\"pgw-host cache entry removed\","
                "\"removed\":1,\"fqdn\":\"%s\"}\n", q->fqdn);
        removed = 1;
    }

    if (written < 0) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "response encode failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }

    *body_len = (size_t)((size_t)written < body_cap ?
            (size_t)written : body_cap - 1);
    ogs_info("admin pgw-host cache invalidated (removed=%d fqdn=%s)",
            removed, q->fqdn ? q->fqdn : "*");
    return 200;
}

/*
 * /admin/queues — one-shot answer to "is the MME working or wedged?".
 *
 * Reports the depth of every internal queue (main event queue, UE shard
 * workers, S1AP TX encode workers, S1AP IO command queue, CONNREFUSED
 * side-queue), the event dispatch lag, and per-eNB TX hold state. All
 * reads are diagnostic (torn reads acceptable, same convention as the
 * other dumpers); the eNB list walk holds ogs_metrics_dump_lock() so
 * main cannot free an eNB under us.
 *
 * verdict:
 *   ok       - queues shallow, lag below the NAS-defer threshold
 *   behind   - lag >= 1.5s or main queue > 75% full (overloaded but
 *              draining; timers already defer, overload control active)
 *   wedged   - an eNB's TX hold list has been non-empty > 15s, or
 *              pending>0 with empty hold and pending_since > 15s
 *              (leaked s1ap_tx_pending: that eNB's downlink is parked;
 *              the watchdog will force-flush it on the next orphan sweep)
 */
#define QSTAT_HOLD_WEDGE_USEC   ogs_time_from_sec(15)

size_t mme_dump_queue_status(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    size_t off = 0;
    int written, i, n;
    unsigned int depth, cap;
    long long lag_ms;
    ogs_time_t now = ogs_time_now();
    const char *verdict = "ok";

    int enb_total = 0, enb_parked = 0, enb_wedged = 0;
    mme_enb_t *enb = NULL;

    (void)page;
    (void)page_size;
    (void)q;

    if (!buf || buflen == 0)
        return 0;

#define QSTAT_APPEND(...) do { \
        written = snprintf(buf + off, buflen - off, __VA_ARGS__); \
        if (written < 0) return off; \
        off += (size_t)written; \
        if (off >= buflen) return buflen - 1; \
    } while (0)

    lag_ms = (long long)(mme_event_lag() / 1000);

    depth = ogs_queue_size(ogs_app()->queue);
    cap = ogs_queue_capacity(ogs_app()->queue);

    if (lag_ms >= 1500 || (cap && depth > cap - cap / 4))
        verdict = "behind";

    QSTAT_APPEND("{\"event_lag_ms\":%lld,"
            "\"main\":{\"depth\":%u,\"cap\":%u},"
            "\"connrefused_depth\":%u,"
            "\"tx_ready_depth\":%u,",
            lag_ms, depth, cap, mme_event_s1ap_connrefused_depth(),
            mme_event_s1ap_tx_ready_depth());

    /* UE shard workers (mme.workers) */
    QSTAT_APPEND("\"shards\":[");
    n = mme_workers_count();
    for (i = 0; i < n; i++) {
        ogs_worker_t *w = mme_worker_by_id(i);
        QSTAT_APPEND("%s{\"id\":%d,\"depth\":%u}", i ? "," : "",
                i, w && w->queue ? ogs_queue_size(w->queue) : 0);
    }
    QSTAT_APPEND("],");

    /* S1AP TX encode workers (mme.s1ap_tx_workers) */
    QSTAT_APPEND("\"tx\":[");
    n = s1ap_tx_worker_count();
    for (i = 0; i < n; i++)
        QSTAT_APPEND("%s{\"id\":%d,\"depth\":%u}", i ? "," : "",
                i, s1ap_tx_queue_depth(i));
    QSTAT_APPEND("],");

    QSTAT_APPEND("\"io_depth\":%u,", s1ap_io_queue_depth());

    /*
     * Kernel RX backlog of the GTP-C socket. The internal queues can all
     * look healthy while S11 replies rot unread in the kernel buffer
     * (seen at 12MB Recv-Q during an attach storm) — this is the
     * blind spot that made "GTP timeout" look like an SGW problem.
     */
    {
        uint64_t rx4 = 0, rx6 = 0;

        if (ogs_gtp_self()->gtpc_sock)
            rx4 = ogs_socket_rx_backlog(ogs_gtp_self()->gtpc_sock->fd);
        if (ogs_gtp_self()->gtpc_sock6)
            rx6 = ogs_socket_rx_backlog(ogs_gtp_self()->gtpc_sock6->fd);

        if (rx4 + rx6 >= 1024 * 1024)   /* >=1MB unread: falling behind */
            verdict = "behind";

        QSTAT_APPEND("\"gtpc_rx_backlog_bytes\":%llu,",
                (unsigned long long)(rx4 + rx6));
    }

    QSTAT_APPEND("\"gtpc_rx_thread\":%s,",
            mme_gtpc_rx_active() ? "true" : "false");

    /*
     * Per-eNB TX hold state: pending encode jobs + parked pkbufs.
     * A hold list non-empty for >15s is the wedge signature.
     */
    QSTAT_APPEND("\"enb_hold\":[");
    ogs_metrics_dump_lock();
    ogs_list_for_each(&mme_self()->enb_list, enb) {
        int pending, held = 0;
        long long age_s = 0;
        ogs_time_t since, pending_since;
        ogs_pkbuf_t *pk = NULL;
        bool wedged;

        enb_total++;

        ogs_thread_mutex_lock(&enb->s1ap_tx_hold_lock);
        pending = __atomic_load_n(&enb->s1ap_tx_pending, __ATOMIC_ACQUIRE);
        since = enb->s1ap_tx_hold_since;
        pending_since = enb->s1ap_tx_pending_since;
        ogs_list_for_each(&enb->s1ap_tx_hold, pk)
            held++;
        ogs_thread_mutex_unlock(&enb->s1ap_tx_hold_lock);

        if (!pending && !held)
            continue;

        enb_parked++;
        /* Prefer hold age; empty-hold pending leak uses pending_since. */
        if (held && since)
            age_s = (long long)ogs_time_to_sec(now - since);
        else if (!held && pending > 0 && pending_since)
            age_s = (long long)ogs_time_to_sec(now - pending_since);
        else if (since)
            age_s = (long long)ogs_time_to_sec(now - since);

        wedged = (held && since &&
                        (now - since) >= QSTAT_HOLD_WEDGE_USEC) ||
                 (!held && pending > 0 && pending_since &&
                        (now - pending_since) >= QSTAT_HOLD_WEDGE_USEC);
        if (wedged) {
            enb_wedged++;
            verdict = "wedged";
        }

        /* cap the detail list; counters above still cover the rest */
        if (enb_parked <= 16)
            QSTAT_APPEND("%s{\"enb_id\":\"0x%x\",\"pending\":%d,"
                    "\"held\":%d,\"held_age_s\":%lld,\"wedged\":%s}",
                    enb_parked > 1 ? "," : "",
                    enb->enb_id, pending, held, age_s,
                    wedged ? "true" : "false");
    }
    ogs_metrics_dump_unlock();
    QSTAT_APPEND("],");

    QSTAT_APPEND("\"enb\":{\"total\":%d,\"with_tx_backlog\":%d,"
            "\"wedged\":%d},\"verdict\":\"%s\"}\n",
            enb_total, enb_parked, enb_wedged, verdict);

#undef QSTAT_APPEND

    return off < buflen ? off : buflen - 1;
}

void mme_admin_api_register(void)
{
    ogs_metrics_register_custom_ep(mme_dump_runtime_config,
            "/admin/config");
    ogs_metrics_register_custom_ep(mme_dump_maintenance_status,
            "/admin/maintenance");
    ogs_metrics_register_custom_ep(mme_dump_queue_status,
            "/admin/queues");

    ogs_metrics_register_admin_ep(mme_admin_enb_detach,
            "/admin/enb/detach",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_ue_detach,
            "/admin/ue/detach",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_ue_page,
            "/admin/ue/page",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_trace_imsi,
            "/admin/trace/imsi",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_pgw_host_cache,
            "/admin/pgw-host/cache",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_maintenance_enable,
            "/admin/maintenance/enable",
            OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_maintenance_enable,
            "/admin/maintenance",
            OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_maintenance_disable,
            "/admin/maintenance/disable",
            OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_maintenance_drain,
            "/admin/maintenance/drain",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_maintenance_status,
            "/admin/maintenance/status",
            OGS_METRICS_ADMIN_METHOD_GET);
    ogs_metrics_register_admin_ep(mme_admin_li_target,
            "/admin/li/target",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
}
