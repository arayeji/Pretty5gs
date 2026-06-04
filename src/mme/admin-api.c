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

#include "admin-api.h"   /* pulls in ogs-metrics.h */

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

    int rv = ogs_queue_push(ogs_app()->queue, e);
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

    ogs_metrics_dump_lock();
    mme_ue_t *mme_ue = mme_ue_find_by_imsi_bcd(q->imsi);
    if (mme_ue) mme_ue_pool_id = mme_ue->id;
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
    e->admin_force = q->force ? 1 : 0;

    int rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        mme_event_free(e);
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

int mme_admin_trace_imsi(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    const char *imsi = (q && q->imsi) ? q->imsi : NULL;
    int i, n;

    /* ?force=1 clears all runtime trace prefixes (no restart) */
    if (q && q->force) {
        ogs_trace_filter_clear();
        *body_len = fmt_json_status(body, body_cap, 200,
                "trace_imsi filters cleared");
        return 200;
    }

    if (imsi && strcmp(imsi, "list") == 0) {
        size_t off = 0;

        off += snprintf(body + off, body_cap - off, "{\"trace_imsi\":[");
        n = ogs_trace_filter_count();
        for (i = 0; i < n; i++) {
            const char *p = ogs_trace_filter_get(i);

            if (!p)
                continue;
            if (i > 0)
                off += snprintf(body + off, body_cap - off, ",");
            off += snprintf(body + off, body_cap - off, "\"%s\"", p);
        }
        off += snprintf(body + off, body_cap - off, "]}\n");
        *body_len = off;
        return 200;
    }

    if (!imsi || !*imsi) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_BAD_REQUEST,
                "use ?imsi=<prefix>|list or ?force=1 to clear");
        return ADMIN_HTTP_BAD_REQUEST;
    }

    if (ogs_trace_filter_add(imsi) != OGS_OK) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "trace_imsi list full");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }

    *body_len = fmt_json_status(body, body_cap, 200,
            "trace_imsi added %s (count=%d)", imsi, ogs_trace_filter_count());
    return 200;
}

void mme_admin_api_register(void)
{
    ogs_metrics_register_admin_ep(mme_admin_enb_detach,
            "/admin/enb/detach",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_ue_detach,
            "/admin/ue/detach",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(mme_admin_trace_imsi,
            "/admin/trace/imsi",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
}
