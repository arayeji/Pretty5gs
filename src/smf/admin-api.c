/*
 * Copyright (C) 2026 by Open5GS contributors
 *
 * SMF admin endpoints (maintenance mode + graceful drain).
 */

#include "ogs-core.h"
#include "ogs-app.h"

#include "context.h"
#include "event.h"

#include "admin-api.h"
#include "runtime-config.h"

#include <stdarg.h>
#include <string.h>
#include <inttypes.h>

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

static int smf_count_sessions(void)
{
    smf_ue_t *ue = NULL;
    int count = 0;

    ogs_list_for_each(&smf_self()->smf_ue_list, ue)
        count += ogs_list_count(&ue->sess_list);

    return count;
}

static void smf_admin_set_maintenance(bool maintenance)
{
    ogs_metrics_dump_lock();
    smf_self()->maintenance_mode = maintenance;
    ogs_metrics_dump_unlock();
}

static int smf_admin_maintenance_queue(smf_event_e id, int force,
        char *body, size_t body_cap, size_t *body_len)
{
    smf_event_t *e = NULL;
    int rv;

    e = smf_event_new(id);
    if (!e) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->admin_force = force;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_event_free(e);
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_SERVICE_UNAVAIL, "event queue full");
        return ADMIN_HTTP_SERVICE_UNAVAIL;
    }

    ogs_pollset_notify(ogs_app()->pollset);

    *body_len = fmt_json_status(body, body_cap, ADMIN_HTTP_ACCEPTED,
            "maintenance event queued");
    return ADMIN_HTTP_ACCEPTED;
}

size_t smf_dump_maintenance_status(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    int sess_count = 0;
    bool maintenance = false;
    bool drain_active = false;
    uint32_t drain_processed = 0;
    int written;

    (void)page;
    (void)page_size;
    (void)q;

    if (!buf || buflen == 0)
        return 0;

    ogs_metrics_dump_lock();
    maintenance = smf_self()->maintenance_mode;
    drain_active = smf_self()->drain_active;
    drain_processed = smf_self()->drain_processed;
    sess_count = smf_count_sessions();
    ogs_metrics_dump_unlock();

    written = snprintf(buf, buflen,
            "{\"maintenance\":%s,\"session_count\":%d,"
            "\"drain\":{\"active\":%s,\"processed\":%u}}\n",
            maintenance ? "true" : "false", sess_count,
            drain_active ? "true" : "false", drain_processed);
    if (written < 0)
        return 0;
    return (size_t)((size_t)written < buflen ? (size_t)written : buflen - 1);
}

static int smf_admin_maintenance_status(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    size_t n;

    (void)q;

    n = smf_dump_maintenance_status(body, body_cap, 0, 0, NULL);
    if (n == 0) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "status encode failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    *body_len = n;
    return 200;
}

static int smf_admin_maintenance_enable(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    (void)q;
    smf_admin_set_maintenance(true);
    (void)smf_admin_maintenance_queue(
            SMF_EVT_ADMIN_MAINTENANCE_ENABLE, 0,
            body, body_cap, body_len);
    return smf_admin_maintenance_status(q, body, body_cap, body_len);
}

static int smf_admin_maintenance_disable(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    (void)q;
    smf_admin_set_maintenance(false);
    (void)smf_admin_maintenance_queue(
            SMF_EVT_ADMIN_MAINTENANCE_DISABLE, 0,
            body, body_cap, body_len);
    return smf_admin_maintenance_status(q, body, body_cap, body_len);
}

static int smf_admin_maintenance_drain(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    smf_admin_set_maintenance(true);
    return smf_admin_maintenance_queue(
            SMF_EVT_ADMIN_MAINTENANCE_DRAIN, q && q->force,
            body, body_cap, body_len);
}

static int smf_admin_session_detach(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    if (!q || !q->imsi || !*q->imsi) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_BAD_REQUEST, "missing ?imsi=...");
        return ADMIN_HTTP_BAD_REQUEST;
    }

    ogs_pool_id_t smf_ue_id = OGS_INVALID_POOL_ID;

    ogs_metrics_dump_lock();
    smf_ue_t *smf_ue = smf_ue_find_by_imsi_bcd(q->imsi);
    if (smf_ue) smf_ue_id = smf_ue->id;
    ogs_metrics_dump_unlock();

    if (smf_ue_id == OGS_INVALID_POOL_ID) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_NOT_FOUND, "session not found");
        return ADMIN_HTTP_NOT_FOUND;
    }

    smf_event_t *e = smf_event_new(SMF_EVT_ADMIN_DETACH_SESSION);
    if (!e) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->smf_ue_id = smf_ue_id;
    e->admin_force = q->force ? 1 : 0;

    int rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_event_free(e);
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_SERVICE_UNAVAIL, "event queue full");
        return ADMIN_HTTP_SERVICE_UNAVAIL;
    }

    ogs_pollset_notify(ogs_app()->pollset);

    *body_len = fmt_json_status(body, body_cap, ADMIN_HTTP_ACCEPTED,
            "session detach queued for imsi=%s mode=%s",
            q->imsi, e->admin_force ? "force" : "graceful");
    return ADMIN_HTTP_ACCEPTED;
}

/*
 * GET /admin/seids
 *
 * Lightweight companion for the NMS stale-session audit: emits ONLY the UPF
 * F-SEIDs this SMF currently owns, one hex value per line, no JSON tree. At
 * 200k sessions this is ~2 MB and a single list pass. The NMS diffs this set
 * against `vppctl show upf association` on the PGW-U/UPF and purges (via
 * /admin/pfcp/purge-seid) any SEID present on VPP but absent here.
 */
static size_t smf_admin_list_seids(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    smf_ue_t *ue = NULL;
    smf_sess_t *sess = NULL;
    char tmp[32];
    size_t pos = 0;
    bool overflow = false;

    (void)page; (void)page_size; (void)q;

    ogs_metrics_dump_lock();
    ogs_list_for_each(&smf_self()->smf_ue_list, ue) {
        ogs_list_for_each(&ue->sess_list, sess) {
            int n;
            if (!sess->upf_n4_seid)
                continue;
            n = snprintf(tmp, sizeof(tmp), "0x%"PRIx64"\n",
                    sess->upf_n4_seid);
            if (n > 0 && pos + (size_t)n < buflen) {
                memcpy(buf + pos, tmp, (size_t)n);
                pos += (size_t)n;
            } else if (n > 0) {
                overflow = true;
            }
        }
    }
    ogs_metrics_dump_unlock();

    /*
     * A truncated SEID list would make the NMS treat the missing sessions
     * as stale and purge them. Returning >= buflen-1 makes the HTTP layer
     * double the buffer and call us again until everything fits.
     */
    if (overflow)
        return buflen;

    return pos;
}

/*
 * POST /admin/pfcp/purge-seid?seid=0x<hex>[&ip=<upf-addr>]
 *
 * Deletes a single stale PFCP session on the UPF by raw UP F-SEID, for SEIDs
 * the NMS audit found on VPP but not in /admin/seids. No local session
 * context is needed or touched; SMF just emits a PFCP Session Deletion to
 * the UPF. With one associated UPF the address is optional; with several,
 * pass ?ip= to name the owner.
 */
static int smf_admin_purge_seid(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    ogs_sockaddr_t *upf_addr = NULL;

    if (!q || !q->has_seid || !q->seid) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_BAD_REQUEST, "missing or invalid ?seid=0x...");
        return ADMIN_HTTP_BAD_REQUEST;
    }

    if (q->ip && *q->ip) {
        if (ogs_getaddrinfo(&upf_addr, AF_UNSPEC, q->ip,
                    ogs_pfcp_self()->pfcp_port, 0) != OGS_OK || !upf_addr) {
            *body_len = fmt_json_status(body, body_cap,
                    ADMIN_HTTP_BAD_REQUEST, "invalid ?ip=%s", q->ip);
            return ADMIN_HTTP_BAD_REQUEST;
        }
    }

    smf_event_t *e = smf_event_new(SMF_EVT_ADMIN_PURGE_SEID);
    if (!e) {
        if (upf_addr) ogs_freeaddrinfo(upf_addr);
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->admin_seid = q->seid;
    e->admin_upf_addr = upf_addr; /* freed by the event handler */

    int rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        if (upf_addr) ogs_freeaddrinfo(upf_addr);
        ogs_event_free(e);
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_SERVICE_UNAVAIL, "event queue full");
        return ADMIN_HTTP_SERVICE_UNAVAIL;
    }

    ogs_pollset_notify(ogs_app()->pollset);

    *body_len = fmt_json_status(body, body_cap, ADMIN_HTTP_ACCEPTED,
            "purge-seid queued seid=0x%"PRIx64"%s%s",
            q->seid, (q->ip && *q->ip) ? " ip=" : "",
            (q->ip && *q->ip) ? q->ip : "");
    return ADMIN_HTTP_ACCEPTED;
}

void smf_admin_api_register(void)
{
    ogs_metrics_register_custom_ep(smf_dump_runtime_config,
            "/admin/config");
    ogs_metrics_register_custom_ep(smf_dump_maintenance_status,
            "/admin/maintenance");
    ogs_metrics_register_admin_ep(smf_admin_maintenance_enable,
            "/admin/maintenance/enable",
            OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(smf_admin_maintenance_enable,
            "/admin/maintenance",
            OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(smf_admin_maintenance_disable,
            "/admin/maintenance/disable",
            OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(smf_admin_maintenance_drain,
            "/admin/maintenance/drain",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(smf_admin_maintenance_status,
            "/admin/maintenance/status",
            OGS_METRICS_ADMIN_METHOD_GET);
    ogs_metrics_register_admin_ep(ogs_metrics_admin_trace_imsi,
            "/admin/trace/imsi",
            OGS_METRICS_ADMIN_METHOD_GET);
    ogs_metrics_register_admin_ep(smf_admin_session_detach,
            "/admin/session/detach",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);

    /* SEID-only listing for the NMS stale-session audit (lightweight). */
    ogs_metrics_register_custom_ep(smf_admin_list_seids,
            "/admin/seids");

    /* Purge one stale UPF SEID: POST /admin/pfcp/purge-seid?seid=0x..[&ip=] */
    ogs_metrics_register_admin_ep(smf_admin_purge_seid,
            "/admin/pfcp/purge-seid",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
}
