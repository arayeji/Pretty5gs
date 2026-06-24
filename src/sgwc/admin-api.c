/*
 * Copyright (C) 2026 by Open5GS contributors
 *
 * SGWC admin endpoints (maintenance mode + graceful drain).
 */

#include "ogs-core.h"
#include "ogs-app.h"
#include "ogs-gtp.h"

#include "context.h"
#include "event.h"
#include "gtp-path.h"
#include "pfcp-path.h"

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

static int sgwc_count_sessions(void)
{
    sgwc_ue_t *ue = NULL;
    int count = 0;

    ogs_list_for_each(&sgwc_self()->sgw_ue_list, ue)
        count += ogs_list_count(&ue->sess_list);

    return count;
}

static void sgwc_admin_set_maintenance(bool maintenance)
{
    ogs_metrics_dump_lock();
    sgwc_self()->maintenance_mode = maintenance;
    ogs_metrics_dump_unlock();
}

static int sgwc_admin_maintenance_queue(sgwc_event_e id, int force,
        char *body, size_t body_cap, size_t *body_len)
{
    sgwc_event_t *e = NULL;
    int rv;

    e = sgwc_event_new(id);
    if (!e) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->admin_force = force;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        sgwc_event_free(e);
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_SERVICE_UNAVAIL, "event queue full");
        return ADMIN_HTTP_SERVICE_UNAVAIL;
    }

    ogs_pollset_notify(ogs_app()->pollset);

    *body_len = fmt_json_status(body, body_cap, ADMIN_HTTP_ACCEPTED,
            "maintenance event queued");
    return ADMIN_HTTP_ACCEPTED;
}

size_t sgwc_dump_maintenance_status(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    int sess_count = 0;
    bool maintenance = false;
    int written;

    (void)page;
    (void)page_size;
    (void)q;

    if (!buf || buflen == 0)
        return 0;

    ogs_metrics_dump_lock();
    maintenance = sgwc_self()->maintenance_mode;
    sess_count = sgwc_count_sessions();
    ogs_metrics_dump_unlock();

    written = snprintf(buf, buflen,
            "{\"maintenance\":%s,\"session_count\":%d}\n",
            maintenance ? "true" : "false", sess_count);
    if (written < 0)
        return 0;
    return (size_t)((size_t)written < buflen ? (size_t)written : buflen - 1);
}

static int sgwc_admin_maintenance_status(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    size_t n;

    (void)q;

    n = sgwc_dump_maintenance_status(body, body_cap, 0, 0, NULL);
    if (n == 0) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "status encode failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    *body_len = n;
    return 200;
}

static int sgwc_admin_maintenance_enable(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    (void)q;
    sgwc_admin_set_maintenance(true);
    (void)sgwc_admin_maintenance_queue(
            SGWC_EVT_ADMIN_MAINTENANCE_ENABLE, 0,
            body, body_cap, body_len);
    return sgwc_admin_maintenance_status(q, body, body_cap, body_len);
}

static int sgwc_admin_maintenance_disable(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    (void)q;
    sgwc_admin_set_maintenance(false);
    (void)sgwc_admin_maintenance_queue(
            SGWC_EVT_ADMIN_MAINTENANCE_DISABLE, 0,
            body, body_cap, body_len);
    return sgwc_admin_maintenance_status(q, body, body_cap, body_len);
}

static int sgwc_admin_maintenance_drain(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    sgwc_admin_set_maintenance(true);
    return sgwc_admin_maintenance_queue(
            SGWC_EVT_ADMIN_MAINTENANCE_DRAIN, q && q->force,
            body, body_cap, body_len);
}

static int sgwc_admin_session_detach(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    if (!q || !q->imsi || !*q->imsi) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_BAD_REQUEST, "missing ?imsi=...");
        return ADMIN_HTTP_BAD_REQUEST;
    }

    ogs_pool_id_t sgwc_ue_id = OGS_INVALID_POOL_ID;

    ogs_metrics_dump_lock();
    sgwc_ue_t *sgwc_ue = sgwc_ue_find_by_imsi_bcd(q->imsi);
    if (sgwc_ue) sgwc_ue_id = sgwc_ue->id;
    ogs_metrics_dump_unlock();

    if (sgwc_ue_id == OGS_INVALID_POOL_ID) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_NOT_FOUND, "session not found");
        return ADMIN_HTTP_NOT_FOUND;
    }

    sgwc_event_t *e = sgwc_event_new(SGWC_EVT_ADMIN_DETACH_SESSION);
    if (!e) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->sgwc_ue_id = sgwc_ue_id;
    e->admin_force = q->force ? 1 : 0;

    int rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        sgwc_event_free(e);
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
 * DELETE /admin/session/delete?imsi=<IMSI>[&apn=<APN>][&force=1]
 *
 * When apn is omitted: tears down ALL sessions for the IMSI (same as detach).
 * When apn is supplied: tears down only the session for that specific APN,
 * leaving other PDN connections for the same UE intact.
 *
 * The teardown chain covers the full path:
 *   SGW-C  ->  SGW-U (PFCP delete)
 *   SGW-C  ->  SMF   (S5 Delete Session Request)
 *   SGW-C  ->  MME   (S11 Delete Session Request, so MME also cleans up)
 */
static int sgwc_admin_session_delete(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    if (!q || !q->imsi || !*q->imsi) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_BAD_REQUEST, "missing ?imsi=...");
        return ADMIN_HTTP_BAD_REQUEST;
    }

    /* No APN filter -> same as full detach */
    if (!q->apn || !*q->apn)
        return sgwc_admin_session_detach(q, body, body_cap, body_len);

    ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;

    ogs_metrics_dump_lock();
    sgwc_ue_t *sgwc_ue = sgwc_ue_find_by_imsi_bcd(q->imsi);
    if (sgwc_ue) {
        /* Strip APN-OI if present (accept "internet" and "internet.mnc001.mcc001.gprs") */
        char apn_ni[OGS_MAX_APN_LEN + 1];
        snprintf(apn_ni, sizeof(apn_ni), "%s", q->apn);
        char *oi = ogs_dnn_oi_from_fqdn(apn_ni);
        if (oi && oi > apn_ni && oi[-1] == '.') oi[-1] = '\0';

        sgwc_sess_t *sess = sgwc_sess_find_by_apn(sgwc_ue, apn_ni);
        if (sess) sess_id = sess->id;
    }
    ogs_metrics_dump_unlock();

    if (sess_id == OGS_INVALID_POOL_ID) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_NOT_FOUND, "session not found for imsi=%s apn=%s",
                q->imsi, q->apn);
        return ADMIN_HTTP_NOT_FOUND;
    }

    sgwc_event_t *e = sgwc_event_new(SGWC_EVT_ADMIN_DETACH_SESS_ONE);
    if (!e) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->admin_sess_id = sess_id;
    e->admin_force   = q->force ? 1 : 0;

    int rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        sgwc_event_free(e);
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_SERVICE_UNAVAIL, "event queue full");
        return ADMIN_HTTP_SERVICE_UNAVAIL;
    }

    ogs_pollset_notify(ogs_app()->pollset);

    *body_len = fmt_json_status(body, body_cap, ADMIN_HTTP_ACCEPTED,
            "session delete queued for imsi=%s apn=%s mode=%s",
            q->imsi, q->apn, e->admin_force ? "force" : "graceful");
    return ADMIN_HTTP_ACCEPTED;
}

/*
 * GET  /admin/sessions[?imsi=<IMSI>][?orphan=1]
 *
 * Lists all SGW-C sessions as a JSON array.  With ?orphan=1 only sessions
 * that were never fully established (incomplete attach) or have no SGW-U
 * PFCP session are returned.
 */
static size_t sgwc_admin_list_sessions(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    sgwc_ue_t *ue = NULL;
    sgwc_sess_t *sess = NULL;
    char tmp[256];
    size_t pos = 0;
    int first = 1;
    bool orphan_only = false;

    (void)page; (void)page_size;

    if (q && q->orphan)
        orphan_only = true;

#define APPEND(fmt, ...) \
    do { \
        int _n = snprintf(tmp, sizeof(tmp), fmt, ##__VA_ARGS__); \
        if (_n > 0 && pos + (size_t)_n < buflen) { \
            memcpy(buf + pos, tmp, (size_t)_n); \
            pos += (size_t)_n; \
        } \
    } while(0)

    APPEND("{\"sessions\":[");

    /*
     * This dumper runs in the Prometheus/MHD HTTP thread, while the main
     * worker thread mutates sgw_ue_list / sess_list under the metrics dump
     * lock (see sgwc_ue_remove / sgwc_sess_remove). Hold the same lock here
     * so we never walk a list that is being spliced underneath us.
     */
    ogs_metrics_dump_lock();
    ogs_list_for_each(&sgwc_self()->sgw_ue_list, ue) {
        if (q && q->imsi && *q->imsi &&
                strcmp(ue->imsi_bcd, q->imsi) != 0)
            continue;

        ogs_list_for_each(&ue->sess_list, sess) {
            bool is_orphan = (!sess->metrics_session_counted ||
                              sess->sgwu_sxa_seid == 0);
            if (orphan_only && !is_orphan) continue;

            if (!first) APPEND(",");
            first = 0;
            APPEND("{\"imsi\":\"%s\","
                   "\"apn\":\"%s\","
                   "\"orphan\":%s,"
                   "\"pfcp_seid\":\"0x%"PRIx64"\","
                   "\"smf_connected\":%s}",
                   ue->imsi_bcd,
                   sess->session.name ? sess->session.name : "",
                   is_orphan ? "true" : "false",
                   sess->sgwu_sxa_seid,
                   sess->gnode ? "true" : "false");
        }
    }
    ogs_metrics_dump_unlock();

    APPEND("]}\n");
#undef APPEND

    return pos;
}

/*
 * POST /admin/sessions/purge-orphans[?force=1]
 *
 * Deletes all sessions that are orphaned — i.e. never completed the
 * full attach (metrics_session_counted==0) or have no SGW-U PFCP session.
 * Each session teardown sends:
 *   - PFCP Session Deletion  -> SGW-U (VPP)
 *   - S5 Delete Session Req  -> SMF
 * MME is not notified (these sessions have no live MME context by definition).
 */
static int sgwc_admin_purge_orphans(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    sgwc_event_t *e = sgwc_event_new(SGWC_EVT_ADMIN_PURGE_ORPHANS);
    if (!e) {
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_INTERNAL_ERROR, "event_new failed");
        return ADMIN_HTTP_INTERNAL_ERROR;
    }
    e->admin_force = 1; /* orphan purge is always a forced immediate removal */

    int rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        sgwc_event_free(e);
        *body_len = fmt_json_status(body, body_cap,
                ADMIN_HTTP_SERVICE_UNAVAIL, "event queue full");
        return ADMIN_HTTP_SERVICE_UNAVAIL;
    }

    ogs_pollset_notify(ogs_app()->pollset);

    *body_len = fmt_json_status(body, body_cap, ADMIN_HTTP_ACCEPTED,
            "orphan purge queued");
    return ADMIN_HTTP_ACCEPTED;
}

void sgwc_admin_api_register(void)
{
    ogs_metrics_register_custom_ep(sgwc_dump_runtime_config,
            "/admin/config");
    ogs_metrics_register_custom_ep(sgwc_dump_maintenance_status,
            "/admin/maintenance");
    ogs_metrics_register_admin_ep(sgwc_admin_maintenance_enable,
            "/admin/maintenance/enable",
            OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(sgwc_admin_maintenance_enable,
            "/admin/maintenance",
            OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(sgwc_admin_maintenance_disable,
            "/admin/maintenance/disable",
            OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(sgwc_admin_maintenance_drain,
            "/admin/maintenance/drain",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
    ogs_metrics_register_admin_ep(sgwc_admin_maintenance_status,
            "/admin/maintenance/status",
            OGS_METRICS_ADMIN_METHOD_GET);
    ogs_metrics_register_admin_ep(ogs_metrics_admin_trace_imsi,
            "/admin/trace/imsi",
            OGS_METRICS_ADMIN_METHOD_GET);
    ogs_metrics_register_admin_ep(sgwc_admin_session_detach,
            "/admin/session/detach",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);

    /* Session delete: ?imsi=<IMSI>[&apn=<APN>][&force=1]
     * With APN:    tears down the single named PDN connection across all NFs.
     * Without APN: tears down all sessions for the IMSI (same as detach). */
    ogs_metrics_register_admin_ep(sgwc_admin_session_delete,
            "/admin/session/delete",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);

    /* Session list: GET /admin/sessions[?imsi=<IMSI>][?orphan=1] */
    ogs_metrics_register_custom_ep(sgwc_admin_list_sessions,
            "/admin/sessions");

    /* Orphan purge: POST /admin/sessions/purge-orphans
     * Removes all sessions that never completed attach or have no SGW-U path.
     * Sends PFCP delete to SGW-U (VPP) and S5 delete to SMF for each. */
    ogs_metrics_register_admin_ep(sgwc_admin_purge_orphans,
            "/admin/sessions/purge-orphans",
            OGS_METRICS_ADMIN_METHOD_GET | OGS_METRICS_ADMIN_METHOD_POST);
}
