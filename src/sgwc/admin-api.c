/*
 * Copyright (C) 2026 by Open5GS contributors
 *
 * SGWC admin endpoints (maintenance mode + graceful drain).
 */

#include "ogs-core.h"
#include "ogs-app.h"

#include "context.h"
#include "event.h"

#include "admin-api.h"
#include "runtime-config.h"

#include <stdarg.h>
#include <string.h>

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
}
