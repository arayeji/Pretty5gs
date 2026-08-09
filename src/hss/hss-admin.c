/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * HSS admin endpoints for PrettyNMS (loopback/private clients only).
 */

#include "hss-admin.h"
#include "hss-context.h"
#include "hss-s6a-path.h"
#include "hss-trace.h"

#include "ogs-metrics.h"
#include "ogs-diameter-s6a.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define ADMIN_HTTP_OK                  200
#define ADMIN_HTTP_BAD_REQUEST         400
#define ADMIN_HTTP_NOT_FOUND           404

static size_t fmt_json(char *body, size_t cap, int status,
        const char *fmt, ...)
{
    va_list ap;
    char detail[512];
    int written;

    if (!body || cap == 0)
        return 0;

    va_start(ap, fmt);
    written = vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    if (written < 0)
        detail[0] = '\0';

    written = snprintf(body, cap,
            "{\"status\":%d,\"detail\":\"%s\"}\n", status, detail);
    if (written < 0)
        return 0;
    return (size_t)((size_t)written < cap ? (size_t)written : cap - 1);
}

/*
 * POST /admin/s6a/clr?imsi=<IMSI>[&reattach=0|1]
 *
 * Sends S6a Cancel-Location-Request to the serving MME learned from the
 * last ULR (subscription_data.mme_host / mme_realm). Default Cancellation-
 * Type is Subscription Withdrawal with Reattach-Required (reattach=1).
 */
static int hss_admin_s6a_clr(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    ogs_subscription_data_t subscription_data;
    bool reattach;
    int written;

    if (!q || !q->imsi || !q->imsi[0]) {
        *body_len = fmt_json(body, body_cap, ADMIN_HTTP_BAD_REQUEST,
                "missing ?imsi=...");
        return ADMIN_HTTP_BAD_REQUEST;
    }

    reattach = q->has_reattach ? (q->reattach != 0) : true;

    memset(&subscription_data, 0, sizeof(subscription_data));
    if (hss_db_subscription_data((char *)q->imsi, &subscription_data) !=
            OGS_OK) {
        *body_len = fmt_json(body, body_cap, ADMIN_HTTP_NOT_FOUND,
                "subscriber imsi=%s not found", q->imsi);
        return ADMIN_HTTP_NOT_FOUND;
    }

    if (!subscription_data.mme_host || !subscription_data.mme_host[0] ||
            !subscription_data.mme_realm || !subscription_data.mme_realm[0] ||
            subscription_data.purge_flag) {
        ogs_subscription_data_free(&subscription_data);
        *body_len = fmt_json(body, body_cap, ADMIN_HTTP_NOT_FOUND,
                "no serving MME for imsi=%s (need prior ULR)", q->imsi);
        return ADMIN_HTTP_NOT_FOUND;
    }

    ogs_info("[%s] Admin CLR to MME host=%s realm=%s reattach=%d",
            q->imsi, subscription_data.mme_host, subscription_data.mme_realm,
            reattach ? 1 : 0);

    hss_s6a_send_clr_ex((char *)q->imsi,
            subscription_data.mme_host, subscription_data.mme_realm,
            OGS_DIAM_S6A_CT_SUBSCRIPTION_WITHDRAWAL, reattach);

    written = snprintf(body, body_cap,
            "{\"status\":%d,\"detail\":\"CLR sent\","
            "\"imsi\":\"%s\",\"mme_host\":\"%s\",\"mme_realm\":\"%s\","
            "\"cancellation_type\":%u,\"reattach\":%d}\n",
            ADMIN_HTTP_OK, q->imsi,
            subscription_data.mme_host, subscription_data.mme_realm,
            (unsigned)OGS_DIAM_S6A_CT_SUBSCRIPTION_WITHDRAWAL,
            reattach ? 1 : 0);
    *body_len = (written < 0) ? 0 :
            (size_t)((size_t)written < body_cap ? (size_t)written : body_cap - 1);

    ogs_subscription_data_free(&subscription_data);
    return ADMIN_HTTP_OK;
}

void hss_admin_api_register(void)
{
    ogs_metrics_register_admin_ep(hss_admin_trace_imsi_ep,
            "/admin/trace/imsi",
            OGS_METRICS_ADMIN_METHOD_GET);
    ogs_metrics_register_admin_ep(hss_admin_s6a_clr,
            "/admin/s6a/clr",
            OGS_METRICS_ADMIN_METHOD_POST);
}
