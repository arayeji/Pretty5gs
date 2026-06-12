/*
 * Copyright (C) 2026 by Open5GS contributors
 */

#include "ogs-metrics.h"
#include "trace-admin.h"

#include <string.h>
#include <strings.h>

#define TRACE_ADMIN_HTTP_OK           200
#define TRACE_ADMIN_HTTP_BAD_REQUEST  400
#define TRACE_ADMIN_HTTP_INTERNAL     500

static size_t trace_admin_append_list(char *body, size_t cap, size_t off)
{
    int i, n;

    if (off >= cap)
        return off;

    off += (size_t)snprintf(body + off, cap - off, "\"trace_imsi\":[");
    n = ogs_trace_filter_count();
    for (i = 0; i < n; i++) {
        char imsi[OGS_TRACE_IMSI_LEN];

        if (ogs_trace_filter_get(i, imsi, sizeof(imsi)) != OGS_OK)
            continue;
        if (i > 0 && off < cap)
            off += (size_t)snprintf(body + off, cap - off, ",");
        if (off < cap)
            off += (size_t)snprintf(body + off, cap - off, "\"%s\"", imsi);
    }
    if (off < cap)
        off += (size_t)snprintf(body + off, cap - off, "]");
    return off;
}

static size_t trace_admin_fmt(char *body, size_t cap, bool ok,
        const char *detail, int http_status)
{
    size_t off = 0;

    if (!body || cap == 0)
        return 0;

    off += (size_t)snprintf(body + off, cap - off,
            "{\"ok\":%s,\"detail\":\"%s\",",
            ok ? "true" : "false", detail ? detail : "");
    off = trace_admin_append_list(body, cap, off);
    if (off < cap)
        off += (size_t)snprintf(body + off, cap - off, "}\n");

    (void)http_status;
    return off;
}

static bool trace_admin_match_exact(const ogs_metrics_query_t *q)
{
    const char *m;

    if (!q || !q->match)
        return false;
    return strcasecmp(q->match, "exact") == 0;
}

int ogs_metrics_admin_trace_imsi(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    const char *imsi = (q && q->imsi) ? q->imsi : NULL;
    bool exact = trace_admin_match_exact(q);
    char detail[256];
    int rv;

    if (!body || body_cap == 0 || !body_len)
        return TRACE_ADMIN_HTTP_BAD_REQUEST;

    if (q && q->force) {
        ogs_trace_filter_clear();
        *body_len = trace_admin_fmt(body, body_cap, true,
                "trace_imsi filters cleared", TRACE_ADMIN_HTTP_OK);
        return TRACE_ADMIN_HTTP_OK;
    }

    if (imsi && strcmp(imsi, "list") == 0) {
        ogs_snprintf(detail, sizeof(detail), "listed %d prefix(es)",
                ogs_trace_filter_count());
        *body_len = trace_admin_fmt(body, body_cap, true, detail,
                TRACE_ADMIN_HTTP_OK);
        return TRACE_ADMIN_HTTP_OK;
    }

    if (!imsi || !imsi[0]) {
        *body_len = trace_admin_fmt(body, body_cap, false,
                "use ?imsi=<prefix>|list, ?force=1, ?remove=1, or ?replace=1",
                TRACE_ADMIN_HTTP_BAD_REQUEST);
        return TRACE_ADMIN_HTTP_BAD_REQUEST;
    }

    if (q->remove) {
        rv = ogs_trace_filter_remove(imsi);
        if (rv != OGS_OK) {
            *body_len = trace_admin_fmt(body, body_cap, false,
                    "trace_imsi prefix not found", TRACE_ADMIN_HTTP_BAD_REQUEST);
            return TRACE_ADMIN_HTTP_BAD_REQUEST;
        }
        ogs_snprintf(detail, sizeof(detail),
                "trace_imsi removed %s (count=%d)", imsi,
                ogs_trace_filter_count());
        *body_len = trace_admin_fmt(body, body_cap, true, detail,
                TRACE_ADMIN_HTTP_OK);
        return TRACE_ADMIN_HTTP_OK;
    }

    if (q->replace) {
        rv = ogs_trace_filter_replace_ex(imsi, exact);
        if (rv != OGS_OK) {
            *body_len = trace_admin_fmt(body, body_cap, false,
                    "trace_imsi replace failed", TRACE_ADMIN_HTTP_INTERNAL);
            return TRACE_ADMIN_HTTP_INTERNAL;
        }
        ogs_snprintf(detail, sizeof(detail),
                "trace_imsi replaced with %s%s (count=%d)", imsi,
                exact ? " [exact]" : "", ogs_trace_filter_count());
        *body_len = trace_admin_fmt(body, body_cap, true, detail,
                TRACE_ADMIN_HTTP_OK);
        return TRACE_ADMIN_HTTP_OK;
    }

    rv = ogs_trace_filter_add_ex(imsi, exact);
    if (rv != OGS_OK) {
        *body_len = trace_admin_fmt(body, body_cap, false,
                "trace_imsi list full", TRACE_ADMIN_HTTP_INTERNAL);
        return TRACE_ADMIN_HTTP_INTERNAL;
    }

    ogs_snprintf(detail, sizeof(detail),
            "trace_imsi added %s%s (count=%d)", imsi,
            exact ? " [exact]" : "", ogs_trace_filter_count());
    *body_len = trace_admin_fmt(body, body_cap, true, detail,
            TRACE_ADMIN_HTTP_OK);
    return TRACE_ADMIN_HTTP_OK;
}
