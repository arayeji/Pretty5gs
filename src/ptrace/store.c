/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "store.h"
#include "cache.h"
#include "context.h"

int ptrace_store_init(void)
{
    return OGS_OK;
}

void ptrace_store_final(void)
{
}

void ptrace_store_put(ptrace_event_t *evt)
{
    ptrace_context_t *ctx = ptrace_self();
    bool keep;

    if (!evt)
        return;

    /* Caching every S1AP frame OOM/stalls workers. Keep identity and
     * session-critical messages only. */
    keep = evt->ids.imsi[0] || evt->ids.guti[0] || evt->ids.msisdn[0] ||
            evt->ids.imei[0] || evt->ids.ue_ip[0] ||
            evt->ids.num_teids > 0 || evt->ids.has_teid ||
            evt->ids.has_seid ||
            evt->ids.has_enb_ue_s1ap_id || evt->ids.has_mme_ue_s1ap_id ||
            evt->ids.has_diam_hbh ||
            (evt->message[0] && (
                strstr(evt->message, "Attach") ||
                strstr(evt->message, "Identity") ||
                strstr(evt->message, "Reject") ||
                strstr(evt->message, "Detach") ||
                strstr(evt->message, "Create Session") ||
                strstr(evt->message, "Modify Bearer") ||
                strstr(evt->message, "Session Establishment") ||
                strstr(evt->message, "Session Modification") ||
                strstr(evt->message, "Initial UE") ||
                strstr(evt->message, "NAS") ||
                strstr(evt->message, "Context Setup") ||
                strstr(evt->message, "UE Context") ||
                !strcmp(evt->message, "AIR") ||
                !strcmp(evt->message, "AIA") ||
                !strcmp(evt->message, "ULR") ||
                !strcmp(evt->message, "ULA") ||
                strstr(evt->message, "PFCP")));

    if (keep)
        ptrace_cache_put(evt);
    if (ctx->redis_enabled)
        ptrace_store_redis_put(evt);
    if (ctx->clickhouse_enabled)
        ptrace_store_clickhouse_put(evt);
    ctx->events_out++;
}

int ptrace_store_query(const char *imsi, const char *ue_ip,
        uint32_t teid, uint64_t seid, uint32_t cause,
        ogs_time_t from, ogs_time_t to,
        ptrace_event_t **out, int max_out)
{
    ptrace_event_t *tmp[PTRACE_MAX_TIMELINE];
    int n, i, count = 0;

    n = ptrace_cache_query_ue(0, from, to, tmp, PTRACE_MAX_TIMELINE);
    for (i = 0; i < n && count < max_out; i++) {
        ptrace_event_t *e = tmp[i];
        if (imsi && imsi[0] && strcmp(e->ids.imsi, imsi))
            continue;
        if (ue_ip && ue_ip[0] && strcmp(e->ids.ue_ip, ue_ip))
            continue;
        if (teid && (!e->ids.has_teid || e->ids.teid != teid))
            continue;
        if (seid && (!e->ids.has_seid || e->ids.seid != seid))
            continue;
        if (cause && e->cause_code != cause)
            continue;
        out[count++] = e;
    }
    return count;
}
