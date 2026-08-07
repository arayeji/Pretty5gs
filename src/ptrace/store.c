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
    if (!evt)
        return;
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
