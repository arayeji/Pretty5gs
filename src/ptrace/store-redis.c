/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Optional Redis hot-map sync via hiredis (stub if unavailable).
 */

#include "store.h"

#if defined(HAVE_HIREDIS)
#include <hiredis/hiredis.h>
static redisContext *rctx;
#endif

int ptrace_store_redis_init(const char *url)
{
#if defined(HAVE_HIREDIS)
    if (!url || !url[0])
        return OGS_OK;
    /* Expect redis://host:port — minimal parse */
    {
        char host[128] = "127.0.0.1";
        int port = 6379;
        const char *p = url;
        if (!strncmp(p, "redis://", 8))
            p += 8;
        sscanf(p, "%127[^:]:%d", host, &port);
        rctx = redisConnect(host, port);
        if (!rctx || rctx->err) {
            ogs_error("redis connect failed");
            if (rctx) {
                redisFree(rctx);
                rctx = NULL;
            }
            return OGS_ERROR;
        }
        ogs_info("ptrace Redis connected %s:%d", host, port);
    }
    return OGS_OK;
#else
    (void)url;
    ogs_warn("ptrace: Redis requested but hiredis not built in");
    return OGS_OK;
#endif
}

void ptrace_store_redis_final(void)
{
#if defined(HAVE_HIREDIS)
    if (rctx) {
        redisFree(rctx);
        rctx = NULL;
    }
#endif
}

void ptrace_store_redis_put(ptrace_event_t *evt)
{
#if defined(HAVE_HIREDIS)
    redisReply *reply;
    if (!rctx || !evt || !evt->ids.imsi[0])
        return;
    reply = redisCommand(rctx,
            "HSET ptrace:ue:%s last_msg %s teid %u seid %llu",
            evt->ids.imsi, evt->message,
            evt->ids.has_teid ? evt->ids.teid : 0,
            (unsigned long long)evt->ids.seid);
    if (reply)
        freeReplyObject(reply);
#else
    (void)evt;
#endif
}
