/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "cache.h"

typedef struct cache_node_s {
    ogs_lnode_t lnode;
    ptrace_event_t evt; /* owned copy of metadata */
} cache_node_t;

typedef struct pin_s {
    ogs_lnode_t lnode;
    uint64_t ue_id;
    ogs_time_t until;
} pin_t;

static ogs_list_t meta_list;
static ogs_list_t pin_list;
static ogs_thread_mutex_t lock;
static ogs_time_t window_usec;
static bool ready;
static uint64_t seq;

int ptrace_cache_init(int duration_minutes)
{
    ogs_list_init(&meta_list);
    ogs_list_init(&pin_list);
    ogs_thread_mutex_init(&lock);
    window_usec = ogs_time_from_sec((ogs_time_t)duration_minutes * 60);
    ready = true;
    return OGS_OK;
}

void ptrace_cache_final(void)
{
    cache_node_t *n, *nn;
    pin_t *p, *pn;
    if (!ready)
        return;
    ogs_thread_mutex_lock(&lock);
    for (n = ogs_list_first(&meta_list); n; n = nn) {
        nn = ogs_list_next(n);
        ogs_list_remove(&meta_list, n);
        ogs_free(n);
    }
    for (p = ogs_list_first(&pin_list); p; p = pn) {
        pn = ogs_list_next(p);
        ogs_list_remove(&pin_list, p);
        ogs_free(p);
    }
    ogs_thread_mutex_unlock(&lock);
    ogs_thread_mutex_destroy(&lock);
    ready = false;
}

static bool is_pinned(uint64_t ue_id, ogs_time_t now)
{
    pin_t *p;
    ogs_list_for_each(&pin_list, p) {
        if (p->ue_id == ue_id && p->until > now)
            return true;
    }
    return false;
}

void ptrace_cache_put(ptrace_event_t *evt)
{
    cache_node_t *n;
    if (!evt || !ready)
        return;
    n = ogs_calloc(1, sizeof(*n));
    if (!n)
        return;
    n->evt = *evt;
    n->evt.id = ++seq;
    ogs_thread_mutex_lock(&lock);
    ogs_list_add(&meta_list, n);
    ogs_thread_mutex_unlock(&lock);
}

void ptrace_cache_pin_ue(uint64_t ue_id, ogs_time_t until)
{
    pin_t *p;
    if (!ready || !ue_id)
        return;
    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&pin_list, p) {
        if (p->ue_id == ue_id) {
            if (until > p->until)
                p->until = until;
            ogs_thread_mutex_unlock(&lock);
            return;
        }
    }
    p = ogs_calloc(1, sizeof(*p));
    if (p) {
        p->ue_id = ue_id;
        p->until = until;
        ogs_list_add(&pin_list, p);
    }
    ogs_thread_mutex_unlock(&lock);
}

void ptrace_cache_expire(void)
{
    cache_node_t *n, *nn;
    pin_t *p, *pn;
    ogs_time_t now, cutoff;

    if (!ready)
        return;
    now = ogs_time_now();
    cutoff = now - window_usec;

    ogs_thread_mutex_lock(&lock);
    for (p = ogs_list_first(&pin_list); p; p = pn) {
        pn = ogs_list_next(p);
        if (p->until <= now) {
            ogs_list_remove(&pin_list, p);
            ogs_free(p);
        }
    }
    for (n = ogs_list_first(&meta_list); n; n = nn) {
        nn = ogs_list_next(n);
        if (n->evt.ts >= cutoff || is_pinned(n->evt.ue_id, now))
            continue;
        ogs_list_remove(&meta_list, n);
        ogs_free(n);
    }
    ogs_thread_mutex_unlock(&lock);
}

int ptrace_cache_query_ue(uint64_t ue_id, ogs_time_t from, ogs_time_t to,
        ptrace_event_t **out, int max_out)
{
    cache_node_t *n;
    int count = 0;
    if (!ready || !out || max_out <= 0)
        return 0;

    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&meta_list, n) {
        if (ue_id && n->evt.ue_id != ue_id)
            continue;
        if (from && n->evt.ts < from)
            continue;
        if (to && n->evt.ts > to)
            continue;
        out[count++] = &n->evt;
        if (count >= max_out)
            break;
    }
    ogs_thread_mutex_unlock(&lock);
    return count;
}
