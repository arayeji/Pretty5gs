/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_CACHE_H)
#define PTRACE_CACHE_H

#include "ptrace.h"

#ifdef __cplusplus
extern "C" {
#endif

int ptrace_cache_init(int duration_minutes);
void ptrace_cache_final(void);
void ptrace_cache_put(ptrace_event_t *evt);
void ptrace_cache_pin_ue(uint64_t ue_id, ogs_time_t until);
bool ptrace_cache_ue_is_pinned(uint64_t ue_id);
void ptrace_cache_remap_ue(uint64_t from_id, uint64_t to_id);
int ptrace_cache_query_ue(uint64_t ue_id, ogs_time_t from, ogs_time_t to,
        ptrace_event_t **out, int max_out);

typedef bool (*ptrace_cache_match_cb)(const ptrace_event_t *evt, void *user);
int ptrace_cache_query_match(ptrace_cache_match_cb match, void *user,
        ogs_time_t from, ogs_time_t to,
        ptrace_event_t **out, int max_out);

void ptrace_cache_expire(void);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_CACHE_H */
