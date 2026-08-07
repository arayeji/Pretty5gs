/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_STORE_H)
#define PTRACE_STORE_H

#include "ptrace.h"

#ifdef __cplusplus
extern "C" {
#endif

int ptrace_store_init(void);
void ptrace_store_final(void);
void ptrace_store_put(ptrace_event_t *evt);
int ptrace_store_query(const char *imsi, const char *ue_ip,
        uint32_t teid, uint64_t seid, uint32_t cause,
        ogs_time_t from, ogs_time_t to,
        ptrace_event_t **out, int max_out);

int ptrace_store_redis_init(const char *url);
void ptrace_store_redis_final(void);
void ptrace_store_redis_put(ptrace_event_t *evt);

int ptrace_store_clickhouse_init(const char *url);
void ptrace_store_clickhouse_final(void);
void ptrace_store_clickhouse_put(ptrace_event_t *evt);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_STORE_H */
