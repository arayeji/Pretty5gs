/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_TRACE_H)
#define PTRACE_TRACE_H

#include "ptrace.h"
#include "correlate.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ptrace_trace_s {
    ogs_lnode_t lnode;
    char id[PTRACE_MAX_ID_LEN];
    char imsi[PTRACE_MAX_ID_LEN];
    uint64_t ue_id;
    ogs_time_t created;
    ogs_time_t until;
    char status[16];
} ptrace_trace_t;

int ptrace_trace_init(void);
void ptrace_trace_final(void);
ptrace_trace_t *ptrace_trace_start(const char *imsi, int duration_sec);
ptrace_trace_t *ptrace_trace_get(const char *id);
bool ptrace_trace_stop(const char *id);
int ptrace_trace_timeline_json(ptrace_trace_t *tr, char *buf, size_t buflen);
int ptrace_trace_export_pcap(ptrace_trace_t *tr, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_TRACE_H */
