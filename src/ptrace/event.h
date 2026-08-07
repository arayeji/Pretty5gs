/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_EVENT_H)
#define PTRACE_EVENT_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PTRACE_EVT_STOP = 0,
    PTRACE_EVT_PACKET,
    PTRACE_EVT_EXPIRE,
} ptrace_fsm_event_e;

typedef struct ptrace_fsm_event_s {
    ptrace_fsm_event_e id;
    ptrace_packet_t *pkt;
} ptrace_fsm_event_t;

void ptrace_event_term(void);
ptrace_fsm_event_t *ptrace_fsm_event_new(ptrace_fsm_event_e id);
void ptrace_fsm_event_free(ptrace_fsm_event_t *e);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_EVENT_H */
