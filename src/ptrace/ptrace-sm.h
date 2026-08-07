/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_SM_H)
#define PTRACE_SM_H

#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

void ptrace_state_initial(ogs_fsm_t *s, ptrace_fsm_event_t *e);
void ptrace_state_final(ogs_fsm_t *s, ptrace_fsm_event_t *e);
void ptrace_state_operational(ogs_fsm_t *s, ptrace_fsm_event_t *e);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_SM_H */
