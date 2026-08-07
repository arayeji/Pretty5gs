/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "ptrace-sm.h"

void ptrace_state_initial(ogs_fsm_t *s, ptrace_fsm_event_t *e)
{
    ogs_assert(s);
    (void)e;
    OGS_FSM_TRAN(s, &ptrace_state_operational);
}

void ptrace_state_final(ogs_fsm_t *s, ptrace_fsm_event_t *e)
{
    (void)s;
    (void)e;
}

void ptrace_state_operational(ogs_fsm_t *s, ptrace_fsm_event_t *e)
{
    ogs_assert(s);
    if (!e)
        return;

    if (e->id == PTRACE_EVT_STOP)
        OGS_FSM_TRAN(s, &ptrace_state_final);
}
