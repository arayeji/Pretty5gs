/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "event.h"

void ptrace_event_term(void)
{
}

ptrace_fsm_event_t *ptrace_fsm_event_new(ptrace_fsm_event_e id)
{
    ptrace_fsm_event_t *e = ogs_calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    e->id = id;
    return e;
}

void ptrace_fsm_event_free(ptrace_fsm_event_t *e)
{
    if (!e)
        return;
    if (e->pkt)
        ptrace_packet_free(e->pkt);
    ogs_free(e);
}
