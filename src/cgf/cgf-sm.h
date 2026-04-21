/*
 * Copyright (C) 2026 by Open5GS Contributors
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef CGF_SM_H
#define CGF_SM_H

#include "context.h"
#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Top-level state. We use a single "running" state and dispatch all
 * events in it; the real state lives on each cgf_peer_t. */
void cgf_state_initial(ogs_fsm_t *s, ogs_event_t *e);
void cgf_state_final(ogs_fsm_t *s, ogs_event_t *e);
void cgf_state_running(ogs_fsm_t *s, ogs_event_t *e);

/* Callbacks invoked by gtpp-path.c on successful parse. Exposed here
 * so the glue between recv and the FSM is explicit. */
void cgf_sm_on_echo_response(cgf_peer_t *peer, uint16_t seq,
        uint8_t cause, uint8_t recovery, bool recovery_present);
void cgf_sm_on_dtrr_response(cgf_peer_t *peer, uint16_t seq, uint8_t cause);

/* Attempt to drain at least one batch from the active spool file to
 * the active peer. No-op if no peer is UP or if the peer already has
 * a DTRR in flight. */
void cgf_sm_try_drain(void);

/* Timer-driven entry points (also callable from tests). */
void cgf_sm_on_echo_tick(void);
void cgf_sm_on_rto_tick(void);
void cgf_sm_on_spool_tick(void);

#ifdef __cplusplus
}
#endif

#endif /* CGF_SM_H */
