/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef SMF_SM_H
#define SMF_SM_H

#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

void smf_state_initial(ogs_fsm_t *s, smf_event_t *e);
void smf_state_final(ogs_fsm_t *s, smf_event_t *e);
void smf_state_operational(ogs_fsm_t *s, smf_event_t *e);
void smf_state_exception(ogs_fsm_t *s, smf_event_t *e);

void smf_gsm_state_initial(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_final(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_wait_epc_auth_initial(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_wait_5gc_sm_policy_association(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_wait_pfcp_establishment(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_operational(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_wait_pfcp_deletion(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_wait_epc_auth_release(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_wait_5gc_n1_n2_release(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_5gc_n1_n2_reject(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_5gc_session_will_deregister(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_session_will_release(ogs_fsm_t *s, smf_event_t *e);
void smf_gsm_state_exception(ogs_fsm_t *s, smf_event_t *e);

void smf_pfcp_state_initial(ogs_fsm_t *s, smf_event_t *e);
void smf_pfcp_state_final(ogs_fsm_t *s, smf_event_t *e);
void smf_pfcp_state_will_associate(ogs_fsm_t *s, smf_event_t *e);
void smf_pfcp_state_associated(ogs_fsm_t *s, smf_event_t *e);
void smf_pfcp_state_exception(ogs_fsm_t *s, smf_event_t *e);

/* Session-level N4 on the owning shard (outside the node FSM). */
void smf_pfcp_session_dispatch(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact, smf_event_t *e);
void smf_pfcp_session_timer(smf_event_t *e);

/* SMF_EVT_N4_RESTORE kinds (e->h.timer_id) */
#define SMF_N4_RESTORE_REESTABLISH  1   /* UPF restarted: re-establish */
#define SMF_N4_RESTORE_RESELECT     2   /* UPF lost: release (5GC)     */
void smf_pfcp_restore_owned(ogs_pfcp_node_t *node, int kind);

#define smf_sm_debug(__pe) \
    ogs_debug("%s(): %s", __func__, smf_event_get_name(__pe))

#ifdef __cplusplus
}
#endif

#endif /* SMF_SM_H */
