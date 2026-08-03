/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef S1AP_HANDLER_H
#define S1AP_HANDLER_H

#include "mme-context.h"
#include "mme-event.h"

#ifdef __cplusplus
extern "C" {
#endif

void s1ap_handle_s1_setup_request(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_enb_configuration_update(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_initial_ue_message(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_uplink_nas_transport(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_ue_capability_info_indication(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_initial_context_setup_response(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_initial_context_setup_failure(
        mme_enb_t *enb, ogs_s1ap_message_t *message);

void s1ap_handle_ue_context_modification_response(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_ue_context_modification_failure(
        mme_enb_t *enb, ogs_s1ap_message_t *message);

void s1ap_handle_ue_context_release_request(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_ue_context_release_complete(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_ue_context_release_action(enb_ue_t *enb_ue);

void s1ap_handle_e_rab_setup_response(
        mme_enb_t *enb, ogs_s1ap_message_t *message);

void s1ap_handle_e_rab_release_indication(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_e_rab_modification_indication(
        mme_enb_t *enb, ogs_s1ap_message_t *message);

void s1ap_handle_path_switch_request(
        mme_enb_t *enb, ogs_s1ap_message_t *message);

/*
 * Handover tails (location update, NH chain, S11 sends). Run on the
 * UE owner thread: called directly when mme.workers is off, or from
 * the MME_EVENT_S1AP_HO_TAIL handler on the owner shard when active.
 */
void s1ap_path_switch_request_complete(enb_ue_t *enb_ue, mme_ue_t *mme_ue);
void s1ap_handover_notify_complete(enb_ue_t *target_ue, mme_ue_t *mme_ue);

/*
 * InitialContextSetupResponse tail (bearer S1-U TEID/IP writes,
 * bearer_to_modify_list, S11 Modify Bearer, paging check). Same owner
 * shard rule as the handover tails; tail is the snapshot the main
 * thread took from the ASN.1 message (mme_event_t.pkbuf).
 */
void s1ap_initial_context_setup_response_complete(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue, mme_ics_rsp_tail_t *tail);

/*
 * UE Context Release Complete tail (mobile-reachable, will-remove,
 * mme_ue_remove, indirect-tunnel teardown, paging). Same owner shard
 * rule (MME_HO_TAIL_UE_REL); old_enb_ue_id names the enb_ue main
 * already removed — stale-link comparison only.
 */
void s1ap_ue_context_release_tail(mme_ue_t *mme_ue, int rel_action,
        ogs_pool_id_t old_enb_ue_id, int rel_flags);

void s1ap_handle_enb_direct_information_transfer(
        mme_enb_t *enb, ogs_s1ap_message_t *message);

void s1ap_handle_handover_required(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_handover_request_ack(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_handover_failure(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_handover_cancel(
        mme_enb_t *enb, ogs_s1ap_message_t *message);

void s1ap_handle_enb_status_transfer(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_enb_configuration_transfer(
        mme_enb_t *enb, ogs_s1ap_message_t *message, ogs_pkbuf_t *pkbuf);
void s1ap_handle_handover_notification(
        mme_enb_t *enb, ogs_s1ap_message_t *message);

void s1ap_handle_s1_reset(
        mme_enb_t *enb, ogs_s1ap_message_t *message);

void s1ap_handle_write_replace_warning_response(
        mme_enb_t *enb, ogs_s1ap_message_t *message);
void s1ap_handle_kill_response(
        mme_enb_t *enb, ogs_s1ap_message_t *message);

#ifdef __cplusplus
}
#endif

#endif /* S1AP_HANDLER_H */
