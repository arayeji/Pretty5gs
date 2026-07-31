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

#ifndef MME_S11_HANDLER_H
#define MME_S11_HANDLER_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

void mme_s11_check_peer_recovery(
        ogs_gtp_node_t *gnode, ogs_gtp2_message_t *message);
void mme_s11_handle_sgw_context_lost(mme_ue_t *mme_ue, uint8_t gtp_cause);

/* Reject attach/TAU (EMM #22 + T3346 for congestion causes) and release
 * the UE context. Shared by Create Session Response failures and Create
 * Session Request GTP timeouts (SGW dead/overloaded). */
void mme_s11_create_session_fail(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        int create_action, uint8_t fail_cause,
        const char *reason);

void mme_s11_handle_echo_request(
        ogs_gtp_xact_t *xact, ogs_gtp2_echo_request_t *req);
void mme_s11_handle_echo_response(
        ogs_gtp_xact_t *xact, ogs_gtp2_echo_response_t *rsp);
void mme_s11_handle_create_session_response(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_create_session_response_t *rsp);
void mme_s11_handle_modify_bearer_response(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_modify_bearer_response_t *rsp);
void mme_s11_handle_delete_session_response(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_delete_session_response_t *rsp);
void mme_s11_handle_create_bearer_request(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_create_bearer_request_t *req);
void mme_s11_handle_update_bearer_request(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_update_bearer_request_t *req);
void mme_s11_handle_delete_bearer_request(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_delete_bearer_request_t *req);

void mme_s11_handle_release_access_bearers_response(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_release_access_bearers_response_t *rsp);
/* Complete S1-side Release Access Bearers actions without (or after) S11. */
void mme_s11_finish_release_access_bearers(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue, int action);
void mme_s11_handle_downlink_data_notification(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_downlink_data_notification_t *noti);
void mme_s11_handle_create_indirect_data_forwarding_tunnel_response(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_create_indirect_data_forwarding_tunnel_response_t *rsp);
void mme_s11_handle_delete_indirect_data_forwarding_tunnel_response(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_delete_indirect_data_forwarding_tunnel_response_t *rsp);

void mme_s11_handle_bearer_resource_failure_indication(
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_bearer_resource_failure_indication_t *ind);

#ifdef __cplusplus
}
#endif

#endif /* MME_S11_HANDLER_H */
