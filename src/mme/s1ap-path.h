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

#ifndef S1AP_PATH_H
#define S1AP_PATH_H

#include "mme-context.h"
#include "mme-event.h"

#ifdef __cplusplus
extern "C" {
#endif

#define S1AP_NON_UE_SIGNALLING   0

#define s1ap_event_push  mme_sctp_event_push

int s1ap_open(void);
void s1ap_close(void);

ogs_sock_t *s1ap_server(ogs_socknode_t *node);
void s1ap_recv_upcall(short when, ogs_socket_t fd, void *data);

int s1ap_send_to_enb(
        mme_enb_t *enb, ogs_pkbuf_t *pkb, uint16_t stream_no);
int s1ap_send_to_enb_ue(enb_ue_t *enb_ue, ogs_pkbuf_t *pkbuf);
int s1ap_delayed_send_to_enb_ue(enb_ue_t *enb_ue,
        ogs_pkbuf_t *pkbuf, ogs_time_t duration);
int s1ap_send_to_nas(enb_ue_t *enb_ue,
        S1AP_ProcedureCode_t procedureCode, S1AP_NAS_PDU_t *nasPdu);
int s1ap_send_to_esm(
        mme_ue_t *mme_ue, ogs_pkbuf_t *esmbuf,
        uint8_t nas_type, int create_action);

int s1ap_send_s1_setup_response(mme_enb_t *enb);
int s1ap_send_s1_setup_failure(
        mme_enb_t *enb, S1AP_Cause_PR group, long cause);

int s1ap_send_enb_configuration_update_ack(mme_enb_t *enb);
int s1ap_send_enb_configuration_update_failure(
        mme_enb_t *enb, S1AP_Cause_PR group, long cause);

int s1ap_send_initial_context_setup_request(mme_ue_t *mme_ue);
int s1ap_send_ue_context_modification_request(mme_ue_t *mme_ue);
int s1ap_send_ue_context_release_command(
    enb_ue_t *enb_ue, S1AP_Cause_PR group, long cause,
    uint8_t action, ogs_time_t duration);

int s1ap_send_paging(mme_ue_t *mme_ue, S1AP_CNDomain_t cn_domain);

int s1ap_send_mme_configuration_transfer(
        mme_enb_t *target_enb,
        S1AP_SONConfigurationTransfer_t *SONConfigurationTransfer);

int s1ap_send_mme_direct_information_transfer(
        mme_enb_t *target_enb, const uint8_t *buf, size_t buf_len);

int s1ap_send_e_rab_modification_confirm(mme_ue_t *mme_ue);

int s1ap_send_path_switch_ack(
        mme_ue_t *mme_ue, bool e_rab_to_switched_in_uplink_list);

int s1ap_send_handover_command(enb_ue_t *source_ue);
int s1ap_send_handover_preparation_failure(
        enb_ue_t *source_ue, S1AP_Cause_PR group, long cause);
int s1ap_send_handover_preparation_failure_from_cause(
        enb_ue_t *source_ue, S1AP_Cause_t *Cause);

/* S1AP Cause group name per TS 36.413 (radioNetwork, nas, ...). */
const char *s1ap_cause_group_name(S1AP_Cause_PR present);

int s1ap_send_handover_request(
        enb_ue_t *source_ue, mme_enb_t *target_enb,
        S1AP_HandoverType_t *handovertype, S1AP_Cause_t *cause,
        S1AP_Source_ToTarget_TransparentContainer_t
            *source_totarget_transparentContainer);

int s1ap_send_handover_cancel_ack(enb_ue_t *source_ue);

int s1ap_send_mme_status_transfer(
        enb_ue_t *target_ue,
        S1AP_ENB_StatusTransfer_TransparentContainer_t
            *enb_statustransfer_transparentContainer);
int s1ap_send_error_indication(
        mme_enb_t *enb,
        S1AP_MME_UE_S1AP_ID_t *mme_ue_s1ap_id,
        S1AP_ENB_UE_S1AP_ID_t *enb_ue_s1ap_id,
        S1AP_Cause_PR group, long cause);
int s1ap_send_error_indication1(
        enb_ue_t *enb_ue, S1AP_Cause_PR group, long cause);
int s1ap_send_error_indication2(
        mme_ue_t *mme_ue, S1AP_Cause_PR group, long cause);
int s1ap_send_s1_reset_ack(
        mme_enb_t *enb,
        S1AP_UE_associatedLogicalS1_ConnectionListRes_t *partOfS1_Interface);

/*
 * MME-initiated S1 Reset (TS 36.413 §8.7.2). Sends a Reset PDU to
 * the eNB asking it to release every UE context on this S1 (i.e.
 * resetType = s1_Interface). Used by the admin "graceful detach"
 * path so the eNB knows the MME is dropping it instead of just
 * seeing SCTP COMM_LOST. The eNB is expected to respond with
 * Reset Acknowledge; that response is handled by the existing
 * s1ap-handler.c::s1ap_handle_reset_ack() (treated as informational
 * since our local release runs on a delayed admin event).
 */
int s1ap_send_s1_reset(
        mme_enb_t *enb, S1AP_Cause_PR group, long cause);

/* Format S1AP Cause for operator logs (group name + value name or number). */
void s1ap_cause_string(char *buf, size_t buflen, S1AP_Cause_t *cause);

/*
 * Emit an INFO trace line with IMSI/APN/EBI context already set via
 * ogs_mme_trace_set(). proc is stored in the trace prefix (e.g. attach-fail).
 */
void s1ap_log_ue_failure(enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        mme_bearer_t *bearer, const char *apn, const char *proc,
        const char *event, S1AP_Cause_t *cause);

#ifdef __cplusplus
}
#endif

#endif /* S1AP_PATH_H */
