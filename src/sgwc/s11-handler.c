/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
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

#include "gtp-path.h"
#include "pfcp-path.h"
#include "sgwc-trace.h"

#include "s11-handler.h"

static bool sgwc_s11_message_recovery(
        ogs_gtp2_message_t *message, uint8_t *recovery)
{
    ogs_gtp2_tlv_recovery_t *tlv = NULL;

    ogs_assert(message);
    ogs_assert(recovery);

    switch (message->h.type) {
    case OGS_GTP2_ECHO_REQUEST_TYPE:
        tlv = &message->echo_request.recovery;
        break;
    case OGS_GTP2_ECHO_RESPONSE_TYPE:
        tlv = &message->echo_response.recovery;
        break;
    case OGS_GTP2_CREATE_SESSION_REQUEST_TYPE:
        tlv = &message->create_session_request.recovery;
        break;
    case OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE:
        tlv = &message->modify_bearer_request.recovery;
        break;
    case OGS_GTP2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
        tlv = &message->create_indirect_data_forwarding_tunnel_request.recovery;
        break;
    case OGS_GTP2_MODIFY_ACCESS_BEARERS_REQUEST_TYPE:
        tlv = &message->modify_access_bearers_request.recovery;
        break;
    default:
        return false;
    }

    if (!tlv->presence)
        return false;

    *recovery = tlv->u8;
    return true;
}

void sgwc_s11_check_peer_recovery(
        ogs_gtp_node_t *gnode, ogs_gtp2_message_t *message)
{
    sgwc_mme_peer_t *peer = NULL;
    uint8_t recovery = 0;

    ogs_assert(gnode);
    ogs_assert(message);

    if (!sgwc_s11_message_recovery(message, &recovery))
        return;

    peer = sgwc_mme_peer_get(gnode);
    if (peer)
        sgwc_mme_recovery_update(peer, recovery);
}

static void gtp_sess_timeout(ogs_gtp_xact_t *xact, void *data)
{
    sgwc_sess_t *sess = NULL;
    ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;
    sgwc_ue_t *sgwc_ue = NULL;
    uint8_t type = 0;

    ogs_assert(xact);
    type = xact->seq[0].type;

    ogs_assert(data);
    sess_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(sess_id >= OGS_MIN_POOL_ID && sess_id <= OGS_MAX_POOL_ID);

    sess = sgwc_sess_find_by_id(sess_id);
    if (!sess) {
        ogs_error("Session has already been removed [%d]", type);
        return;
    }

    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);

    switch (type) {
    case OGS_GTP2_DELETE_SESSION_REQUEST_TYPE:
        ogs_error("[%s] No Delete Session Response", sgwc_ue->imsi_bcd);
        ogs_assert(OGS_OK ==
            sgwc_pfcp_send_session_deletion_request(
                sess, OGS_INVALID_POOL_ID, NULL));
        break;
    default:
        ogs_error("GTP Timeout : IMSI[%s] Message-Type[%d]",
                sgwc_ue->imsi_bcd, type);
    }
}

static void gtp_bearer_timeout(ogs_gtp_xact_t *xact, void *data)
{
    sgwc_bearer_t *bearer = NULL;
    ogs_pool_id_t bearer_id = OGS_INVALID_POOL_ID;
    sgwc_sess_t *sess = NULL;
    sgwc_ue_t *sgwc_ue = NULL;
    uint8_t type = 0;

    ogs_assert(xact);
    type = xact->seq[0].type;

    ogs_assert(data);
    bearer_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(bearer_id >= OGS_MIN_POOL_ID && bearer_id <= OGS_MAX_POOL_ID);

    bearer = sgwc_bearer_find_by_id(bearer_id);
    if (!bearer) {
        ogs_error("Bearer has already been removed [%d]", type);
        return;
    }

    sess = sgwc_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);

    ogs_error("GTP Timeout : IMSI[%s] Message-Type[%d]",
            sgwc_ue->imsi_bcd, type);
}

static void pfcp_sess_timeout(ogs_pfcp_xact_t *xact, void *data)
{
    sgwc_sess_t *sess = NULL;
    ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;
    uint8_t type;

    ogs_assert(xact);
    type = xact->seq[0].type;

    ogs_assert(data);
    sess_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(sess_id >= OGS_MIN_POOL_ID && sess_id <= OGS_MAX_POOL_ID);

    sess = sgwc_sess_find_by_id(sess_id);
    if (!sess) {
        ogs_error("Session has already been removed [%d]", type);
        return;
    }

    switch (type) {
    case OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
        ogs_error("No PFCP session establishment response");
        break;
    case OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE: {
        sgwc_ue_t *sgwc_ue = NULL;
        ogs_gtp_xact_t *s11_xact = NULL;
        uint8_t gtp_rsp_type = 0;

        ogs_error("No PFCP session modification response");
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        s11_xact = ogs_gtp_xact_find_by_id(xact->assoc_xact_id);
        if (sgwc_ue && s11_xact && s11_xact->seq[0].type) {
            gtp_rsp_type = s11_xact->seq[0].type + 1;
            ogs_gtp_send_error_message(
                    s11_xact, sgwc_ue->mme_s11_teid,
                    gtp_rsp_type,
                    OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
        }
        break;
    }
    case OGS_PFCP_SESSION_DELETION_REQUEST_TYPE:
        ogs_error("No PFCP session deletion response");
        break;
    default:
        ogs_error("Not implemented [type:%d]", type);
        break;
    }
}

/* This code was created in case it will be used later,
 * and is currently not being used.  */
static uint8_t pfcp_cause_from_gtp(uint8_t gtp_cause)
{
    switch (gtp_cause) {
    case OGS_GTP2_CAUSE_REQUEST_ACCEPTED:
        return OGS_PFCP_CAUSE_REQUEST_ACCEPTED;
    case OGS_GTP2_CAUSE_REQUEST_REJECTED_REASON_NOT_SPECIFIED:
        return OGS_PFCP_CAUSE_REQUEST_REJECTED;
    case OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND:
        return OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
    case OGS_GTP2_CAUSE_MANDATORY_IE_MISSING:
        return OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
    case OGS_GTP2_CAUSE_CONDITIONAL_IE_MISSING:
        return OGS_PFCP_CAUSE_CONDITIONAL_IE_MISSING;
    case OGS_GTP2_CAUSE_INVALID_LENGTH:
        return OGS_PFCP_CAUSE_INVALID_LENGTH;
    case OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT:
        return OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
    case OGS_GTP2_CAUSE_INVALID_MESSAGE_FORMAT:
        return OGS_PFCP_CAUSE_INVALID_FORWARDING_POLICY;
    case OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING:
        return OGS_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION;
    case OGS_GTP2_CAUSE_SEMANTIC_ERROR_IN_THE_TFT_OPERATION:
        return OGS_PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;
    case OGS_GTP2_CAUSE_GTP_C_ENTITY_CONGESTION:
        return OGS_PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION;
    case OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE:
        return OGS_PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
    case OGS_GTP2_CAUSE_SERVICE_NOT_SUPPORTED:
        return OGS_PFCP_CAUSE_SERVICE_NOT_SUPPORTED;
    case OGS_GTP2_CAUSE_SYSTEM_FAILURE:
        return OGS_PFCP_CAUSE_SYSTEM_FAILURE;
    default:
        return OGS_PFCP_CAUSE_SYSTEM_FAILURE;
    }

    return OGS_PFCP_CAUSE_SYSTEM_FAILURE;
}

static void sgwc_s11_create_session_proceed(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv, i;
    uint8_t cause_value = 0;

    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;

    ogs_gtp2_create_session_request_t *req = NULL;

    uint16_t decoded;
    ogs_gtp2_f_teid_t *mme_s11_teid = NULL;
    ogs_gtp2_f_teid_t *pgw_s5c_teid = NULL;
    ogs_gtp2_uli_t uli;
    ogs_gtp2_bearer_qos_t bearer_qos;
    char apn[OGS_MAX_APN_LEN+1];
    char *apn_oi = NULL;

    ogs_assert(sgwc_ue);
    ogs_assert(s11_xact);
    ogs_assert(gtpbuf);
    ogs_assert(message);
    req = &message->create_session_request;
    ogs_assert(req);

    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (ogs_fqdn_parse(apn, req->access_point_name.data,
            ogs_min(req->access_point_name.len, OGS_MAX_APN_LEN)) <= 0) {
        sgwc_ue_error(sgwc_ue, NULL, "s11", NULL, "Invalid APN");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
        goto cleanup;
    }

    /* TS 23.003 9.1.1: the APN-NI shall not end in ".gprs". A full APN
     * (APN-NI + APN-OI) can arrive here via a Gn/Gp-SGSN handover path;
     * the Sxa Network Instance (TS 29.244 8.2.4) must carry the APN-NI
     * only, so strip a trailing APN-OI if present. */
    apn_oi = ogs_dnn_oi_from_fqdn(apn);
    if (apn_oi && apn_oi > apn && apn_oi[-1] == '.')
        apn_oi[-1] = '\0';

    sess = sgwc_sess_add(sgwc_ue, apn);
    ogs_assert(sess);

    if (req->rat_type.presence)
        sess->gtp_rat_type = req->rat_type.u8;

    /* Control-plane TEIDs from Create Session Request */
    if (req->sender_f_teid_for_control_plane.presence &&
            req->sender_f_teid_for_control_plane.data) {
        mme_s11_teid = req->sender_f_teid_for_control_plane.data;
        sgwc_ue->mme_s11_teid = be32toh(mme_s11_teid->teid);
    }
    if (req->pgw_s5_s8_address_for_control_plane_or_pmip.presence &&
            req->pgw_s5_s8_address_for_control_plane_or_pmip.data) {
        pgw_s5c_teid = req->pgw_s5_s8_address_for_control_plane_or_pmip.data;
        sess->pgw_s5c_teid = be32toh(pgw_s5c_teid->teid);
    }

    sgwc_ue_info(sgwc_ue, sess, "s11", NULL,
            "S11 session ready SGW-S5C=0x%x PGW-S5C=0x%x",
            sess->sgw_s5c_teid, sess->pgw_s5c_teid);

    /* MSISDN (optional IE; forwarded by MME for SGW/PGW CDRs) */
    if (req->msisdn.presence == 1 && req->msisdn.len && req->msisdn.data) {
        if (req->msisdn.len > (int)sizeof(sgwc_ue->msisdn)) {
            ogs_warn("MSISDN too long (%u), truncating for SGW-CDR",
                    (unsigned)req->msisdn.len);
            sgwc_ue->msisdn_len = sizeof(sgwc_ue->msisdn);
        } else {
            sgwc_ue->msisdn_len = req->msisdn.len;
        }
        memcpy(sgwc_ue->msisdn, req->msisdn.data, sgwc_ue->msisdn_len);
        ogs_buffer_to_bcd(sgwc_ue->msisdn,
                sgwc_ue->msisdn_len, sgwc_ue->msisdn_bcd);
    }

    /* Set User Location Information */
    if (req->user_location_information.presence == 1) {
        decoded = ogs_gtp2_parse_uli(&uli, &req->user_location_information);
        if (req->user_location_information.len == decoded) {
            sgwc_ue->uli_presence = true;
            sgwc_ue_store_uli_raw(sgwc_ue,
                    req->user_location_information.data,
                    req->user_location_information.len);

            ogs_nas_to_plmn_id(&sgwc_ue->e_tai.plmn_id, &uli.tai.nas_plmn_id);
            sgwc_ue->e_tai.tac = uli.tai.tac;
            ogs_nas_to_plmn_id(&sgwc_ue->e_cgi.plmn_id, &uli.e_cgi.nas_plmn_id);
            sgwc_ue->e_cgi.cell_id = uli.e_cgi.cell_id;

            ogs_debug("    TAI[PLMN_ID:%06x,TAC:%d]",
                    ogs_plmn_id_hexdump(&sgwc_ue->e_tai.plmn_id),
                    sgwc_ue->e_tai.tac);
            ogs_debug("    E_CGI[PLMN_ID:%06x,CELL_ID:0x%x]",
                    ogs_plmn_id_hexdump(&sgwc_ue->e_cgi.plmn_id),
                    sgwc_ue->e_cgi.cell_id);

            memcpy(&sess->serving_plmn_id, &sgwc_ue->e_tai.plmn_id,
                    sizeof(sess->serving_plmn_id));
        } else
            ogs_error("Invalid User Location Info(ULI)");
    }

    if (req->serving_network.presence == 1) {
        ogs_nas_to_plmn_id(&sess->serving_plmn_id, req->serving_network.data);
    }

    sgwc_inbound_roam_teid_offset_apply(sgwc_ue, sess);

    /* Select SGW-U based on UE Location Information */
    sgwc_sess_select_sgwu(sess);

    if (!sess->pfcp_node) {
        ogs_error("[IMSI:%s PLMN:%d/%d APN:%s] No PFCP-associated SGW-U "
                "(check open5gs-sgwud and sgwc.yaml pfcp.client)",
                sgwc_ue->imsi_bcd,
                ogs_plmn_id_mcc(&sess->serving_plmn_id),
                ogs_plmn_id_mnc(&sess->serving_plmn_id),
                sess->session.name);
        cause_value = OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING;
        goto cleanup;
    }

    /* Check if selected SGW-U is associated with SGW-C */
    if (!OGS_FSM_CHECK(&sess->pfcp_node->sm, sgwc_pfcp_state_associated)) {
        ogs_error("[%s:%s] SGW-U [%s] not PFCP-associated with SGWC",
                sgwc_ue->imsi_bcd, sess->session.name,
                ogs_sockaddr_to_string_static(sess->pfcp_node->addr_list));
        cause_value = OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING;
        goto cleanup;
    }

    /* Remove all previous bearer */
    sgwc_bearer_remove_all(sess);

    /* Setup Bearer */
    for (i = 0; i < OGS_BEARER_PER_UE; i++) {
        if (req->bearer_contexts_to_be_created[i].presence == 0)
            break;
        if (req->bearer_contexts_to_be_created[i].eps_bearer_id.presence == 0) {
            ogs_error("No EPS Bearer ID");
            break;
        }
        if (req->bearer_contexts_to_be_created[i].
                bearer_level_qos.presence == 0) {
            ogs_error("No Bearer QoS");
            break;
        }

        decoded = ogs_gtp2_parse_bearer_qos(&bearer_qos,
                &req->bearer_contexts_to_be_created[i].bearer_level_qos);
        if (GTP2_BEARER_QOS_LEN != decoded) {
            ogs_error("Invalid Bearer QoS IE in Create Session Request "
                    "(decoded=%d, expected=%d)", decoded, GTP2_BEARER_QOS_LEN);
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
            goto cleanup;
        }

        bearer = sgwc_bearer_add(sess);
        if (!bearer) {
            ogs_error("[%s] Could not allocate bearer context",
                    sgwc_ue->imsi_bcd);
            cause_value = OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE;
            goto cleanup;
        }

        /* Set Bearer EBI */
        bearer->ebi = req->bearer_contexts_to_be_created[i].eps_bearer_id.u8;

        if (req->bearer_contexts_to_be_created[i].s1_u_enodeb_f_teid.presence) {

            sgwc_tunnel_t *dl_tunnel = NULL;
            ogs_pfcp_far_t *far = NULL;
            ogs_gtp2_f_teid_t *enb_s1u_teid = NULL;

            dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
            ogs_assert(dl_tunnel);

            /* Data Plane(DL) : eNB-S1U */
            enb_s1u_teid = req->bearer_contexts_to_be_created[i].
                            s1_u_enodeb_f_teid.data;
            dl_tunnel->remote_teid = be32toh(enb_s1u_teid->teid);

            rv = ogs_gtp2_f_teid_to_ip(enb_s1u_teid, &dl_tunnel->remote_ip);
            if (rv != OGS_OK) {
                ogs_error("No IPv4 or IPv6 in eNB-S1U(DL)");
                cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
                goto cleanup;
            }

            far = dl_tunnel->far;
            ogs_assert(far);

            far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

            rv = ogs_pfcp_ip_to_outer_header_creation(
                    &dl_tunnel->remote_ip, &far->outer_header_creation,
                    &far->outer_header_creation_len);
            if (rv != OGS_OK) {
                ogs_error("No IPv4 or IPv6 in DL-Tunnel");
                cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
                goto cleanup;
            }
            far->outer_header_creation.teid = dl_tunnel->remote_teid;
        }

        if (req->bearer_contexts_to_be_created[i].s5_s8_u_sgw_f_teid.presence) {

            sgwc_tunnel_t *ul_tunnel = NULL;
            ogs_pfcp_far_t *far = NULL;
            ogs_gtp2_f_teid_t *pgw_s5u_teid = NULL;

            ul_tunnel = sgwc_ul_tunnel_in_bearer(bearer);
            ogs_assert(ul_tunnel);

            /* Data Plane(UL) : PGW-S5U */
            pgw_s5u_teid = req->bearer_contexts_to_be_created[i].
                            s5_s8_u_sgw_f_teid.data;
            ul_tunnel->remote_teid = be32toh(pgw_s5u_teid->teid);

            rv = ogs_gtp2_f_teid_to_ip(pgw_s5u_teid, &ul_tunnel->remote_ip);
            if (rv != OGS_OK) {
                ogs_error("No IPv4 or IPv6 in PGW-S5U(UL)");
                cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
                goto cleanup;
            }

            far = ul_tunnel->far;
            ogs_assert(far);

            far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

            rv = ogs_pfcp_ip_to_outer_header_creation(
                    &ul_tunnel->remote_ip, &far->outer_header_creation,
                    &far->outer_header_creation_len);
            if (rv != OGS_OK) {
                ogs_error("No IPv4 or IPv6 in UL-Tunnel");
                cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
                goto cleanup;
            }
            far->outer_header_creation.teid = ul_tunnel->remote_teid;
        }

        /* Set Session QoS from Default Bearer Level QoS */
        if (i == 0) {
            sess->session.qos.index = bearer_qos.qci;
            sess->session.qos.arp.priority_level = bearer_qos.priority_level;
            sess->session.qos.arp.pre_emption_capability =
                            bearer_qos.pre_emption_capability;
            sess->session.qos.arp.pre_emption_vulnerability =
                            bearer_qos.pre_emption_vulnerability;
        }
    }

    /* Receive Control Plane(DL) : MME-S11 */
    mme_s11_teid = req->sender_f_teid_for_control_plane.data;
    ogs_assert(mme_s11_teid);
    sgwc_ue->mme_s11_teid = be32toh(mme_s11_teid->teid);

    /* Receive Control Plane(UL) : PGW-S5C (TEID may be 0 before PGW answers) */
    if (req->pgw_s5_s8_address_for_control_plane_or_pmip.presence &&
            req->pgw_s5_s8_address_for_control_plane_or_pmip.data) {
        pgw_s5c_teid = req->pgw_s5_s8_address_for_control_plane_or_pmip.data;
        sess->pgw_s5c_teid = be32toh(pgw_s5c_teid->teid);
    }

    ogs_sgwc_trace_set(sgwc_ue, sess, NULL, "create-session");
    ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
        sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);

    sess->create_session_t0 = ogs_time_now();

    ogs_assert(OGS_OK ==
        sgwc_pfcp_send_session_establishment_request(
            sess, s11_xact->id, gtpbuf, 0));

    return;

cleanup:
    ogs_assert(cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED);
    ogs_error("[%s] Create Session failed before SGW-U/SMF [GTP cause:%u]",
            sgwc_ue ? sgwc_ue->imsi_bcd : "-", cause_value);
    if (sess)
        sgwc_sess_abort_create(sess);

    ogs_gtp_send_error_message(
            s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
            OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
            cause_value);
}

bool sgwc_csr_replace_start(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *old_sess,
        ogs_gtp_xact_t *s11_xact, ogs_pkbuf_t *gtpbuf)
{
    ogs_assert(sgwc_ue);
    ogs_assert(old_sess);
    ogs_assert(s11_xact);
    ogs_assert(gtpbuf);

    if (sgwc_ue->csr_replace_s11_xact_id != OGS_INVALID_POOL_ID) {
        ogs_warn("[%s] CSR replace already pending", sgwc_ue->imsi_bcd);
        return false;
    }

    if (!old_sess->sgwu_sxa_seid || !old_sess->pfcp_node) {
        ogs_error("[%s] CSR replace without UP session", sgwc_ue->imsi_bcd);
        return false;
    }

    sgwc_ue->csr_replace_s11_xact_id = s11_xact->id;
    sgwc_ue->csr_replace_gtpbuf = ogs_pkbuf_copy(gtpbuf);
    if (!sgwc_ue->csr_replace_gtpbuf) {
        ogs_error("[%s] ogs_pkbuf_copy() failed", sgwc_ue->imsi_bcd);
        sgwc_ue->csr_replace_s11_xact_id = OGS_INVALID_POOL_ID;
        return false;
    }
    sgwc_ue->csr_replace_sess_id = old_sess->id;

    if (sgwc_pfcp_send_session_deletion_request(
            old_sess, OGS_INVALID_POOL_ID, NULL) != OGS_OK) {
        ogs_error("[%s] PFCP Session Deletion failed for CSR replace",
                sgwc_ue->imsi_bcd);
        ogs_pkbuf_free(sgwc_ue->csr_replace_gtpbuf);
        sgwc_ue->csr_replace_gtpbuf = NULL;
        sgwc_ue->csr_replace_s11_xact_id = OGS_INVALID_POOL_ID;
        sgwc_ue->csr_replace_sess_id = OGS_INVALID_POOL_ID;
        sgwc_ue->csr_replace_t0 = 0;
        return false;
    }

    sgwc_ue->csr_replace_t0 = ogs_time_now();

    ogs_info("[%s] CSR replace: waiting for PFCP Session Deletion "
            "(EBI collision, SGWU-SEID=0x%llx)",
            sgwc_ue->imsi_bcd,
            (unsigned long long)old_sess->sgwu_sxa_seid);
    return true;
}

void sgwc_csr_replace_continue(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *old_sess, bool proceed)
{
    ogs_gtp_xact_t *s11_xact = NULL;
    ogs_pkbuf_t *gtpbuf = NULL;
    ogs_gtp2_message_t message;
    int rv;

    ogs_assert(sgwc_ue);
    ogs_assert(old_sess);

    s11_xact = ogs_gtp_xact_find_by_id(sgwc_ue->csr_replace_s11_xact_id);
    gtpbuf = sgwc_ue->csr_replace_gtpbuf;

    sgwc_ue->csr_replace_s11_xact_id = OGS_INVALID_POOL_ID;
    sgwc_ue->csr_replace_gtpbuf = NULL;
    sgwc_ue->csr_replace_sess_id = OGS_INVALID_POOL_ID;
    sgwc_ue->csr_replace_t0 = 0;

    /*
     * Tear down the OLD PGW-C/SMF session on S5/S8 before dropping it.
     *
     * CSR replace only deleted the old SGW-U (PFCP) session; the old PDN
     * connection on PGW-C/SMF was abandoned silently, so SMF accumulates
     * orphaned (control-plane-only) sessions on every re-attach collision.
     *
     * Fire-and-forget: the new Create Session proceeds independently below,
     * and the eventual S5 Delete Session Response is ignored because this
     * transaction has no associated S11 transaction. Send it BEFORE
     * sgwc_sess_remove() frees old_sess (it uses pgw_s5c_teid/gnode/bearer).
     */
    if (old_sess->gnode && old_sess->pgw_s5c_teid)
        sgwc_gtp_send_s5c_delete_session_request(old_sess);

    old_sess->sgwu_sxa_seid = 0;
    sgwc_sess_remove(old_sess);

    if (!proceed || !s11_xact || !gtpbuf) {
        if (s11_xact) {
            ogs_gtp_send_error_message(
                    s11_xact, sgwc_ue->mme_s11_teid,
                    OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                    OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
        }
        if (gtpbuf)
            ogs_pkbuf_free(gtpbuf);
        return;
    }

    rv = ogs_gtp2_parse_msg(&message, gtpbuf);
    if (rv != OGS_OK) {
        ogs_error("[%s] ogs_gtp2_parse_msg() failed", sgwc_ue->imsi_bcd);
        ogs_gtp_send_error_message(
                s11_xact, sgwc_ue->mme_s11_teid,
                OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_INVALID_MESSAGE_FORMAT);
        ogs_pkbuf_free(gtpbuf);
        return;
    }

    sgwc_s11_create_session_proceed(sgwc_ue, s11_xact, gtpbuf, &message);
    ogs_pkbuf_free(gtpbuf);
}

void sgwc_s11_handle_create_session_request(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    uint8_t cause_value = 0;

    sgwc_sess_t *sess = NULL;

    ogs_gtp2_create_session_request_t *req = NULL;

    char apn[OGS_MAX_APN_LEN+1];
    char *apn_oi = NULL;

    ogs_assert(s11_xact);
    ogs_assert(gtpbuf);
    ogs_assert(message);
    req = &message->create_session_request;
    ogs_assert(req);

    if (sgwc_self()->maintenance_mode) {
        ogs_warn("Create Session rejected: SGWC maintenance mode");
        ogs_gtp_send_error_message(
                s11_xact,
                sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
                OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE);
        return;
    }

    if (sgwc_ue && req->sender_f_teid_for_control_plane.presence &&
            req->sender_f_teid_for_control_plane.data) {
        ogs_gtp2_f_teid_t *ft =
            req->sender_f_teid_for_control_plane.data;
        sgwc_ue->mme_s11_teid = be32toh(ft->teid);
    }

    /************************
     * Check SGWC-UE Context
     ************************/
    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!sgwc_ue) {
        ogs_error("No Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /*****************************************
     * Check Mandatory/Conditional IE Missing
     *****************************************/
    if (req->imsi.presence == 0) {
        ogs_error("No IMSI");
        cause_value = OGS_GTP2_CAUSE_CONDITIONAL_IE_MISSING;
    }
    if (req->bearer_contexts_to_be_created[0].presence == 0) {
        ogs_error("No Bearer");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }
    if (req->bearer_contexts_to_be_created[0].eps_bearer_id.presence == 0) {
        ogs_error("No EPS Bearer ID");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }
    if (req->bearer_contexts_to_be_created[0].bearer_level_qos.presence == 0) {
        ogs_error("No Bearer QoS");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }
    if (req->access_point_name.presence == 0) {
        ogs_error("No APN");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    } else {
        if (ogs_fqdn_parse(apn, req->access_point_name.data,
            ogs_min(req->access_point_name.len, OGS_MAX_APN_LEN)) <= 0) {
            ogs_error("Invalid APN");
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
        } else {
            /* TS 23.003 9.1.1: strip a trailing APN-OI; the APN-NI is
             * what session lookup and the Sxa Network Instance use. */
            apn_oi = ogs_dnn_oi_from_fqdn(apn);
            if (apn_oi && apn_oi > apn && apn_oi[-1] == '.')
                apn_oi[-1] = '\0';
        }
    }
    if (req->sender_f_teid_for_control_plane.presence == 0) {
        ogs_error("No Sender F-TEID");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }
    if (req->pgw_s5_s8_address_for_control_plane_or_pmip.presence == 0) {
        ogs_error("No PGW IP");
        cause_value = OGS_GTP2_CAUSE_CONDITIONAL_IE_MISSING;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    sgwc_ue_info(sgwc_ue, NULL, "s11", apn, "Create Session Request");

    sess = sgwc_sess_find_by_ebi(sgwc_ue,
            req->bearer_contexts_to_be_created[0].eps_bearer_id.u8);
    if (sess) {
        ogs_gtp_xact_t *pending_s5 = NULL;

        /*
         * MME retransmits Create Session Request (~7s) while SGWC still
         * waits on S5/PFCP. Do not tear down the in-flight session.
         */
        if (s11_xact && s11_xact->assoc_xact_id)
            pending_s5 = ogs_gtp_xact_find_by_id(s11_xact->assoc_xact_id);
        if (pending_s5 &&
                pending_s5->seq[0].type ==
                    OGS_GTP2_CREATE_SESSION_REQUEST_TYPE &&
                pending_s5->assoc_xact_id == s11_xact->id) {
            sgwc_ue_info(sgwc_ue, sess, "s11", apn,
                    "duplicate Create Session Request while S5 pending "
                    "EBI=%d - ignoring",
                    req->bearer_contexts_to_be_created[0].eps_bearer_id.u8);
            return;
        }

        if (sgwc_ue->csr_replace_s11_xact_id != OGS_INVALID_POOL_ID) {
            sgwc_ue_info(sgwc_ue, sess, "s11", apn,
                    "duplicate Create Session Request while CSR replace "
                    "pending EBI=%d - ignoring",
                    req->bearer_contexts_to_be_created[0].eps_bearer_id.u8);
            return;
        }

        if (sess->sgwu_sxa_seid && sess->pfcp_node) {
            if (sgwc_csr_replace_start(sgwc_ue, sess, s11_xact, gtpbuf))
                return;
            cause_value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;
            goto cleanup;
        }

        ogs_info("OLD Session Release [IMSI:%s,APN:%s]",
                sgwc_ue->imsi_bcd, sess->session.name);
        sgwc_sess_abort_create(sess);
    }

    sgwc_s11_create_session_proceed(sgwc_ue, s11_xact, gtpbuf, message);
    return;

cleanup:
    ogs_assert(cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED);
    ogs_error("[%s] Create Session failed before SGW-U/SMF [GTP cause:%u]",
            sgwc_ue ? sgwc_ue->imsi_bcd : "-", cause_value);

    ogs_gtp_send_error_message(
            s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
            OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
            cause_value);
}

void sgwc_s11_handle_modify_bearer_request(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv, i = 0;
    uint16_t decoded;
    uint8_t cause_value = 0;

    OGS_LIST(pfcp_xact_list);
    ogs_pfcp_xact_t *pfcp_xact = NULL;

    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *dl_tunnel = NULL;
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_ip_t remote_ip;
    ogs_ip_t zero_ip;

    ogs_gtp2_modify_bearer_request_t *req = NULL;

    ogs_gtp2_uli_t uli;
    ogs_gtp2_f_teid_t *enb_s1u_teid = NULL;

    ogs_assert(s11_xact);
    ogs_assert(message);
    req = &message->modify_bearer_request;
    ogs_assert(req);

    sgwc_ue_info(sgwc_ue, NULL, "s11", NULL, "Modify Bearer Request");

    /************************
     * Check SGWC-UE Context
     ************************/
    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!sgwc_ue) {
        ogs_error("No Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /*****************************************
     * Check Mandatory/Conditional IE Missing
     *****************************************/
    for (i = 0; i < OGS_BEARER_PER_UE; i++) {
        ogs_pfcp_xact_t *current_xact = NULL;

        if (req->bearer_contexts_to_be_modified[i].presence == 0) {
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
            break;
        }
        if (req->bearer_contexts_to_be_modified[i].eps_bearer_id.
            presence == 0) {
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
            break;
        }
        if (req->bearer_contexts_to_be_modified[i].s1_u_enodeb_f_teid.
            presence == 0) {
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
            break;
        }

        bearer = sgwc_bearer_find_by_ue_ebi(sgwc_ue,
                    req->bearer_contexts_to_be_modified[i].eps_bearer_id.u8);
        if (!bearer) {
            ogs_error("Unknown EPS Bearer ID[%d]",
                    req->bearer_contexts_to_be_modified[i].eps_bearer_id.u8);
            cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
            break;
        }

        sess = sgwc_sess_find_by_id(bearer->sess_id);
        ogs_assert(sess);

        ogs_list_for_each_entry(&pfcp_xact_list, pfcp_xact, tmpnode) {
            if (pfcp_xact->modify_flags & OGS_PFCP_MODIFY_SESSION) {
                ogs_pool_id_t sess_id = OGS_POINTER_TO_UINT(pfcp_xact->data);
                ogs_assert(sess_id >= OGS_MIN_POOL_ID &&
                        sess_id <= OGS_MAX_POOL_ID);
                if (sess->id == sess_id) {
                    current_xact = pfcp_xact;
                    break;
                }
            }
        }

        if (!current_xact) {
            current_xact = sgwc_pfcp_find_session_modify_xact(sess,
                    OGS_PFCP_MODIFY_SESSION|OGS_PFCP_MODIFY_DL_ONLY|
                    OGS_PFCP_MODIFY_OUTER_HEADER_REMOVAL|
                    OGS_PFCP_MODIFY_ACTIVATE);
        }

        /*
         * MME retransmits Modify Bearer while PFCP modification is still
         * in flight. Reuse the pending PFCP xact and retarget the S11 xact
         * instead of starting a second modification (UPG-VPP answers the
         * first XID; the duplicate orphan xact then drops the response with
         * "invalid step[0] type[53]" in lib/pfcp/xact.c).
         */
        if (current_xact && current_xact->step >= 1) {
            current_xact->assoc_xact_id = s11_xact->id;
            if (gtpbuf) {
                if (current_xact->gtpbuf)
                    ogs_pkbuf_free(current_xact->gtpbuf);
                current_xact->gtpbuf = ogs_pkbuf_copy(gtpbuf);
                ogs_assert(current_xact->gtpbuf);
            }

            ogs_list_for_each_entry(&pfcp_xact_list, pfcp_xact, tmpnode) {
                if (pfcp_xact == current_xact)
                    goto next_bearer;
            }
            ogs_list_add(&pfcp_xact_list, &current_xact->tmpnode);
            goto next_bearer;
        }

        if (!current_xact) {
            current_xact = ogs_pfcp_xact_local_create(
                    sess->pfcp_node, pfcp_sess_timeout,
                    OGS_UINT_TO_POINTER(sess->id));
            ogs_assert(current_xact);

            current_xact->assoc_xact_id = s11_xact->id;
            current_xact->modify_flags =
                OGS_PFCP_MODIFY_SESSION|OGS_PFCP_MODIFY_DL_ONLY|
                OGS_PFCP_MODIFY_OUTER_HEADER_REMOVAL|
                OGS_PFCP_MODIFY_ACTIVATE;
            if (gtpbuf) {
                current_xact->gtpbuf = ogs_pkbuf_copy(gtpbuf);
                ogs_assert(current_xact->gtpbuf);
            }
            current_xact->local_seid = sess->sgwc_sxa_seid;

            ogs_list_add(&pfcp_xact_list, &current_xact->tmpnode);
        }

        dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
        ogs_assert(dl_tunnel);

        /* Data Plane(DL) : eNB-S1U */
        enb_s1u_teid =
            req->bearer_contexts_to_be_modified[i].s1_u_enodeb_f_teid.data;
        if (!enb_s1u_teid) {
            ogs_error("No eNB-S1U F-TEID data");
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
            goto cleanup;
        }
        dl_tunnel->remote_teid = be32toh(enb_s1u_teid->teid);

        rv = ogs_gtp2_f_teid_to_ip(enb_s1u_teid, &remote_ip);
        if (rv != OGS_OK) {
            ogs_error("No IPv4 or IPv6 in eNB-S1U(DL)");
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
            goto cleanup;
        }

        memset(&zero_ip, 0, sizeof(ogs_ip_t));

        if (memcmp(&dl_tunnel->remote_ip, &zero_ip, sizeof(ogs_ip_t)) != 0 &&
            memcmp(&dl_tunnel->remote_ip, &remote_ip, sizeof(ogs_ip_t)) != 0) {

            if (!sess->pfcp_node) {
                ogs_warn("No PFCP node during handover End Marker check");
            } else if (sess->pfcp_node->up_function_features.empu) {
                current_xact->modify_flags |= OGS_PFCP_MODIFY_END_MARKER;
            } else {
                ogs_error("SGW-U does not support End Marker");
            }
        }

        memcpy(&dl_tunnel->remote_ip, &remote_ip, sizeof(ogs_ip_t));

        pdr = dl_tunnel->pdr;
        ogs_assert(pdr);

        pdr->outer_header_removal_len = 1;
        pdr->outer_header_removal.description =
            OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;

        far = dl_tunnel->far;
        ogs_assert(far);

        far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

        rv = ogs_pfcp_ip_to_outer_header_creation(&dl_tunnel->remote_ip,
                &far->outer_header_creation, &far->outer_header_creation_len);
        if (rv != OGS_OK) {
            ogs_error("No IPv4 or IPv6 in DL-Tunnel");
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
            goto cleanup;
        }
        far->outer_header_creation.teid = dl_tunnel->remote_teid;

        ogs_debug("    sess_id=%d current_xact=%p flags=0x%llx, bearer[EBI=%d]",
                sess->id, current_xact,
                (unsigned long long)current_xact->modify_flags, bearer->ebi);

        ogs_list_add(&current_xact->bearer_to_modify_list,
                        &bearer->to_modify_node);
next_bearer:
        ;
    }

    if (i == 0) {
        ogs_error("No Bearer");
        goto cleanup;
    }

    if (req->user_location_information.presence == 1) {
        decoded = ogs_gtp2_parse_uli(&uli, &req->user_location_information);
        if (req->user_location_information.len == decoded) {
            sgwc_ue->uli_presence = true;
            sgwc_ue_store_uli_raw(sgwc_ue,
                    req->user_location_information.data,
                    req->user_location_information.len);

            ogs_nas_to_plmn_id(&sgwc_ue->e_tai.plmn_id, &uli.tai.nas_plmn_id);
            sgwc_ue->e_tai.tac = uli.tai.tac;
            ogs_nas_to_plmn_id(&sgwc_ue->e_cgi.plmn_id, &uli.e_cgi.nas_plmn_id);
            sgwc_ue->e_cgi.cell_id = uli.e_cgi.cell_id;

            ogs_debug("    TAI[PLMN_ID:%06x,TAC:%d]",
                    ogs_plmn_id_hexdump(&sgwc_ue->e_tai.plmn_id),
                    sgwc_ue->e_tai.tac);
            ogs_debug("    E_CGI[PLMN_ID:%06x,CELL_ID:0x%x]",
                    ogs_plmn_id_hexdump(&sgwc_ue->e_cgi.plmn_id),
                    sgwc_ue->e_cgi.cell_id);
        } else
            ogs_error("Invalid User Location Info(ULI)");
    }

    ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
        sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);
    if (dl_tunnel) {
        ogs_debug("    ENB_S1U_TEID[%d] SGW_S1U_TEID[%d]",
            dl_tunnel->remote_teid, dl_tunnel->local_teid);
    }

    ogs_list_for_each_entry(&pfcp_xact_list, pfcp_xact, tmpnode) {
        if (pfcp_xact->modify_flags & OGS_PFCP_MODIFY_SESSION) {
            sgwc_sess_t *sess = NULL;

            ogs_pool_id_t sess_id = OGS_POINTER_TO_UINT(pfcp_xact->data);
            ogs_assert(sess_id >= OGS_MIN_POOL_ID &&
                    sess_id <= OGS_MAX_POOL_ID);

            sess = sgwc_sess_find_by_id(sess_id);
            ogs_assert(sess);

            ogs_debug("    sess_id=%d xact=%p flags=0x%llx",
                    sess->id, pfcp_xact,
                    (unsigned long long)pfcp_xact->modify_flags);
            if (pfcp_xact->step >= 1)
                continue;
            sgwc_pfcp_send_bearer_to_modify_list(sess, pfcp_xact);
        }
    }

    return;

cleanup:
    ogs_assert(cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED);

    ogs_gtp_send_error_message(
            s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
            OGS_GTP2_MODIFY_BEARER_RESPONSE_TYPE, cause_value);
}

void sgwc_s11_handle_delete_session_request(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv;
    uint8_t cause_value = 0;
    sgwc_sess_t *sess = NULL;
    ogs_gtp_xact_t *s5c_xact = NULL;
    ogs_gtp2_delete_session_request_t *req = NULL;
    ogs_gtp2_indication_t *indication = NULL;

    ogs_assert(s11_xact);
    ogs_assert(gtpbuf);
    ogs_assert(message);
    req = &message->delete_session_request;
    ogs_assert(req);

    ogs_info("Delete Session Request");

    /************************
     * Check SGWC-UE Context
     ************************/
    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!sgwc_ue) {
        ogs_error("No Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    } else {
        if (req->linked_eps_bearer_id.presence == 0) {
            ogs_error("No EPS Bearer ID");
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        }

        if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
            sess = sgwc_sess_find_by_ebi(sgwc_ue, req->linked_eps_bearer_id.u8);
            if (!sess) {
                ogs_error("Unknown EPS Bearer [IMSI:%s, EBI:%d]",
                        sgwc_ue->imsi_bcd, req->linked_eps_bearer_id.u8);
                cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
            }
        }
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /*****************************************
     * Check Mandatory/Conditional IE Missing
     *****************************************/
    if (req->indication_flags.presence &&
        req->indication_flags.data && req->indication_flags.len) {
        indication = req->indication_flags.data;
    }

    if (indication &&
        indication->operation_indication == 1 &&
        indication->scope_indication == 1) {
        ogs_error("Invalid Indication");
        cause_value = OGS_GTP2_CAUSE_INVALID_MESSAGE_FORMAT;
        goto cleanup;
    }

    /********************
     * Check ALL Context
     ********************/
    ogs_assert(sgwc_ue);
    ogs_assert(sess);

    /*
     * sess->gnode is the S5C peer (PGW/SMF). It is NULL when the PDN was never
     * fully established on S5 (e.g. PFCP establishment rejected with cause 73,
     * or a roaming session whose PGW node was never resolved). The MME can
     * still send a Delete Session Request for such a session; forwarding it to
     * a NULL gnode used to abort the entire SGW-C. Instead, tear down the local
     * context and acknowledge so the MME can release its bearer.
     */
    if (!sess->gnode) {
        ogs_error("[%s] Delete Session Request for session with no S5C peer; "
                "removing locally", sgwc_ue->imsi_bcd);
        sgwc_sess_remove(sess);
        ogs_gtp_send_error_message(
                s11_xact, sgwc_ue->mme_s11_teid,
                OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_REQUEST_ACCEPTED);
        /* Release the UE context if this was its last session. */
        sgwc_ue_remove_if_empty(sgwc_ue);
        return;
    }

    ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
        sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);
    ogs_debug("    SGW_S5C_TEID[0x%x] PGW_S5C_TEID[0x%x]",
        sess->sgw_s5c_teid, sess->pgw_s5c_teid);

    if (indication &&
        indication->operation_indication == 0 &&
        indication->scope_indication == 1) {

        ogs_assert(OGS_OK ==
            sgwc_pfcp_send_session_deletion_request(
                sess, s11_xact->id, gtpbuf));

    } else {
        message->h.type = OGS_GTP2_DELETE_SESSION_REQUEST_TYPE;
        message->h.teid = sess->pgw_s5c_teid;

        gtpbuf = ogs_gtp2_build_msg(message);
        if (!gtpbuf) {
            ogs_error("ogs_gtp2_build_msg() failed");
            return;
        }

        s5c_xact = ogs_gtp_xact_local_create(
                sess->gnode, &message->h, gtpbuf, gtp_sess_timeout,
                OGS_UINT_TO_POINTER(sess->id));
        if (!s5c_xact) {
            ogs_error("ogs_gtp_xact_local_create() failed");
            ogs_pkbuf_free(gtpbuf);
            return;
        }
        s5c_xact->local_teid = sess->sgw_s5c_teid;

        ogs_gtp_xact_associate(s11_xact, s5c_xact);

        rv = ogs_gtp_xact_commit(s5c_xact);
        ogs_expect(rv == OGS_OK);
    }

    return;

cleanup:
    ogs_assert(cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED);

    ogs_gtp_send_error_message(
            s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
            OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE,
            cause_value);
}

void sgwc_s11_handle_create_bearer_response(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv;
    ogs_gtp2_cause_t *cause = NULL;
    uint8_t cause_value;
    uint16_t decoded;

    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;
    ogs_pool_id_t bearer_id = OGS_INVALID_POOL_ID;
    sgwc_tunnel_t *dl_tunnel = NULL, *ul_tunnel = NULL;
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;

    ogs_gtp_xact_t *s5c_xact = NULL;

    ogs_gtp2_create_bearer_response_t *rsp = NULL;
    ogs_gtp2_f_teid_t *sgw_s1u_teid = NULL, *enb_s1u_teid = NULL;
    ogs_gtp2_uli_t uli;

    ogs_assert(message);
    rsp = &message->create_bearer_response;
    ogs_assert(rsp);

    sgwc_ue_info(sgwc_ue, NULL, "s11", NULL, "Create Bearer Response");

    /********************
     * Check Transaction
     ********************/
    ogs_assert(s11_xact);
    s5c_xact = ogs_gtp_xact_find_by_id(s11_xact->assoc_xact_id);
    ogs_assert(s5c_xact);

    if (s11_xact->xid & OGS_GTP_CMD_XACT_ID) {
        /* MME received Bearer Resource Modification Request */
        ogs_assert(s5c_xact->data);
        bearer_id = OGS_POINTER_TO_UINT(s5c_xact->data);
        ogs_assert(bearer_id >= OGS_MIN_POOL_ID &&
                bearer_id <= OGS_MAX_POOL_ID);

        bearer = sgwc_bearer_find_by_id(bearer_id);
        if (!bearer)
            ogs_error("No Bearer ID [%d]", bearer_id);
    } else {
        ogs_assert(s11_xact->data);
        bearer_id = OGS_POINTER_TO_UINT(s11_xact->data);
        ogs_assert(bearer_id >= OGS_MIN_POOL_ID &&
                bearer_id <= OGS_MAX_POOL_ID);

        bearer = sgwc_bearer_find_by_id(bearer_id);
        if (!bearer)
            ogs_error("No Bearer ID [%d]", bearer_id);
    }

    if (bearer) {
        sess = sgwc_sess_find_by_id(bearer->sess_id);
        if (!sess)
            ogs_error("No Session ID [%d]", bearer->sess_id);
    }

    if (sess) {
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        if (!sgwc_ue)
            ogs_error("No SGWC-UE ID [%d]", sess->sgwc_ue_id);
    }

    rv = ogs_gtp_xact_commit(s11_xact);
    ogs_expect(rv == OGS_OK);

    /*****************************************
     * Check Mandatory/Conditional IE Missing
     *****************************************/
    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!bearer) {
        ogs_error("No Bearer Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }
    if (!sess) {
        ogs_error("No Session Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }
    if (!sgwc_ue) {
        ogs_error("No SGWC-UE Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (rsp->cause.presence == 0) {
        ogs_error("No Cause");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    } else {
        cause = rsp->cause.data;
        ogs_assert(cause);
        if (cause->value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
            ogs_error("GTP Cause [Value:%d]", cause->value);
            cause_value = cause->value;
            if (bearer) {
                ogs_debug("    bearer[EBI=%d]", bearer->ebi);
                ogs_assert(OGS_OK ==
                    sgwc_pfcp_send_bearer_modification_request(
                        bearer, OGS_INVALID_POOL_ID, NULL,
                        OGS_PFCP_MODIFY_UL_ONLY|OGS_PFCP_MODIFY_REMOVE));
            }
            goto cleanup;
        }
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        if (bearer) {
            ogs_debug("    bearer[EBI=%d]", bearer->ebi);
            ogs_assert(OGS_OK ==
                sgwc_pfcp_send_bearer_modification_request(
                    bearer, OGS_INVALID_POOL_ID, NULL,
                    OGS_PFCP_MODIFY_UL_ONLY|OGS_PFCP_MODIFY_REMOVE));
        }
        goto cleanup;
    }

    if (rsp->bearer_contexts.presence == 0) {
        ogs_error("No Bearer");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }
    if (rsp->bearer_contexts.eps_bearer_id.presence == 0) {
        ogs_error("No EPS Bearer ID");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }
    if (rsp->bearer_contexts.s1_u_enodeb_f_teid.presence == 0) {
        ogs_error("No eNB TEID");
        cause_value = OGS_GTP2_CAUSE_CONDITIONAL_IE_MISSING;
    }
    if (rsp->bearer_contexts.s4_u_sgsn_f_teid.presence == 0) {
        ogs_error("No SGW TEID");
        cause_value = OGS_GTP2_CAUSE_CONDITIONAL_IE_MISSING;
    }
    if (rsp->bearer_contexts.cause.presence == 0) {
        ogs_error("No Bearer Cause");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        if (bearer) {
            ogs_debug("    bearer[EBI=%d]", bearer->ebi);
            ogs_assert(OGS_OK ==
                sgwc_pfcp_send_bearer_modification_request(
                    bearer, OGS_INVALID_POOL_ID, NULL,
                    OGS_PFCP_MODIFY_UL_ONLY|OGS_PFCP_MODIFY_REMOVE));
        }
        goto cleanup;
    }

    /********************
     * Check Cause Value
     ********************/
    cause = rsp->bearer_contexts.cause.data;
    ogs_assert(cause);
    cause_value = cause->value;
    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("GTP Cause [Value:%d]", cause_value);
        ogs_debug("    bearer[EBI=%d]", bearer->ebi);
        ogs_assert(OGS_OK ==
            sgwc_pfcp_send_bearer_modification_request(
                bearer, OGS_INVALID_POOL_ID, NULL,
                OGS_PFCP_MODIFY_UL_ONLY|OGS_PFCP_MODIFY_REMOVE));
        goto cleanup;
    }

    /********************
     * Check ALL Context
     ********************/
    ogs_assert(sgwc_ue);
    ogs_assert(sess);
    ogs_assert(bearer);

    /* Correlate with SGW-S1U-TEID */
    sgw_s1u_teid = rsp->bearer_contexts.s4_u_sgsn_f_teid.data;
    ogs_assert(sgw_s1u_teid);

    /* Find the Tunnel by SGW-S1U-TEID */
    ul_tunnel = sgwc_tunnel_find_by_teid(sgwc_ue, be32toh(sgw_s1u_teid->teid));
    if (!ul_tunnel) {
        ogs_error("No UL-tunnel [EBI:%d, TEID:0x%x]",
                bearer->ebi, be32toh(sgw_s1u_teid->teid));
        cause_value = OGS_GTP2_CAUSE_GRE_KEY_NOT_FOUND;
        goto cleanup;
    }
    dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
    if (!dl_tunnel) {
        ogs_error("No DL-tunnel [EBI:%d, TEID:0x%x]",
                bearer->ebi, be32toh(sgw_s1u_teid->teid));
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
        goto cleanup;
    }

    /* Set EBI */
    bearer->ebi = rsp->bearer_contexts.eps_bearer_id.u8;

    /* Data Plane(DL) : eNB-S1U */
    enb_s1u_teid = rsp->bearer_contexts.s1_u_enodeb_f_teid.data;
    dl_tunnel->remote_teid = be32toh(enb_s1u_teid->teid);

    ogs_debug("    ENB_S1U_TEID[%d] SGW_S1U_TEID[%d]",
        dl_tunnel->remote_teid, dl_tunnel->local_teid);

    rv = ogs_gtp2_f_teid_to_ip(enb_s1u_teid, &dl_tunnel->remote_ip);
    if (rv != OGS_OK) {
        ogs_error("No IPv4 or IPv6 in eNB-S1U");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
        goto cleanup;
    }

    pdr = dl_tunnel->pdr;
    ogs_assert(pdr);

    pdr->outer_header_removal_len = 1;
    pdr->outer_header_removal.description =
        OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;

    far = dl_tunnel->far;
    ogs_assert(far);

    far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

    rv = ogs_pfcp_ip_to_outer_header_creation(&dl_tunnel->remote_ip,
            &far->outer_header_creation, &far->outer_header_creation_len);
    if (rv != OGS_OK) {
        ogs_error("No IPv4 or IPv6 in DL-Tunnel");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
        goto cleanup;
    }
    far->outer_header_creation.teid = dl_tunnel->remote_teid;

    if (rsp->user_location_information.presence == 1) {
        decoded = ogs_gtp2_parse_uli(&uli, &rsp->user_location_information);
        if (rsp->user_location_information.len == decoded) {
            sgwc_ue->uli_presence = true;
            sgwc_ue_store_uli_raw(sgwc_ue,
                    rsp->user_location_information.data,
                    rsp->user_location_information.len);

            ogs_nas_to_plmn_id(&sgwc_ue->e_tai.plmn_id, &uli.tai.nas_plmn_id);
            sgwc_ue->e_tai.tac = uli.tai.tac;
            ogs_nas_to_plmn_id(&sgwc_ue->e_cgi.plmn_id, &uli.e_cgi.nas_plmn_id);
            sgwc_ue->e_cgi.cell_id = uli.e_cgi.cell_id;

            ogs_debug("    TAI[PLMN_ID:%06x,TAC:%d]",
                    ogs_plmn_id_hexdump(&sgwc_ue->e_tai.plmn_id),
                    sgwc_ue->e_tai.tac);
            ogs_debug("    E_CGI[PLMN_ID:%06x,CELL_ID:0x%x]",
                    ogs_plmn_id_hexdump(&sgwc_ue->e_cgi.plmn_id),
                    sgwc_ue->e_cgi.cell_id);
        } else
            ogs_error("Invalid User Location Info(ULI)");
    }

    ogs_debug("    bearer[EBI=%d] xact=%p", bearer->ebi, s5c_xact);
    ogs_assert(OGS_OK ==
        sgwc_pfcp_send_bearer_modification_request(
            bearer, s5c_xact->id, gtpbuf,
            OGS_PFCP_MODIFY_DL_ONLY|OGS_PFCP_MODIFY_CREATE));

    return;

cleanup:
    ogs_assert(cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED);

    ogs_gtp_send_error_message(s5c_xact, sess ? sess->pgw_s5c_teid : 0,
            OGS_GTP2_CREATE_BEARER_RESPONSE_TYPE,
            cause_value);
}

void sgwc_s11_handle_update_bearer_response(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv;
    ogs_gtp2_cause_t *cause = NULL;
    uint8_t cause_value;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *s5c_xact = NULL;
    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;
    ogs_pool_id_t bearer_id = OGS_INVALID_POOL_ID;
    ogs_gtp2_update_bearer_response_t *rsp = NULL;

    ogs_assert(message);
    rsp = &message->update_bearer_response;
    ogs_assert(rsp);

    ogs_info("Update Bearer Response");

    /********************
     * Check Transaction
     ********************/
    ogs_assert(s11_xact);
    s5c_xact = ogs_gtp_xact_find_by_id(s11_xact->assoc_xact_id);
    ogs_assert(s5c_xact);

    if (s11_xact->xid & OGS_GTP_CMD_XACT_ID) {
        /* MME received Bearer Resource Modification Request */
        ogs_assert(s5c_xact->data);
        bearer_id = OGS_POINTER_TO_UINT(s5c_xact->data);
        ogs_assert(bearer_id >= OGS_MIN_POOL_ID &&
                bearer_id <= OGS_MAX_POOL_ID);

        bearer = sgwc_bearer_find_by_id(bearer_id);
        if (!bearer)
            ogs_error("No Bearer ID [%d]", bearer_id);
    } else {
        ogs_assert(s11_xact->data);
        bearer_id = OGS_POINTER_TO_UINT(s11_xact->data);
        ogs_assert(bearer_id >= OGS_MIN_POOL_ID &&
                bearer_id <= OGS_MAX_POOL_ID);

        bearer = sgwc_bearer_find_by_id(bearer_id);
        if (!bearer)
            ogs_error("No Bearer ID [%d]", bearer_id);
    }

    if (bearer) {
        sess = sgwc_sess_find_by_id(bearer->sess_id);
        if (!sess)
            ogs_error("No Session ID [%d]", bearer->sess_id);
    }

    if (sess) {
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        if (!sgwc_ue)
            ogs_error("No SGWC-UE ID [%d]", sess->sgwc_ue_id);
    }

    rv = ogs_gtp_xact_commit(s11_xact);
    ogs_expect(rv == OGS_OK);

    /*****************************************
     * Check Mandatory/Conditional IE Missing
     *****************************************/
    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (rsp->bearer_contexts.presence == 0) {
        ogs_error("No Bearer");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }
    if (rsp->bearer_contexts.eps_bearer_id.presence == 0) {
        ogs_error("No EPS Bearer ID");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }

    if (rsp->cause.presence == 0) {
        ogs_error("No Cause");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }
    if (rsp->bearer_contexts.cause.presence == 0) {
        ogs_error("No Bearer Cause");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }

    if (!bearer) {
        ogs_error("No Bearer Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }
    if (!sess) {
        ogs_error("No Session Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }
    if (!sgwc_ue) {
        ogs_error("No SGWC-UE Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /********************
     * Check Cause Value
     ********************/
    cause = rsp->bearer_contexts.cause.data;
    ogs_assert(cause);
    cause_value = cause->value;
    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("GTP Bearer Cause [VALUE:%d]", cause_value);
        goto cleanup;
    }

    cause = rsp->cause.data;
    ogs_assert(cause);
    cause_value = cause->value;
    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("GTP Cause [Value:%d]", cause_value);
        goto cleanup;
    }

    /********************
     * Check ALL Context
     ********************/
    ogs_assert(sgwc_ue);
    ogs_assert(sess);

    ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
        sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);
    ogs_debug("    SGW_S5C_TEID[0x%x] PGW_S5C_TEID[0x%x]",
        sess->sgw_s5c_teid, sess->pgw_s5c_teid);

    message->h.type = OGS_GTP2_UPDATE_BEARER_RESPONSE_TYPE;
    message->h.teid = sess->pgw_s5c_teid;

    pkbuf = ogs_gtp2_build_msg(message);
    if (!pkbuf) {
        ogs_error("ogs_gtp2_build_msg() failed");
        return;
    }

    rv = ogs_gtp_xact_update_tx(s5c_xact, &message->h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_update_tx() failed");
        return;
    }

    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);

    return;

cleanup:
    ogs_assert(cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED);

    ogs_gtp_send_error_message(s5c_xact, sess ? sess->pgw_s5c_teid : 0,
            OGS_GTP2_UPDATE_BEARER_RESPONSE_TYPE, cause_value);
}

void sgwc_s11_handle_delete_bearer_response(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv;
    uint8_t cause_value;
    ogs_gtp_xact_t *s5c_xact = NULL;

    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;
    ogs_pool_id_t bearer_id = OGS_INVALID_POOL_ID;
    ogs_gtp2_delete_bearer_response_t *rsp = NULL;

    ogs_assert(message);
    rsp = &message->delete_bearer_response;
    ogs_assert(rsp);

    ogs_info("Delete Bearer Response");

    /********************
     * Check Transaction
     ********************/
    ogs_assert(s11_xact);
    s5c_xact = ogs_gtp_xact_find_by_id(s11_xact->assoc_xact_id);
    if (!s5c_xact) {
        /*
         * No associated S5C transaction: this Delete Bearer Response arrived
         * for an admin-initiated (not PGW-forwarded) deletion.  Commit the
         * S11 transaction, then fall through to send a PFCP Session Deletion
         * to SGW-U with no GTP relay context.  The SXA cleanup cascade will
         * remove the local session.
         */
        ogs_info("[%s] Delete Bearer Response from MME (admin delete) "
                 "-- cascading to SGW-U PFCP cleanup",
                 sgwc_ue ? sgwc_ue->imsi_bcd : "-");
    }

    if (s11_xact->xid & OGS_GTP_CMD_XACT_ID) {
        /* MME received Bearer Resource Modification Request: s5c_xact required */
        if (!s5c_xact || !s5c_xact->data) {
            ogs_error("Delete Bearer Response (CMD path): missing S5C xact");
            rv = ogs_gtp_xact_commit(s11_xact);
            ogs_expect(rv == OGS_OK);
            return;
        }
        bearer_id = OGS_POINTER_TO_UINT(s5c_xact->data);
        ogs_assert(bearer_id >= OGS_MIN_POOL_ID &&
                bearer_id <= OGS_MAX_POOL_ID);

        bearer = sgwc_bearer_find_by_id(bearer_id);
        if (!bearer)
            ogs_error("No Bearer ID [%d]", bearer_id);
    } else {
        ogs_assert(s11_xact->data);
        bearer_id = OGS_POINTER_TO_UINT(s11_xact->data);
        ogs_assert(bearer_id >= OGS_MIN_POOL_ID &&
                bearer_id <= OGS_MAX_POOL_ID);

        bearer = sgwc_bearer_find_by_id(bearer_id);
        if (!bearer)
            ogs_error("No Bearer ID [%d]", bearer_id);
    }

    if (bearer) {
        sess = sgwc_sess_find_by_id(bearer->sess_id);
        if (!sess)
            ogs_error("No Session ID [%d]", bearer->sess_id);
    }

    if (sess) {
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        if (!sgwc_ue)
            ogs_error("No SGWC-UE ID [%d]", sess->sgwc_ue_id);
    }

    rv = ogs_gtp_xact_commit(s11_xact);
    ogs_expect(rv == OGS_OK);

    /************************
     * Check SGWC-UE Context
     ************************/
    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!bearer) {
        ogs_error("No Bearer Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }
    if (!sess) {
        ogs_error("No Session Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }
    if (!sgwc_ue) {
        ogs_error("No SGWC-UE Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    if (rsp->linked_eps_bearer_id.presence ||
            bearer == sgwc_default_bearer_in_sess(sess)) {
       /*
        * << Linked EPS Bearer ID >>
        *
        * 1. SMF sends Delete Bearer Request(DEFAULT BEARER) to SGW/MME.
        * 2. MME sends Delete Bearer Response to SGW/SMF.
        *
        * OR
        *
        * 1. SMF sends Delete Bearer Request(DEFAULT BEARER) to ePDG.
        * 2. ePDG sends Delete Bearer Response(DEFAULT BEARER) to SMF.
        *
        * Route on our own bearer context too, not only on the response IE:
        * an MME that answers with an error cause (UE unreachable, paging
        * failure) may omit linked_eps_bearer_id entirely. Deleting the
        * DEFAULT bearer always tears down the whole PDN connection -- the
        * PGW/SMF has already released its side -- so falling into the
        * dedicated-bearer branch here stranded a bearer-less session on
        * SGW-C and its twin PFCP session on SGW-U.
        */
        if (!rsp->linked_eps_bearer_id.presence)
            ogs_warn("[%s] Delete Bearer Response without Linked EBI for "
                    "default bearer EBI[%d]; treating as PDN teardown",
                    sgwc_ue->imsi_bcd, bearer->ebi);
        if (rsp->cause.presence) {
            ogs_gtp2_cause_t *cause = rsp->cause.data;
            ogs_assert(cause);

            cause_value = cause->value;
            if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
            } else {
                ogs_error("GTP Cause [Value:%d]", cause_value);
            }
        } else {
            ogs_error("No Cause");
        }

        ogs_assert(OGS_OK ==
            sgwc_pfcp_send_session_deletion_request(
                sess,
                s5c_xact ? s5c_xact->id : OGS_INVALID_POOL_ID,
                s5c_xact ? gtpbuf : NULL));
    } else {
       /*
        * << EPS Bearer IDs >>
        *
        * 1. MME sends Bearer Resource Command to SGW/SMF.
        * 2. SMF sends Delete Bearer Request(DEDICATED BEARER) to SGW/MME.
        * 3. MME sends Delete Bearer Response(DEDICATED BEARER) to SGW/SMF.
        *
        * OR
        *
        * 1. SMF sends Delete Bearer Request(DEDICATED BEARER) to SGW/MME.
        * 2. MME sends Delete Bearer Response(DEDICATED BEARER) to SGW/SMF.
        */
        if (rsp->bearer_contexts.presence == 0) {
            ogs_error("No Bearer");
        }
        if (rsp->bearer_contexts.eps_bearer_id.presence == 0) {
            ogs_error("No EPS Bearer ID");
        }

        if (rsp->cause.presence) {
            ogs_gtp2_cause_t *cause = rsp->cause.data;
            ogs_assert(cause);

            cause_value = cause->value;
            if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
                if (rsp->bearer_contexts.cause.presence) {
                    cause = rsp->bearer_contexts.cause.data;
                    ogs_assert(cause);

                    if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
                    } else {
                        ogs_error("GTP Cause [Value:%d]", cause_value);
                    }
                } else {
                    ogs_error("No Cause");
                }
            } else {
                ogs_error("GTP Cause [Value:%d]", cause_value);
            }
        } else {
            ogs_error("No Cause");
        }

        ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
            sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);
        ogs_debug("    SGW_S5C_TEID[0x%x] PGW_S5C_TEID[0x%x]",
            sess->sgw_s5c_teid, sess->pgw_s5c_teid);

        ogs_debug("    bearer[EBI=%d] xact=%p", bearer->ebi, s5c_xact);
        ogs_assert(OGS_OK ==
            sgwc_pfcp_send_bearer_modification_request(
                bearer,
                s5c_xact ? s5c_xact->id : OGS_INVALID_POOL_ID,
                s5c_xact ? gtpbuf : NULL,
                OGS_PFCP_MODIFY_REMOVE));
    }

    return;

cleanup:
    ogs_assert(cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED);

    if (s5c_xact)
        ogs_gtp_send_error_message(s5c_xact, sess ? sess->pgw_s5c_teid : 0,
                OGS_GTP2_DELETE_BEARER_RESPONSE_TYPE, cause_value);
}

void sgwc_s11_handle_release_access_bearers_request(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    sgwc_sess_t *sess = NULL;
    uint8_t cause_value;

    ogs_gtp2_release_access_bearers_request_t *req = NULL;

    ogs_assert(s11_xact);
    ogs_assert(message);
    req = &message->release_access_bearers_request;
    ogs_assert(req);

    ogs_info("Release Access Bearers Request");

    /************************
     * Check SGWC-UE Context
     ************************/
    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!sgwc_ue) {
        uint32_t sgw_s11_teid =
                message->h.teid_presence ? message->h.teid : 0;

        /*
         * Release Access Bearers Request carries no IMSI (TS 29.274). When
         * the SGWC-UE context is already gone, IMSI cannot be recovered on
         * SGW-C; the enriched prefix shows IMSI:- and the SGW-S11-TEID from
         * the GTP header when the MME had one assigned.
         */
        sgwc_ue_warn_no_ctx("s11", sgw_s11_teid,
                "Release Access Bearers Request: no SGWC-UE context for "
                "SGW-S11-TEID[0x%x] - context already released (stale MME "
                "state, prior Delete Session, failed attach, or SGW-C "
                "restart); replying CONTEXT_NOT_FOUND so MME re-syncs",
                sgw_s11_teid);
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_gtp_send_error_message(
                s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
                OGS_GTP2_RELEASE_ACCESS_BEARERS_RESPONSE_TYPE, cause_value);
        return;
    }

    ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
        sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);

    int num_of_modify = 0;

    ogs_list_for_each(&sgwc_ue->sess_list, sess) {

        /*
         * A session with no bearers (half-established / failed setup) has no
         * S1-U bearer to deactivate, and a session with no PFCP node has no
         * SGW-U to talk to. Sending a PFCP modification for either used to
         * abort the entire SGW-C. Skip such sessions instead.
         */
        if (ogs_list_count(&sess->bearer_list) == 0) {
            ogs_error("[%s] Release Access Bearers: session has no bearers, "
                    "skipping", sgwc_ue->imsi_bcd);
            continue;
        }
        if (!sess->pfcp_node) {
            ogs_error("[%s] Release Access Bearers: session has no PFCP node, "
                    "skipping", sgwc_ue->imsi_bcd);
            continue;
        }

        ogs_debug("    sess_id=%d xact=%p", sess->id, s11_xact);
        ogs_assert(OGS_OK ==
            sgwc_pfcp_send_session_modification_request(
                sess, s11_xact->id, gtpbuf,
                OGS_PFCP_MODIFY_DL_ONLY|OGS_PFCP_MODIFY_DEACTIVATE));
        num_of_modify++;
    }

    /*
     * If no session could be modified (all empty / no UPF), the PFCP-response
     * path that normally builds the Release Access Bearers Response never runs.
     * Acknowledge the MME directly so it does not retransmit.
     */
    if (num_of_modify == 0) {
        ogs_warn("[%s] Release Access Bearers: no modifiable session; "
                "responding accepted", sgwc_ue->imsi_bcd);
        ogs_gtp_send_error_message(
                s11_xact, sgwc_ue->mme_s11_teid,
                OGS_GTP2_RELEASE_ACCESS_BEARERS_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_REQUEST_ACCEPTED);
    }
}

void sgwc_s11_handle_downlink_data_notification_ack(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv;
    uint8_t cause_value;

    sgwc_bearer_t *bearer = NULL;
    ogs_pool_id_t bearer_id = OGS_INVALID_POOL_ID;
    sgwc_sess_t *sess = NULL;

    ogs_gtp2_downlink_data_notification_acknowledge_t *ack = NULL;

    ogs_assert(message);
    ack = &message->downlink_data_notification_acknowledge;
    ogs_assert(ack);

    /********************
     * Check Transaction
     ********************/
    ogs_assert(s11_xact);

    if (!s11_xact->data) {
        ogs_error("No Transaction Data in Downlink Data Notification Ack");
        goto out;
    }

    bearer_id = OGS_POINTER_TO_UINT(s11_xact->data);
    if (bearer_id < OGS_MIN_POOL_ID || bearer_id > OGS_MAX_POOL_ID) {
        ogs_error("Invalid Bearer ID [%d] in Downlink Data Notification Ack",
                bearer_id);
        goto out;
    }

    bearer = sgwc_bearer_find_by_id(bearer_id);
    if (!bearer) {
        ogs_warn("Bearer Not Found [id:%d] in Downlink Data Notification Ack",
                bearer_id);
        goto out;
    }

    sess = sgwc_sess_find_by_id(bearer->sess_id);
    if (!sess) {
        ogs_warn("Session Not Found [id:%d] in Downlink Data Notification Ack",
                bearer->sess_id);
        goto out;
    }

out:
    rv = ogs_gtp_xact_commit(s11_xact);
    ogs_expect(rv == OGS_OK);

    /************************
     * Check SGWC-UE Context
     ************************/
    if (ack->cause.presence) {
        ogs_gtp2_cause_t *cause = ack->cause.data;
        ogs_assert(cause);

        cause_value = cause->value;
        if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED && 
            cause_value != OGS_GTP2_CAUSE_UE_ALREADY_RE_ATTACHED)
            ogs_warn("GTP Cause [Value:%d] - PFCP_CAUSE[%d]",
                    cause_value, pfcp_cause_from_gtp(cause_value));
    } else {
        ogs_error("No Cause");
    }

    ogs_info("Downlink Data Notification Acknowledge%s%s",
            s11_xact->data ? " bearer_id present" : "",
            sgwc_ue ? " ue present" : "");

    if (sgwc_ue)
        ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
            sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);
    if (sess)
        ogs_debug("    SGW_S5C_TEID[%d] PGW_S5C_TEID[%d]",
            sess->sgw_s5c_teid, sess->pgw_s5c_teid);
    if (bearer)
        ogs_debug("    BEARER ID[%d] EBI[%d]", bearer->id, bearer->ebi);
}

void sgwc_s11_handle_create_indirect_data_forwarding_tunnel_request(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv, i;

    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *tunnel = NULL;
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;

    ogs_gtp2_create_indirect_data_forwarding_tunnel_request_t *req = NULL;
    ogs_gtp2_f_teid_t *req_teid = NULL;
    uint8_t cause_value = 0;

    ogs_assert(s11_xact);
    ogs_assert(message);
    req = &message->create_indirect_data_forwarding_tunnel_request;
    ogs_assert(req);

    ogs_info("Create Indirect Data Forwarding Tunnel Request");

    /************************
     * Check SGWC-UE Context
     ************************/
    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!sgwc_ue) {
        ogs_error("No Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
        sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);

    for (i = 0; req->bearer_contexts[i].presence; i++) {
        if (req->bearer_contexts[i].eps_bearer_id.presence == 0) {
            ogs_error("No EBI");
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
            goto cleanup;
        }

        bearer = sgwc_bearer_find_by_ue_ebi(sgwc_ue,
                    req->bearer_contexts[i].eps_bearer_id.u8);
        if (!bearer) {
            ogs_error("No Bearer Context [%d]",
                    req->bearer_contexts[i].eps_bearer_id.u8);
            cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
            goto cleanup;
        }

        sess = sgwc_sess_find_by_id(bearer->sess_id);
        ogs_assert(sess);

        if (req->bearer_contexts[i].s1_u_enodeb_f_teid.presence) {
            req_teid = req->bearer_contexts[i].s1_u_enodeb_f_teid.data;
            ogs_assert(req_teid);

            tunnel = sgwc_tunnel_add(bearer,
                    OGS_GTP2_F_TEID_SGW_GTP_U_FOR_DL_DATA_FORWARDING);
            if (!tunnel) {
                ogs_error("sgwc_tunnel_add() failed");
                cause_value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;
                goto cleanup;
            }

            tunnel->remote_teid = be32toh(req_teid->teid);

            rv = ogs_gtp2_f_teid_to_ip(req_teid, &tunnel->remote_ip);
            if (rv != OGS_OK) {
                ogs_error("No IPv4 or IPv6 in REQ-TEID");
                cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
                goto cleanup;
            }

            pdr = tunnel->pdr;
            ogs_assert(pdr);

            pdr->outer_header_removal_len = 1;
            pdr->outer_header_removal.description =
                OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;

            far = tunnel->far;
            ogs_assert(far);

            far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

            rv = ogs_pfcp_ip_to_outer_header_creation(
                    &tunnel->remote_ip,
                    &far->outer_header_creation,
                    &far->outer_header_creation_len);
            if (rv != OGS_OK) {
                ogs_error("No IPv4 or IPv6 in Tunnel");
                cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
                goto cleanup;
            }
            far->outer_header_creation.teid = tunnel->remote_teid;

            ogs_debug("    SGW_DL_TEID[%d] ENB_DL_TEID[%d]",
                    tunnel->local_teid, tunnel->remote_teid);
        }

        if (req->bearer_contexts[i].s12_rnc_f_teid.presence) {
            req_teid = req->bearer_contexts[i].s12_rnc_f_teid.data;
            ogs_assert(req_teid);

            tunnel = sgwc_tunnel_add(bearer,
                    OGS_GTP2_F_TEID_SGW_GTP_U_FOR_UL_DATA_FORWARDING);
            if (!tunnel) {
                ogs_error("sgwc_tunnel_add() failed");
                cause_value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;
                goto cleanup;
            }

            tunnel->remote_teid = be32toh(req_teid->teid);

            rv = ogs_gtp2_f_teid_to_ip(req_teid, &tunnel->remote_ip);
            if (rv != OGS_OK) {
                ogs_error("No IPv4 or IPv6 in REQ-TEID");
                cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
                goto cleanup;
            }

            pdr = tunnel->pdr;
            ogs_assert(pdr);

            pdr->outer_header_removal_len = 1;
            pdr->outer_header_removal.description =
                OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;

            far = tunnel->far;
            ogs_assert(far);

            far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

            rv = ogs_pfcp_ip_to_outer_header_creation(
                    &tunnel->remote_ip,
                    &far->outer_header_creation,
                    &far->outer_header_creation_len);
            if (rv != OGS_OK) {
                ogs_error("No IPv4 or IPv6 in Tunnel");
                cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
                goto cleanup;
            }
            far->outer_header_creation.teid = tunnel->remote_teid;

            ogs_debug("    SGW_UL_TEID[%d] ENB_UL_TEID[%d]",
                    tunnel->local_teid, tunnel->remote_teid);
        }
    }

    int num_of_modify = 0;

    ogs_list_for_each(&sgwc_ue->sess_list, sess) {
        bool has_indirect = false;

        if (ogs_list_count(&sess->bearer_list) == 0) {
            ogs_warn("[%s] Create Indirect Data Forwarding: session has no "
                    "bearers APN[%s] sess_id[%d], skipping (stale session?)",
                    sgwc_log_imsi(sgwc_ue),
                    sess->session.name ? sess->session.name : "-",
                    sess->id);
            continue;
        }
        if (!sess->pfcp_node) {
            ogs_warn("[%s] Create Indirect Data Forwarding: session has no "
                    "PFCP node APN[%s] sess_id[%d], skipping",
                    sgwc_log_imsi(sgwc_ue),
                    sess->session.name ? sess->session.name : "-",
                    sess->id);
            continue;
        }

        ogs_list_for_each(&sess->bearer_list, bearer) {
            ogs_list_for_each(&bearer->tunnel_list, tunnel) {
                if ((tunnel->interface_type ==
                         OGS_GTP2_F_TEID_SGW_GTP_U_FOR_DL_DATA_FORWARDING) ||
                    (tunnel->interface_type ==
                         OGS_GTP2_F_TEID_SGW_GTP_U_FOR_UL_DATA_FORWARDING)) {
                    has_indirect = true;
                    break;
                }
            }
            if (has_indirect) break;
        }

        if (has_indirect == true) {
            ogs_debug("    sess_id=%d xact=%p", sess->id, s11_xact);
            rv = sgwc_pfcp_send_session_modification_request(
                    sess, s11_xact->id, gtpbuf,
                    OGS_PFCP_MODIFY_INDIRECT|OGS_PFCP_MODIFY_CREATE);
            if (rv != OGS_OK) {
                ogs_error("[%s] PFCP modification failed for indirect "
                        "forwarding APN[%s] sess_id[%d]",
                        sgwc_log_imsi(sgwc_ue),
                        sess->session.name ? sess->session.name : "-",
                        sess->id);
            } else {
                num_of_modify++;
            }
        } else {
            ogs_error("No Indirect Tunnel");
            ogs_error("    UE IMSI[%s] APN[%s]",
                    sgwc_ue->imsi_bcd, sess->session.name);
            ogs_error("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
                    sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);
            ogs_list_for_each(&sess->bearer_list, bearer) {
                ogs_error("    EBI[%d]", bearer->ebi);
                ogs_list_for_each(&bearer->tunnel_list, tunnel) {
                    ogs_error("TUNNEL[%d] INF[%d]",
                            tunnel->id, tunnel->interface_type);
                }
            }
        }
    }

    if (num_of_modify == 0) {
        ogs_error("[%s] Create Indirect Data Forwarding: no modifiable session",
                sgwc_log_imsi(sgwc_ue));
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
        goto cleanup;
    }

    return;

cleanup:
    ogs_assert(cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED);

    ogs_gtp_send_error_message(s11_xact,
            sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
            OGS_GTP2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE_TYPE,
            cause_value);
}

void sgwc_s11_handle_delete_indirect_data_forwarding_tunnel_request(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *recv_message)
{
    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *tunnel = NULL;
    uint8_t cause_value = 0;

    ogs_assert(s11_xact);

    ogs_info("Delete Indirect Data Forwarding Tunnel Request");

    /************************
     * Check SGWC-UE Context
     ************************/
    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!sgwc_ue) {
        ogs_error("No Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_gtp_send_error_message(
                s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
                OGS_GTP2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE_TYPE,
                cause_value);
        return;
    }

    /********************
     * Check ALL Context
     ********************/
    ogs_assert(sgwc_ue);

    ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
        sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);

    ogs_list_for_each(&sgwc_ue->sess_list, sess) {
        bool has_indirect = false;
        ogs_list_for_each(&sess->bearer_list, bearer) {
            ogs_list_for_each(&bearer->tunnel_list, tunnel) {
                if (tunnel->interface_type ==
                        OGS_GTP2_F_TEID_SGW_GTP_U_FOR_DL_DATA_FORWARDING ||
                    tunnel->interface_type ==
                        OGS_GTP2_F_TEID_SGW_GTP_U_FOR_UL_DATA_FORWARDING) {
                    has_indirect = true;
                    break;
                }
            }
            if (has_indirect) break;
        }

        if (has_indirect) {
            ogs_debug("    sess_id=%d xact=%p", sess->id, s11_xact);
            ogs_assert(OGS_OK ==
                sgwc_pfcp_send_session_modification_request(
                    sess, s11_xact->id, gtpbuf,
                    OGS_PFCP_MODIFY_INDIRECT|OGS_PFCP_MODIFY_REMOVE));
        } else {
            ogs_error("No Indirect Tunnel");
            ogs_error("    UE IMSI[%s] APN[%s]",
                    sgwc_ue->imsi_bcd, sess->session.name);
            ogs_error("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
                    sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);
            ogs_list_for_each(&sess->bearer_list, bearer) {
                ogs_error("    EBI[%d]", bearer->ebi);
                ogs_list_for_each(&bearer->tunnel_list, tunnel) {
                    ogs_error("TUNNEL[%d] INF[%d]",
                            tunnel->id, tunnel->interface_type);
                }
            }
        }
    }
}

void sgwc_s11_handle_bearer_resource_command(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp2_bearer_resource_command_t *cmd = NULL;

    uint8_t cause_value = 0;
    ogs_gtp_xact_t *s5c_xact = NULL;

    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;

    ogs_assert(s11_xact);
    ogs_assert(message);
    cmd = &message->bearer_resource_command;
    ogs_assert(cmd);

    ogs_info("Bearer Resource Command");

    /************************
     * Check SGWC-UE Context
     ************************/
    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!sgwc_ue) {
        ogs_error("No Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    } else {
        if (cmd->linked_eps_bearer_id.presence == 0) {
            ogs_error("No Linked EPS Bearer ID");
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        }

        if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
            uint8_t ebi = cmd->linked_eps_bearer_id.u8;

            if (cmd->eps_bearer_id.presence)
                ebi = cmd->eps_bearer_id.u8;

            bearer = sgwc_bearer_find_by_ue_ebi(sgwc_ue, ebi);
            if (!bearer) {
                ogs_error("No Context for Linked EPS Bearer ID[%d:%d]",
                        cmd->linked_eps_bearer_id.u8, ebi);
                cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
            }
        }
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_gtp_send_error_message(
                s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
                OGS_GTP2_BEARER_RESOURCE_FAILURE_INDICATION_TYPE, cause_value);
        return;
    }

    /*****************************************
     * Check Mandatory/Conditional IE Missing
     *****************************************/
    if (cmd->procedure_transaction_id.presence == 0) {
        ogs_error("No PTI");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }
    if (cmd->traffic_aggregate_description.presence == 0) {
        ogs_error("No Traffic aggregate description(TAD)");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_gtp_send_error_message(
                s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
                OGS_GTP2_BEARER_RESOURCE_FAILURE_INDICATION_TYPE, cause_value);
        return;
    }

    /********************
     * Check ALL Context
     ********************/
    ogs_assert(bearer);
    sess = sgwc_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    ogs_assert(sess->gnode);
    ogs_assert(sgwc_ue);

    ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
        sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);
    ogs_debug("    SGW_S5C_TEID[0x%x] PGW_S5C_TEID[0x%x]",
        sess->sgw_s5c_teid, sess->pgw_s5c_teid);

    message->h.type = OGS_GTP2_BEARER_RESOURCE_COMMAND_TYPE;
    message->h.teid = sess->pgw_s5c_teid;

    pkbuf = ogs_gtp2_build_msg(message);
    if (!pkbuf) {
        ogs_error("ogs_gtp2_build_msg() failed");
        return;
    }

    s5c_xact = ogs_gtp_xact_local_create(
            sess->gnode, &message->h, pkbuf, gtp_bearer_timeout,
            OGS_UINT_TO_POINTER(bearer->id));
    if (!s5c_xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        ogs_pkbuf_free(pkbuf);
        return;
    }
    s5c_xact->local_teid = sess->sgw_s5c_teid;

    ogs_gtp_xact_associate(s11_xact, s5c_xact);

    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);
}
