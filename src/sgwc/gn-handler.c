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

#include "gn-handler.h"
#include "gn-build.h"
#include "gtp-path.h"
#include "pfcp-path.h"
#include "s11-handler.h"
#include "sgwc-trace.h"

static void sgwc_gn_create_pdp_proceed(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *gn_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp1_message_t *message);

void sgwc_gn_handle_echo_request(
        ogs_gtp_xact_t *xact, ogs_gtp1_echo_request_t *req)
{
    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("[SGW] Receiving Gn Echo Request");
    ogs_gtp1_send_echo_response(xact, sgwc_self()->gn_gtpc_recovery);
}

static ogs_pkbuf_t *sgwc_gn_build_empty_gtp1_response(uint8_t type)
{
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp1_header_t *h = NULL;

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_GTPV1C_HEADER_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, OGS_GTPV1C_HEADER_LEN);

    h = (ogs_gtp1_header_t *)pkbuf->data;
    memset(h, 0, OGS_GTPV1C_HEADER_LEN);
    h->version = 1;
    h->pt = 1;
    h->type = type;
    h->length = 0;

    ogs_pkbuf_trim(pkbuf, OGS_GTPV1C_HEADER_LEN - OGS_GTP1_TEID_LEN);
    return pkbuf;
}

static int sgwc_gn_send_empty_response(
        ogs_gtp_xact_t *xact, uint8_t response_type)
{
    int rv;
    ogs_gtp1_header_t hdesc;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(xact);

    memset(&hdesc, 0, sizeof(hdesc));
    hdesc.type = response_type;

    pkbuf = sgwc_gn_build_empty_gtp1_response(response_type);
    if (!pkbuf) {
        ogs_error("sgwc_gn_build_empty_gtp1_response() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp1_xact_update_tx(xact, &hdesc, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);
    return rv;
}

bool sgwc_gn_handle_known_request(
        ogs_gtp_node_t *gnode, ogs_pkbuf_t *recvbuf)
{
    ogs_gtp1_header_t hdesc;
    ogs_gtp1_header_t *gh = NULL;
    ogs_gtp_xact_t *xact = NULL;
    int rv;
    uint8_t response_type = 0;

    ogs_assert(gnode);
    ogs_assert(recvbuf);

    if (recvbuf->len < OGS_GTPV1C_HEADER_LEN - OGS_GTP1_TEID_LEN)
        return false;

    gh = (ogs_gtp1_header_t *)recvbuf->data;
    if (gh->version != 1)
        return false;

    memset(&hdesc, 0, sizeof(hdesc));
    hdesc.version = gh->version;
    hdesc.pt = gh->pt;
    hdesc.type = gh->type;
    hdesc.length = be16toh(gh->length);
    hdesc.teid = be32toh(gh->teid);
    hdesc.e = gh->e;
    hdesc.s = gh->s;
    hdesc.pn = gh->pn;
    if (gh->s)
        hdesc.sqn = gh->sqn;

    switch (gh->type) {
    case OGS_GTP1_NODE_ALIVE_REQUEST_TYPE:
        response_type = OGS_GTP1_NODE_ALIVE_RESPONSE_TYPE;
        break;
    case OGS_GTP1_ECHO_RESPONSE_TYPE:
        rv = ogs_gtp1_xact_receive(gnode, &hdesc, &xact);
        if (rv == OGS_OK)
            ogs_debug("[SGW] Gn Echo Response received");
        else
            ogs_debug("[SGW] Gn Echo Response ignored (no matching xact)");
        return true;
    default:
        return false;
    }

    rv = ogs_gtp1_xact_receive(gnode, &hdesc, &xact);
    if (rv != OGS_OK || !xact)
        return false;

    ogs_debug("[SGW] Gn request type %u", gh->type);
    return sgwc_gn_send_empty_response(xact, response_type) == OGS_OK;
}

void sgwc_gn_send_create_reject(
        sgwc_sess_t *sess, sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *gn_xact,
        uint8_t gtp2_cause)
{
    uint8_t gtp1_cause;

    ogs_assert(gn_xact);

    gtp1_cause = sgwc_gtp2_to_gtp1_cause(gtp2_cause);

    ogs_gtp1_send_error_message(gn_xact,
            sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
            OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE, gtp1_cause);

    if (sess)
        sgwc_sess_remove(sess);
}

void sgwc_gtp_create_reject(
        sgwc_sess_t *sess, sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *xact,
        uint8_t gtp2_cause)
{
    if (sess && sess->gn)
        sgwc_gn_send_create_reject(sess, sgwc_ue, xact, gtp2_cause);
    else
        ogs_gtp_send_error_message(xact,
                sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
                OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE, gtp2_cause);
}

static bool sgwc_gn_create_matches_active_sess(
        sgwc_sess_t *sess, ogs_gtp1_create_pdp_context_request_t *req)
{
    char apn[OGS_MAX_APN_LEN+1];
    char *apn_oi = NULL;
    ogs_ip_t req_ip, sess_ip;
    uint8_t pdu_session_type = 0;
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *dl_tunnel = NULL;

    ogs_assert(sess);
    ogs_assert(req);

    if (!sess->pgw_s5c_teid || !sess->gnode ||
            !sess->sgwu_sxa_seid || !sess->pfcp_node)
        return false;

    if (req->access_point_name.presence) {
        if (ogs_fqdn_parse(apn, req->access_point_name.data,
                ogs_min(req->access_point_name.len, OGS_MAX_APN_LEN)) <= 0)
            return false;
        apn_oi = ogs_dnn_oi_from_fqdn(apn);
        if (apn_oi && apn_oi > apn && apn_oi[-1] == '.')
            apn_oi[-1] = '\0';
        if (!sess->session.name ||
                strcmp(apn, sess->session.name) != 0)
            return false;
    }

    if (req->end_user_address.presence && sess->paa.session_type) {
        ogs_eua_t *eua = req->end_user_address.data;

        ogs_assert(eua);
        if (ogs_gtp1_eua_to_ip(eua, req->end_user_address.len, &req_ip,
                &pdu_session_type) != OGS_OK)
            return false;
        if (ogs_paa_to_ip(&sess->paa, &sess_ip) != OGS_OK)
            return false;
        if (req_ip.ipv4) {
            if (!sess_ip.ipv4 || req_ip.addr != sess_ip.addr)
                return false;
        }
        if (req_ip.ipv6) {
            if (!sess_ip.ipv6 ||
                    memcmp(req_ip.addr6, sess_ip.addr6, OGS_IPV6_LEN))
                return false;
        }
    }

    bearer = sgwc_default_bearer_in_sess(sess);
    if (!bearer)
        return false;

    dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
    if (!dl_tunnel)
        return false;

    if (req->tunnel_endpoint_identifier_data_i.presence &&
            dl_tunnel->remote_teid &&
            req->tunnel_endpoint_identifier_data_i.u32 !=
                dl_tunnel->remote_teid)
        return false;

    if (req->sgsn_address_for_user_traffic.presence &&
            (dl_tunnel->remote_ip.ipv4 || dl_tunnel->remote_ip.ipv6)) {
        ogs_ip_t req_sgsn_ip;

        if (ogs_gtp1_gsn_addr_to_ip(
                req->sgsn_address_for_user_traffic.data,
                req->sgsn_address_for_user_traffic.len,
                &req_sgsn_ip) != OGS_OK)
            return false;
        if (req_sgsn_ip.ipv4 && dl_tunnel->remote_ip.ipv4 &&
                req_sgsn_ip.addr != dl_tunnel->remote_ip.addr)
            return false;
        if (req_sgsn_ip.ipv6 && dl_tunnel->remote_ip.ipv6 &&
                memcmp(req_sgsn_ip.addr6, dl_tunnel->remote_ip.addr6,
                    OGS_IPV6_LEN))
            return false;
    }

    return true;
}

/*
 * Prefer Alternative SGSN Address for User Traffic when present — the RNC
 * often puts the reachable PC/data-plane address (e.g. 192.168.14.32) there
 * and a routed CP address (e.g. 10.234.241.21) in the primary IE.
 */
static int sgwc_gn_apply_sgsn_user_traffic_to_dl(
        sgwc_tunnel_t *dl_tunnel,
        ogs_gtp1_tlv_gsn_address_t *sgsn_user,
        ogs_gtp1_tlv_gsn_address_t *alt_sgsn_user,
        uint32_t remote_teid)
{
    ogs_gtp1_tlv_gsn_address_t *pick = sgsn_user;
    ogs_pfcp_far_t *far = NULL;
    int rv;

    ogs_assert(dl_tunnel);

    if (remote_teid)
        dl_tunnel->remote_teid = remote_teid;

    if (alt_sgsn_user && alt_sgsn_user->presence)
        pick = alt_sgsn_user;
    else if (!sgsn_user || !sgsn_user->presence)
        return OGS_ERROR;

    rv = ogs_gtp1_gsn_addr_to_ip(
            pick->data, pick->len, &dl_tunnel->remote_ip);
    if (rv != OGS_OK)
        return OGS_ERROR;

    far = dl_tunnel->far;
    if (!far)
        return OGS_OK;

    far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;
    rv = ogs_pfcp_ip_to_outer_header_creation(
            &dl_tunnel->remote_ip, &far->outer_header_creation,
            &far->outer_header_creation_len);
    if (rv == OGS_OK)
        far->outer_header_creation.teid = dl_tunnel->remote_teid;

    return OGS_OK;
}

static void sgwc_gn_create_pdp_proceed(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *gn_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp1_message_t *message)
{
    int rv;
    uint8_t cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;

    ogs_gtp1_create_pdp_context_request_t *req = NULL;
    ogs_gtp1_uli_t uli;

    ogs_pkbuf_t *csr_pkbuf = NULL;

    char apn[OGS_MAX_APN_LEN+1];
    char *apn_oi = NULL;
    uint8_t qci = 9;

    ogs_assert(sgwc_ue);
    ogs_assert(gn_xact);
    ogs_assert(gtpbuf);
    ogs_assert(message);
    req = &message->create_pdp_context_request;
    ogs_assert(req);

    if (req->access_point_name.presence == 0 ||
            req->access_point_name.len == 0) {
        ogs_error("No APN");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        goto cleanup;
    }

    if (ogs_fqdn_parse(apn, req->access_point_name.data,
            ogs_min(req->access_point_name.len, OGS_MAX_APN_LEN)) <= 0) {
        ogs_error("Invalid APN");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
        goto cleanup;
    }

    apn_oi = ogs_dnn_oi_from_fqdn(apn);
    if (apn_oi && apn_oi > apn && apn_oi[-1] == '.')
        apn_oi[-1] = '\0';

    sess = sgwc_sess_add(sgwc_ue, apn);
    if (!sess) {
        cause_value = OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE;
        goto cleanup;
    }

    sess->apn_fqdn_len = ogs_min(req->access_point_name.len,
            (int)sizeof(sess->apn_fqdn));
    memcpy(sess->apn_fqdn, req->access_point_name.data, sess->apn_fqdn_len);

    sess->gn = 1;
    sess->gn_nsapi = req->nsapi.u8;

    if (req->rat_type.presence) {
        switch (req->rat_type.u8) {
        case OGS_GTP1_RAT_TYPE_UTRAN:
            sess->gtp_rat_type = OGS_GTP2_RAT_TYPE_UTRAN;
            break;
        case OGS_GTP1_RAT_TYPE_GERAN:
            sess->gtp_rat_type = OGS_GTP2_RAT_TYPE_GERAN;
            break;
        case OGS_GTP1_RAT_TYPE_WLAN:
            sess->gtp_rat_type = OGS_GTP2_RAT_TYPE_WLAN;
            break;
        case OGS_GTP1_RAT_TYPE_GAN:
            sess->gtp_rat_type = OGS_GTP2_RAT_TYPE_GAN;
            break;
        case OGS_GTP1_RAT_TYPE_HSPA_EVOLUTION:
            sess->gtp_rat_type = OGS_GTP2_RAT_TYPE_HSPA_EVOLUTION;
            break;
        case OGS_GTP1_RAT_TYPE_EUTRAN:
            sess->gtp_rat_type = OGS_GTP2_RAT_TYPE_EUTRAN;
            break;
        default:
            sess->gtp_rat_type = OGS_GTP2_RAT_TYPE_UTRAN;
            break;
        }
    }

    if (req->tunnel_endpoint_identifier_control_plane.presence)
        sgwc_ue->mme_s11_teid =
            req->tunnel_endpoint_identifier_control_plane.u32;

    if (req->imsi.presence) {
        sgwc_ue->imsi_len = ogs_min(req->imsi.len, OGS_MAX_IMSI_LEN);
        memcpy(sgwc_ue->imsi, req->imsi.data, sgwc_ue->imsi_len);
        ogs_buffer_to_bcd(sgwc_ue->imsi, sgwc_ue->imsi_len, sgwc_ue->imsi_bcd);
    }

    if (req->msisdn.presence && req->msisdn.len > 1) {
        sgwc_ue->msisdn_len = req->msisdn.len - 1;
        if (sgwc_ue->msisdn_len > (int)sizeof(sgwc_ue->msisdn))
            sgwc_ue->msisdn_len = sizeof(sgwc_ue->msisdn);
        memcpy(sgwc_ue->msisdn, (uint8_t *)req->msisdn.data + 1,
                sgwc_ue->msisdn_len);
        ogs_buffer_to_bcd(sgwc_ue->msisdn,
                sgwc_ue->msisdn_len, sgwc_ue->msisdn_bcd);
    }

    if (req->user_location_information.presence) {
        if (ogs_gtp1_parse_uli(&uli, &req->user_location_information) > 0) {
            sgwc_ue->uli_presence = true;
            sgwc_ue_store_uli_raw(sgwc_ue,
                    req->user_location_information.data,
                    req->user_location_information.len);

            switch (uli.geo_loc_type) {
            case OGS_GTP1_GEO_LOC_TYPE_CGI:
                ogs_nas_to_plmn_id(&sgwc_ue->e_tai.plmn_id, &uli.cgi.nas_plmn_id);
                sgwc_ue->e_tai.tac = uli.cgi.lac;
                ogs_nas_to_plmn_id(&sgwc_ue->e_cgi.plmn_id, &uli.cgi.nas_plmn_id);
                sgwc_ue->e_cgi.cell_id = uli.cgi.ci;
                break;
            case OGS_GTP1_GEO_LOC_TYPE_SAI:
                ogs_nas_to_plmn_id(&sgwc_ue->e_tai.plmn_id, &uli.sai.nas_plmn_id);
                sgwc_ue->e_tai.tac = uli.sai.lac;
                break;
            case OGS_GTP1_GEO_LOC_TYPE_RAI:
                ogs_nas_to_plmn_id(&sgwc_ue->e_tai.plmn_id, &uli.rai.nas_plmn_id);
                sgwc_ue->e_tai.tac = uli.rai.lac;
                break;
            default:
                break;
            }
            memcpy(&sess->serving_plmn_id, &sgwc_ue->e_tai.plmn_id,
                    sizeof(sess->serving_plmn_id));
        }
    }

    if (req->quality_of_service_profile.presence) {
        rv = ogs_gtp1_parse_qos_profile(&sess->gn_qos_pdec,
                &req->quality_of_service_profile);
        if (rv < 0) {
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
            goto cleanup;
        }
        ogs_gtp1_qos_profile_to_qci(&sess->gn_qos_pdec, &qci);
        sess->session.qos.index = qci;
        sess->session.qos.arp.priority_level =
            sess->gn_qos_pdec.qos_profile.arp;
        if (sess->gn_qos_pdec.data_octet6_to_13_present) {
            sess->session.ambr.downlink =
                sess->gn_qos_pdec.dec_mbr_kbps_dl * 1000;
            sess->session.ambr.uplink =
                sess->gn_qos_pdec.dec_mbr_kbps_ul * 1000;
        }
    }

    if (req->apn_ambr.presence &&
            req->apn_ambr.len >= sizeof(ogs_gtp1_apn_ambr_t)) {
        ogs_gtp1_apn_ambr_t *apn_ambr = req->apn_ambr.data;

        sess->session.ambr.uplink = be32toh(apn_ambr->uplink) * 1000;
        sess->session.ambr.downlink = be32toh(apn_ambr->downlink) * 1000;
    }

    sgwc_sess_select_sgwu(sess);
    if (!sess->pfcp_node ||
            !OGS_FSM_CHECK(&sess->pfcp_node->sm, sgwc_pfcp_state_associated)) {
        ogs_error("[%s] No PFCP-associated SGW-U", sgwc_ue->imsi_bcd);
        cause_value = OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING;
        goto cleanup;
    }

    bearer = sgwc_bearer_add(sess);
    if (!bearer) {
        cause_value = OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE;
        goto cleanup;
    }

    bearer->ebi = req->nsapi.u8;

    if (req->tunnel_endpoint_identifier_data_i.presence &&
            req->sgsn_address_for_user_traffic.presence) {
        sgwc_tunnel_t *dl_tunnel = NULL;

        dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
        ogs_assert(dl_tunnel);

        rv = sgwc_gn_apply_sgsn_user_traffic_to_dl(
                dl_tunnel, &req->sgsn_address_for_user_traffic, NULL,
                req->tunnel_endpoint_identifier_data_i.u32);
        if (rv != OGS_OK) {
            cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
            goto cleanup;
        }
    }

    csr_pkbuf = sgwc_gn_build_create_session_request_pkbuf(
            sess, sgwc_ue, req);
    if (!csr_pkbuf) {
        cause_value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;
        goto cleanup;
    }

    ogs_sgwc_trace_set(sgwc_ue, sess, NULL, "gn-create-pdp");
    sess->create_session_t0 = ogs_time_now();

    rv = sgwc_pfcp_send_session_establishment_request(
            sess, gn_xact->id, csr_pkbuf, 0);
    ogs_pkbuf_free(csr_pkbuf);
    if (rv != OGS_OK) {
        cause_value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;
        goto cleanup;
    }

    return;

cleanup:
    ogs_assert(cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED);
    sgwc_gn_send_create_reject(sess, sgwc_ue, gn_xact, cause_value);
}

void sgwc_gn_csr_replace_continue(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *old_sess, bool proceed)
{
    ogs_gtp_xact_t *gn_xact = NULL;
    ogs_pkbuf_t *gtpbuf = NULL;
    ogs_gtp1_message_t message;
    int rv;

    ogs_assert(sgwc_ue);
    ogs_assert(old_sess);

    gn_xact = ogs_gtp_xact_find_by_id(sgwc_ue->csr_replace_s11_xact_id);
    gtpbuf = sgwc_ue->csr_replace_gtpbuf;

    sgwc_ue->csr_replace_s11_xact_id = OGS_INVALID_POOL_ID;
    sgwc_ue->csr_replace_gtpbuf = NULL;
    sgwc_ue->csr_replace_sess_id = OGS_INVALID_POOL_ID;

    old_sess->sgwu_sxa_seid = 0;
    sgwc_sess_remove(old_sess);

    if (!proceed || !gn_xact || !gtpbuf) {
        if (gn_xact) {
            sgwc_gn_send_create_reject(NULL, sgwc_ue, gn_xact,
                    OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
        }
        if (gtpbuf)
            ogs_pkbuf_free(gtpbuf);
        return;
    }

    rv = ogs_gtp1_parse_msg(&message, gtpbuf);
    if (rv != OGS_OK) {
        ogs_error("[%s] ogs_gtp1_parse_msg() failed", sgwc_ue->imsi_bcd);
        sgwc_gn_send_create_reject(NULL, sgwc_ue, gn_xact,
                OGS_GTP2_CAUSE_INVALID_MESSAGE_FORMAT);
        ogs_pkbuf_free(gtpbuf);
        return;
    }

    sgwc_gn_create_pdp_proceed(sgwc_ue, gn_xact, gtpbuf, &message);
    ogs_pkbuf_free(gtpbuf);
}

void sgwc_gn_handle_create_pdp_context_request(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *gn_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp1_message_t *message)
{
    ogs_gtp1_create_pdp_context_request_t *req = NULL;

    ogs_assert(gn_xact);
    ogs_assert(gtpbuf);
    ogs_assert(message);
    req = &message->create_pdp_context_request;

    if (sgwc_self()->maintenance_mode) {
        ogs_gtp1_send_error_message(gn_xact, 0,
                OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_NO_RESOURCES_AVAILABLE);
        return;
    }

    if (req->imsi.presence == 0) {
        ogs_gtp1_send_error_message(gn_xact, 0,
                OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_MANDATORY_IE_MISSING);
        return;
    }

    if (req->nsapi.presence == 0 ||
            req->tunnel_endpoint_identifier_data_i.presence == 0 ||
            req->sgsn_address_for_user_traffic.presence == 0) {
        ogs_gtp1_send_error_message(gn_xact, 0,
                OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_MANDATORY_IE_MISSING);
        return;
    }

    if (!sgwc_ue) {
        sgwc_ue = sgwc_ue_add(req->imsi.data, req->imsi.len);
        if (!sgwc_ue) {
            ogs_gtp1_send_error_message(gn_xact, 0,
                    OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE,
                    OGS_GTP1_CAUSE_NO_RESOURCES_AVAILABLE);
            return;
        }
        sgwc_ue->gn = 1;
    }

    if (message->h.teid == 0 && req->tunnel_endpoint_identifier_control_plane.presence)
        sgwc_ue->mme_s11_teid =
            req->tunnel_endpoint_identifier_control_plane.u32;

    if (sgwc_ue->gnode == NULL && gn_xact->gnode)
        OGS_SETUP_GTP_NODE(sgwc_ue, gn_xact->gnode);

    {
        sgwc_sess_t *sess = NULL;
        ogs_gtp_xact_t *pending_s5 = NULL;

        sess = sgwc_sess_find_by_nsapi(sgwc_ue, req->nsapi.u8);
        if (sess) {
            /*
             * SGSN retransmits Create PDP Context Request while SGWC still
             * waits on S5/PFCP. Do not tear down the in-flight session.
             */
            if (gn_xact && gn_xact->assoc_xact_id)
                pending_s5 = ogs_gtp_xact_find_by_id(gn_xact->assoc_xact_id);
            if (pending_s5 &&
                    pending_s5->seq[0].type ==
                        OGS_GTP2_CREATE_SESSION_REQUEST_TYPE &&
                    pending_s5->assoc_xact_id == gn_xact->id) {
                ogs_info("[%s] duplicate Create PDP Context Request while S5 "
                        "pending - ignoring (NSAPI=%u)",
                        sgwc_ue->imsi_bcd, req->nsapi.u8);
                return;
            }

            if (sgwc_ue->csr_replace_s11_xact_id != OGS_INVALID_POOL_ID) {
                ogs_info("[%s] duplicate Create PDP Context Request while CSR "
                        "replace pending - ignoring (NSAPI=%u)",
                        sgwc_ue->imsi_bcd, req->nsapi.u8);
                return;
            }

            if (sess->sgwu_sxa_seid && sess->pfcp_node) {
                if (sgwc_gn_create_matches_active_sess(sess, req)) {
                    ogs_info("[%s] duplicate Create PDP matches active "
                            "session - re-sending Accept (NSAPI=%u)",
                            sgwc_ue->imsi_bcd, req->nsapi.u8);
                    sgwc_gtp_send_create_pdp_context_response(
                            sess, gn_xact, NULL);
                    return;
                }
                if (sgwc_csr_replace_start(sgwc_ue, sess, gn_xact, gtpbuf))
                    return;
                sgwc_gn_send_create_reject(sess, sgwc_ue, gn_xact,
                        OGS_GTP2_CAUSE_SYSTEM_FAILURE);
                return;
            } else {
                ogs_info("[%s] duplicate Create PDP Context Request while "
                        "session establishment pending - ignoring (NSAPI=%u)",
                        sgwc_ue->imsi_bcd, req->nsapi.u8);
                return;
            }
        }
    }

    sgwc_gn_create_pdp_proceed(sgwc_ue, gn_xact, gtpbuf, message);
}

void sgwc_gn_handle_delete_pdp_context_request(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess, ogs_gtp_xact_t *gn_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp1_message_t *message)
{
    int rv;
    ogs_gtp_xact_t *s5c_xact = NULL;
    ogs_gtp2_message_t gtp2_message;
    ogs_gtp2_delete_session_request_t *req = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    sgwc_bearer_t *bearer = NULL;

    ogs_assert(gn_xact);
    ogs_assert(gtpbuf);
    ogs_assert(message);

    ogs_info("Delete PDP Context Request");

    if (!sess) {
        ogs_gtp1_send_error_message(gn_xact, 0,
                OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_NON_EXISTENT);
        return;
    }

    if (!sgwc_ue)
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);

    if (!sgwc_ue) {
        ogs_gtp1_send_error_message(gn_xact, 0,
                OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_NON_EXISTENT);
        return;
    }

    bearer = sgwc_default_bearer_in_sess(sess);
    if (!bearer) {
        ogs_gtp1_send_error_message(gn_xact, sgwc_ue->mme_s11_teid,
                OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_NON_EXISTENT);
        return;
    }

    if (!sess->gnode) {
        ogs_warn("[%s] Delete PDP without S5 peer; removing locally",
                sgwc_ue->imsi_bcd);
        if (sess->pfcp_node && sess->sgwu_sxa_seid) {
            rv = sgwc_pfcp_send_session_deletion_request(
                    sess, gn_xact->id, gtpbuf);
            ogs_expect(rv == OGS_OK);
        } else {
            sgwc_sess_remove(sess);
            ogs_gtp1_send_error_message(gn_xact, sgwc_ue->mme_s11_teid,
                    OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE,
                    OGS_GTP1_CAUSE_REQUEST_ACCEPTED);
        }
        return;
    }

    memset(&gtp2_message, 0, sizeof(gtp2_message));
    req = &gtp2_message.delete_session_request;
    req->linked_eps_bearer_id.presence = 1;
    req->linked_eps_bearer_id.u8 = bearer->ebi;

    gtp2_message.h.type = OGS_GTP2_DELETE_SESSION_REQUEST_TYPE;
    gtp2_message.h.teid = sess->pgw_s5c_teid;

    pkbuf = ogs_gtp2_build_msg(&gtp2_message);
    if (!pkbuf) {
        ogs_gtp1_send_error_message(gn_xact, sgwc_ue->mme_s11_teid,
                OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_SYSTEM_FAILURE);
        return;
    }

    s5c_xact = ogs_gtp_xact_local_create(
            sess->gnode, &gtp2_message.h, pkbuf, NULL,
            OGS_UINT_TO_POINTER(sess->id));
    if (!s5c_xact) {
        ogs_gtp1_send_error_message(gn_xact, sgwc_ue->mme_s11_teid,
                OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_SYSTEM_FAILURE);
        return;
    }
    s5c_xact->local_teid = sess->sgw_s5c_teid;
    ogs_gtp_xact_associate(gn_xact, s5c_xact);

    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);
}

void sgwc_gn_handle_update_pdp_context_request(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess, ogs_gtp_xact_t *gn_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp1_message_t *message)
{
    int rv;
    ogs_gtp_xact_t *s5c_xact = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp1_update_pdp_context_request_t *req = NULL;
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *dl_tunnel = NULL;
    ogs_pfcp_far_t *far = NULL;

    ogs_assert(gn_xact);
    ogs_assert(message);
    req = &message->update_pdp_context_request;

    if (!sess) {
        ogs_gtp1_send_error_message(gn_xact, 0,
                OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_NON_EXISTENT);
        return;
    }

    if (!sgwc_ue)
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    if (!sgwc_ue) {
        ogs_gtp1_send_error_message(gn_xact, 0,
                OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_NON_EXISTENT);
        return;
    }

    bearer = sgwc_default_bearer_in_sess(sess);
    if (!bearer) {
        ogs_gtp1_send_error_message(gn_xact, sgwc_ue->mme_s11_teid,
                OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_NON_EXISTENT);
        return;
    }

    dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
    ogs_assert(dl_tunnel);

    if (req->tunnel_endpoint_identifier_data_i.presence ||
            req->sgsn_address_for_user_traffic.presence ||
            req->alternative_sgsn_address_for_user_traffic.presence) {
        uint32_t remote_teid = dl_tunnel->remote_teid;

        if (req->tunnel_endpoint_identifier_data_i.presence)
            remote_teid = req->tunnel_endpoint_identifier_data_i.u32;

        rv = sgwc_gn_apply_sgsn_user_traffic_to_dl(
                dl_tunnel, &req->sgsn_address_for_user_traffic,
                &req->alternative_sgsn_address_for_user_traffic,
                remote_teid);
        if (rv != OGS_OK) {
            ogs_gtp1_send_error_message(gn_xact, sgwc_ue->mme_s11_teid,
                    OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE,
                    OGS_GTP1_CAUSE_MANDATORY_IE_INCORRECT);
            return;
        }
    }

    if (req->quality_of_service_profile.presence) {
        rv = ogs_gtp1_parse_qos_profile(&sess->gn_qos_pdec,
                &req->quality_of_service_profile);
        if (rv < 0) {
            ogs_gtp1_send_error_message(gn_xact, sgwc_ue->mme_s11_teid,
                    OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE,
                    OGS_GTP1_CAUSE_MANDATORY_IE_INCORRECT);
            return;
        }
    }

    if (req->user_location_information.presence) {
        ogs_gtp1_uli_t uli;
        if (ogs_gtp1_parse_uli(&uli, &req->user_location_information) > 0) {
            sgwc_ue_store_uli_raw(sgwc_ue,
                    req->user_location_information.data,
                    req->user_location_information.len);
        }
    }

    if (!sess->gnode || !sess->pgw_s5c_teid) {
        pkbuf = sgwc_gn_build_update_pdp_context_response(
                OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE, sess,
                OGS_GTP1_CAUSE_REQUEST_ACCEPTED);
        if (!pkbuf) {
            ogs_gtp1_send_error_message(gn_xact, sgwc_ue->mme_s11_teid,
                    OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE,
                    OGS_GTP1_CAUSE_SYSTEM_FAILURE);
            return;
        }
        rv = sgwc_gtp_send_update_pdp_context_response(
                gn_xact, sgwc_ue->mme_s11_teid, pkbuf);
        ogs_expect(rv == OGS_OK);

        if (dl_tunnel->far && dl_tunnel->far->apply_action) {
            rv = sgwc_pfcp_send_session_modification_request(
                    sess, OGS_INVALID_POOL_ID, NULL,
                    OGS_PFCP_MODIFY_DL_ONLY|
                    OGS_PFCP_MODIFY_OUTER_HEADER_REMOVAL|
                    OGS_PFCP_MODIFY_ACTIVATE);
            ogs_expect(rv == OGS_OK);
        }
        return;
    }

    pkbuf = sgwc_gn_build_modify_bearer_request_pkbuf(sess, req);
    if (!pkbuf) {
        ogs_gtp1_send_error_message(gn_xact, sgwc_ue->mme_s11_teid,
                OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_SYSTEM_FAILURE);
        return;
    }

    {
        ogs_gtp2_header_t h;

        memset(&h, 0, sizeof(h));
        h.type = OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE;
        h.teid = sess->pgw_s5c_teid;

        s5c_xact = ogs_gtp_xact_local_create(
                sess->gnode, &h, pkbuf, NULL,
                OGS_UINT_TO_POINTER(sess->id));
    }
    if (!s5c_xact) {
        ogs_gtp1_send_error_message(gn_xact, sgwc_ue->mme_s11_teid,
                OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE,
                OGS_GTP1_CAUSE_SYSTEM_FAILURE);
        return;
    }
    s5c_xact->local_teid = sess->sgw_s5c_teid;
    ogs_gtp_xact_associate(gn_xact, s5c_xact);

    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);
}
