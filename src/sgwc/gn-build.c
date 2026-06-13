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

#include "gn-build.h"
#include "sgwc-gtp-interop.h"

static ogs_pkbuf_t *sgwc_gn_encapsulate_gtp2_header(
        ogs_pkbuf_t *pkbuf, uint8_t type, uint32_t teid)
{
    ogs_gtp2_header_t *h;
    int gtp_hlen;

    ogs_assert(pkbuf);

    if (type > OGS_GTP2_VERSION_NOT_SUPPORTED_INDICATION_TYPE)
        gtp_hlen = OGS_GTPV2C_HEADER_LEN;
    else
        gtp_hlen = OGS_GTPV2C_HEADER_LEN - OGS_GTP2_TEID_LEN;

    ogs_pkbuf_push(pkbuf, gtp_hlen);
    h = (ogs_gtp2_header_t *)pkbuf->data;
    memset(h, 0, gtp_hlen);

    h->version = 2;
    h->type = type;

    if (type > OGS_GTP2_VERSION_NOT_SUPPORTED_INDICATION_TYPE) {
        h->teid_presence = 1;
        h->teid = htobe32(teid);
        h->sqn = 0;
    } else {
        h->teid_presence = 0;
        h->sqn_only = 0;
    }
    h->length = htobe16(pkbuf->len - 4);

    return pkbuf;
}

static int sgwc_gn_gtp1_uli_to_gtp2(
        ogs_gtp2_uli_t *gtp2_uli, ogs_tlv_octet_t *gtp1_uli,
        char *uli_buf, int uli_buf_len)
{
    ogs_gtp1_uli_t uli;
    ogs_plmn_id_t plmn_id;
    ogs_tlv_octet_t gtp2_uli_tlv;

    ogs_assert(gtp2_uli);
    ogs_assert(gtp1_uli);
    ogs_assert(uli_buf);

    if (ogs_gtp1_parse_uli(&uli, gtp1_uli) == 0)
        return OGS_ERROR;

    memset(gtp2_uli, 0, sizeof(*gtp2_uli));

    switch (uli.geo_loc_type) {
    case OGS_GTP1_GEO_LOC_TYPE_CGI:
        gtp2_uli->flags.e_cgi = 1;
        gtp2_uli->flags.tai = 1;
        ogs_nas_to_plmn_id(&plmn_id, &uli.cgi.nas_plmn_id);
        ogs_nas_from_plmn_id(&gtp2_uli->e_cgi.nas_plmn_id, &plmn_id);
        gtp2_uli->e_cgi.cell_id = uli.cgi.ci;
        ogs_nas_from_plmn_id(&gtp2_uli->tai.nas_plmn_id, &plmn_id);
        gtp2_uli->tai.tac = uli.cgi.lac;
        break;
    case OGS_GTP1_GEO_LOC_TYPE_SAI:
        gtp2_uli->flags.tai = 1;
        ogs_nas_to_plmn_id(&plmn_id, &uli.sai.nas_plmn_id);
        ogs_nas_from_plmn_id(&gtp2_uli->tai.nas_plmn_id, &plmn_id);
        gtp2_uli->tai.tac = uli.sai.lac;
        break;
    case OGS_GTP1_GEO_LOC_TYPE_RAI:
        gtp2_uli->flags.tai = 1;
        ogs_nas_to_plmn_id(&plmn_id, &uli.rai.nas_plmn_id);
        ogs_nas_from_plmn_id(&gtp2_uli->tai.nas_plmn_id, &plmn_id);
        gtp2_uli->tai.tac = uli.rai.lac;
        break;
    default:
        return OGS_ERROR;
    }

    gtp2_uli_tlv.data = uli_buf;
    gtp2_uli_tlv.len = ogs_gtp2_build_uli(&gtp2_uli_tlv, gtp2_uli,
            uli_buf, uli_buf_len);
    if (gtp2_uli_tlv.len <= 0)
        return OGS_ERROR;

    return gtp2_uli_tlv.len;
}

uint8_t sgwc_gtp2_to_gtp1_cause(uint8_t gtp2_cause)
{
    switch (gtp2_cause) {
    case OGS_GTP2_CAUSE_REQUEST_ACCEPTED:
        return OGS_GTP1_CAUSE_REQUEST_ACCEPTED;
    case OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND:
        return OGS_GTP1_CAUSE_NON_EXISTENT;
    case OGS_GTP2_CAUSE_MANDATORY_IE_MISSING:
        return OGS_GTP1_CAUSE_MANDATORY_IE_MISSING;
    case OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT:
        return OGS_GTP1_CAUSE_MANDATORY_IE_INCORRECT;
    case OGS_GTP2_CAUSE_INVALID_MESSAGE_FORMAT:
        return OGS_GTP1_CAUSE_INVALID_MESSAGE_FORMAT;
    case OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE:
        return OGS_GTP1_CAUSE_NO_RESOURCES_AVAILABLE;
    case OGS_GTP2_CAUSE_SERVICE_NOT_SUPPORTED:
        return OGS_GTP1_CAUSE_SERVICE_NOT_SUPPORTED;
    case OGS_GTP2_CAUSE_SYSTEM_FAILURE:
        return OGS_GTP1_CAUSE_SYSTEM_FAILURE;
    case OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING:
        return OGS_GTP1_CAUSE_NO_RESOURCES_AVAILABLE;
    default:
        return OGS_GTP1_CAUSE_SYSTEM_FAILURE;
    }
}

static ogs_pkbuf_t *sgwc_gn_build_create_session_request(
        sgwc_sess_t *sess, sgwc_ue_t *sgwc_ue,
        ogs_gtp1_create_pdp_context_request_t *req)
{
    ogs_gtp2_message_t message;
    ogs_gtp2_create_session_request_t *csr = NULL;
    ogs_gtp2_bearer_qos_t bearer_qos;
    ogs_gtp2_uli_t uli;
    ogs_gtp2_ambr_t ambr;
    ogs_nas_plmn_id_t nas_plmn_id;
    char uli_buf[OGS_GTP2_MAX_ULI_LEN];
    char bearer_qos_buf[GTP2_BEARER_QOS_LEN];
    char apn[OGS_MAX_APN_LEN+1];
    uint8_t qci = 9;
    int decoded;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(sgwc_ue);
    ogs_assert(req);

    memset(&message, 0, sizeof(message));
    csr = &message.create_session_request;

    message.h.type = OGS_GTP2_CREATE_SESSION_REQUEST_TYPE;

    if (sgwc_ue->imsi_len == 0) {
        ogs_error("No IMSI on SGWC UE for Gn CSR");
        return NULL;
    }

    csr->imsi.presence = 1;
    csr->imsi.data = sgwc_ue->imsi;
    csr->imsi.len = sgwc_ue->imsi_len;

    if (req->msisdn.presence && req->msisdn.len > 1) {
        csr->msisdn.presence = 1;
        csr->msisdn.data = (uint8_t *)req->msisdn.data + 1;
        csr->msisdn.len = req->msisdn.len - 1;
    }

    if (req->imei.presence && req->imei.len > 0) {
        csr->me_identity.presence = 1;
        csr->me_identity.data = req->imei.data;
        csr->me_identity.len = req->imei.len;
    }

    if (req->rat_type.presence) {
        csr->rat_type.presence = 1;
        switch (req->rat_type.u8) {
        case OGS_GTP1_RAT_TYPE_UTRAN:
            csr->rat_type.u8 = OGS_GTP2_RAT_TYPE_UTRAN;
            break;
        case OGS_GTP1_RAT_TYPE_GERAN:
            csr->rat_type.u8 = OGS_GTP2_RAT_TYPE_GERAN;
            break;
        case OGS_GTP1_RAT_TYPE_EUTRAN:
            csr->rat_type.u8 = OGS_GTP2_RAT_TYPE_EUTRAN;
            break;
        default:
            csr->rat_type.u8 = OGS_GTP2_RAT_TYPE_UTRAN;
            break;
        }
    }

    if (req->user_location_information.presence) {
        decoded = sgwc_gn_gtp1_uli_to_gtp2(
                &uli, &req->user_location_information, uli_buf,
                sizeof(uli_buf));
        if (decoded > 0) {
            csr->user_location_information.presence = 1;
            csr->user_location_information.data = uli_buf;
            csr->user_location_information.len = decoded;
        }
    }

    ogs_nas_from_plmn_id(&nas_plmn_id, &sess->serving_plmn_id);
    csr->serving_network.presence = 1;
    csr->serving_network.data = (uint8_t *)&nas_plmn_id;
    csr->serving_network.len = OGS_PLMN_ID_LEN;

    if (req->access_point_name.presence) {
        if (sess->apn_fqdn_len > 0) {
            csr->access_point_name.presence = 1;
            csr->access_point_name.data = sess->apn_fqdn;
            csr->access_point_name.len = sess->apn_fqdn_len;
        } else if (ogs_fqdn_parse(apn, req->access_point_name.data,
                ogs_min(req->access_point_name.len, OGS_MAX_APN_LEN)) > 0) {
            char *apn_oi = ogs_dnn_oi_from_fqdn(apn);
            if (apn_oi && apn_oi > apn && apn_oi[-1] == '.')
                apn_oi[-1] = '\0';
            sess->apn_fqdn_len = ogs_fqdn_build((char *)sess->apn_fqdn,
                    sess->session.name, strlen(sess->session.name));
            csr->access_point_name.presence = 1;
            csr->access_point_name.data = sess->apn_fqdn;
            csr->access_point_name.len = sess->apn_fqdn_len;
        }
    }

    if (req->selection_mode.presence) {
        csr->selection_mode.presence = 1;
        csr->selection_mode.u8 = req->selection_mode.u8 & 0x03;
    }

    if (req->protocol_configuration_options.presence) {
        csr->protocol_configuration_options.presence = 1;
        csr->protocol_configuration_options.data =
            req->protocol_configuration_options.data;
        csr->protocol_configuration_options.len =
            req->protocol_configuration_options.len;
    }

    if (req->ms_time_zone.presence) {
        csr->ue_time_zone.presence = 1;
        csr->ue_time_zone.data = req->ms_time_zone.data;
        csr->ue_time_zone.len = req->ms_time_zone.len;
    }

    if (req->charging_characteristics.presence) {
        csr->charging_characteristics.presence = 1;
        csr->charging_characteristics.data =
            req->charging_characteristics.data;
        csr->charging_characteristics.len =
            req->charging_characteristics.len;
    }

    if (sgwc_self()->gn_pgw_f_teid_len) {
        csr->pgw_s5_s8_address_for_control_plane_or_pmip.presence = 1;
        csr->pgw_s5_s8_address_for_control_plane_or_pmip.data =
            &sgwc_self()->gn_pgw_f_teid;
        csr->pgw_s5_s8_address_for_control_plane_or_pmip.len =
            sgwc_self()->gn_pgw_f_teid_len;
    }

    ogs_gtp1_qos_profile_to_qci(&sess->gn_qos_pdec, &qci);

    memset(&bearer_qos, 0, sizeof(bearer_qos));
    bearer_qos.qci = qci;
    bearer_qos.priority_level = sess->gn_qos_pdec.qos_profile.arp;
    if (bearer_qos.priority_level == 0)
        bearer_qos.priority_level = 1;
    bearer_qos.pre_emption_capability = 0;
    bearer_qos.pre_emption_vulnerability = 0;

    csr->bearer_contexts_to_be_created[0].presence = 1;
    csr->bearer_contexts_to_be_created[0].eps_bearer_id.presence = 1;
    csr->bearer_contexts_to_be_created[0].eps_bearer_id.u8 = sess->gn_nsapi;
    csr->bearer_contexts_to_be_created[0].bearer_level_qos.presence = 1;
    ogs_gtp2_build_bearer_qos(
            &csr->bearer_contexts_to_be_created[0].bearer_level_qos,
            &bearer_qos, bearer_qos_buf, sizeof(bearer_qos_buf));

    if (req->end_user_address.presence) {
        ogs_eua_t *eua = req->end_user_address.data;
        ogs_ip_t ip;
        uint8_t pdu_session_type = 0;
        uint32_t zero_addr = 0;
        uint8_t zero_addr6[OGS_IPV6_LEN];

        ogs_assert(eua);
        if (ogs_gtp1_eua_to_ip(eua, req->end_user_address.len, &ip,
                &pdu_session_type) == OGS_OK) {
            csr->pdn_type.presence = 1;
            csr->pdn_type.u8 = pdu_session_type;

            if (ogs_ip_to_paa(&ip, &sess->paa) != OGS_OK)
                ogs_error("ogs_ip_to_paa() failed");

            memset(zero_addr6, 0, sizeof(zero_addr6));
            if (pdu_session_type == OGS_PDU_SESSION_TYPE_IPV4 &&
                    ip.ipv4 && memcmp(&ip.addr, &zero_addr, sizeof(zero_addr))) {
                csr->pdn_address_allocation.presence = 1;
                csr->pdn_address_allocation.data = &sess->paa;
                csr->pdn_address_allocation.len = OGS_PAA_IPV4_LEN;
            } else if (pdu_session_type == OGS_PDU_SESSION_TYPE_IPV6 &&
                    ip.ipv6 &&
                    memcmp(ip.addr6, zero_addr6, sizeof(zero_addr6))) {
                csr->pdn_address_allocation.presence = 1;
                csr->pdn_address_allocation.data = &sess->paa;
                csr->pdn_address_allocation.len = OGS_PAA_IPV6_LEN;
            } else if (pdu_session_type == OGS_PDU_SESSION_TYPE_IPV4V6 &&
                    ((ip.ipv4 &&
                      memcmp(&ip.addr, &zero_addr, sizeof(zero_addr))) ||
                     (ip.ipv6 &&
                      memcmp(ip.addr6, zero_addr6, sizeof(zero_addr6)))) {
                csr->pdn_address_allocation.presence = 1;
                csr->pdn_address_allocation.data = &sess->paa;
                csr->pdn_address_allocation.len = OGS_PAA_IPV4V6_LEN;
            }
        }
    }

    if (req->apn_ambr.presence &&
            req->apn_ambr.len >= sizeof(ogs_gtp1_apn_ambr_t)) {
        ogs_gtp1_apn_ambr_t *apn_ambr = req->apn_ambr.data;

        ambr.uplink = be32toh(apn_ambr->uplink);
        ambr.downlink = be32toh(apn_ambr->downlink);
        csr->aggregate_maximum_bit_rate.presence = 1;
        csr->aggregate_maximum_bit_rate.data = &ambr;
        csr->aggregate_maximum_bit_rate.len = sizeof(ambr);
    } else if (sess->gn_qos_pdec.data_octet6_to_13_present) {
        /* session.ambr is bps; GTPv2 APN-AMBR IE is kbps */
        ambr.uplink = sess->session.ambr.uplink / 1000;
        ambr.downlink = sess->session.ambr.downlink / 1000;
        csr->aggregate_maximum_bit_rate.presence = 1;
        csr->aggregate_maximum_bit_rate.data = &ambr;
        csr->aggregate_maximum_bit_rate.len = sizeof(ambr);
    }

    pkbuf = ogs_gtp2_build_msg(&message);
    if (!pkbuf)
        return NULL;

    return sgwc_gn_encapsulate_gtp2_header(
            pkbuf, OGS_GTP2_CREATE_SESSION_REQUEST_TYPE, 0);
}

void sgwc_gn_reapply_create_session_request(
        ogs_gtp2_create_session_request_t *csr,
        sgwc_sess_t *sess, sgwc_ue_t *sgwc_ue,
        ogs_nas_plmn_id_t *nas_plmn_id)
{
    ogs_assert(csr);
    ogs_assert(sess);
    ogs_assert(sgwc_ue);
    ogs_assert(nas_plmn_id);

    if (sgwc_ue->imsi_len > 0) {
        csr->imsi.presence = 1;
        csr->imsi.data = sgwc_ue->imsi;
        csr->imsi.len = sgwc_ue->imsi_len;
    }

    if (sess->apn_fqdn_len > 0) {
        csr->access_point_name.presence = 1;
        csr->access_point_name.data = sess->apn_fqdn;
        csr->access_point_name.len = sess->apn_fqdn_len;
    } else if (sess->session.name && sess->session.name[0]) {
        sess->apn_fqdn_len = ogs_fqdn_build((char *)sess->apn_fqdn,
                sess->session.name, strlen(sess->session.name));
        csr->access_point_name.presence = 1;
        csr->access_point_name.data = sess->apn_fqdn;
        csr->access_point_name.len = sess->apn_fqdn_len;
    }

    if (sess->gtp_rat_type) {
        csr->rat_type.presence = 1;
        csr->rat_type.u8 = sess->gtp_rat_type;
    }

    ogs_nas_from_plmn_id(nas_plmn_id, &sess->serving_plmn_id);
    csr->serving_network.presence = 1;
    csr->serving_network.data = (uint8_t *)nas_plmn_id;
    csr->serving_network.len = OGS_PLMN_ID_LEN;

    if (!csr->pdn_type.presence && sess->paa.session_type) {
        csr->pdn_type.presence = 1;
        csr->pdn_type.u8 = sess->paa.session_type;
    }

    if (!csr->pdn_address_allocation.presence && sess->paa.session_type) {
        uint32_t zero_addr = 0;
        uint8_t zero_addr6[OGS_IPV6_LEN];

        memset(zero_addr6, 0, sizeof(zero_addr6));
        if (sess->paa.session_type == OGS_PDU_SESSION_TYPE_IPV4 &&
                memcmp(&sess->paa.addr, &zero_addr, sizeof(zero_addr))) {
            csr->pdn_address_allocation.presence = 1;
            csr->pdn_address_allocation.data = &sess->paa;
            csr->pdn_address_allocation.len = OGS_PAA_IPV4_LEN;
        } else if (sess->paa.session_type == OGS_PDU_SESSION_TYPE_IPV6 &&
                memcmp(sess->paa.addr6, zero_addr6, sizeof(zero_addr6))) {
            csr->pdn_address_allocation.presence = 1;
            csr->pdn_address_allocation.data = &sess->paa;
            csr->pdn_address_allocation.len = OGS_PAA_IPV6_LEN;
        } else if (sess->paa.session_type == OGS_PDU_SESSION_TYPE_IPV4V6 &&
                (memcmp(&sess->paa.both.addr, &zero_addr, sizeof(zero_addr)) ||
                 memcmp(sess->paa.both.addr6, zero_addr6, sizeof(zero_addr6)))) {
            csr->pdn_address_allocation.presence = 1;
            csr->pdn_address_allocation.data = &sess->paa;
            csr->pdn_address_allocation.len = OGS_PAA_IPV4V6_LEN;
        }
    }
}

ogs_pkbuf_t *sgwc_gn_build_create_session_request_pkbuf(
        sgwc_sess_t *sess, sgwc_ue_t *sgwc_ue,
        ogs_gtp1_create_pdp_context_request_t *req)
{
    return sgwc_gn_build_create_session_request(sess, sgwc_ue, req);
}

ogs_pkbuf_t *sgwc_gn_build_create_pdp_context_response(
        uint8_t type, sgwc_sess_t *sess,
        ogs_gtp2_create_session_response_t *s5_rsp)
{
    int rv;
    sgwc_ue_t *sgwc_ue = NULL;
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *ul_tunnel = NULL;

    ogs_gtp1_message_t gtp1_message;
    ogs_gtp1_create_pdp_context_response_t *rsp = NULL;

    ogs_gtp1_gsn_addr_t sgw_gnc_gsnaddr, sgw_gnu_gsnaddr;
    ogs_gtp1_gsn_addr_t sgw_gnc_altgsnaddr, sgw_gnu_altgsnaddr;
    int gsn_len, gsn_altlen;
    ogs_ip_t ip_eua;
    ogs_eua_t eua;
    uint8_t eua_len = 0;
    char qos_pdec_buf[OGS_GTP1_QOS_PROFILE_MAX_LEN];

    ogs_assert(sess);
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);
    bearer = sgwc_default_bearer_in_sess(sess);
    ogs_assert(bearer);
    ul_tunnel = sgwc_ul_tunnel_in_bearer(bearer);
    ogs_assert(ul_tunnel);

    rsp = &gtp1_message.create_pdp_context_response;
    memset(&gtp1_message, 0, sizeof(gtp1_message));

    rsp->cause.presence = 1;
    rsp->cause.u8 = OGS_GTP1_CAUSE_REQUEST_ACCEPTED;

    rsp->reordering_required.presence = 1;
    rsp->reordering_required.u8 = 0;

    rsp->recovery.presence = 1;
    rsp->recovery.u8 = sgwc_self()->gn_gtpc_recovery;

    rsp->tunnel_endpoint_identifier_data_i.presence = 1;
    rsp->tunnel_endpoint_identifier_data_i.u32 = ul_tunnel->local_teid;
    rsp->tunnel_endpoint_identifier_control_plane.presence = 1;
    rsp->tunnel_endpoint_identifier_control_plane.u32 = sess->sgw_s5c_teid;

    rsp->nsapi.presence = 1;
    rsp->nsapi.u8 = sess->gn_nsapi;

    /*
     * Charging ID is mandatory in an accepted Create PDP Context Response
     * (TS 29.060). SMF sends it in S5 Bearer Context, not PDN Connection
     * Charging ID — map either source for Gn.
     */
    if (s5_rsp && s5_rsp->pdn_connection_charging_id.presence)
        rsp->charging_id.u32 = s5_rsp->pdn_connection_charging_id.u32;
    else if (s5_rsp &&
            s5_rsp->bearer_contexts_created[0].charging_id.presence)
        rsp->charging_id.u32 =
            s5_rsp->bearer_contexts_created[0].charging_id.u32;
    else if (sess->charging_id)
        rsp->charging_id.u32 = sess->charging_id;
    else
        rsp->charging_id.u32 = sess->id;
    rsp->charging_id.presence = 1;
    sess->charging_id = rsp->charging_id.u32;

    if (sess->paa.session_type) {
        rv = ogs_paa_to_ip(&sess->paa, &ip_eua);
        if (rv == OGS_OK) {
            rv = ogs_gtp1_ip_to_eua(sess->session.session_type, &ip_eua, &eua,
                    &eua_len);
            if (rv == OGS_OK) {
                rsp->end_user_address.presence = 1;
                rsp->end_user_address.data = &eua;
                rsp->end_user_address.len = eua_len;
            }
        }
    }

    if (sgwc_self()->gn_addr && sgwc_self()->gn_addr6) {
        if (ul_tunnel->local_addr) {
            rv = ogs_gtp1_sockaddr_to_gsn_addr(sgwc_self()->gn_addr, NULL,
                    &sgw_gnc_gsnaddr, &gsn_len);
            ogs_expect(rv == OGS_OK);
            rv = ogs_gtp1_sockaddr_to_gsn_addr(NULL, sgwc_self()->gn_addr6,
                    &sgw_gnc_altgsnaddr, &gsn_altlen);
            ogs_expect(rv == OGS_OK);
        } else {
            rv = ogs_gtp1_sockaddr_to_gsn_addr(NULL, sgwc_self()->gn_addr6,
                    &sgw_gnc_gsnaddr, &gsn_len);
            ogs_expect(rv == OGS_OK);
            rv = ogs_gtp1_sockaddr_to_gsn_addr(sgwc_self()->gn_addr, NULL,
                    &sgw_gnc_altgsnaddr, &gsn_altlen);
            ogs_expect(rv == OGS_OK);
        }
        rsp->alternative_ggsn_address_for_control_plane.presence = 1;
        rsp->alternative_ggsn_address_for_control_plane.data =
            &sgw_gnc_altgsnaddr;
        rsp->alternative_ggsn_address_for_control_plane.len = gsn_altlen;
    } else {
        rv = ogs_gtp1_sockaddr_to_gsn_addr(
                sgwc_self()->gn_addr, sgwc_self()->gn_addr6,
                &sgw_gnc_gsnaddr, &gsn_len);
        ogs_expect(rv == OGS_OK);
    }
    rsp->ggsn_address_for_control_plane.presence = 1;
    rsp->ggsn_address_for_control_plane.data = &sgw_gnc_gsnaddr;
    rsp->ggsn_address_for_control_plane.len = gsn_len;

    /*
     * GGSN user-plane address/TEID must match SGW-U access F-TEID (S1-U),
     * same as S11 Create Session Response — not the S5 DL tunnel (core).
     */
    if (ul_tunnel->local_addr && ul_tunnel->local_addr6) {
        if (ul_tunnel->local_addr) {
            rv = ogs_gtp1_sockaddr_to_gsn_addr(ul_tunnel->local_addr, NULL,
                    &sgw_gnu_gsnaddr, &gsn_len);
            ogs_expect(rv == OGS_OK);
            rv = ogs_gtp1_sockaddr_to_gsn_addr(NULL, ul_tunnel->local_addr6,
                    &sgw_gnu_altgsnaddr, &gsn_altlen);
            ogs_expect(rv == OGS_OK);
        } else {
            rv = ogs_gtp1_sockaddr_to_gsn_addr(NULL, ul_tunnel->local_addr6,
                    &sgw_gnu_gsnaddr, &gsn_len);
            ogs_expect(rv == OGS_OK);
            rv = ogs_gtp1_sockaddr_to_gsn_addr(ul_tunnel->local_addr, NULL,
                    &sgw_gnu_altgsnaddr, &gsn_altlen);
            ogs_expect(rv == OGS_OK);
        }
        rsp->alternative_ggsn_address_for_user_traffic.presence = 1;
        rsp->alternative_ggsn_address_for_user_traffic.data =
            &sgw_gnu_altgsnaddr;
        rsp->alternative_ggsn_address_for_user_traffic.len = gsn_altlen;
    } else {
        rv = ogs_gtp1_sockaddr_to_gsn_addr(
                ul_tunnel->local_addr, ul_tunnel->local_addr6,
                &sgw_gnu_gsnaddr, &gsn_len);
        ogs_expect(rv == OGS_OK);
    }
    rsp->ggsn_address_for_user_traffic.presence = 1;
    rsp->ggsn_address_for_user_traffic.data = &sgw_gnu_gsnaddr;
    rsp->ggsn_address_for_user_traffic.len = gsn_len;

    rsp->quality_of_service_profile.presence = 1;
    ogs_gtp1_build_qos_profile(&rsp->quality_of_service_profile,
            &sess->gn_qos_pdec, qos_pdec_buf, OGS_GTP1_QOS_PROFILE_MAX_LEN);

    gtp1_message.h.type = type;
    return ogs_gtp1_build_msg(&gtp1_message);
}

ogs_pkbuf_t *sgwc_gn_build_delete_pdp_context_response(
        uint8_t type, sgwc_sess_t *sess, uint8_t cause)
{
    ogs_gtp1_message_t gtp1_message;
    ogs_gtp1_delete_pdp_context_response_t *rsp = NULL;

    rsp = &gtp1_message.delete_pdp_context_response;
    memset(&gtp1_message, 0, sizeof(gtp1_message));

    rsp->cause.presence = 1;
    rsp->cause.u8 = cause;

    gtp1_message.h.type = type;
    return ogs_gtp1_build_msg(&gtp1_message);
}

ogs_pkbuf_t *sgwc_gn_build_update_pdp_context_response(
        uint8_t type, sgwc_sess_t *sess, uint8_t cause)
{
    int rv;
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *ul_tunnel = NULL;
    ogs_gtp1_message_t gtp1_message;
    ogs_gtp1_update_pdp_context_response_t *rsp = NULL;
    ogs_gtp1_gsn_addr_t sgw_gnc_gsnaddr, sgw_gnu_gsnaddr;
    ogs_gtp1_gsn_addr_t sgw_gnc_altgsnaddr, sgw_gnu_altgsnaddr;
    int gsn_len, gsn_altlen;
    char qos_pdec_buf[OGS_GTP1_QOS_PROFILE_MAX_LEN];
    uint32_t charging_id = 0;

    ogs_assert(sess);
    bearer = sgwc_default_bearer_in_sess(sess);
    ogs_assert(bearer);
    ul_tunnel = sgwc_ul_tunnel_in_bearer(bearer);
    ogs_assert(ul_tunnel);

    rsp = &gtp1_message.update_pdp_context_response;
    memset(&gtp1_message, 0, sizeof(gtp1_message));

    rsp->cause.presence = 1;
    rsp->cause.u8 = cause;

    if (cause == OGS_GTP1_CAUSE_REQUEST_ACCEPTED) {
        rsp->tunnel_endpoint_identifier_data_i.presence = 1;
        rsp->tunnel_endpoint_identifier_data_i.u32 = ul_tunnel->local_teid;
        rsp->tunnel_endpoint_identifier_control_plane.presence = 1;
        rsp->tunnel_endpoint_identifier_control_plane.u32 = sess->sgw_s5c_teid;

        if (sess->charging_id)
            charging_id = sess->charging_id;
        else
            charging_id = sess->id;
        rsp->charging_id.presence = 1;
        rsp->charging_id.u32 = charging_id;
        sess->charging_id = charging_id;

        if (sgwc_self()->gn_addr && sgwc_self()->gn_addr6) {
            if (ul_tunnel->local_addr) {
                rv = ogs_gtp1_sockaddr_to_gsn_addr(sgwc_self()->gn_addr, NULL,
                        &sgw_gnc_gsnaddr, &gsn_len);
                ogs_expect(rv == OGS_OK);
                rv = ogs_gtp1_sockaddr_to_gsn_addr(NULL, sgwc_self()->gn_addr6,
                        &sgw_gnc_altgsnaddr, &gsn_altlen);
                ogs_expect(rv == OGS_OK);
            } else {
                rv = ogs_gtp1_sockaddr_to_gsn_addr(NULL, sgwc_self()->gn_addr6,
                        &sgw_gnc_gsnaddr, &gsn_len);
                ogs_expect(rv == OGS_OK);
                rv = ogs_gtp1_sockaddr_to_gsn_addr(sgwc_self()->gn_addr, NULL,
                        &sgw_gnc_altgsnaddr, &gsn_altlen);
                ogs_expect(rv == OGS_OK);
            }
            rsp->alternative_ggsn_address_for_control_plane.presence = 1;
            rsp->alternative_ggsn_address_for_control_plane.data =
                &sgw_gnc_altgsnaddr;
            rsp->alternative_ggsn_address_for_control_plane.len = gsn_altlen;
        } else {
            rv = ogs_gtp1_sockaddr_to_gsn_addr(
                    sgwc_self()->gn_addr, sgwc_self()->gn_addr6,
                    &sgw_gnc_gsnaddr, &gsn_len);
            ogs_expect(rv == OGS_OK);
        }
        rsp->ggsn_address_for_control_plane.presence = 1;
        rsp->ggsn_address_for_control_plane.data = &sgw_gnc_gsnaddr;
        rsp->ggsn_address_for_control_plane.len = gsn_len;

        if (ul_tunnel->local_addr && ul_tunnel->local_addr6) {
            if (ul_tunnel->local_addr) {
                rv = ogs_gtp1_sockaddr_to_gsn_addr(ul_tunnel->local_addr, NULL,
                        &sgw_gnu_gsnaddr, &gsn_len);
                ogs_expect(rv == OGS_OK);
                rv = ogs_gtp1_sockaddr_to_gsn_addr(NULL, ul_tunnel->local_addr6,
                        &sgw_gnu_altgsnaddr, &gsn_altlen);
                ogs_expect(rv == OGS_OK);
            } else {
                rv = ogs_gtp1_sockaddr_to_gsn_addr(NULL, ul_tunnel->local_addr6,
                        &sgw_gnu_gsnaddr, &gsn_len);
                ogs_expect(rv == OGS_OK);
                rv = ogs_gtp1_sockaddr_to_gsn_addr(ul_tunnel->local_addr, NULL,
                        &sgw_gnu_altgsnaddr, &gsn_altlen);
                ogs_expect(rv == OGS_OK);
            }
            rsp->alternative_ggsn_address_for_user_traffic.presence = 1;
            rsp->alternative_ggsn_address_for_user_traffic.data =
                &sgw_gnu_altgsnaddr;
            rsp->alternative_ggsn_address_for_user_traffic.len = gsn_altlen;
        } else {
            rv = ogs_gtp1_sockaddr_to_gsn_addr(
                    ul_tunnel->local_addr, ul_tunnel->local_addr6,
                    &sgw_gnu_gsnaddr, &gsn_len);
            ogs_expect(rv == OGS_OK);
        }
        rsp->ggsn_address_for_user_traffic.presence = 1;
        rsp->ggsn_address_for_user_traffic.data = &sgw_gnu_gsnaddr;
        rsp->ggsn_address_for_user_traffic.len = gsn_len;

        rsp->quality_of_service_profile.presence = 1;
        ogs_gtp1_build_qos_profile(&rsp->quality_of_service_profile,
                &sess->gn_qos_pdec, qos_pdec_buf,
                OGS_GTP1_QOS_PROFILE_MAX_LEN);
    }

    gtp1_message.h.type = type;
    return ogs_gtp1_build_msg(&gtp1_message);
}

static ogs_pkbuf_t *sgwc_gn_build_modify_bearer_request(
        sgwc_sess_t *sess, ogs_gtp1_update_pdp_context_request_t *req)
{
    ogs_gtp2_message_t message;
    ogs_gtp2_modify_bearer_request_t *mbr = NULL;
    ogs_gtp2_bearer_qos_t bearer_qos;
    ogs_gtp2_uli_t uli;
    char uli_buf[OGS_GTP2_MAX_ULI_LEN];
    char bearer_qos_buf[GTP2_BEARER_QOS_LEN];
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *dl_tunnel = NULL;
    ogs_gtp2_f_teid_t sgw_s5u_teid;
    int sgw_s5u_len = 0;
    int rv, decoded;
    uint8_t qci = 9;

    ogs_assert(sess);
    ogs_assert(req);

    bearer = sgwc_default_bearer_in_sess(sess);
    ogs_assert(bearer);
    dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
    ogs_assert(dl_tunnel);

    memset(&message, 0, sizeof(message));
    mbr = &message.modify_bearer_request;
    message.h.type = OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE;
    message.h.teid = sess->pgw_s5c_teid;

    if (req->user_location_information.presence) {
        decoded = sgwc_gn_gtp1_uli_to_gtp2(
                &uli, &req->user_location_information, uli_buf,
                sizeof(uli_buf));
        if (decoded > 0) {
            mbr->user_location_information.presence = 1;
            mbr->user_location_information.data = uli_buf;
            mbr->user_location_information.len = decoded;
        }
    }

    if (req->rat_type.presence) {
        mbr->rat_type.presence = 1;
        switch (req->rat_type.u8) {
        case OGS_GTP1_RAT_TYPE_UTRAN:
            mbr->rat_type.u8 = OGS_GTP2_RAT_TYPE_UTRAN;
            break;
        case OGS_GTP1_RAT_TYPE_GERAN:
            mbr->rat_type.u8 = OGS_GTP2_RAT_TYPE_GERAN;
            break;
        default:
            mbr->rat_type.u8 = OGS_GTP2_RAT_TYPE_UTRAN;
            break;
        }
    }

    if (req->quality_of_service_profile.presence) {
        ogs_gtp1_parse_qos_profile(&sess->gn_qos_pdec,
                &req->quality_of_service_profile);
        ogs_gtp1_qos_profile_to_qci(&sess->gn_qos_pdec, &qci);
        sess->session.qos.index = qci;
        sess->session.qos.arp.priority_level =
            sess->gn_qos_pdec.qos_profile.arp;
    }

    ogs_gtp1_qos_profile_to_qci(&sess->gn_qos_pdec, &qci);
    memset(&bearer_qos, 0, sizeof(bearer_qos));
    bearer_qos.qci = qci;
    bearer_qos.priority_level = sess->gn_qos_pdec.qos_profile.arp;

    mbr->bearer_contexts_to_be_modified[0].presence = 1;
    mbr->bearer_contexts_to_be_modified[0].eps_bearer_id.presence = 1;
    mbr->bearer_contexts_to_be_modified[0].eps_bearer_id.u8 = bearer->ebi;
    mbr->bearer_contexts_to_be_modified[0].bearer_level_qos.presence = 1;
    ogs_gtp2_build_bearer_qos(
            &mbr->bearer_contexts_to_be_modified[0].bearer_level_qos,
            &bearer_qos, bearer_qos_buf, sizeof(bearer_qos_buf));

    if (req->tunnel_endpoint_identifier_data_i.presence ||
            req->sgsn_address_for_user_traffic.presence) {
        if (req->tunnel_endpoint_identifier_data_i.presence)
            dl_tunnel->remote_teid =
                req->tunnel_endpoint_identifier_data_i.u32;
        if (req->sgsn_address_for_user_traffic.presence) {
            rv = ogs_gtp1_gsn_addr_to_ip(
                    req->sgsn_address_for_user_traffic.data,
                    req->sgsn_address_for_user_traffic.len,
                    &dl_tunnel->remote_ip);
            if (rv != OGS_OK)
                return NULL;
        }
    }

    memset(&sgw_s5u_teid, 0, sizeof(sgw_s5u_teid));
    sgw_s5u_teid.teid = htobe32(dl_tunnel->local_teid);
    sgw_s5u_teid.interface_type = dl_tunnel->interface_type;
    rv = ogs_gtp2_sockaddr_to_f_teid(
            dl_tunnel->local_addr, dl_tunnel->local_addr6,
            &sgw_s5u_teid, &sgw_s5u_len);
    if (rv != OGS_OK)
        return NULL;

    mbr->bearer_contexts_to_be_modified[0].s4_u_sgsn_f_teid.presence = 1;
    mbr->bearer_contexts_to_be_modified[0].s4_u_sgsn_f_teid.data =
        &sgw_s5u_teid;
    mbr->bearer_contexts_to_be_modified[0].s4_u_sgsn_f_teid.len =
        sgw_s5u_len;

    return ogs_gtp2_build_msg(&message);
}

ogs_pkbuf_t *sgwc_gn_build_modify_bearer_request_pkbuf(
        sgwc_sess_t *sess, ogs_gtp1_update_pdp_context_request_t *req)
{
    return sgwc_gn_build_modify_bearer_request(sess, req);
}
