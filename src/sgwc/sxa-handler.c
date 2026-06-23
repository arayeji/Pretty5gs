/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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

#include "context.h"
#include "pfcp-path.h"
#include "gtp-path.h"
#include "s11-handler.h"
#include "sxa-handler.h"
#include "sgwc-trace.h"
#include "ga-writer.h"
#include "sgwc-trace.h"
#include "sgwc-gtp-interop.h"
#include "gn-handler.h"
#include "gn-build.h"

static void sgwc_log_urr_report(
        const char *phase, sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess,
        uint32_t urr_id, ogs_pfcp_volume_measurement_t *volume,
        uint32_t duration_s, ogs_pfcp_tlv_usage_report_trigger_t *trigger_tlv)
{
    ogs_pfcp_usage_report_trigger_t rep_trig;
    uint64_t ul = 0, dl = 0;

    if (volume) {
        if (volume->ulvol)
            ul = volume->uplink_volume;
        if (volume->dlvol)
            dl = volume->downlink_volume;
    }

    memset(&rep_trig, 0, sizeof(rep_trig));
    if (trigger_tlv && trigger_tlv->presence)
        ogs_pfcp_parse_usage_report_trigger(&rep_trig, trigger_tlv);

    ogs_info("[SGWC-URR:%s] IMSI:%s APN:%s urr_id=%u UL=%llu DL=%llu dur=%us "
            "trigger(time:%u vol:%u term:%u periodic:%u)",
            phase,
            (sgwc_ue && sgwc_ue->imsi_bcd[0]) ? sgwc_ue->imsi_bcd : "-",
            sess ? sess->session.name : "-",
            urr_id, (unsigned long long)ul, (unsigned long long)dl, duration_s,
            rep_trig.time_threshold, rep_trig.volume_threshold,
            rep_trig.termination_report, rep_trig.periodic_reporting);
}

static uint8_t gtp_cause_from_pfcp(uint8_t pfcp_cause)
{
    switch (pfcp_cause) {
    case OGS_PFCP_CAUSE_REQUEST_ACCEPTED:
        return OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
    case OGS_PFCP_CAUSE_REQUEST_REJECTED:
        return OGS_GTP2_CAUSE_REQUEST_REJECTED_REASON_NOT_SPECIFIED;
    case OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND:
        return OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    case OGS_PFCP_CAUSE_MANDATORY_IE_MISSING:
        return OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    case OGS_PFCP_CAUSE_CONDITIONAL_IE_MISSING:
        return OGS_GTP2_CAUSE_CONDITIONAL_IE_MISSING;
    case OGS_PFCP_CAUSE_INVALID_LENGTH:
        return OGS_GTP2_CAUSE_INVALID_LENGTH;
    case OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT:
        return OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
    case OGS_PFCP_CAUSE_INVALID_FORWARDING_POLICY:
    case OGS_PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION:
        return OGS_GTP2_CAUSE_INVALID_MESSAGE_FORMAT;
    case OGS_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION:
        return OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING;
    case OGS_PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE:
        return OGS_GTP2_CAUSE_SEMANTIC_ERROR_IN_THE_TFT_OPERATION;
    case OGS_PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION:
        return OGS_GTP2_CAUSE_GTP_C_ENTITY_CONGESTION;
    case OGS_PFCP_CAUSE_NO_RESOURCES_AVAILABLE:
        return OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE;
    case OGS_PFCP_CAUSE_SERVICE_NOT_SUPPORTED:
        return OGS_GTP2_CAUSE_SERVICE_NOT_SUPPORTED;
    case OGS_PFCP_CAUSE_SYSTEM_FAILURE:
        return OGS_GTP2_CAUSE_SYSTEM_FAILURE;
    default:
        return OGS_GTP2_CAUSE_SYSTEM_FAILURE;
    }

    return OGS_GTP2_CAUSE_SYSTEM_FAILURE;
}

static void sess_timeout(ogs_gtp_xact_t *xact, void *data)
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

    type = xact->seq[0].type;

    switch (type) {
    case OGS_GTP2_CREATE_SESSION_REQUEST_TYPE: {
        ogs_gtp_xact_t *s11_xact = NULL;
        char peer[OGS_ADDRSTRLEN];

        s11_xact = ogs_gtp_xact_find_by_id(xact->assoc_xact_id);
        if (xact->gnode) {
            ogs_error("[%s] S5 timeout: no Create Session Response from "
                    "SMF/PGW [%s]:%d",
                    sgwc_ue->imsi_bcd,
                    OGS_ADDR(&xact->gnode->addr, peer),
                    OGS_PORT(&xact->gnode->addr));
        } else {
            ogs_error("[%s] S5 timeout: no Create Session Response "
                    "(SMF/PGW peer unknown)", sgwc_ue->imsi_bcd);
        }

        if (s11_xact) {
            if (sess && sess->gn) {
                sgwc_gn_send_create_reject(sess, sgwc_ue, s11_xact,
                        OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
            } else {
                ogs_gtp_send_error_message(
                        s11_xact, sgwc_ue->mme_s11_teid,
                        OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                        OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
                sgwc_sess_remove(sess);
            }
        } else {
            sgwc_sess_remove(sess);
        }
        /* Release the UE context if this create-session was its last. */
        sgwc_ue_remove_if_empty(sgwc_ue);
        break;
    }
    default:
        ogs_error("GTP Timeout : IMSI[%s] Message-Type[%d]",
                sgwc_ue->imsi_bcd, type);
    }
}

static void bearer_timeout(ogs_gtp_xact_t *xact, void *data)
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
        ogs_warn("Bearer has already been removed [%d]", type);
        return;
    }

    sess = sgwc_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);

    switch (type) {
    case OGS_GTP2_CREATE_BEARER_REQUEST_TYPE:
        sgwc_ue_error(sgwc_ue, NULL, "sxa", NULL,
                "No Create Bearer Response");
        ogs_debug("    bearer[EBI=%d]", bearer->ebi);
        ogs_assert(OGS_OK ==
            sgwc_pfcp_send_bearer_modification_request(
                bearer, OGS_INVALID_POOL_ID, NULL,
                OGS_PFCP_MODIFY_UL_ONLY|OGS_PFCP_MODIFY_REMOVE));
        break;
    default:
        ogs_error("GTP Timeout : IMSI[%s] Message-Type[%d]",
                sgwc_ue->imsi_bcd, type);
    }
}

#define SGWC_PFCP_CSR_UL_MODIFY_FLAGS \
    (OGS_PFCP_MODIFY_UL_ONLY| \
     OGS_PFCP_MODIFY_OUTER_HEADER_REMOVAL| \
     OGS_PFCP_MODIFY_ACTIVATE|OGS_PFCP_MODIFY_SESSION)

void sgwc_sxa_handle_unexpected_modification_response(
        sgwc_sess_t *rsp_sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_pfcp_session_modification_response_t *pfcp_rsp)
{
    ogs_gtp_xact_t *s11_xact = NULL;
    sgwc_sess_t *est_sess = NULL;
    sgwc_sess_t *sess = NULL;
    sgwc_ue_t *sgwc_ue = NULL;
    ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;
    uint8_t cause_value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;

    ogs_assert(pfcp_xact);
    ogs_assert(pfcp_rsp);

    if (pfcp_rsp->cause.presence)
        cause_value = gtp_cause_from_pfcp(pfcp_rsp->cause.u8);

    if (pfcp_xact->seq[0].type !=
            OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE) {
        ogs_warn("Unexpected PFCP Session Modification Response "
                "(xid=%u org=%d seq0_type=%u pfcp_cause=%u)",
                pfcp_xact->xid, pfcp_xact->org, pfcp_xact->seq[0].type,
                pfcp_rsp->cause.presence ? pfcp_rsp->cause.u8 : 0);
        ogs_pfcp_xact_commit(pfcp_xact);
        return;
    }

    ogs_warn("PFCP Mod Rsp matched establishment xact (xid=%u pfcp_cause=%u)",
            pfcp_xact->xid,
            pfcp_rsp->cause.presence ? pfcp_rsp->cause.u8 : 0);

    s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);
    sess_id = OGS_POINTER_TO_UINT(pfcp_xact->data);
    if (sess_id >= OGS_MIN_POOL_ID && sess_id <= OGS_MAX_POOL_ID)
        est_sess = sgwc_sess_find_by_id(sess_id);

    if (s11_xact && est_sess) {
        sgwc_ue_t *xact_ue = sgwc_ue_find_by_id(est_sess->sgwc_ue_id);

        if (!xact_ue || s11_xact->local_teid != xact_ue->sgw_s11_teid ||
                s11_xact->assoc_xact_id != pfcp_xact->id) {
            ogs_warn("Stale S11 xact ignored (pfcp_xid=%u s11_id=%d)",
                    pfcp_xact->xid, pfcp_xact->assoc_xact_id);
            s11_xact = NULL;
        }
    }

    sess = rsp_sess ? rsp_sess : est_sess;

    /*
     * Under load, SGW-U may return Session Modification Response with an
     * XID that still maps to a pending Session Establishment transaction
     * (another session's UL-activate after PGW CSR). Do not fail unrelated
     * Create Session procedures when PFCP cause is Request Accepted.
     */
    if (pfcp_rsp->cause.presence &&
            pfcp_rsp->cause.u8 == OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
        ogs_pfcp_xact_t *mod_xact = NULL;
        ogs_gtp2_message_t gtp_message;

        if (sess)
            mod_xact = sgwc_pfcp_find_session_modify_xact(
                    sess, SGWC_PFCP_CSR_UL_MODIFY_FLAGS);

        if (mod_xact && mod_xact->gtpbuf &&
                ogs_gtp2_parse_msg(&gtp_message, mod_xact->gtpbuf) == OGS_OK) {
            ogs_warn("PFCP Mod Rsp xid collision (xid=%u); "
                    "rerouting to pending UL-modify [%s]",
                    pfcp_xact->xid, sess->session.name);
            ogs_pfcp_xact_commit(pfcp_xact);
            sgwc_sxa_handle_session_modification_response(
                    sess, mod_xact, &gtp_message, pfcp_rsp);
            return;
        }

        if (est_sess && est_sess->pgw_s5c_teid && pfcp_xact->gtpbuf &&
                ogs_gtp2_parse_msg(&gtp_message, pfcp_xact->gtpbuf) == OGS_OK) {
            pfcp_xact->modify_flags = SGWC_PFCP_CSR_UL_MODIFY_FLAGS;
            ogs_warn("PFCP Mod Rsp on establishment xact (xid=%u); "
                    "treating as CSR UL-activate [%s]",
                    pfcp_xact->xid, est_sess->session.name);
            sgwc_sxa_handle_session_modification_response(
                    est_sess, pfcp_xact, &gtp_message, pfcp_rsp);
            return;
        }

        ogs_warn("PFCP Mod Rsp on establishment xact (xid=%u); "
                "ignored (no pending UL-modify or PGW CSR yet)",
                pfcp_xact->xid);
        ogs_pfcp_xact_commit(pfcp_xact);
        return;
    }

    if (s11_xact) {
        if (est_sess)
            sgwc_ue = sgwc_ue_find_by_id(est_sess->sgwc_ue_id);
        if (est_sess && est_sess->gn) {
            sgwc_gn_send_create_reject(est_sess, sgwc_ue, s11_xact,
                    cause_value);
            est_sess = NULL;
        } else {
            ogs_gtp_send_error_message(
                    s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
                    OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE, cause_value);
        }
    }

    if (est_sess) {
        sgwc_ue_t *est_ue = sgwc_ue_find_by_id(est_sess->sgwc_ue_id);
        sgwc_sess_remove(est_sess);
        sgwc_ue_remove_if_empty(est_ue);
    }

    ogs_pfcp_xact_commit(pfcp_xact);
}

static bool sgwc_resolve_pgw_s5c_teid(
        sgwc_sess_t *sess,
        ogs_gtp2_create_session_request_t *create_session_request,
        ogs_gtp2_f_teid_t **pgw_s5c_teid_out)
{
    ogs_gtp2_f_teid_t *pgw_s5c_teid = NULL;

    ogs_assert(sess);
    ogs_assert(create_session_request);
    ogs_assert(pgw_s5c_teid_out);

    *pgw_s5c_teid_out = NULL;

    if (create_session_request->
            pgw_s5_s8_address_for_control_plane_or_pmip.presence &&
            create_session_request->
            pgw_s5_s8_address_for_control_plane_or_pmip.data) {
        pgw_s5c_teid = create_session_request->
            pgw_s5_s8_address_for_control_plane_or_pmip.data;
    } else if (sess->gn && sgwc_self()->gn_pgw_f_teid_len) {
        pgw_s5c_teid = &sgwc_self()->gn_pgw_f_teid;
        ogs_debug("Gn session: PGW S5-C F-TEID from sgwc.gn.pgw/smf");
    }

    if (!pgw_s5c_teid)
        return false;

    if (pgw_s5c_teid->teid)
        sess->pgw_s5c_teid = be32toh(pgw_s5c_teid->teid);

    *pgw_s5c_teid_out = pgw_s5c_teid;
    return true;
}

void sgwc_sxa_handle_session_establishment_response(
        sgwc_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_gtp2_message_t *recv_message,
        ogs_pfcp_session_establishment_response_t *pfcp_rsp,
        ogs_pkbuf_t *pfcp_pkbuf)
{
    int rv;
    uint8_t cause_value = 0;

    ogs_pfcp_f_seid_t *up_f_seid = NULL;

    int sgw_s5c_len;
    ogs_gtp2_f_teid_t sgw_s5c_teid;
    ogs_gtp2_f_teid_t *pgw_s5c_teid = NULL;

    int i, num_of_sgw_s5u;
    uint8_t ebi[OGS_BEARER_PER_UE];
    int sgw_s5u_len[OGS_BEARER_PER_UE];
    ogs_gtp2_f_teid_t sgw_s5u_teid[OGS_BEARER_PER_UE];

    ogs_gtp_xact_t *s11_xact = NULL, *s5c_xact = NULL;
    ogs_gtp_node_t *pgw = NULL;

    sgwc_ue_t *sgwc_ue = NULL;
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *dl_tunnel = NULL;

    ogs_gtp2_create_session_request_t *create_session_request = NULL;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_gtp2_indication_t *indication = NULL;
    ogs_nas_plmn_id_t gn_serving_plmn_id;

    ogs_debug("Session Establishment Response");

    ogs_assert(pfcp_xact);
    ogs_assert(pfcp_rsp);
    ogs_assert(recv_message);

    create_session_request = &recv_message->create_session_request;
    ogs_assert(create_session_request);

    s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);
    if (!s11_xact) {
        ogs_error("GTP transaction(S11) has already been removed [%d]",
                pfcp_xact->assoc_xact_id);
        ogs_pfcp_xact_commit(pfcp_xact);
        return;
    }

    ogs_pfcp_xact_commit(pfcp_xact);

    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_error("No Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (pfcp_rsp->up_f_seid.presence == 0) {
        ogs_error("No UP F-SEID");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }

    if (pfcp_rsp->cause.presence) {
        if (pfcp_rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_error("PFCP Cause [%d:%s] : Not Accepted",
                    pfcp_rsp->cause.u8,
                    ogs_pfcp_cause_get_name(pfcp_rsp->cause.u8));
            if (ogs_pfcp_cause_no_association(pfcp_rsp->cause.u8) && sess)
                sgwc_pfcp_request_reassociation(sess->pfcp_node);
            cause_value = gtp_cause_from_pfcp(pfcp_rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        int i;

        uint8_t pfcp_cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;
        uint8_t offending_ie_value = 0;

        sgwc_tunnel_t *tunnel = NULL;
        ogs_pfcp_pdr_t *pdr = NULL;
        ogs_pfcp_far_t *far = NULL;

        ogs_assert(sess);
        for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
            pdr = ogs_pfcp_handle_created_pdr(
                    &sess->pfcp, &pfcp_rsp->created_pdr[i],
                    &pfcp_cause_value, &offending_ie_value);

            if (!pdr)
                break;
        }

        ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
            far = pdr->far;
            if (!far) {
                ogs_error("No FAR for PDR");
                pfcp_cause_value = OGS_PFCP_CAUSE_SYSTEM_FAILURE;
                break;
            }

            if (pdr->src_if == OGS_PFCP_INTERFACE_CP_FUNCTION &&
                    ogs_pfcp_setup_pdr_gtpu_node(pdr) == OGS_ERROR) {
                ogs_error("ogs_pfcp_setup_pdr_gtpu_node() failed");
                pfcp_cause_value = OGS_PFCP_CAUSE_SYSTEM_FAILURE;
                break;
            }

            if (far->dst_if == OGS_PFCP_INTERFACE_CP_FUNCTION)
                ogs_pfcp_far_teid_hash_set(far);

            tunnel = sgwc_tunnel_find_by_pdr_id(sess, pdr->id);
            if (tunnel) {
                if (!sess->pfcp_node) {
                    ogs_error("No PFCP node");
                    pfcp_cause_value = OGS_PFCP_CAUSE_SYSTEM_FAILURE;
                    break;
                }
                if (sess->pfcp_node->up_function_features.ftup &&
                    pdr->f_teid_len) {
                    if (tunnel->local_addr)
                        ogs_freeaddrinfo(tunnel->local_addr);
                    if (tunnel->local_addr6)
                        ogs_freeaddrinfo(tunnel->local_addr6);

                    rv = ogs_pfcp_f_teid_to_sockaddr(
                            &pdr->f_teid, pdr->f_teid_len,
                            &tunnel->local_addr, &tunnel->local_addr6);
                    if (rv != OGS_OK) {
                        ogs_error("ogs_pfcp_f_teid_to_sockaddr() failed");
                        pfcp_cause_value = OGS_PFCP_CAUSE_SYSTEM_FAILURE;
                        break;
                    }
                    tunnel->local_teid = pdr->f_teid.teid;
                }
            }
        }

        cause_value = gtp_cause_from_pfcp(pfcp_cause_value);
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        char sgwu_peer[OGS_ADDRSTRLEN];
        char mme_peer[OGS_ADDRSTRLEN];
        char pgw_peer[OGS_ADDRSTRLEN];
        char vpp_detail[512];
        uint16_t offending_ie = 0;

        vpp_detail[0] = '\0';
        if (pfcp_pkbuf &&
                !ogs_pfcp_travelping_error_message(
                    pfcp_pkbuf, vpp_detail, sizeof(vpp_detail)))
            vpp_detail[0] = '\0';

        if (pfcp_rsp->offending_ie.presence)
            offending_ie = pfcp_rsp->offending_ie.u16;

        if (sess) sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        sgwc_log_sgwu_peer(sgwu_peer, sizeof(sgwu_peer), sess);
        sgwc_log_mme_peer(mme_peer, sizeof(mme_peer), sgwc_ue);
        sgwc_log_pgw_peer(pgw_peer, sizeof(pgw_peer), sess);
        sgwc_ue_error(sgwc_ue, sess, "sxa",
                sess && sess->session.name ? sess->session.name : NULL,
                "SGW-U rejected PFCP Session Establishment "
                "SGW-U[%s] MME[%s] PGW[%s] PFCP cause[%u:%s] -> S11 cause[%u] "
                "sess_id[%d] offending_ie[%u] vpp[%s]",
                sgwu_peer[0] ? sgwu_peer : "-",
                mme_peer[0] ? mme_peer : "-",
                pgw_peer[0] ? pgw_peer : "-",
                pfcp_rsp->cause.presence ? pfcp_rsp->cause.u8 : 0,
                pfcp_rsp->cause.presence ?
                    ogs_pfcp_cause_get_name(pfcp_rsp->cause.u8) : "-",
                cause_value, sess ? sess->id : 0,
                offending_ie,
                vpp_detail[0] ? vpp_detail : "-");
        sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact, cause_value);
        if (sess && !sess->gn) {
            sgwc_sess_remove(sess);
            sgwc_ue_remove_if_empty(sgwc_ue);
        }
        return;
    }

    ogs_assert(sess);

    ogs_debug("    SGW_S5C_TEID[0x%x] PGW_S5C_TEID[0x%x]",
        sess->sgw_s5c_teid, sess->pgw_s5c_teid);

    /* Data Plane(DL) : SGW-S5U */
    i = 0;
    ogs_list_for_each(&sess->bearer_list, bearer) {
        if (i >= OGS_BEARER_PER_UE) {
            ogs_error("Too many bearers");
            break;
        }

        dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
        if (!dl_tunnel) {
            sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
            ogs_error("No DL tunnel");
            sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                    OGS_GTP2_CAUSE_SYSTEM_FAILURE);
            if (!sess->gn) {
                sgwc_sess_remove(sess);
                sgwc_ue_remove_if_empty(sgwc_ue);
            }
            return;
        }

        ogs_debug("    SGW_S5U_TEID[%d] PGW_S5U_TEID[%d]",
            dl_tunnel->local_teid, dl_tunnel->remote_teid);

        if (dl_tunnel->local_addr == NULL && dl_tunnel->local_addr6 == NULL) {
            sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
            ogs_error("No UP F-TEID");
            sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                    OGS_GTP2_CAUSE_GRE_KEY_NOT_FOUND);
            if (!sess->gn) {
                sgwc_sess_remove(sess);
                sgwc_ue_remove_if_empty(sgwc_ue);
            }
            return;
        }

        ebi[i] = bearer->ebi;

        memset(&sgw_s5u_teid[i], 0, sizeof(ogs_gtp2_f_teid_t));
        sgw_s5u_teid[i].teid = htobe32(dl_tunnel->local_teid);
        sgw_s5u_teid[i].interface_type = dl_tunnel->interface_type;
        if (!dl_tunnel->local_addr && !dl_tunnel->local_addr6) {
            sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
            ogs_error("No local F-TEID address");
            sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                    OGS_GTP2_CAUSE_GRE_KEY_NOT_FOUND);
            if (!sess->gn) {
                sgwc_sess_remove(sess);
                sgwc_ue_remove_if_empty(sgwc_ue);
            }
            return;
        }
        rv = ogs_gtp2_sockaddr_to_f_teid(
                dl_tunnel->local_addr, dl_tunnel->local_addr6,
                &sgw_s5u_teid[i], &sgw_s5u_len[i]);
        if (rv != OGS_OK) {
            sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
            ogs_error("ogs_gtp2_sockaddr_to_f_teid() failed");
            sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                    OGS_GTP2_CAUSE_SYSTEM_FAILURE);
            if (!sess->gn) {
                sgwc_sess_remove(sess);
                sgwc_ue_remove_if_empty(sgwc_ue);
            }
            return;
        }

        i++;
    }

    num_of_sgw_s5u = i;

    /* Send Control Plane(DL) : SGW-S5C */
    memset(&sgw_s5c_teid, 0, sizeof(ogs_gtp2_f_teid_t));
    sgw_s5c_teid.interface_type = OGS_GTP2_F_TEID_S5_S8_SGW_GTP_C;
    sgw_s5c_teid.teid = htobe32(sess->sgw_s5c_teid);
    {
        ogs_sockaddr_t *gtpc_addr = NULL, *gtpc_addr6 = NULL;
        sgwc_gtpc_f_teid_addr(sess, &gtpc_addr, &gtpc_addr6);
        rv = ogs_gtp2_sockaddr_to_f_teid(
                gtpc_addr, gtpc_addr6, &sgw_s5c_teid, &sgw_s5c_len);
    }
    if (rv != OGS_OK) {
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        ogs_error("ogs_gtp2_sockaddr_to_f_teid(S5C) failed");
        sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                OGS_GTP2_CAUSE_SYSTEM_FAILURE);
        if (!sess->gn) {
            sgwc_sess_remove(sess);
            sgwc_ue_remove_if_empty(sgwc_ue);
        }
        return;
    }

    /* UP F-SEID */
    up_f_seid = pfcp_rsp->up_f_seid.data;
    if (!up_f_seid) {
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        ogs_error("No UP F-SEID data");
        sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                OGS_GTP2_CAUSE_MANDATORY_IE_MISSING);
        if (!sess->gn) {
            sgwc_sess_remove(sess);
            sgwc_ue_remove_if_empty(sgwc_ue);
        }
        return;
    }
    sess->sgwu_sxa_seid = be64toh(up_f_seid->seid);

    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    sgwc_ue_info(sgwc_ue, sess, "sxa", NULL,
            "PFCP session established SGWU-SEID=0x%llx",
            (unsigned long long)sess->sgwu_sxa_seid);
    sgwc_create_session_phase(sess, sgwc_ue, "pfcp-establish-ok");

    /* Receive Control Plane(UL) : PGW-S5C */
    if (sgwc_resolve_pgw_s5c_teid(sess, create_session_request, &pgw_s5c_teid)) {
        pgw = ogs_gtp_node_find_by_f_teid(
                &sgwc_self()->pgw_s5c_list, pgw_s5c_teid);
        if (!pgw) {
            pgw = ogs_gtp_node_add_by_f_teid(
                    &sgwc_self()->pgw_s5c_list,
                    pgw_s5c_teid, ogs_gtp_self()->gtpc_port);
            if (!pgw) {
                ogs_error("ogs_gtp_node_add_by_f_teid() failed");
                sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                        OGS_GTP2_CAUSE_SYSTEM_FAILURE);
                if (!sess->gn) {
                    sgwc_sess_remove(sess);
                    sgwc_ue_remove_if_empty(sgwc_ue);
                }
                return;
            }

            rv = sgwc_gtp_connect_peer(sess, pgw);
            if (rv != OGS_OK) {
                ogs_error("sgwc_gtp_connect_peer() failed");
                sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                        OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
                if (!sess->gn) {
                    sgwc_sess_remove(sess);
                    sgwc_ue_remove_if_empty(sgwc_ue);
                }
                return;
            }
        }
        /* Setup GTP Node */
        OGS_SETUP_GTP_NODE(sess, pgw);
    } else if (sess->gnode) {
        /*
         * Duplicate or late PFCP Session Establishment Response:
         * the buffered S11 Create Session Request may no longer expose
         * the PGW F-TEID IE, but the S5 peer was already resolved.
         */
        ogs_warn("No PGW F-TEID in buffered Create Session Request; "
                "reusing S5 peer (PGW_S5C_TEID=0x%x)",
                sess->pgw_s5c_teid);
        pgw = sess->gnode;
    } else {
        ogs_error("No PGW S5-C F-TEID in Create Session Request "
                "(PGW_S5C_TEID=0x%x)", sess->pgw_s5c_teid);
        sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                OGS_GTP2_CAUSE_CONDITIONAL_IE_MISSING);
        if (!sess->gn) {
            sgwc_sess_remove(sess);
            sgwc_ue_remove_if_empty(sgwc_ue);
        }
        return;
    }

    /* Check Indication */
    if (create_session_request->indication_flags.presence &&
        create_session_request->indication_flags.data &&
        create_session_request->indication_flags.len) {
        indication = create_session_request->indication_flags.data;
    }

    if (indication && indication->operation_indication) {
        ogs_gtp2_message_t send_message;
        ogs_gtp2_modify_bearer_request_t *modify_bearer_request =
            &send_message.modify_bearer_request;

        /*
         * Operation Indication:
         * This flag shall be set to 1 on the S4/S11 interface
         * for a TAU/RAU procedure with SGW relocation, Enhanced
         * SRNS Relocation with SGW relocation, X2-based handovers
         * with SGW relocation and MME triggered Serving GW relocation
         */
        memset(&send_message, 0, sizeof(ogs_gtp2_message_t));

        send_message.h.type = OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE;
        send_message.h.teid = sess->pgw_s5c_teid;

        /* Send Control Plane(DL) : SGW-S5C */
        modify_bearer_request->sender_f_teid_for_control_plane.presence = 1;
        modify_bearer_request->sender_f_teid_for_control_plane.
            data = &sgw_s5c_teid;
        modify_bearer_request->sender_f_teid_for_control_plane.
            len = sgw_s5c_len;

        for (i = 0; i < num_of_sgw_s5u; i++) {
            modify_bearer_request->bearer_contexts_to_be_modified[i].
                presence = 1;
            modify_bearer_request->bearer_contexts_to_be_modified[i].
                eps_bearer_id.presence = 1;

            /* Bearer Context : EBI */
            modify_bearer_request->bearer_contexts_to_be_modified[i].
                eps_bearer_id.u8 = ebi[i];

            /* Data Plane(DL) : SGW-S5U */
            modify_bearer_request->bearer_contexts_to_be_modified[i].
                s4_u_sgsn_f_teid.presence = 1;
            modify_bearer_request->bearer_contexts_to_be_modified[i].
                s4_u_sgsn_f_teid.data = &sgw_s5u_teid[i];
            modify_bearer_request->bearer_contexts_to_be_modified[i].
                s4_u_sgsn_f_teid.len = sgw_s5u_len[i];
        }

        pkbuf = ogs_gtp2_build_msg(&send_message);
        if (!pkbuf) {
            ogs_error("ogs_gtp2_build_msg() failed");
            return;
        }

        if (!sess->gnode) {
            ogs_error("No S5 peer (gnode)");
            sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                    OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
            if (!sess->gn) {
                sgwc_sess_remove(sess);
                sgwc_ue_remove_if_empty(sgwc_ue);
            }
            return;
        }
        s5c_xact = ogs_gtp_xact_local_create(
                sess->gnode, &send_message.h, pkbuf, sess_timeout,
                OGS_UINT_TO_POINTER(sess->id));
        if (!s5c_xact) {
            ogs_error("ogs_gtp_xact_local_create() failed");
            return;
        }
        s5c_xact->local_teid = sess->sgw_s5c_teid;

        s5c_xact->modify_action = OGS_GTP_MODIFY_IN_PATH_SWITCH_REQUEST;

    } else {

        /* Create Session Request */
        recv_message->h.type = OGS_GTP2_CREATE_SESSION_REQUEST_TYPE;
        recv_message->h.teid = sess->pgw_s5c_teid;

        /* Send Control Plane(DL) : SGW-S5C */
        create_session_request->sender_f_teid_for_control_plane.presence = 1;
        create_session_request->sender_f_teid_for_control_plane.
            data = &sgw_s5c_teid;
        create_session_request->sender_f_teid_for_control_plane.
            len = sgw_s5c_len;

        /* Remove PGW-S5C */
        create_session_request->pgw_s5_s8_address_for_control_plane_or_pmip.
            presence = 0;

        /* Bearer Contexts */
        for (i = 0; i < num_of_sgw_s5u; i++) {
            create_session_request->bearer_contexts_to_be_created[i].
                s5_s8_u_sgw_f_teid.presence = 1;
            create_session_request->bearer_contexts_to_be_created[i].
                s5_s8_u_sgw_f_teid.data = &sgw_s5u_teid[i];
            create_session_request->bearer_contexts_to_be_created[i].
                s5_s8_u_sgw_f_teid.len = sgw_s5u_len[i];
        }

        if (sgwc_self()->inbound_roam_gtpc_send_recovery_on_s5_csr) {
            create_session_request->recovery.presence = 1;
            create_session_request->recovery.u8 =
                sgwc_self()->gtpc_recovery;
        }

        /* APN/PCO: forward unchanged from MME on S11. */
        if (sess->gn && sgwc_ue) {
            sgwc_gn_reapply_create_session_request(
                    create_session_request, sess, sgwc_ue,
                    &gn_serving_plmn_id);
        }

        pkbuf = ogs_gtp2_build_msg(recv_message);
        if (!pkbuf) {
            ogs_error("ogs_gtp2_build_msg() failed");
            return;
        }

        if (!sess->gnode) {
            ogs_error("No S5 peer (gnode)");
            sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                    OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
            if (!sess->gn) {
                sgwc_sess_remove(sess);
                sgwc_ue_remove_if_empty(sgwc_ue);
            }
            return;
        }
        s5c_xact = ogs_gtp_xact_local_create(
                sess->gnode, &recv_message->h, pkbuf, sess_timeout,
                OGS_UINT_TO_POINTER(sess->id));
        if (!s5c_xact) {
            ogs_error("ogs_gtp_xact_local_create() failed");
            return;
        }
        s5c_xact->local_teid = sess->sgw_s5c_teid;
    }

    ogs_gtp_xact_associate(s11_xact, s5c_xact);

    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);
}

void sgwc_sxa_handle_session_modification_response(
        sgwc_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_gtp2_message_t *recv_message,
        ogs_pfcp_session_modification_response_t *pfcp_rsp)
{
    int i, rv, len = 0;
    uint8_t cause_value = 0;
    uint64_t flags;

    ogs_gtp_xact_t *s11_xact = NULL;
    ogs_gtp_xact_t *s5c_xact = NULL;

    ogs_gtp2_message_t send_message;

    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *dl_tunnel = NULL, *ul_tunnel = NULL;
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_pkbuf_t *pkbuf = NULL;

    ogs_gtp2_cause_t cause;

    ogs_debug("Session Modification Response");

    ogs_assert(pfcp_xact);
    ogs_assert(pfcp_rsp);

    flags = pfcp_xact->modify_flags;
    if (!flags) {
        ogs_error("PFCP Session Modification Response without modify_flags "
                "(xid=%u org=%d seq0_type=%u local_seid=0x%llx)",
                pfcp_xact->xid, pfcp_xact->org, pfcp_xact->seq[0].type,
                (unsigned long long)pfcp_xact->local_seid);
        ogs_pfcp_xact_commit(pfcp_xact);
        return;
    }

    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (flags & OGS_PFCP_MODIFY_SESSION) {
        if (!sess) {
            ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;

            ogs_error("No Session Context");

            sess_id = OGS_POINTER_TO_UINT(pfcp_xact->data);
            if (sess_id >= OGS_MIN_POOL_ID && sess_id <= OGS_MAX_POOL_ID) {
                sess = sgwc_sess_find_by_id(sess_id);
                if (!sess) {
                    ogs_error("Session not found [%d]", sess_id);
                    cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
                }
            } else {
                ogs_error("Invalid session id: %u", sess_id);
                cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
            }
        }

        if (sess && cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
            sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
            if (!sgwc_ue) {
                ogs_error("UE not found [%d]", sess->sgwc_ue_id);
                cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
            }
        }

    } else {
        ogs_pool_id_t bearer_id = OGS_POINTER_TO_UINT(pfcp_xact->data);
        if (bearer_id >= OGS_MIN_POOL_ID && bearer_id <= OGS_MAX_POOL_ID) {
            bearer = sgwc_bearer_find_by_id(bearer_id);
            if (!bearer) {
                ogs_error("No Bearer Context [%d]", bearer_id);
                cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
            } else {
                if (!sess) {
                    ogs_error("No Session Context");

                    sess = sgwc_sess_find_by_id(bearer->sess_id);
                    if (!sess) {
                        ogs_error("Session not found [%d]", bearer->sess_id);
                        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
                    }
                }

                if (sess && cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
                    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
                    if (!sgwc_ue) {
                        ogs_error("UE not found [%d]", sess->sgwc_ue_id);
                        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
                    }
                }
            }
        } else {
            ogs_error("Invalid bearer id: %u", bearer_id);
            cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
        }
    }

    if (pfcp_rsp->cause.presence) {
        if (pfcp_rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_warn("PFCP Cause [%d:%s] : Not Accepted",
                    pfcp_rsp->cause.u8,
                    ogs_pfcp_cause_get_name(pfcp_rsp->cause.u8));
            if (ogs_pfcp_cause_no_association(pfcp_rsp->cause.u8) && sess)
                sgwc_pfcp_request_reassociation(sess->pfcp_node);
            cause_value = gtp_cause_from_pfcp(pfcp_rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        uint8_t pfcp_cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;
        uint8_t offending_ie_value = 0;

        sgwc_tunnel_t *tunnel = NULL;
        ogs_pfcp_pdr_t *pdr = NULL;
        ogs_pfcp_far_t *far = NULL;

        OGS_LIST(pdr_to_create_list);

        ogs_assert(sess);

        ogs_list_copy(&pdr_to_create_list, &pfcp_xact->pdr_to_create_list);

        for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
            pdr = ogs_pfcp_handle_created_pdr(
                    &sess->pfcp, &pfcp_rsp->created_pdr[i],
                    &pfcp_cause_value, &offending_ie_value);

            if (!pdr)
                break;
        }

        ogs_list_for_each_entry(&pdr_to_create_list, pdr, to_create_node) {
            far = pdr->far;
            if (!far) {
                ogs_error("No FAR for PDR");
                pfcp_cause_value = OGS_PFCP_CAUSE_SYSTEM_FAILURE;
                break;
            }

            if (pdr->src_if == OGS_PFCP_INTERFACE_CP_FUNCTION &&
                    ogs_pfcp_setup_pdr_gtpu_node(pdr) == OGS_ERROR) {
                ogs_error("ogs_pfcp_setup_pdr_gtpu_node() failed");
                pfcp_cause_value = OGS_PFCP_CAUSE_SYSTEM_FAILURE;
                break;
            }

            if (far->dst_if == OGS_PFCP_INTERFACE_CP_FUNCTION)
                ogs_pfcp_far_teid_hash_set(far);

            tunnel = sgwc_tunnel_find_by_pdr_id(sess, pdr->id);
            if (tunnel) {
                if (!sess->pfcp_node) {
                    ogs_error("No PFCP node");
                    pfcp_cause_value = OGS_PFCP_CAUSE_SYSTEM_FAILURE;
                    break;
                }
                if (sess->pfcp_node->up_function_features.ftup &&
                    pdr->f_teid_len) {
                    if (tunnel->local_addr)
                        ogs_freeaddrinfo(tunnel->local_addr);
                    if (tunnel->local_addr6)
                        ogs_freeaddrinfo(tunnel->local_addr6);

                    rv = ogs_pfcp_f_teid_to_sockaddr(
                            &pdr->f_teid, pdr->f_teid_len,
                            &tunnel->local_addr, &tunnel->local_addr6);
                    if (rv != OGS_OK) {
                        ogs_error("ogs_pfcp_f_teid_to_sockaddr() failed");
                        pfcp_cause_value = OGS_PFCP_CAUSE_SYSTEM_FAILURE;
                        break;
                    }
                    tunnel->local_teid = pdr->f_teid.teid;
                }
            }
        }

        cause_value = gtp_cause_from_pfcp(pfcp_cause_value);
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        /*
         * You should not change the following order to support
         * OGS_PFCP_MODIFY_REMOVE|OGS_PFCP_MODIFY_CREATE.
         *
         * 1. if (flags & OGS_PFCP_MODIFY_REMOVE) {
         * 2. } else if (flags & OGS_PFCP_MODIFY_CREATE) {
         *    }
         */
        if (flags & OGS_PFCP_MODIFY_REMOVE) {
            s5c_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);

            if (s5c_xact) {
                ogs_gtp_send_error_message(
                        s5c_xact, sess ? sess->pgw_s5c_teid : 0,
                        OGS_GTP2_DELETE_BEARER_RESPONSE_TYPE, cause_value);
            }

            if (bearer)
                sgwc_bearer_remove(bearer);
            else
                ogs_error("No Bearer");

        } else if (flags & OGS_PFCP_MODIFY_CREATE) {
            s5c_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);

            if (s5c_xact) {
                ogs_gtp_send_error_message(
                        s5c_xact, sess ? sess->pgw_s5c_teid : 0,
                        OGS_GTP2_CREATE_BEARER_RESPONSE_TYPE, cause_value);
            } else {
                ogs_error("GTP transaction(S5C) has already been removed [%d]",
                        pfcp_xact->assoc_xact_id);
            }


        } else if (flags & OGS_PFCP_MODIFY_ACTIVATE) {
            if (flags & OGS_PFCP_MODIFY_UL_ONLY) {
                s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);

                if (s11_xact) {
                    if (sess && sess->gn) {
                        sgwc_gn_send_create_reject(sess, sgwc_ue, s11_xact,
                                cause_value);
                    } else {
                        ogs_gtp_send_error_message(
                                s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
                                OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                                cause_value);
                    }
                } else {
                    ogs_error("GTP transaction(S11) has already been "
                            "removed [%d]", pfcp_xact->assoc_xact_id);
                }

            } else if (flags & OGS_PFCP_MODIFY_DL_ONLY) {
                s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);

                if (s11_xact) {
                    ogs_gtp_send_error_message(
                            s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
                            OGS_GTP2_MODIFY_BEARER_RESPONSE_TYPE, cause_value);
                } else {
                    ogs_error("GTP transaction(S11) has already been "
                            "removed [%d]", pfcp_xact->assoc_xact_id);
                }
            } else {
                ogs_error("Invalid modify_flags[0x%llx] on PFCP failure path",
                        (long long)flags);
            }
        } else if (flags & OGS_PFCP_MODIFY_DEACTIVATE) {
            if (flags & OGS_PFCP_MODIFY_ERROR_INDICATION) {
                /* It's faked method for receiving `bearer` context */
                bearer = sgwc_bearer_find_by_id(pfcp_xact->assoc_xact_id);
                if (!bearer) {
                    ogs_error("Bearer has already been removed [%d]",
                            pfcp_xact->assoc_xact_id);
                    ogs_pfcp_xact_commit(pfcp_xact);
                    return;
                }
                sgwc_ue = sgwc_ue_find_by_id(bearer->sgwc_ue_id);
                if (!sgwc_ue) {
                    ogs_error("No UE context");
                    ogs_pfcp_xact_commit(pfcp_xact);
                    return;
                }

                if (!(flags & OGS_PFCP_MODIFY_SESSION)) {
                    ogs_error("Missing OGS_PFCP_MODIFY_SESSION flag");
                    ogs_pfcp_xact_commit(pfcp_xact);
                    return;
                }
                if (SGWC_SESSION_SYNC_DONE(sgwc_ue,
                        OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE, flags)) {
                    if (sgwc_gtp_send_downlink_data_notification(
                            OGS_GTP2_CAUSE_ERROR_INDICATION_RECEIVED,
                            bearer) != OGS_OK)
                        ogs_error("sgwc_gtp_send_downlink_data_notification() failed");
                }
            } else {
                s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);

                if (s11_xact) {
                    ogs_gtp_send_error_message(
                            s11_xact, sgwc_ue ? sgwc_ue->mme_s11_teid : 0,
                            OGS_GTP2_RELEASE_ACCESS_BEARERS_RESPONSE_TYPE,
                            cause_value);
                } else {
                   ogs_error("No s11_xact: IMSI[%s] flags[0x%llx] "
                           "assoc_xact_id[%u]",
                           sgwc_ue ? sgwc_ue->imsi_bcd : "unknown",
                           (long long)flags, pfcp_xact->assoc_xact_id);
                }
            }
        }

        ogs_pfcp_xact_commit(pfcp_xact);
        return;
    }

    if (flags & OGS_PFCP_MODIFY_SESSION) {

        /* Nothing */

    } else {
        ogs_assert(bearer);

        dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
        ogs_assert(dl_tunnel);
        ul_tunnel = sgwc_ul_tunnel_in_bearer(bearer);
        ogs_assert(ul_tunnel);
    }

    /*
     * You should not change the following order to support
     * OGS_PFCP_MODIFY_REMOVE|OGS_PFCP_MODIFY_CREATE.
     *
     * 1. if (flags & OGS_PFCP_MODIFY_REMOVE) {
     * 2. } else if (flags & OGS_PFCP_MODIFY_CREATE) {
     *    }
     */
    if (flags & OGS_PFCP_MODIFY_REMOVE) {
        if (flags & OGS_PFCP_MODIFY_INDIRECT) {
            s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);
            if (!s11_xact) {
                ogs_error("GTP transaction(S11) has already been removed [%d]",
                        pfcp_xact->assoc_xact_id);
                ogs_pfcp_xact_commit(pfcp_xact);
                return;
            }

            ogs_pfcp_xact_commit(pfcp_xact);

            ogs_assert(flags & OGS_PFCP_MODIFY_SESSION);
            if (SGWC_SESSION_SYNC_DONE(sgwc_ue,
                OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE, flags)) {

                sgwc_tunnel_t *tunnel = NULL, *next_tunnel = NULL;
                ogs_gtp2_delete_indirect_data_forwarding_tunnel_response_t
                    *gtp_rsp = NULL;

                ogs_list_for_each(&sgwc_ue->sess_list, sess) {
                    ogs_list_for_each(&sess->bearer_list, bearer) {
                        ogs_list_for_each_safe(&bearer->tunnel_list,
                                next_tunnel, tunnel) {
                            if (tunnel->interface_type ==
                            OGS_GTP2_F_TEID_SGW_GTP_U_FOR_DL_DATA_FORWARDING ||
                                tunnel->interface_type ==
                            OGS_GTP2_F_TEID_SGW_GTP_U_FOR_UL_DATA_FORWARDING) {
                                sgwc_tunnel_remove(tunnel);
                            }
                        }
                    }
                }

                gtp_rsp = &send_message.
                    delete_indirect_data_forwarding_tunnel_response;
                ogs_assert(gtp_rsp);

                memset(&send_message, 0, sizeof(ogs_gtp2_message_t));

                memset(&cause, 0, sizeof(cause));
                cause.value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

                gtp_rsp->cause.presence = 1;
                gtp_rsp->cause.data = &cause;
                gtp_rsp->cause.len = sizeof(cause);

                send_message.h.type =
                OGS_GTP2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE_TYPE;
                send_message.h.teid = sgwc_ue->mme_s11_teid;

                pkbuf = ogs_gtp2_build_msg(&send_message);
                if (!pkbuf) {
                    ogs_error("ogs_gtp2_build_msg() failed");
                    return;
                }

                rv = ogs_gtp_xact_update_tx(s11_xact, &send_message.h, pkbuf);
                if (rv != OGS_OK) {
                    ogs_error("ogs_gtp_xact_update_tx() failed");
                    return;
                }

                rv = ogs_gtp_xact_commit(s11_xact);
                ogs_expect(rv == OGS_OK);
            }

        } else {
            s5c_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);

            ogs_pfcp_xact_commit(pfcp_xact);

            if (s5c_xact) {
                ogs_assert(recv_message);
                recv_message->h.type = OGS_GTP2_DELETE_BEARER_RESPONSE_TYPE;
                recv_message->h.teid = sess->pgw_s5c_teid;

                pkbuf = ogs_gtp2_build_msg(recv_message);
                if (!pkbuf) {
                    ogs_error("ogs_gtp2_build_msg() failed");
                    return;
                }

                rv = ogs_gtp_xact_update_tx(s5c_xact, &recv_message->h, pkbuf);
                if (rv != OGS_OK) {
                    ogs_error("ogs_gtp_xact_update_tx() failed");
                    return;
                }

                rv = ogs_gtp_xact_commit(s5c_xact);
                ogs_expect(rv == OGS_OK);
            }

            sgwc_bearer_remove(bearer);
        }

    } else if (flags & OGS_PFCP_MODIFY_CREATE) {
        if (flags & OGS_PFCP_MODIFY_UL_ONLY) {
            ogs_gtp2_create_bearer_request_t *gtp_req = NULL;
            ogs_gtp2_f_teid_t sgw_s1u_teid;

            s5c_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);
            if (!s5c_xact) {
                ogs_error("GTP transaction(S5C) has already been removed [%d]",
                        pfcp_xact->assoc_xact_id);
                ogs_pfcp_xact_commit(pfcp_xact);
                return;
            }

            ogs_pfcp_xact_commit(pfcp_xact);

            ogs_assert(recv_message);
            gtp_req = &recv_message->create_bearer_request;
            ogs_assert(gtp_req);

            /* Send Data Plane(UL) : SGW-S1U */
            memset(&sgw_s1u_teid, 0, sizeof(ogs_gtp2_f_teid_t));
            sgw_s1u_teid.interface_type = ul_tunnel->interface_type;
            sgw_s1u_teid.teid = htobe32(ul_tunnel->local_teid);
            if (!ul_tunnel->local_addr && !ul_tunnel->local_addr6) {
                ogs_error("No S1-U local F-TEID");
                return;
            }
            rv = ogs_gtp2_sockaddr_to_f_teid(
                    ul_tunnel->local_addr, ul_tunnel->local_addr6,
                    &sgw_s1u_teid, &len);
            if (rv != OGS_OK) {
                ogs_error("ogs_gtp2_sockaddr_to_f_teid() failed");
                return;
            }
            gtp_req->bearer_contexts.s1_u_enodeb_f_teid.presence = 1;
            gtp_req->bearer_contexts.s1_u_enodeb_f_teid.data = &sgw_s1u_teid;
            gtp_req->bearer_contexts.s1_u_enodeb_f_teid.len = len;

            recv_message->h.type = OGS_GTP2_CREATE_BEARER_REQUEST_TYPE;
            recv_message->h.teid = sgwc_ue->mme_s11_teid;

            pkbuf = ogs_gtp2_build_msg(recv_message);
            if (!pkbuf) {
                ogs_error("ogs_gtp2_build_msg() failed");
                return;
            }

            if (!sgwc_ue->gnode || !bearer) {
                ogs_error("Missing gnode or bearer");
                return;
            }
            s11_xact = ogs_gtp_xact_local_create(sgwc_ue->gnode,
                    &recv_message->h, pkbuf, bearer_timeout,
                    OGS_UINT_TO_POINTER(bearer->id));
            if (!s11_xact) {
                ogs_error("ogs_gtp_xact_local_create() failed");
                return;
            }
            s11_xact->local_teid = sgwc_ue->sgw_s11_teid;

            ogs_gtp_xact_associate(s5c_xact, s11_xact);

            rv = ogs_gtp_xact_commit(s11_xact);
            ogs_expect(rv == OGS_OK);

        } else if (flags & OGS_PFCP_MODIFY_DL_ONLY) {
            ogs_gtp2_create_bearer_response_t *gtp_rsp = NULL;
            ogs_gtp2_f_teid_t sgw_s5u_teid, pgw_s5u_teid;

            s5c_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);
            if (!s5c_xact) {
                ogs_error("GTP transaction(S5C) has already been removed [%d]",
                        pfcp_xact->assoc_xact_id);
                ogs_pfcp_xact_commit(pfcp_xact);
                return;
            }

            ogs_pfcp_xact_commit(pfcp_xact);

            ogs_assert(recv_message);
            gtp_rsp = &recv_message->create_bearer_response;
            ogs_assert(gtp_rsp);

            /* Remove SGW-S1U-TEID */
            gtp_rsp->bearer_contexts.s4_u_sgsn_f_teid.presence = 0;

            /* Remove S1U-F-TEID */
            gtp_rsp->bearer_contexts.s1_u_enodeb_f_teid.presence = 0;

            /* Data Plane(DL) : SGW-S5U */
            ogs_assert(dl_tunnel);
            memset(&sgw_s5u_teid, 0, sizeof(ogs_gtp2_f_teid_t));
            sgw_s5u_teid.interface_type = OGS_GTP2_F_TEID_S5_S8_SGW_GTP_U;
            sgw_s5u_teid.teid = htobe32(dl_tunnel->local_teid);
            if (!dl_tunnel->local_addr && !dl_tunnel->local_addr6) {
                ogs_error("No S5-U local F-TEID");
                ogs_gtp_send_error_message(
                        s5c_xact, sess->pgw_s5c_teid,
                        OGS_GTP2_CREATE_BEARER_RESPONSE_TYPE,
                        OGS_GTP2_CAUSE_GRE_KEY_NOT_FOUND);
                return;
            }
            rv = ogs_gtp2_sockaddr_to_f_teid(
                    dl_tunnel->local_addr, dl_tunnel->local_addr6,
                    &sgw_s5u_teid, &len);
            if (rv != OGS_OK) {
                ogs_error("ogs_gtp2_sockaddr_to_f_teid(S5U) failed");
                ogs_gtp_send_error_message(
                        s5c_xact, sess->pgw_s5c_teid,
                        OGS_GTP2_CREATE_BEARER_RESPONSE_TYPE,
                        OGS_GTP2_CAUSE_SYSTEM_FAILURE);
                return;
            }
            gtp_rsp->bearer_contexts.s5_s8_u_sgw_f_teid.presence = 1;
            gtp_rsp->bearer_contexts.s5_s8_u_sgw_f_teid.data = &sgw_s5u_teid;
            gtp_rsp->bearer_contexts.s5_s8_u_sgw_f_teid.len = len;

            /* Data Plane(UL) : PGW-S5U */
            ogs_assert(ul_tunnel);
            pgw_s5u_teid.interface_type = OGS_GTP2_F_TEID_S5_S8_PGW_GTP_U;
            pgw_s5u_teid.teid = htobe32(ul_tunnel->remote_teid);
            rv = ogs_gtp2_ip_to_f_teid(
                    &ul_tunnel->remote_ip, &pgw_s5u_teid, &len);
            /* Clang scan-build SA: Value stored is not used: add ogs_assert(). */
            if (rv != OGS_OK) {
                ogs_error("ogs_gtp2_ip_to_f_teid() failed");
                return;
            }
            gtp_rsp->bearer_contexts.s5_s8_u_pgw_f_teid.presence = 1;
            gtp_rsp->bearer_contexts.s5_s8_u_pgw_f_teid.data = &pgw_s5u_teid;
            gtp_rsp->bearer_contexts.s5_s8_u_pgw_f_teid.len = len;

            recv_message->h.type = OGS_GTP2_CREATE_BEARER_RESPONSE_TYPE;
            recv_message->h.teid = sess->pgw_s5c_teid;

            pkbuf = ogs_gtp2_build_msg(recv_message);
            if (!pkbuf) {
                ogs_error("ogs_gtp2_build_msg() failed");
                return;
            }

            rv = ogs_gtp_xact_update_tx(s5c_xact, &recv_message->h, pkbuf);
            if (rv != OGS_OK) {
                ogs_error("ogs_gtp_xact_update_tx() failed");
                return;
            }

            rv = ogs_gtp_xact_commit(s5c_xact);
            ogs_expect(rv == OGS_OK);

        } else if (flags & OGS_PFCP_MODIFY_INDIRECT) {
            s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);
            if (!s11_xact) {
                ogs_error("GTP transaction(S11) has already been removed [%d]",
                        pfcp_xact->assoc_xact_id);
                ogs_pfcp_xact_commit(pfcp_xact);
                return;
            }

            ogs_pfcp_xact_commit(pfcp_xact);

            ogs_assert(flags & OGS_PFCP_MODIFY_SESSION);
            if (SGWC_SESSION_SYNC_DONE(sgwc_ue,
                OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE, flags)) {

                sgwc_tunnel_t *tunnel = NULL;

                ogs_gtp2_create_indirect_data_forwarding_tunnel_request_t
                    *gtp_req = NULL;
                ogs_gtp2_create_indirect_data_forwarding_tunnel_response_t
                    *gtp_rsp = NULL;

                ogs_gtp2_f_teid_t rsp_dl_teid[OGS_GTP2_MAX_INDIRECT_TUNNEL];
                ogs_gtp2_f_teid_t rsp_ul_teid[OGS_GTP2_MAX_INDIRECT_TUNNEL];

                ogs_assert(recv_message);
                gtp_req = &recv_message->
                    create_indirect_data_forwarding_tunnel_request;
                ogs_assert(gtp_req);
                gtp_rsp = &send_message.
                    create_indirect_data_forwarding_tunnel_response;
                ogs_assert(gtp_rsp);

                memset(&send_message, 0, sizeof(ogs_gtp2_message_t));

                memset(&cause, 0, sizeof(cause));
                cause.value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

                gtp_rsp->cause.presence = 1;
                gtp_rsp->cause.data = &cause;
                gtp_rsp->cause.len = sizeof(cause);

                for (i = 0; gtp_req->bearer_contexts[i].presence; i++) {
                    ogs_assert(gtp_req->
                            bearer_contexts[i].eps_bearer_id.presence);
                    bearer = sgwc_bearer_find_by_ue_ebi(sgwc_ue,
                                gtp_req->bearer_contexts[i].eps_bearer_id.u8);
                    ogs_assert(bearer);

                    ogs_list_for_each(&bearer->tunnel_list, tunnel) {
                        if (tunnel->interface_type ==
                            OGS_GTP2_F_TEID_SGW_GTP_U_FOR_DL_DATA_FORWARDING) {

                            if (!tunnel->local_addr && !tunnel->local_addr6) {
                                ogs_error("No local F-TEID for DL indirect "
                                        "forwarding tunnel [EBI:%d]",
                                        bearer->ebi);
                                cause.value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;
                                goto indirect_fail;
                            }

                            memset(&rsp_dl_teid[i],
                                    0, sizeof(ogs_gtp2_f_teid_t));
                            rsp_dl_teid[i].interface_type =
                                tunnel->interface_type;
                            rsp_dl_teid[i].teid = htobe32(tunnel->local_teid);
                            rv = ogs_gtp2_sockaddr_to_f_teid(
                                tunnel->local_addr, tunnel->local_addr6,
                                &rsp_dl_teid[i], &len);
                            if (rv != OGS_OK) {
                                ogs_error("ogs_gtp2_sockaddr_to_f_teid(DL "
                                        "indirect) failed [EBI:%d]",
                                        bearer->ebi);
                                cause.value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;
                                goto indirect_fail;
                            }
                            gtp_rsp->bearer_contexts[i].
                                s4_u_sgsn_f_teid.presence = 1;
                            gtp_rsp->bearer_contexts[i].
                                s4_u_sgsn_f_teid.data = &rsp_dl_teid[i];
                            gtp_rsp->bearer_contexts[i].
                                s4_u_sgsn_f_teid.len = len;

                        } else if (tunnel->interface_type ==
                            OGS_GTP2_F_TEID_SGW_GTP_U_FOR_UL_DATA_FORWARDING) {

                            if (!tunnel->local_addr && !tunnel->local_addr6) {
                                ogs_error("No local F-TEID for UL indirect "
                                        "forwarding tunnel [EBI:%d]",
                                        bearer->ebi);
                                cause.value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;
                                goto indirect_fail;
                            }

                            memset(&rsp_ul_teid[i],
                                0, sizeof(ogs_gtp2_f_teid_t));
                            rsp_ul_teid[i].teid = htobe32(tunnel->local_teid);
                            rsp_ul_teid[i].interface_type =
                                tunnel->interface_type;
                            rv = ogs_gtp2_sockaddr_to_f_teid(
                                tunnel->local_addr, tunnel->local_addr6,
                                &rsp_ul_teid[i], &len);
                            if (rv != OGS_OK) {
                                ogs_error("ogs_gtp2_sockaddr_to_f_teid(UL "
                                        "indirect) failed [EBI:%d]",
                                        bearer->ebi);
                                cause.value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;
                                goto indirect_fail;
                            }
                            gtp_rsp->bearer_contexts[i].
                                s2b_u_epdg_f_teid_5.presence = 1;
                            gtp_rsp->bearer_contexts[i].
                                s2b_u_epdg_f_teid_5.data = &rsp_ul_teid[i];
                            gtp_rsp->bearer_contexts[i].
                                s2b_u_epdg_f_teid_5.len = len;

                        }

                    }

                    if (gtp_rsp->bearer_contexts[i].
                            s4_u_sgsn_f_teid.presence ||
                        gtp_rsp->bearer_contexts[i].
                            s2b_u_epdg_f_teid_5.presence) {

                        gtp_rsp->bearer_contexts[i].presence = 1;
                        gtp_rsp->bearer_contexts[i].eps_bearer_id.presence = 1;
                        gtp_rsp->bearer_contexts[i].eps_bearer_id.u8 =
                            bearer->ebi;

                        gtp_rsp->bearer_contexts[i].cause.presence = 1;
                        gtp_rsp->bearer_contexts[i].cause.data = &cause;
                        gtp_rsp->bearer_contexts[i].cause.len = sizeof(cause);
                    }
                }

indirect_fail:
                if (cause.value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
                    ogs_gtp_send_error_message(
                            s11_xact, sgwc_ue->mme_s11_teid,
                            OGS_GTP2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE_TYPE,
                            cause.value);
                    return;
                }

                send_message.h.type =
                OGS_GTP2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE_TYPE;
                send_message.h.teid = sgwc_ue->mme_s11_teid;

                pkbuf = ogs_gtp2_build_msg(&send_message);
                if (!pkbuf) {
                    ogs_error("ogs_gtp2_build_msg() failed");
                    return;
                }

                rv = ogs_gtp_xact_update_tx(s11_xact, &send_message.h, pkbuf);
                if (rv != OGS_OK) {
                    ogs_error("ogs_gtp_xact_update_tx() failed");
                    return;
                }

                rv = ogs_gtp_xact_commit(s11_xact);
                ogs_expect(rv == OGS_OK);
            }
        } else {
            ogs_error("Invalid modify_flags[0x%llx]", (long long)flags);
            ogs_pfcp_xact_commit(pfcp_xact);
            return;
        }

    } else if (flags & OGS_PFCP_MODIFY_ACTIVATE) {
        OGS_LIST(bearer_to_modify_list);

        s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);
        if (!s11_xact) {
            if (sess && sess->gn && (flags & OGS_PFCP_MODIFY_DL_ONLY)) {
                ogs_pfcp_xact_commit(pfcp_xact);
                return;
            }
            ogs_error("GTP transaction(S11) has already been removed [%d]",
                    pfcp_xact->assoc_xact_id);
            ogs_pfcp_xact_commit(pfcp_xact);
            return;
        }

        ogs_list_copy(&bearer_to_modify_list,
                &pfcp_xact->bearer_to_modify_list);

        ogs_pfcp_xact_commit(pfcp_xact);

        ogs_assert(flags & OGS_PFCP_MODIFY_SESSION);
        if (flags & OGS_PFCP_MODIFY_UL_ONLY) {
            ogs_gtp2_create_session_response_t *gtp_rsp = NULL;
            ogs_gtp2_f_teid_t sgw_s11_teid;
            ogs_gtp2_f_teid_t sgw_s1u_teid[OGS_BEARER_PER_UE];
            int sgw_s1u_len[OGS_BEARER_PER_UE];

            ogs_assert(recv_message);
            gtp_rsp = &recv_message->create_session_response;
            ogs_assert(gtp_rsp);

            /* Send Control Plane(UL) : SGW-S11 */
            memset(&sgw_s11_teid, 0, sizeof(ogs_gtp2_f_teid_t));
            sgw_s11_teid.interface_type = OGS_GTP2_F_TEID_S11_S4_SGW_GTP_C;
            sgw_s11_teid.teid = htobe32(sgwc_ue->sgw_s11_teid);
            rv = ogs_gtp2_sockaddr_to_f_teid(
                    ogs_gtp_self()->gtpc_addr, ogs_gtp_self()->gtpc_addr6,
                    &sgw_s11_teid, &len);
            if (rv != OGS_OK) {
                ogs_error("ogs_gtp2_sockaddr_to_f_teid(S11) failed");
                sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                        OGS_GTP2_CAUSE_SYSTEM_FAILURE);
                return;
            }
            gtp_rsp->sender_f_teid_for_control_plane.presence = 1;
            gtp_rsp->sender_f_teid_for_control_plane.data = &sgw_s11_teid;
            gtp_rsp->sender_f_teid_for_control_plane.len = len;

            /* Send Data Plane(UL) : SGW-S1U */
            i = 0;
            ogs_list_for_each_entry(
                    &bearer_to_modify_list, bearer, to_modify_node) {
                if (i >= OGS_BEARER_PER_UE) {
                    ogs_error("Too many bearers");
                    break;
                }

                ul_tunnel = sgwc_ul_tunnel_in_bearer(bearer);
                if (!ul_tunnel) {
                    ogs_error("No UL tunnel");
                    sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                            OGS_GTP2_CAUSE_SYSTEM_FAILURE);
                    return;
                }

                memset(&sgw_s1u_teid[i], 0, sizeof(ogs_gtp2_f_teid_t));
                sgw_s1u_teid[i].interface_type = ul_tunnel->interface_type;
                sgw_s1u_teid[i].teid = htobe32(ul_tunnel->local_teid);
                if (!ul_tunnel->local_addr && !ul_tunnel->local_addr6) {
                    ogs_error("No S1-U local F-TEID");
                    sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                            OGS_GTP2_CAUSE_GRE_KEY_NOT_FOUND);
                    return;
                }
                rv = ogs_gtp2_sockaddr_to_f_teid(
                    ul_tunnel->local_addr, ul_tunnel->local_addr6,
                    &sgw_s1u_teid[i], &sgw_s1u_len[i]);
                if (rv != OGS_OK) {
                    ogs_error("ogs_gtp2_sockaddr_to_f_teid(S1U) failed");
                    sgwc_gtp_create_reject(sess, sgwc_ue, s11_xact,
                            OGS_GTP2_CAUSE_SYSTEM_FAILURE);
                    return;
                }
                gtp_rsp->bearer_contexts_created[i].s1_u_enodeb_f_teid.
                    presence = 1;
                gtp_rsp->bearer_contexts_created[i].s1_u_enodeb_f_teid.
                    data = &sgw_s1u_teid[i];
                gtp_rsp->bearer_contexts_created[i].s1_u_enodeb_f_teid.
                    len = sgw_s1u_len[i];

                i++;
            }

            recv_message->h.type = OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE;
            recv_message->h.teid = sgwc_ue->mme_s11_teid;

            if (sess->gn) {
                rv = sgwc_gtp_send_create_pdp_context_response(
                        sess, s11_xact, gtp_rsp);
                ogs_expect(rv == OGS_OK);
                sgwc_ue_info(sgwc_ue, sess, "sxa", NULL,
                        "Create PDP Context Response sent to SGSN");
                sgwc_create_session_phase(sess, sgwc_ue, "gn-rsp-sent");
                return;
            }

            pkbuf = ogs_gtp2_build_msg(recv_message);
            if (!pkbuf) {
                ogs_error("ogs_gtp2_build_msg() failed");
                return;
            }

            rv = ogs_gtp_xact_update_tx(s11_xact, &recv_message->h, pkbuf);
            if (rv != OGS_OK) {
                ogs_error("ogs_gtp_xact_update_tx() failed");
                return;
            }

            rv = ogs_gtp_xact_commit(s11_xact);
            ogs_expect(rv == OGS_OK);

            sgwc_ue_info(sgwc_ue, sess, "sxa", NULL,
                    "Create Session Response sent to MME");
            sgwc_create_session_phase(sess, sgwc_ue, "s11-rsp-sent");

        } else if (flags & OGS_PFCP_MODIFY_DL_ONLY) {
            if (SGWC_SESSION_SYNC_DONE(sgwc_ue,
                    OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE, flags)) {
                ogs_gtp2_modify_bearer_request_t *gtp_req = NULL;
                ogs_gtp2_modify_bearer_response_t *gtp_rsp = NULL;

                ogs_gtp2_indication_t *indication = NULL;

                ogs_assert(recv_message);
                gtp_req = &recv_message->modify_bearer_request;
                ogs_assert(gtp_req);

                if (gtp_req->indication_flags.presence &&
                    gtp_req->indication_flags.data &&
                    gtp_req->indication_flags.len) {
                    indication = gtp_req->indication_flags.data;
                }

                if (indication && indication->handover_indication) {
                    recv_message->h.type = OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE;
                    recv_message->h.teid = sess->pgw_s5c_teid;

                    pkbuf = ogs_gtp2_build_msg(recv_message);
                    if (!pkbuf) {
                        ogs_error("ogs_gtp2_build_msg() failed");
                        return;
                    }

                    ogs_assert(sess->gnode);
                    s5c_xact = ogs_gtp_xact_local_create(
                            sess->gnode, &recv_message->h, pkbuf,
                            sess_timeout, OGS_UINT_TO_POINTER(sess->id));
                    if (!s5c_xact) {
                        ogs_error("ogs_gtp_xact_local_create() failed");
                        return;
                    }
                    s5c_xact->local_teid = sess->sgw_s5c_teid;

                    ogs_gtp_xact_associate(s11_xact, s5c_xact);

                    rv = ogs_gtp_xact_commit(s5c_xact);
                    ogs_expect(rv == OGS_OK);

                } else {
                    gtp_rsp = &send_message.modify_bearer_response;
                    ogs_assert(gtp_rsp);

                    memset(&send_message, 0, sizeof(ogs_gtp2_message_t));

                    memset(&cause, 0, sizeof(cause));
                    cause.value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

                    gtp_rsp->cause.presence = 1;
                    gtp_rsp->cause.data = &cause;
                    gtp_rsp->cause.len = sizeof(cause);

        /* Copy Bearer-Contexts-Modified from Modify-Bearer-Request
         *
         * TS 29.274 Table 7.2.8-2
         * NOTE 1: The SGW shall not change its F-TEID for a given interface
         * during the Handover, Service Request, E-UTRAN Initial Attach,
         * UE Requested PDN connectivity and PDP Context Activation procedures.
         * The SGW F-TEID shall be same for S1-U, S4-U and S12. During Handover
         * and Service Request the target eNodeB/RNC/SGSN may use a different
         * IP type than the one used by the source eNodeB/RNC/SGSN.
         * In order to support such a scenario, the SGW F-TEID should contain
         * both an IPv4 address and an IPv6 address
         * (see also subclause 8.22 "F-TEID").
         */
                    for (i = 0; i < OGS_BEARER_PER_UE; i++) {
                        if (gtp_req->bearer_contexts_to_be_modified[i].
                            presence == 0)
                            break;
                        if (gtp_req->bearer_contexts_to_be_modified[i].
                            eps_bearer_id.presence == 0)
                            break;
                        if (gtp_req->bearer_contexts_to_be_modified[i].
                            s1_u_enodeb_f_teid.presence == 0)
                            break;

                        gtp_rsp->bearer_contexts_modified[i].presence = 1;
                        gtp_rsp->bearer_contexts_modified[i].eps_bearer_id.
                            presence = 1;
                        gtp_rsp->bearer_contexts_modified[i].eps_bearer_id.u8 =
                            gtp_req->bearer_contexts_to_be_modified[i].
                                eps_bearer_id.u8;
                        gtp_rsp->bearer_contexts_modified[i].
                                s1_u_enodeb_f_teid.presence = 1;
                        gtp_rsp->bearer_contexts_modified[i].
                            s1_u_enodeb_f_teid.data =
                                gtp_req->bearer_contexts_to_be_modified[i].
                                    s1_u_enodeb_f_teid.data;
                        gtp_rsp->bearer_contexts_modified[i].
                            s1_u_enodeb_f_teid.len =
                                gtp_req->bearer_contexts_to_be_modified[i].
                                    s1_u_enodeb_f_teid.len;

                        gtp_rsp->bearer_contexts_modified[i].cause.presence = 1;
                        gtp_rsp->bearer_contexts_modified[i].cause.len =
                            sizeof(cause);
                        gtp_rsp->bearer_contexts_modified[i].cause.data =
                            &cause;
                    }

                    send_message.h.type = OGS_GTP2_MODIFY_BEARER_RESPONSE_TYPE;
                    send_message.h.teid = sgwc_ue->mme_s11_teid;

                    pkbuf = ogs_gtp2_build_msg(&send_message);
                    if (!pkbuf) {
                        ogs_error("ogs_gtp2_build_msg() failed");
                        return;
                    }

                    rv = ogs_gtp_xact_update_tx(
                            s11_xact, &send_message.h, pkbuf);
                    if (rv != OGS_OK) {
                        ogs_error("ogs_gtp_xact_update_tx() failed");
                        return;
                    }

                    rv = ogs_gtp_xact_commit(s11_xact);
                    ogs_expect(rv == OGS_OK);
                }
            }
        } else {
            ogs_error("Invalid modify_flags[0x%llx]", (long long)flags);
            return;
        }
    } else if (flags & OGS_PFCP_MODIFY_DEACTIVATE) {
        if (flags & OGS_PFCP_MODIFY_ERROR_INDICATION) {
            /* It's faked method for receiving `bearer` context */
            bearer = sgwc_bearer_find_by_id(pfcp_xact->assoc_xact_id);
            if (!bearer) {
                ogs_error("Bearer has already been removed [%d]",
                        pfcp_xact->assoc_xact_id);
                return;
            }

            ogs_pfcp_xact_commit(pfcp_xact);

            if (!(flags & OGS_PFCP_MODIFY_SESSION)) {
                ogs_error("Missing OGS_PFCP_MODIFY_SESSION flag");
                return;
            }
            if (SGWC_SESSION_SYNC_DONE(sgwc_ue,
                    OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE, flags)) {
                if (sgwc_gtp_send_downlink_data_notification(
                        OGS_GTP2_CAUSE_ERROR_INDICATION_RECEIVED,
                        bearer) != OGS_OK)
                    ogs_error("sgwc_gtp_send_downlink_data_notification() failed");
            }

        } else {
            s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);
            if (!s11_xact)
                ogs_error("GTP xact has already been removed [%d]",
                        pfcp_xact->assoc_xact_id);

            ogs_pfcp_xact_commit(pfcp_xact);

            if (!(flags & OGS_PFCP_MODIFY_SESSION)) {
                ogs_error("Missing OGS_PFCP_MODIFY_SESSION flag");
                return;
            }
            if (s11_xact && SGWC_SESSION_SYNC_DONE(sgwc_ue,
                    OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE, flags)) {

                ogs_gtp2_release_access_bearers_response_t *gtp_rsp = NULL;

                gtp_rsp = &send_message.release_access_bearers_response;
                if (!gtp_rsp) {
                    ogs_error("No GTP response buffer");
                    return;
                }

                memset(&send_message, 0, sizeof(ogs_gtp2_message_t));

                memset(&cause, 0, sizeof(cause));
                cause.value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

                gtp_rsp->cause.presence = 1;
                gtp_rsp->cause.data = &cause;
                gtp_rsp->cause.len = sizeof(cause);

                send_message.h.type =
                    OGS_GTP2_RELEASE_ACCESS_BEARERS_RESPONSE_TYPE;
                send_message.h.teid = sgwc_ue->mme_s11_teid;

                pkbuf = ogs_gtp2_build_msg(&send_message);
                if (!pkbuf) {
                    ogs_error("ogs_gtp2_build_msg() failed");
                    return;
                }

                rv = ogs_gtp_xact_update_tx(s11_xact, &send_message.h, pkbuf);
                if (rv != OGS_OK) {
                    ogs_error("ogs_gtp_xact_update_tx() failed");
                    return;
                }

                rv = ogs_gtp_xact_commit(s11_xact);
                ogs_expect(rv == OGS_OK);
            }
        }
    } else {
        ogs_error("Invalid modify_flags[0x%llx]", (long long)flags);
        return;
    }
}

void sgwc_sxa_handle_session_deletion_response(
        sgwc_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_gtp2_message_t *gtp_message,
        ogs_pfcp_session_deletion_response_t *pfcp_rsp)
{
    int rv;
    uint8_t cause_value = 0;
    uint32_t teid = 0;

    sgwc_ue_t *sgwc_ue = NULL;

    ogs_gtp_xact_t *gtp_xact = NULL;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_info("Session Deletion Response");

    ogs_assert(pfcp_xact);
    ogs_assert(pfcp_rsp);

    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_error("No Context");
        cause_value = OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (pfcp_rsp->cause.presence) {
        if (pfcp_rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_warn("PFCP Cause[%d] : Not Accepted", pfcp_rsp->cause.u8);
            cause_value = gtp_cause_from_pfcp(pfcp_rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }

    gtp_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);

    ogs_pfcp_xact_commit(pfcp_xact);

    if (!gtp_message) {
        sgwc_ue_t *sgwc_ue = NULL;
        bool proceed = false;

        if (sess)
            sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);

        if (sgwc_ue && sess &&
                sgwc_ue->csr_replace_sess_id == sess->id) {
            if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
                proceed = true;
            else if (pfcp_rsp->cause.presence &&
                    pfcp_rsp->cause.u8 ==
                        OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND)
                proceed = true;

            if (sess->gn)
                sgwc_gn_csr_replace_continue(sgwc_ue, sess, proceed);
            else
                sgwc_csr_replace_continue(sgwc_ue, sess, proceed);
            return;
        }
        goto cleanup;
    }

    if (gtp_message->h.type == OGS_GTP2_DELETE_SESSION_REQUEST_TYPE) {
        /*
         * X2-based Handover with SGW change
         * 1. MME sends Delete Session Request to SGW-C
         * 2. SGW-C sends Delete Session Response to MME.
         */
        gtp_message->h.type = OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE;
    }

    switch (gtp_message->h.type) {
    case OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE:
        /*
         * 1. MME sends Delete Session Request to SGW/SMF.
         * 2. SMF sends Delete Session Response to SGW/MME.
         */
        if (sess) sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        teid = sgwc_ue ? sgwc_ue->mme_s11_teid : 0;
        break;
    case OGS_GTP2_DELETE_BEARER_RESPONSE_TYPE:
        /*
         * 1. SMF sends Delete Bearer Request(DEFAULT BEARER) to SGW/MME.
         * 2. MME sends Delete Bearer Response to SGW/SMF.
         *
         * OR
         *
         * 1. SMF sends Delete Bearer Request(DEFAULT BEARER) to ePDG.
         * 2. ePDG sends Delete Bearer Response(DEFAULT BEARER) to SMF.
         *
         * Note that the following messages are not processed here.
         * - Bearer Resource Command
         * - Delete Bearer Request/Response with DEDICATED BEARER.
         */
        teid = sess ? sess->pgw_s5c_teid : 0;
        break;
    default:
        ogs_error("Unknown GTP message type [%d]", gtp_message->h.type);
        return;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        if (gtp_xact) {
            ogs_gtp_send_error_message(
                    gtp_xact, teid, gtp_message->h.type, cause_value);
        }
        return;
    }

    ogs_assert(sess);

    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);

    /* Final usage report on session deletion (interval deltas). */
    {
        unsigned int ui;
        sgwc_bearer_t *bearer = NULL;

        for (ui = 0; ui < OGS_ARRAY_SIZE(pfcp_rsp->usage_report); ui++) {
            ogs_pfcp_tlv_usage_report_session_deletion_response_t *use_rep =
                &pfcp_rsp->usage_report[ui];
            uint32_t urr_id;
            int16_t decoded;
            ogs_pfcp_volume_measurement_t volume;

            if (use_rep->presence == 0)
                break;
            if (use_rep->urr_id.presence == 0)
                continue;

            urr_id = use_rep->urr_id.u32;
            ogs_list_for_each(&sess->bearer_list, bearer) {
                if (bearer->urr && bearer->urr->id == urr_id)
                    break;
            }
            if (!bearer || !bearer->urr || bearer->urr->id != urr_id)
                continue;

            decoded = ogs_pfcp_parse_volume_measurement(
                    &volume, &use_rep->volume_measurement);
            if (use_rep->volume_measurement.len != decoded)
                continue;

            sgwc_log_urr_report("final", sgwc_ue, sess, urr_id, &volume,
                    use_rep->duration_measurement.presence ?
                        use_rep->duration_measurement.u32 : 0,
                    &use_rep->usage_report_trigger);

            sgwc_sess_usage_accumulate(sess,
                    volume.ulvol ? volume.uplink_volume : 0,
                    volume.dlvol ? volume.downlink_volume : 0,
                    use_rep->duration_measurement.presence ?
                        use_rep->duration_measurement.u32 : 0);
        }
    }

    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);

    if (gtp_xact) {
        if (sess && sess->gn &&
                gtp_message->h.type == OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE) {
            rv = sgwc_gtp_send_delete_pdp_context_response(
                    sess, gtp_xact, OGS_GTP1_CAUSE_REQUEST_ACCEPTED);
            ogs_expect(rv == OGS_OK);
        } else {
        /*
         * If gtp_message->h.type == OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE
         * Then gtp_xact is S11-XACT
         *
         * If gtp_message->h.type == OGS_GTP2_DELETE_BEARER_RESPONSE_TYPE
         * Then gtp_xact is S5C-XACT
         */
        gtp_message->h.teid = teid;

        pkbuf = ogs_gtp2_build_msg(gtp_message);
        if (!pkbuf) {
            ogs_error("ogs_gtp2_build_msg() failed");
            return;
        }

        rv = ogs_gtp_xact_update_tx(gtp_xact, &gtp_message->h, pkbuf);
        if (rv != OGS_OK) {
            ogs_error("ogs_gtp_xact_update_tx() failed");
            return;
        }

        rv = ogs_gtp_xact_commit(gtp_xact);
        ogs_expect(rv == OGS_OK);
        }
    }

cleanup:
    if (sess) {
        sgwc_ue_t *owner_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);

        sess->sgwu_sxa_seid = 0;
        sgwc_sess_remove(sess);

        /* Release the UE context once its last PDN connection is gone. */
        sgwc_ue_remove_if_empty(owner_ue);
    } else
        ogs_error("No Session");
}

void sgwc_sxa_handle_session_report_request(
        sgwc_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_pfcp_session_report_request_t *pfcp_req)
{
    sgwc_ue_t *sgwc_ue = NULL;
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *tunnel = NULL;
    ogs_pfcp_far_t *far = NULL;

    ogs_pfcp_report_type_t report_type;
    uint8_t cause_value = 0;
    uint16_t pdr_id = 0;

    ogs_debug("Session Report Request");

    ogs_assert(pfcp_xact);
    ogs_assert(pfcp_req);

    cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    /************************
     * Check Session Context
     *
     * - Session could be deleted before a message is received from SMF.
     ************************/
    if (!sess) {
        ogs_error("No Context");
        cause_value = OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
    }

    if (pfcp_req->report_type.presence == 0) {
        ogs_error("No Report Type");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_pfcp_send_error_message(pfcp_xact, 0,
                OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE,
                cause_value, 0);
        return;
    }

    if (!sess) {
        ogs_error("No session context");
        ogs_pfcp_send_error_message(pfcp_xact, 0,
                OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    if (!sgwc_ue) {
        ogs_error("No UE context");
        ogs_pfcp_send_error_message(pfcp_xact, sess->sgwu_sxa_seid,
                OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    if (!sgwc_ue->gnode) {
        ogs_error("No SGWC-UE GTP Node");
        ogs_pfcp_send_error_message(pfcp_xact, sess ? sess->sgwu_sxa_seid : 0,
                OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    if (sgwc_pfcp_send_session_report_response(
            pfcp_xact, sess, OGS_PFCP_CAUSE_REQUEST_ACCEPTED) != OGS_OK) {
        ogs_error("sgwc_pfcp_send_session_report_response() failed");
        return;
    }

    report_type.value = pfcp_req->report_type.u8;

    if (report_type.downlink_data_report) {
        if (pfcp_req->downlink_data_report.presence == 0) {
            ogs_error("No Downlink Data Report");
            return;
        }

        if (pfcp_req->downlink_data_report.pdr_id.presence == 0) {
            ogs_error("No PDR-ID");
            return;
        }

        pdr_id = pfcp_req->downlink_data_report.pdr_id.u16;

        ogs_list_for_each(&sess->bearer_list, bearer) {
            ogs_list_for_each(&bearer->tunnel_list, tunnel) {
                if (!tunnel || !tunnel->pdr)
                    continue;
                if (tunnel->pdr->id == pdr_id) {
                    if (sgwc_gtp_send_downlink_data_notification(
                            OGS_GTP2_CAUSE_UNDEFINED_VALUE, bearer) != OGS_OK)
                        ogs_error("sgwc_gtp_send_downlink_data_notification() failed");
                    return;
                }
            }
        }

        ogs_error("Cannot find the PDR-ID[%d]", pdr_id);

    } else if (report_type.error_indication_report) {
        far = ogs_pfcp_far_find_by_pfcp_session_report(
                &sess->pfcp, &pfcp_req->error_indication_report);
        if (far) {
            tunnel = sgwc_tunnel_find_by_far_id(sess, far->id);
            if (!tunnel) {
                ogs_error("No tunnel for FAR");
                return;
            }
            bearer = sgwc_bearer_find_by_id(tunnel->bearer_id);
            if (!bearer) {
                ogs_error("No bearer for tunnel");
                return;
            }
            if (far->dst_if == OGS_PFCP_INTERFACE_ACCESS) {
                ogs_warn("[%s] Error Indication from eNB", sgwc_ue->imsi_bcd);
                ogs_list_for_each(&sgwc_ue->sess_list, sess) {
                    if (ogs_list_count(&sess->bearer_list) == 0)
                        continue;
                    ogs_debug("    sess_id=%d", sess->id);
                    if (sgwc_pfcp_send_session_modification_request(sess,
                    /* We only use the `assoc_xact` parameter temporarily here
                     * to pass the `bearer` context. */
                            bearer->id,
                            NULL,
                            OGS_PFCP_MODIFY_DL_ONLY|OGS_PFCP_MODIFY_DEACTIVATE|
                            OGS_PFCP_MODIFY_ERROR_INDICATION) != OGS_OK)
                        ogs_error("sgwc_pfcp_send_session_modification_request() failed");
                }
            } else if (far->dst_if == OGS_PFCP_INTERFACE_CORE) {
                if (sgwc_default_bearer_in_sess(sess) == bearer) {
                    ogs_error("[%s] Error Indication(Default Bearer) from SMF",
                                sgwc_ue->imsi_bcd);
                    if (sgwc_pfcp_send_session_deletion_request(
                            sess, OGS_INVALID_POOL_ID, NULL) != OGS_OK)
                        ogs_error("sgwc_pfcp_send_session_deletion_request() failed");
                } else {
                    ogs_error("[%s] Error Indication(Dedicated Bearer) "
                            "from SMF", sgwc_ue->imsi_bcd);
                    ogs_debug("    bearer[EBI=%d]", bearer->ebi);
                    if (sgwc_pfcp_send_bearer_modification_request(
                            bearer, OGS_INVALID_POOL_ID, NULL,
                            OGS_PFCP_MODIFY_REMOVE) != OGS_OK)
                        ogs_error("sgwc_pfcp_send_bearer_modification_request() failed");
                }
            } else {
                ogs_error("Error Indication Ignored for Indirect Tunnel");
            }
        } else
            ogs_error("Cannot find Session in Error Indication");

    } else if (report_type.usage_report) {
        unsigned int i;
        uint32_t interval_duration_s = 0;

        for (i = 0; i < OGS_ARRAY_SIZE(pfcp_req->usage_report); i++) {
            ogs_pfcp_tlv_usage_report_session_report_request_t *use_rep =
                &pfcp_req->usage_report[i];
            uint32_t urr_id;
            sgwc_bearer_t *bearer = NULL;
            int16_t decoded;
            ogs_pfcp_volume_measurement_t volume;

            if (use_rep->presence == 0)
                break;
            if (use_rep->urr_id.presence == 0)
                continue;

            urr_id = use_rep->urr_id.u32;
            ogs_list_for_each(&sess->bearer_list, bearer) {
                if (bearer->urr && bearer->urr->id == urr_id)
                    break;
            }
            if (!bearer || !bearer->urr || bearer->urr->id != urr_id)
                continue;

            decoded = ogs_pfcp_parse_volume_measurement(
                    &volume, &use_rep->volume_measurement);
            if (use_rep->volume_measurement.len != decoded) {
                ogs_error("Invalid Volume Measurement");
                continue;
            }

            sgwc_log_urr_report("interim", sgwc_ue, sess, urr_id, &volume,
                    use_rep->duration_measurement.presence ?
                        use_rep->duration_measurement.u32 : 0,
                    &use_rep->usage_report_trigger);

            sgwc_sess_usage_accumulate(sess,
                    volume.ulvol ? volume.uplink_volume : 0,
                    volume.dlvol ? volume.downlink_volume : 0,
                    use_rep->duration_measurement.presence ?
                        use_rep->duration_measurement.u32 : 0);

            if (use_rep->duration_measurement.presence)
                interval_duration_s = use_rep->duration_measurement.u32;
        }

        sgwc_ga_cdr_session_interim(sess, interval_duration_s);

    } else if (report_type.user_plane_inactivity_report) {
        bearer = sgwc_default_bearer_in_sess(sess);
        if (!bearer) {
            ogs_warn("[%s] User-plane inactivity: no default bearer",
                    sgwc_ue->imsi_bcd);
            return;
        }

        ogs_warn("[%s] User-plane inactivity reported by UPF",
                sgwc_ue->imsi_bcd);

        if (ogs_list_count(&sess->bearer_list) > 0) {
            if (sgwc_pfcp_send_session_modification_request(sess,
                    OGS_INVALID_POOL_ID, NULL,
                    OGS_PFCP_MODIFY_DL_ONLY|OGS_PFCP_MODIFY_DEACTIVATE) !=
                    OGS_OK)
                ogs_error("sgwc_pfcp_send_session_modification_request() "
                        "failed");
        }

        if (sgwc_gtp_send_downlink_data_notification(
                OGS_GTP2_CAUSE_PDN_CONNECTION_INACTIVITY_TIMER_EXPIRES,
                bearer) != OGS_OK)
            ogs_error("sgwc_gtp_send_downlink_data_notification() failed");

    } else {
        ogs_error("Not supported Report Type[%d]", report_type.value);
    }
}
