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

#include "context.h"
#include "event.h"
#include "gtp-path.h"
#include "pfcp-path.h"
#include "n4-build.h"
#include "smf-trace.h"
#include "s11-relay.h"

/* The UPF allocates independent F-TEIDs for the access side (UL PDR,
 * DEFAULT_CHOOSE_ID) and the core side (DL PDR): a distinct CHOOSE ID
 * keeps the two allocations separate. */
#define SMF_S11_RELAY_CORE_CHOOSE_ID (OGS_PFCP_DEFAULT_CHOOSE_ID + 1)

static void relay_s5_timeout(ogs_gtp_xact_t *xact, void *data)
{
    smf_sess_t *sess = NULL;
    smf_ue_t *smf_ue = NULL;
    ogs_pool_id_t sess_id;
    uint8_t type;

    ogs_assert(xact);
    type = xact->seq[0].type;

    sess_id = OGS_POINTER_TO_UINT(data);
    sess = smf_sess_find_active_by_id(sess_id);
    if (!sess) {
        ogs_error("S8 relay: GTP timeout type[%d], session[%u] removed",
                type, sess_id);
        return;
    }
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);

    ogs_error("[%s:%s] S8 relay: no response from home PGW (type:%d)",
            smf_ue ? smf_ue->imsi_bcd : "-",
            sess->session.name ? sess->session.name : "-", type);

    /*
     * The MME's own S11 transaction will time out and the UE retries.
     * A half-open relay session would shadow the retry, so clean up.
     */
    if (type == OGS_GTP2_CREATE_SESSION_REQUEST_TYPE) {
        if (sess->upf_n4_seid)
            smf_epc_pfcp_send_session_deletion_best_effort(sess);
        smf_sess_remove(sess);
    }
}

static void relay_pfcp_timeout(ogs_pfcp_xact_t *xact, void *data)
{
    ogs_pool_id_t sess_id;

    ogs_assert(xact);
    sess_id = OGS_POINTER_TO_UINT(data);
    ogs_error("S8 relay: PFCP timeout type[%d] session[%u]",
            xact->seq[0].type, sess_id);
}

static ogs_gtp_node_t *relay_pgw_gnode(ogs_gtp2_f_teid_t *pgw_f_teid)
{
    int rv;
    ogs_ip_t pgw_ip;
    ogs_sockaddr_t *pgw_addr = NULL;
    ogs_gtp_node_t *gnode = NULL;

    ogs_assert(pgw_f_teid);

    rv = ogs_gtp2_f_teid_to_ip(pgw_f_teid, &pgw_ip);
    if (rv != OGS_OK)
        return NULL;

    rv = ogs_ip_to_sockaddr(&pgw_ip, ogs_gtp_self()->gtpc_port, &pgw_addr);
    if (rv != OGS_OK)
        return NULL;

    gnode = ogs_gtp_node_find_by_addr(&smf_self()->sgw_s5c_list, pgw_addr);
    if (!gnode) {
        gnode = ogs_gtp_node_add_by_addr(&smf_self()->sgw_s5c_list, pgw_addr);
        if (!gnode) {
            ogs_error("S8 relay: gnode pool full for home PGW");
            ogs_freeaddrinfo(pgw_addr);
            return NULL;
        }
        gnode->sock = pgw_addr->ogs_sa_family == AF_INET6 ?
            ogs_gtp_self()->gtpc_sock6 : ogs_gtp_self()->gtpc_sock;
        smf_gtp_node_new(gnode);
        smf_metrics_inst_global_inc(SMF_METR_GLOB_GAUGE_GTP_PEERS_ACTIVE);
    }
    ogs_freeaddrinfo(pgw_addr);

    return gnode;
}

/* Build our GTP-C F-TEID with the session-local TEID. */
static int relay_local_f_teid(
        ogs_gtp2_f_teid_t *f_teid, uint8_t interface_type,
        uint32_t teid, int *len)
{
    memset(f_teid, 0, sizeof(*f_teid));
    f_teid->interface_type = interface_type;
    f_teid->teid = htobe32(teid);
    if (ogs_gtp_self()->gtpc_ip.ipv4 || ogs_gtp_self()->gtpc_ip.ipv6)
        return ogs_gtp2_ip_to_f_teid(&ogs_gtp_self()->gtpc_ip, f_teid, len);
    return ogs_gtp2_sockaddr_to_f_teid(
            ogs_gtp_self()->gtpc_addr, ogs_gtp_self()->gtpc_addr6,
            f_teid, len);
}

void smf_s11_relay_handle_create_session_request(
        smf_sess_t *sess, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv;
    smf_ue_t *smf_ue = NULL;
    smf_bearer_t *bearer = NULL;
    ogs_gtp2_create_session_request_t *req = NULL;
    ogs_gtp2_f_teid_t *pgw_f_teid = NULL;
    uint8_t cause_value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;

    ogs_pfcp_xact_t *pfcp_xact = NULL;
    ogs_pfcp_header_t h;
    ogs_pkbuf_t *n4buf = NULL;

    ogs_assert(sess);
    ogs_assert(s11_xact);
    ogs_assert(gtpbuf);
    ogs_assert(message);
    req = &message->create_session_request;

    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    ogs_info("[%s:%s] S8 relay: Create Session Request for home-routed "
            "roamer", smf_ue->imsi_bcd, sess->session.name);

    if (req->sender_f_teid_for_control_plane.presence == 0 ||
            !req->sender_f_teid_for_control_plane.data) {
        ogs_error("S8 relay: no Sender F-TEID");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        goto cleanup;
    }
    if (req->bearer_contexts_to_be_created[0].presence == 0 ||
            req->bearer_contexts_to_be_created[0].
                eps_bearer_id.presence == 0) {
        ogs_error("S8 relay: no Bearer Context / EPS Bearer ID");
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        goto cleanup;
    }
    if (req->pgw_s5_s8_address_for_control_plane_or_pmip.presence == 0 ||
            !req->pgw_s5_s8_address_for_control_plane_or_pmip.data) {
        ogs_error("S8 relay: no PGW S5/S8 Address");
        cause_value = OGS_GTP2_CAUSE_CONDITIONAL_IE_MISSING;
        goto cleanup;
    }
    pgw_f_teid = req->pgw_s5_s8_address_for_control_plane_or_pmip.data;

    /* MME endpoint (sgw_s5c_teid already set by the generic CSR path) */
    rv = ogs_gtp2_f_teid_to_ip(
            req->sender_f_teid_for_control_plane.data, &sess->sgw_s5c_ip);
    if (rv != OGS_OK) {
        cause_value = OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
        goto cleanup;
    }

    /* Home PGW endpoint (control plane) */
    sess->pgw_gnode = relay_pgw_gnode(pgw_f_teid);
    if (!sess->pgw_gnode) {
        cause_value = OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE;
        goto cleanup;
    }
    /* TEID is usually 0 in the address IE; the real one arrives in the
     * Create Session Response. */
    sess->pgw_s5c_teid = be32toh(pgw_f_teid->teid);
    rv = ogs_gtp2_f_teid_to_ip(pgw_f_teid, &sess->pgw_s5c_ip);
    ogs_assert(rv == OGS_OK);

    if (req->pdn_type.presence) {
        sess->ue_session_type = req->pdn_type.u8;
        sess->session.session_type = req->pdn_type.u8;
    }

    /* UPF */
    if (!sess->pfcp_node)
        smf_sess_select_upf(sess);
    if (!sess->pfcp_node) {
        ogs_error("S8 relay: no UPF available");
        cause_value = OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE;
        goto cleanup;
    }

    /*
     * Default bearer as a pure GTP-U forwarder:
     *   UL: PDR(src ACCESS, F-TEID choose, OHR) -> FAR(dst CORE),
     *       target home PGW S5/S8-U (learned from the CSR response)
     *   DL: PDR(src CORE, F-TEID choose, OHR) -> FAR(dst ACCESS),
     *       buffering until the eNB F-TEID arrives (Modify Bearer)
     * No UE IP address in either PDI - the home PGW anchors the IP.
     */
    bearer = smf_bearer_add(sess);
    ogs_assert(bearer);
    bearer->ebi = req->bearer_contexts_to_be_created[0].eps_bearer_id.u8;

    ogs_assert(bearer->dl_pdr && bearer->ul_pdr);
    ogs_assert(bearer->dl_far && bearer->ul_far);

    /* Core side carries GTP-U from the home PGW */
    bearer->dl_pdr->src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_S5_S8_U;
    bearer->dl_pdr->outer_header_removal_len = 1;
    bearer->dl_pdr->outer_header_removal.description =
        OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;
    bearer->ul_far->dst_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_S5_S8_U;

    /* dl_far stays BUFF|NOCP (smf_bearer_add default);
     * ul_far stays FORW - OHC to the PGW is added on the CSR response,
     * before any eNB can send uplink. */

    if (sess->pfcp_node->up_function_features.ftup) {
        bearer->ul_pdr->f_teid.ipv4 = 1;
        bearer->ul_pdr->f_teid.ipv6 = 1;
        bearer->ul_pdr->f_teid.ch = 1;
        bearer->ul_pdr->f_teid.chid = 1;
        bearer->ul_pdr->f_teid.choose_id = OGS_PFCP_DEFAULT_CHOOSE_ID;
        bearer->ul_pdr->f_teid_len = 2;

        bearer->dl_pdr->f_teid.ipv4 = 1;
        bearer->dl_pdr->f_teid.ipv6 = 1;
        bearer->dl_pdr->f_teid.ch = 1;
        bearer->dl_pdr->f_teid.chid = 1;
        bearer->dl_pdr->f_teid.choose_id = SMF_S11_RELAY_CORE_CHOOSE_ID;
        bearer->dl_pdr->f_teid_len = 2;
    } else {
        ogs_error("S8 relay: UPF without FTUP (F-TEID allocation in UP) "
                "is not supported");
        cause_value = OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE;
        goto cleanup;
    }

    bearer->dl_pdr->precedence = smf_self()->default_pdr_precedence;
    bearer->ul_pdr->precedence = smf_self()->default_pdr_precedence;

    /* PFCP Session Establishment; the S11 CSR is buffered in the PFCP
     * transaction so it can be rewritten into the S5 CSR afterwards. */
    pfcp_xact = ogs_pfcp_xact_local_create(
            sess->pfcp_node, relay_pfcp_timeout,
            OGS_UINT_TO_POINTER(sess->id));
    ogs_assert(pfcp_xact);

    pfcp_xact->epc = true;
    pfcp_xact->assoc_xact_id = s11_xact->id;
    pfcp_xact->local_seid = sess->smf_n4_seid;
    pfcp_xact->gtpbuf = ogs_pkbuf_copy(gtpbuf);
    ogs_assert(pfcp_xact->gtpbuf);

    memset(&h, 0, sizeof(ogs_pfcp_header_t));
    h.type = OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE;
    h.seid = sess->upf_n4_seid;

    n4buf = smf_n4_build_session_establishment_request(h.type, sess,
            pfcp_xact);
    if (!n4buf) {
        ogs_error("S8 relay: establishment build failed");
        cause_value = OGS_GTP2_CAUSE_SYSTEM_FAILURE;
        goto cleanup;
    }

    rv = ogs_pfcp_xact_update_tx(pfcp_xact, &h, n4buf);
    ogs_assert(rv == OGS_OK);
    rv = ogs_pfcp_xact_commit(pfcp_xact);
    ogs_assert(rv == OGS_OK);
    return;

cleanup:
    ogs_gtp2_send_error_message(s11_xact, sess->sgw_s5c_teid,
            OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE, cause_value);
    smf_sess_remove(sess);
}

void smf_s11_relay_pfcp_establishment_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_gtp2_message_t *recv_message,
        ogs_pfcp_session_establishment_response_t *rsp)
{
    int i, rv, len;
    smf_ue_t *smf_ue = NULL;
    smf_bearer_t *bearer = NULL;
    ogs_gtp_xact_t *s11_xact = NULL, *s5c_xact = NULL;
    ogs_gtp2_create_session_request_t *req = NULL;

    ogs_gtp2_f_teid_t sgw_s5c_f_teid;
    ogs_gtp2_f_teid_t sgw_s5u_f_teid;
    int sgw_s5u_len = 0;

    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_f_seid_t *up_f_seid = NULL;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    uint8_t pfcp_cause = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;
    uint8_t offending_ie_value = 0;

    ogs_assert(sess);
    ogs_assert(pfcp_xact);
    ogs_assert(rsp);

    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);

    ogs_pfcp_xact_commit(pfcp_xact);

    if (!s11_xact) {
        ogs_error("S8 relay: S11 transaction gone; dropping establishment "
                "response");
        goto establishment_failed;
    }
    if (!recv_message) {
        ogs_error("S8 relay: buffered S11 CSR gone");
        goto establishment_failed;
    }
    req = &recv_message->create_session_request;

    if (rsp->cause.presence == 0 ||
            rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("S8 relay: PFCP establishment rejected [%d]",
                rsp->cause.presence ? rsp->cause.u8 : -1);
        if (rsp->cause.presence &&
                ogs_pfcp_cause_no_association(rsp->cause.u8))
            smf_pfcp_request_reassociation(sess->pfcp_node);
        ogs_gtp2_send_error_message(s11_xact, sess->sgw_s5c_teid,
                OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE);
        goto establishment_failed;
    }

    /* UP F-SEID */
    up_f_seid = rsp->up_f_seid.data;
    if (up_f_seid)
        sess->upf_n4_seid = be64toh(up_f_seid->seid);

    /* UPF-chosen F-TEIDs */
    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        pdr = ogs_pfcp_handle_created_pdr(
                &sess->pfcp, &rsp->created_pdr[i],
                &pfcp_cause, &offending_ie_value);
        if (!pdr)
            break;
    }

    bearer = smf_default_bearer_in_sess(sess);
    ogs_assert(bearer);

    if (bearer->ul_pdr->f_teid_len) {
        ogs_assert(OGS_OK == ogs_pfcp_f_teid_to_sockaddr(
                &bearer->ul_pdr->f_teid, bearer->ul_pdr->f_teid_len,
                &bearer->pgw_s5u_addr, &bearer->pgw_s5u_addr6));
        bearer->pgw_s5u_teid = bearer->ul_pdr->f_teid.teid;
    }
    if (bearer->dl_pdr->f_teid_len) {
        ogs_assert(OGS_OK == ogs_pfcp_f_teid_to_sockaddr(
                &bearer->dl_pdr->f_teid, bearer->dl_pdr->f_teid_len,
                &bearer->relay_core_addr, &bearer->relay_core_addr6));
        bearer->relay_core_teid = bearer->dl_pdr->f_teid.teid;
    }
    if ((!bearer->pgw_s5u_addr && !bearer->pgw_s5u_addr6) ||
            (!bearer->relay_core_addr && !bearer->relay_core_addr6)) {
        ogs_error("S8 relay: UPF did not allocate both F-TEIDs");
        ogs_gtp2_send_error_message(s11_xact, sess->sgw_s5c_teid,
                OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE);
        goto establishment_failed;
    }

    /*
     * Rewrite the buffered S11 CSR into the S5 CSR (in place, like the
     * SGW-C does):
     *  - Sender F-TEID -> our S5/S8 SGW GTP-C F-TEID
     *  - bearer S5/S8-U SGW F-TEID (instance 2) -> UPF core-side F-TEID
     *  - drop the PGW address IE
     */
    recv_message->h.type = OGS_GTP2_CREATE_SESSION_REQUEST_TYPE;
    recv_message->h.teid = sess->pgw_s5c_teid;

    rv = relay_local_f_teid(&sgw_s5c_f_teid,
            OGS_GTP2_F_TEID_S5_S8_SGW_GTP_C, sess->smf_n4_teid, &len);
    if (rv != OGS_OK) {
        ogs_error("S8 relay: SGW S5C F-TEID build failed");
        goto establishment_failed;
    }
    req->sender_f_teid_for_control_plane.presence = 1;
    req->sender_f_teid_for_control_plane.data = &sgw_s5c_f_teid;
    req->sender_f_teid_for_control_plane.len = len;

    memset(&sgw_s5u_f_teid, 0, sizeof(sgw_s5u_f_teid));
    sgw_s5u_f_teid.interface_type = OGS_GTP2_F_TEID_S5_S8_SGW_GTP_U;
    sgw_s5u_f_teid.teid = htobe32(bearer->relay_core_teid);
    rv = ogs_gtp2_sockaddr_to_f_teid(
            bearer->relay_core_addr, bearer->relay_core_addr6,
            &sgw_s5u_f_teid, &sgw_s5u_len);
    if (rv != OGS_OK) {
        ogs_error("S8 relay: SGW S5U F-TEID build failed");
        goto establishment_failed;
    }
    req->bearer_contexts_to_be_created[0].s5_s8_u_sgw_f_teid.presence = 1;
    req->bearer_contexts_to_be_created[0].s5_s8_u_sgw_f_teid.data =
        &sgw_s5u_f_teid;
    req->bearer_contexts_to_be_created[0].s5_s8_u_sgw_f_teid.len =
        sgw_s5u_len;
    /* The MME never sends an eNB F-TEID at attach, but scrub instance 0
     * defensively so the PGW cannot misread it. */
    req->bearer_contexts_to_be_created[0].s1_u_enodeb_f_teid.presence = 0;

    req->pgw_s5_s8_address_for_control_plane_or_pmip.presence = 0;

    pkbuf = ogs_gtp2_build_msg(recv_message);
    if (!pkbuf) {
        ogs_error("S8 relay: S5 CSR build failed");
        goto establishment_failed;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_CREATE_SESSION_REQUEST_TYPE;
    h.teid = sess->pgw_s5c_teid;

    s5c_xact = ogs_gtp_xact_local_create(sess->pgw_gnode, &h, pkbuf,
            relay_s5_timeout, OGS_UINT_TO_POINTER(sess->id));
    if (!s5c_xact) {
        ogs_error("S8 relay: S5 transaction create failed");
        goto establishment_failed;
    }
    s5c_xact->local_teid = sess->smf_n4_teid;
    ogs_gtp_xact_associate(s11_xact, s5c_xact);

    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);

    ogs_info("[%s:%s] S8 relay: Create Session Request sent to home PGW",
            smf_ue->imsi_bcd, sess->session.name);
    return;

establishment_failed:
    if (sess->upf_n4_seid)
        smf_epc_pfcp_send_session_deletion_best_effort(sess);
    smf_sess_remove(sess);
}

void smf_s11_relay_handle_create_session_response(
        smf_sess_t *sess, ogs_gtp_xact_t *s5c_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv;
    smf_ue_t *smf_ue = NULL;
    smf_bearer_t *bearer = NULL;
    ogs_gtp_xact_t *s11_xact = NULL;
    ogs_gtp2_create_session_response_t *rsp = NULL;
    ogs_gtp2_cause_t *cause = NULL;
    ogs_gtp2_f_teid_t *pgw_c_f_teid = NULL, *pgw_u_f_teid = NULL;
    ogs_pfcp_xact_t *pfcp_xact = NULL;

    ogs_assert(sess);
    ogs_assert(s5c_xact);
    ogs_assert(gtpbuf);
    ogs_assert(message);
    rsp = &message->create_session_response;

    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    s11_xact = ogs_gtp_xact_find_by_id(s5c_xact->assoc_xact_id);

    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);

    if (!s11_xact) {
        ogs_error("[%s] S8 relay: S11 transaction gone; dropping Create "
                "Session Response", smf_ue->imsi_bcd);
        smf_epc_pfcp_send_session_deletion_best_effort(sess);
        smf_sess_remove(sess);
        return;
    }

    cause = rsp->cause.presence ? rsp->cause.data : NULL;
    if (!cause ||
            (cause->value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED &&
             cause->value !=
                OGS_GTP2_CAUSE_NEW_PDN_TYPE_DUE_TO_NETWORK_PREFERENCE &&
             cause->value !=
                OGS_GTP2_CAUSE_NEW_PDN_TYPE_DUE_TO_SINGLE_ADDRESS_BEARER_ONLY)) {
        ogs_error("[%s:%s] S8 relay: home PGW rejected Create Session "
                "[cause:%d]", smf_ue->imsi_bcd, sess->session.name,
                cause ? cause->value : -1);
        ogs_gtp2_send_error_message(s11_xact, sess->sgw_s5c_teid,
                OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                cause ? cause->value : OGS_GTP2_CAUSE_SYSTEM_FAILURE);
        smf_epc_pfcp_send_session_deletion_best_effort(sess);
        smf_sess_remove(sess);
        return;
    }

    /* Home PGW control-plane F-TEID */
    if (rsp->pgw_s5_s8__s2a_s2b_f_teid_for_pmip_based_interface_or_for_gtp_based_control_plane_interface.presence &&
            rsp->pgw_s5_s8__s2a_s2b_f_teid_for_pmip_based_interface_or_for_gtp_based_control_plane_interface.data) {
        pgw_c_f_teid =
            rsp->pgw_s5_s8__s2a_s2b_f_teid_for_pmip_based_interface_or_for_gtp_based_control_plane_interface.data;
        sess->pgw_s5c_teid = be32toh(pgw_c_f_teid->teid);
        rv = ogs_gtp2_f_teid_to_ip(pgw_c_f_teid, &sess->pgw_s5c_ip);
        ogs_assert(rv == OGS_OK);
    }

    /* PAA (kept for logging / accounting; the PGW anchors the address) */
    if (rsp->pdn_address_allocation.presence &&
            rsp->pdn_address_allocation.data &&
            rsp->pdn_address_allocation.len <= OGS_PAA_IPV4V6_LEN)
        memcpy(&sess->paa, rsp->pdn_address_allocation.data,
                rsp->pdn_address_allocation.len);

    /* Home PGW user-plane F-TEID (bearer instance 2) */
    bearer = smf_default_bearer_in_sess(sess);
    ogs_assert(bearer);

    if (rsp->bearer_contexts_created[0].presence == 0 ||
            rsp->bearer_contexts_created[0].
                s5_s8_u_sgw_f_teid.presence == 0 ||
            !rsp->bearer_contexts_created[0].s5_s8_u_sgw_f_teid.data) {
        ogs_error("[%s] S8 relay: no PGW S5/S8-U F-TEID in Create Session "
                "Response", smf_ue->imsi_bcd);
        ogs_gtp2_send_error_message(s11_xact, sess->sgw_s5c_teid,
                OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_MANDATORY_IE_MISSING);
        smf_epc_pfcp_send_session_deletion_best_effort(sess);
        smf_sess_remove(sess);
        return;
    }
    pgw_u_f_teid = rsp->bearer_contexts_created[0].s5_s8_u_sgw_f_teid.data;
    bearer->relay_pgw_s5u_teid = be32toh(pgw_u_f_teid->teid);
    ogs_assert(OGS_OK ==
            ogs_gtp2_f_teid_to_ip(pgw_u_f_teid, &bearer->relay_pgw_s5u_ip));

    if (rsp->bearer_contexts_created[0].eps_bearer_id.presence)
        bearer->ebi = rsp->bearer_contexts_created[0].eps_bearer_id.u8;

    /* Point the UL FAR at the home PGW and activate it. */
    ogs_assert(bearer->ul_far);
    bearer->ul_far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;
    ogs_assert(OGS_OK ==
        ogs_pfcp_ip_to_outer_header_creation(
            &bearer->relay_pgw_s5u_ip,
            &bearer->ul_far->outer_header_creation,
            &bearer->ul_far->outer_header_creation_len));
    bearer->ul_far->outer_header_creation.teid = bearer->relay_pgw_s5u_teid;

    ogs_list_init(&sess->qos_flow_to_modify_list);
    ogs_list_add(&sess->qos_flow_to_modify_list, &bearer->to_modify_node);

    pfcp_xact = ogs_pfcp_xact_local_create(
            sess->pfcp_node, relay_pfcp_timeout,
            OGS_UINT_TO_POINTER(sess->id));
    ogs_assert(pfcp_xact);

    pfcp_xact->epc = true;
    pfcp_xact->assoc_xact_id = s11_xact->id;
    pfcp_xact->modify_flags =
        OGS_PFCP_MODIFY_UL_ONLY|OGS_PFCP_MODIFY_ACTIVATE;
    pfcp_xact->gtp_pti = OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED;
    pfcp_xact->gtp_cause = OGS_GTP2_CAUSE_UNDEFINED_VALUE;
    pfcp_xact->local_seid = sess->smf_n4_seid;

    /* Buffer the S5 CSR response; it is rewritten into the S11 response
     * once the UPF confirms the UL path. */
    pfcp_xact->gtpbuf = ogs_pkbuf_copy(gtpbuf);
    ogs_assert(pfcp_xact->gtpbuf);

    ogs_assert(OGS_OK == smf_pfcp_send_modify_list(
            sess, smf_n4_build_qos_flow_to_modify_list, pfcp_xact, 0));
}

void smf_s11_relay_forward_create_session_response(
        smf_sess_t *sess, ogs_gtp_xact_t *s11_xact,
        ogs_gtp2_message_t *recv_message)
{
    int rv, len;
    smf_ue_t *smf_ue = NULL;
    smf_bearer_t *bearer = NULL;
    ogs_gtp2_create_session_response_t *rsp = NULL;

    ogs_gtp2_f_teid_t sgw_s11_f_teid;
    ogs_gtp2_f_teid_t sgw_s1u_f_teid;
    int sgw_s1u_len = 0;

    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(s11_xact);
    ogs_assert(recv_message);
    rsp = &recv_message->create_session_response;

    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    bearer = smf_default_bearer_in_sess(sess);
    ogs_assert(bearer);

    /*
     * Rewrite the home PGW's Create Session Response into the S11
     * response (in place, like the SGW-C does):
     *  - Sender F-TEID -> our S11/S4 SGW GTP-C F-TEID
     *  - bearer S1-U SGW F-TEID (instance 0) -> UPF access-side F-TEID
     * Everything else (Cause, PAA, PCO, AMBR, PGW CP F-TEID inst 1,
     * bearer PGW-S5U inst 2) passes through untouched.
     */
    rv = relay_local_f_teid(&sgw_s11_f_teid,
            OGS_GTP2_F_TEID_S11_S4_SGW_GTP_C, sess->smf_n4_teid, &len);
    if (rv != OGS_OK) {
        ogs_error("S8 relay: SGW S11 F-TEID build failed");
        return;
    }
    rsp->sender_f_teid_for_control_plane.presence = 1;
    rsp->sender_f_teid_for_control_plane.data = &sgw_s11_f_teid;
    rsp->sender_f_teid_for_control_plane.len = len;

    memset(&sgw_s1u_f_teid, 0, sizeof(sgw_s1u_f_teid));
    sgw_s1u_f_teid.interface_type = OGS_GTP2_F_TEID_S1_U_SGW_GTP_U;
    sgw_s1u_f_teid.teid = htobe32(bearer->pgw_s5u_teid);
    rv = ogs_gtp2_sockaddr_to_f_teid(
            bearer->pgw_s5u_addr, bearer->pgw_s5u_addr6,
            &sgw_s1u_f_teid, &sgw_s1u_len);
    if (rv != OGS_OK) {
        ogs_error("S8 relay: SGW S1U F-TEID build failed");
        return;
    }
    rsp->bearer_contexts_created[0].s1_u_enodeb_f_teid.presence = 1;
    rsp->bearer_contexts_created[0].s1_u_enodeb_f_teid.data =
        &sgw_s1u_f_teid;
    rsp->bearer_contexts_created[0].s1_u_enodeb_f_teid.len = sgw_s1u_len;

    recv_message->h.type = OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE;
    recv_message->h.teid = sess->sgw_s5c_teid;

    pkbuf = ogs_gtp2_build_msg(recv_message);
    if (!pkbuf) {
        ogs_error("S8 relay: S11 CSR response build failed");
        return;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE;
    h.teid = sess->sgw_s5c_teid;

    rv = ogs_gtp_xact_update_tx(s11_xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("S8 relay: S11 response update_tx failed");
        return;
    }
    rv = ogs_gtp_xact_commit(s11_xact);
    ogs_expect(rv == OGS_OK);

    smf_ue_info(smf_ue, sess, "s8-relay",
            "session established via home PGW "
            "(PGW_S5C_TEID=0x%x PGW_S5U_TEID=0x%x)",
            sess->pgw_s5c_teid, bearer->relay_pgw_s5u_teid);
}

void smf_s11_relay_handle_delete_session_request(
        smf_sess_t *sess, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv;
    smf_ue_t *smf_ue = NULL;
    ogs_gtp_xact_t *s5c_xact = NULL;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(s11_xact);
    ogs_assert(message);

    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    ogs_info("[%s:%s] S8 relay: Delete Session Request -> home PGW",
            smf_ue->imsi_bcd, sess->session.name);

    message->h.type = OGS_GTP2_DELETE_SESSION_REQUEST_TYPE;
    message->h.teid = sess->pgw_s5c_teid;

    pkbuf = ogs_gtp2_build_msg(message);
    if (!pkbuf) {
        ogs_error("S8 relay: S5 DSR build failed");
        ogs_gtp2_send_error_message(s11_xact, sess->sgw_s5c_teid,
                OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_SYSTEM_FAILURE);
        return;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DELETE_SESSION_REQUEST_TYPE;
    h.teid = sess->pgw_s5c_teid;

    s5c_xact = ogs_gtp_xact_local_create(sess->pgw_gnode, &h, pkbuf,
            relay_s5_timeout, OGS_UINT_TO_POINTER(sess->id));
    if (!s5c_xact) {
        ogs_error("S8 relay: S5 DSR transaction create failed");
        ogs_gtp2_send_error_message(s11_xact, sess->sgw_s5c_teid,
                OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_SYSTEM_FAILURE);
        return;
    }
    s5c_xact->local_teid = sess->smf_n4_teid;
    ogs_gtp_xact_associate(s11_xact, s5c_xact);

    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);
}

void smf_s11_relay_handle_delete_session_response(
        smf_sess_t *sess, ogs_gtp_xact_t *s5c_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message)
{
    int rv;
    ogs_gtp_xact_t *s11_xact = NULL;
    ogs_pfcp_xact_t *pfcp_xact = NULL;
    ogs_pfcp_header_t h;
    ogs_pkbuf_t *n4buf = NULL;

    ogs_assert(sess);
    ogs_assert(s5c_xact);
    ogs_assert(gtpbuf);
    ogs_assert(message);

    s11_xact = ogs_gtp_xact_find_by_id(s5c_xact->assoc_xact_id);

    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);

    /* Tear down the UPF forwarding session; the deletion response relays
     * the buffered S5 response to the MME and removes the session. */
    pfcp_xact = ogs_pfcp_xact_local_create(
            sess->pfcp_node, relay_pfcp_timeout,
            OGS_UINT_TO_POINTER(sess->id));
    ogs_assert(pfcp_xact);

    pfcp_xact->epc = true;
    pfcp_xact->assoc_xact_id =
        s11_xact ? s11_xact->id : OGS_INVALID_POOL_ID;
    pfcp_xact->local_seid = sess->smf_n4_seid;
    pfcp_xact->gtpbuf = ogs_pkbuf_copy(gtpbuf);
    ogs_assert(pfcp_xact->gtpbuf);

    memset(&h, 0, sizeof(ogs_pfcp_header_t));
    h.type = OGS_PFCP_SESSION_DELETION_REQUEST_TYPE;
    h.seid = sess->upf_n4_seid;

    n4buf = smf_n4_build_session_deletion_request(h.type, sess);
    ogs_assert(n4buf);

    rv = ogs_pfcp_xact_update_tx(pfcp_xact, &h, n4buf);
    ogs_assert(rv == OGS_OK);
    rv = ogs_pfcp_xact_commit(pfcp_xact);
    ogs_expect(rv == OGS_OK);
}

void smf_s11_relay_pfcp_deletion_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_gtp2_message_t *recv_message)
{
    int rv;
    smf_ue_t *smf_ue = NULL;
    ogs_gtp_xact_t *s11_xact = NULL;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(pfcp_xact);

    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);

    s11_xact = ogs_gtp_xact_find_by_id(pfcp_xact->assoc_xact_id);

    ogs_pfcp_xact_commit(pfcp_xact);

    if (s11_xact && recv_message) {
        recv_message->h.type = OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE;
        recv_message->h.teid = sess->sgw_s5c_teid;

        pkbuf = ogs_gtp2_build_msg(recv_message);
        if (pkbuf) {
            memset(&h, 0, sizeof(ogs_gtp2_header_t));
            h.type = OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE;
            h.teid = sess->sgw_s5c_teid;

            rv = ogs_gtp_xact_update_tx(s11_xact, &h, pkbuf);
            if (rv == OGS_OK) {
                rv = ogs_gtp_xact_commit(s11_xact);
                ogs_expect(rv == OGS_OK);
            }
        } else {
            ogs_error("S8 relay: S11 DSR response build failed");
        }
    } else {
        ogs_error("S8 relay: no S11 transaction for Delete Session "
                "Response relay");
    }

    ogs_info("[%s:%s] S8 relay: session deleted",
            smf_ue ? smf_ue->imsi_bcd : "-",
            sess->session.name ? sess->session.name : "-");

    smf_sess_remove(sess);
}

void smf_s11_relay_bearer_request_to_mme(
        smf_sess_t *sess, ogs_gtp_xact_t *s5c_xact,
        ogs_gtp2_message_t *message)
{
    int rv;
    ogs_gtp_xact_t *s11_xact = NULL;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(s5c_xact);
    ogs_assert(message);

    /* Remember the owning session on the (remote) S5 transaction so the
     * MME's response can be re-targeted to it. */
    s5c_xact->local_teid = sess->smf_n4_teid;

    message->h.teid = sess->sgw_s5c_teid;

    pkbuf = ogs_gtp2_build_msg(message);
    if (!pkbuf) {
        ogs_error("S8 relay: bearer request rebuild failed (type:%d)",
                message->h.type);
        return;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = message->h.type;
    h.teid = sess->sgw_s5c_teid;

    s11_xact = ogs_gtp_xact_local_create(sess->gnode, &h, pkbuf,
            relay_s5_timeout, OGS_UINT_TO_POINTER(sess->id));
    if (!s11_xact) {
        ogs_error("S8 relay: S11 bearer transaction create failed");
        return;
    }
    s11_xact->local_teid = sess->smf_n4_teid;
    ogs_gtp_xact_associate(s5c_xact, s11_xact);

    rv = ogs_gtp_xact_commit(s11_xact);
    ogs_expect(rv == OGS_OK);
}

void smf_s11_relay_bearer_response_to_pgw(
        smf_sess_t *sess, ogs_gtp_xact_t *s11_xact,
        ogs_gtp2_message_t *message)
{
    int rv;
    ogs_gtp_xact_t *s5c_xact = NULL;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    bool default_bearer_teardown = false;

    ogs_assert(sess);
    ogs_assert(s11_xact);
    ogs_assert(message);

    if (message->h.type == OGS_GTP2_DELETE_BEARER_RESPONSE_TYPE &&
            message->delete_bearer_response.linked_eps_bearer_id.presence)
        default_bearer_teardown = true;

    s5c_xact = ogs_gtp_xact_find_by_id(s11_xact->assoc_xact_id);

    /*
     * The MME answers with the UE-scoped S11 TEID, which may name a
     * sibling PDN connection. The S5 transaction was created with the
     * owning session's local TEID - use it to re-target.
     */
    if (s5c_xact && s5c_xact->local_teid) {
        smf_sess_t *target =
            smf_sess_find_active_by_teid(s5c_xact->local_teid);
        if (target && target->s11_relay)
            sess = target;
    }

    rv = ogs_gtp_xact_commit(s11_xact);
    ogs_expect(rv == OGS_OK);

    if (!s5c_xact) {
        ogs_error("S8 relay: no S5 transaction for bearer response "
                "(type:%d)", message->h.type);
        return;
    }

    message->h.teid = sess->pgw_s5c_teid;

    pkbuf = ogs_gtp2_build_msg(message);
    if (!pkbuf) {
        ogs_error("S8 relay: bearer response rebuild failed (type:%d)",
                message->h.type);
        return;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = message->h.type;
    h.teid = sess->pgw_s5c_teid;

    rv = ogs_gtp_xact_update_tx(s5c_xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("S8 relay: bearer response update_tx failed");
        return;
    }
    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);

    /*
     * A Delete Bearer Response for the default bearer completes a
     * PGW-initiated PDN teardown: nothing else will arrive on either
     * leg, so release the UPF session and the session context now.
     */
    if (default_bearer_teardown) {
        smf_ue_t *smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
        ogs_info("[%s:%s] S8 relay: PDN torn down by home PGW",
                smf_ue ? smf_ue->imsi_bcd : "-",
                sess->session.name ? sess->session.name : "-");
        smf_epc_pfcp_send_session_deletion_best_effort(sess);
        smf_sess_remove(sess);
    }
}
