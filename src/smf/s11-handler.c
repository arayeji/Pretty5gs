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
#include "s11-handler.h"

bool smf_s11_csr_is_s11(ogs_gtp2_create_session_request_t *req)
{
    ogs_gtp2_f_teid_t *f_teid = NULL;

    ogs_assert(req);

    if (req->sender_f_teid_for_control_plane.presence == 0)
        return false;
    f_teid = req->sender_f_teid_for_control_plane.data;
    if (!f_teid)
        return false;

    return f_teid->interface_type == OGS_GTP2_F_TEID_S11_MME_GTP_C;
}

bool smf_s11_csr_pgw_is_local(ogs_gtp2_create_session_request_t *req)
{
    ogs_gtp2_f_teid_t *pgw_f_teid = NULL;
    ogs_ip_t pgw_ip;
    ogs_ip_t local_ip;

    ogs_assert(req);

    /* No PGW address selected by the MME: anchor locally. */
    if (req->pgw_s5_s8_address_for_control_plane_or_pmip.presence == 0)
        return true;
    pgw_f_teid = req->pgw_s5_s8_address_for_control_plane_or_pmip.data;
    if (!pgw_f_teid)
        return true;

    if (ogs_gtp2_f_teid_to_ip(pgw_f_teid, &pgw_ip) != OGS_OK)
        return true;

    memset(&local_ip, 0, sizeof(local_ip));
    if (ogs_gtp_self()->gtpc_ip.ipv4 || ogs_gtp_self()->gtpc_ip.ipv6) {
        /* Advertised GTP-C address configured */
        memcpy(&local_ip, &ogs_gtp_self()->gtpc_ip, sizeof(local_ip));
    } else {
        if (ogs_sockaddr_to_ip(
                ogs_gtp_self()->gtpc_addr, ogs_gtp_self()->gtpc_addr6,
                &local_ip) != OGS_OK)
            return true;
    }

    if (pgw_ip.ipv4 && local_ip.ipv4 &&
            pgw_ip.addr == local_ip.addr)
        return true;
    if (pgw_ip.ipv6 && local_ip.ipv6 &&
            memcmp(pgw_ip.addr6, local_ip.addr6, OGS_IPV6_LEN) == 0)
        return true;

    return false;
}

smf_sess_t *smf_s11_sess_find_by_ebi(smf_sess_t *any_sess, uint8_t ebi)
{
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *sess = NULL;

    ogs_assert(any_sess);
    smf_ue = smf_ue_find_by_id(any_sess->smf_ue_id);
    if (!smf_ue)
        return NULL;

    ogs_list_for_each(&smf_ue->sess_list, sess) {
        if (!sess->s11)
            continue;
        if (smf_bearer_find_by_ebi(sess, ebi))
            return sess;
    }

    return NULL;
}

void smf_s11_handle_release_access_bearers_request(
        smf_sess_t *sess, ogs_gtp_xact_t *xact, ogs_pkbuf_t *gtpbuf,
        ogs_gtp2_release_access_bearers_request_t *req)
{
    int rv;
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *s = NULL;
    smf_bearer_t *bearer = NULL;
    int num_of_modify = 0;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Release Access Bearers Request [s11]");

    if (!sess) {
        ogs_warn("Release Access Bearers Request: no session for "
                "TEID - context already released; replying "
                "CONTEXT_NOT_FOUND so MME re-syncs");
        ogs_gtp2_send_error_message(xact, 0,
                OGS_GTP2_RELEASE_ACCESS_BEARERS_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND);
        return;
    }

    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    /*
     * The MME releases access bearers per UE (all PDN connections).
     * Deactivate the downlink FAR of every S11 session of this UE so the
     * UPF buffers DL traffic and reports it (Downlink Data Report -> DDN).
     *
     * The first modifiable session carries the S11 transaction; its PFCP
     * Session Modification Response triggers the Release Access Bearers
     * Response (see smf_epc_n4_handle_session_modification_response()).
     */
    ogs_list_for_each(&smf_ue->sess_list, s) {
        if (!s->s11 || !s->epc)
            continue;
        if (ogs_list_count(&s->bearer_list) == 0) {
            ogs_error("[%s] Release Access Bearers: session has no "
                    "bearers, skipping", smf_ue->imsi_bcd);
            continue;
        }
        if (!s->pfcp_node) {
            ogs_error("[%s] Release Access Bearers: session has no "
                    "PFCP node, skipping", smf_ue->imsi_bcd);
            continue;
        }

        /* The eNB S1-U tunnel is gone: clear the local mirror so the next
         * Modify Bearer Request does not try to send End Marker packets
         * to a stale eNB F-TEID. */
        ogs_list_for_each(&s->bearer_list, bearer) {
            bearer->sgw_s5u_teid = 0;
            memset(&bearer->sgw_s5u_ip, 0, sizeof(bearer->sgw_s5u_ip));
        }

        rv = smf_epc_pfcp_send_all_pdr_modification_request(
                s,
                num_of_modify == 0 ? xact->id : OGS_INVALID_POOL_ID,
                num_of_modify == 0 ? gtpbuf : NULL,
                OGS_PFCP_MODIFY_DL_ONLY|OGS_PFCP_MODIFY_DEACTIVATE|
                OGS_PFCP_MODIFY_S11_BUFFER,
                OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED,
                OGS_GTP2_CAUSE_UNDEFINED_VALUE);
        if (rv != OGS_OK) {
            ogs_error("[%s] Release Access Bearers: PFCP modification "
                    "failed", smf_ue->imsi_bcd);
            continue;
        }
        num_of_modify++;
    }

    if (num_of_modify == 0) {
        ogs_warn("[%s] Release Access Bearers: no modifiable session; "
                "responding accepted", smf_ue->imsi_bcd);
        ogs_gtp2_send_error_message(xact, sess->sgw_s5c_teid,
                OGS_GTP2_RELEASE_ACCESS_BEARERS_RESPONSE_TYPE,
                OGS_GTP2_CAUSE_REQUEST_ACCEPTED);
    }
}

void smf_s11_handle_downlink_data_notification_ack(
        smf_sess_t *sess, ogs_gtp_xact_t *xact,
        ogs_gtp2_downlink_data_notification_acknowledge_t *ack)
{
    int rv;
    uint8_t cause_value;

    ogs_assert(xact);
    ogs_assert(ack);

    ogs_debug("Downlink Data Notification Acknowledge [s11]");

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    if (ack->cause.presence && ack->cause.data) {
        ogs_gtp2_cause_t *cause = ack->cause.data;

        cause_value = cause->value;
        if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED &&
            cause_value != OGS_GTP2_CAUSE_UE_ALREADY_RE_ATTACHED)
            ogs_warn("Downlink Data Notification Ack: GTP Cause [%d]",
                    cause_value);
    } else {
        ogs_error("Downlink Data Notification Ack: no Cause");
    }
}

static void ddn_timeout(ogs_gtp_xact_t *xact, void *data)
{
    smf_bearer_t *bearer = NULL;
    ogs_pool_id_t bearer_id;

    ogs_assert(data);
    bearer_id = OGS_POINTER_TO_UINT(data);

    bearer = smf_bearer_find_by_id(bearer_id);
    if (!bearer) {
        ogs_warn("Downlink Data Notification timeout: bearer already "
                "removed [%d]", bearer_id);
        return;
    }

    ogs_error("Downlink Data Notification: no response from MME "
            "(bearer EBI[%d])", bearer->ebi);
}

static ogs_pkbuf_t *s11_build_downlink_data_notification(
        uint8_t cause_value, smf_bearer_t *bearer, smf_sess_t *sess)
{
    ogs_gtp2_message_t message;
    ogs_gtp2_downlink_data_notification_t *noti = NULL;
    ogs_gtp2_cause_t cause;
    ogs_gtp2_arp_t arp;

    ogs_assert(bearer);
    ogs_assert(sess);

    noti = &message.downlink_data_notification;
    memset(&message, 0, sizeof(ogs_gtp2_message_t));

    /*
     * TS 29.274 8.4 Cause Value
     * 0 : Reserved. Shall not be sent and
     *     if received the Cause shall be treated as an invalid IE
     */
    if (cause_value != OGS_GTP2_CAUSE_UNDEFINED_VALUE) {
        memset(&cause, 0, sizeof(cause));
        cause.value = cause_value;
        noti->cause.presence = 1;
        noti->cause.len = sizeof(cause);
        noti->cause.data = &cause;
    }

    noti->eps_bearer_id.presence = 1;
    noti->eps_bearer_id.u8 = bearer->ebi;

    memset(&arp, 0, sizeof(arp));
    arp.pre_emption_vulnerability =
        sess->session.qos.arp.pre_emption_vulnerability;
    arp.priority_level = sess->session.qos.arp.priority_level;
    arp.pre_emption_capability =
        sess->session.qos.arp.pre_emption_capability;

    noti->allocation_retention_priority.presence = 1;
    noti->allocation_retention_priority.data = &arp;
    noti->allocation_retention_priority.len = sizeof(arp);

    message.h.type = OGS_GTP2_DOWNLINK_DATA_NOTIFICATION_TYPE;
    return ogs_gtp2_build_msg(&message);
}

int smf_s11_send_downlink_data_notification(
        uint8_t cause_value, smf_bearer_t *bearer)
{
    int rv;
    smf_sess_t *sess = NULL;
    smf_ue_t *smf_ue = NULL;
    ogs_gtp_xact_t *xact = NULL;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(bearer);
    sess = smf_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);

    if (!sess->gnode) {
        ogs_error("Downlink Data Notification: no MME GTP node");
        return OGS_ERROR;
    }

    ogs_info("[%s:%s] Downlink Data Notification (EBI[%d]) [s11]",
            smf_ue ? smf_ue->imsi_bcd : "-", sess->session.name,
            bearer->ebi);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DOWNLINK_DATA_NOTIFICATION_TYPE;
    h.teid = sess->sgw_s5c_teid; /* MME S11 TEID */

    pkbuf = s11_build_downlink_data_notification(cause_value, bearer, sess);
    if (!pkbuf) {
        ogs_error("s11_build_downlink_data_notification() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp_xact_local_create(sess->gnode, &h, pkbuf,
            ddn_timeout, OGS_UINT_TO_POINTER(bearer->id));
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        return OGS_ERROR;
    }
    xact->local_teid = sess->smf_n4_teid;

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}
