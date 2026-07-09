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

#include "pfcp-path.h"
#include "sxa-handler.h"
#include "gn-handler.h"
#include "metrics.h"

static void pfcp_restoration(ogs_pfcp_node_t *node);
static void node_timeout(ogs_pfcp_xact_t *xact, void *data);

void sgwc_pfcp_state_initial(ogs_fsm_t *s, sgwc_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;

    ogs_assert(s);
    ogs_assert(e);

    sgwc_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    node->t_no_heartbeat = ogs_timer_add(ogs_app()->timer_mgr,
            sgwc_timer_pfcp_no_heartbeat, node);
    ogs_assert(node->t_no_heartbeat);

    OGS_FSM_TRAN(s, &sgwc_pfcp_state_will_associate);
}

void sgwc_pfcp_state_final(ogs_fsm_t *s, sgwc_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;
    ogs_assert(s);
    ogs_assert(e);

    sgwc_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    ogs_timer_delete(node->t_no_heartbeat);
}

void sgwc_pfcp_state_will_associate(ogs_fsm_t *s, sgwc_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;
    ogs_pfcp_xact_t *xact = NULL;
    ogs_pfcp_message_t *message = NULL;

    ogs_assert(s);
    ogs_assert(e);

    sgwc_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        if (node->t_association) {
            ogs_timer_start(node->t_association,
                    ogs_local_conf()->time.message.pfcp.association_interval);

            ogs_pfcp_cp_send_association_setup_request(node, node_timeout);
        }
        break;

    case OGS_FSM_EXIT_SIG:
        if (node->t_association) {
            ogs_timer_stop(node->t_association);
        }
        break;

    case SGWC_EVT_SXA_TIMER:
        switch(e->timer_id) {
        case SGWC_TIMER_PFCP_ASSOCIATION:
            node = e->pfcp_node;
            ogs_assert(node);

            ogs_warn("Retry association with peer failed %s",
                    ogs_sockaddr_to_string_static(node->addr_list));

            ogs_assert(node->t_association);
            ogs_timer_start(node->t_association,
                ogs_local_conf()->time.message.pfcp.association_interval);

            ogs_pfcp_cp_send_association_setup_request(node, node_timeout);
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    sgwc_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    case SGWC_EVT_SXA_MESSAGE:
        message = e->pfcp_message;
        ogs_assert(message);
        xact = ogs_pfcp_xact_find_by_id(e->pfcp_xact_id);
        ogs_assert(xact);

        switch (message->h.type) {
        case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_request(node, xact,
                    &message->pfcp_heartbeat_request));
            break;
        case OGS_PFCP_HEARTBEAT_RESPONSE_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_response(node, xact,
                    &message->pfcp_heartbeat_response));
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
            ogs_pfcp_cp_handle_association_setup_request(node, xact,
                    &message->pfcp_association_setup_request);
            OGS_FSM_TRAN(s, sgwc_pfcp_state_associated);
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
            ogs_pfcp_cp_handle_association_setup_response(node, xact,
                    &message->pfcp_association_setup_response);
            OGS_FSM_TRAN(s, sgwc_pfcp_state_associated);
            break;
        case OGS_PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE:
            ogs_pfcp_cp_handle_association_release_request(node, xact,
                    &message->pfcp_association_release_request);
            ogs_warn("PFCP Association Release Request from %s",
                    ogs_sockaddr_to_string_static(node->addr_list));
            node->restoration_required = true;
            OGS_FSM_TRAN(s, sgwc_pfcp_state_will_associate);
            break;
        default:
            ogs_warn("cannot handle PFCP message type[%d]",
                    message->h.type);
            break;
        }
        break;
    case SGWC_EVT_SXA_REASSOCIATE:
        break;
    default:
        ogs_error("Unknown event %s", sgwc_event_get_name(e));
        break;
    }
}

void sgwc_pfcp_state_associated(ogs_fsm_t *s, sgwc_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;
    ogs_pfcp_xact_t *xact = NULL;
    ogs_pfcp_message_t *message = NULL;

    sgwc_sess_t *sess = NULL;

    ogs_assert(s);
    ogs_assert(e);

    sgwc_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        ogs_info("PFCP associated %s",
            ogs_sockaddr_to_string_static(node->addr_list));
        ogs_timer_start(node->t_no_heartbeat,
                ogs_local_conf()->time.message.pfcp.no_heartbeat_duration);
        ogs_assert(OGS_OK ==
            ogs_pfcp_send_heartbeat_request(node, node_timeout));

        sgwc_metrics_inst_global_inc(SGWC_METR_GLOB_GAUGE_PFCP_PEERS_ACTIVE);
        sgwc_metrics_pfcp_peer_up(
                ogs_sockaddr_to_string_static(node->addr_list), 1);

        if (node->restoration_required == true) {
            pfcp_restoration(node);
            node->restoration_required = false;
            ogs_error("PFCP restoration");
        }
        break;
    case OGS_FSM_EXIT_SIG:
        ogs_info("PFCP de-associated %s",
            ogs_sockaddr_to_string_static(node->addr_list));
        ogs_timer_stop(node->t_no_heartbeat);

        sgwc_metrics_inst_global_dec(SGWC_METR_GLOB_GAUGE_PFCP_PEERS_ACTIVE);
        sgwc_metrics_pfcp_peer_up(
                ogs_sockaddr_to_string_static(node->addr_list), 0);
        break;
    case SGWC_EVT_SXA_MESSAGE:
        message = e->pfcp_message;
        ogs_assert(message);
        xact = ogs_pfcp_xact_find_by_id(e->pfcp_xact_id);
        ogs_assert(xact);

        if (message->h.seid_presence && message->h.seid != 0) {
            sess = sgwc_sess_find_by_seid(message->h.seid);
        } else if (xact->local_seid) { /* rx no SEID or SEID=0 */
            /* 3GPP TS 29.244 7.2.2.4.2: we receive SEID=0 under some
             * conditions, such as cause "Session context not found". In those
             * cases, we still want to identify the local session which
             * originated the message, so try harder by using the SEID we
             * locally stored in xact when sending the original request: */
            sess = sgwc_sess_find_by_seid(xact->local_seid);
        }

        /* Session Establishment Request stores sess->id in xact->data. After
         * PFCP restoration both CP-side and UP-side SEIDs in header/xact can
         * be 0 until the response carries the new UP F-SEID; resolve session
         * from the transaction in that case. */
        if (!sess && message->h.type ==
                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE) {
            ogs_pool_id_t sess_id = OGS_POINTER_TO_UINT(xact->data);
            if (sess_id >= OGS_MIN_POOL_ID && sess_id <= OGS_MAX_POOL_ID)
                sess = sgwc_sess_find_by_id(sess_id);
        }

        switch (message->h.type) {
        case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_request(node, xact,
                    &message->pfcp_heartbeat_request));
            if (node->restoration_required == true) {
                if (node->t_association) {
        /*
         * node->t_association that the PFCP entity attempts an association.
         *
         * In this case, even if Remote PFCP entity is restarted,
         * PFCP restoration must be performed after PFCP association.
         *
         * Otherwise, Session related PFCP cannot be initiated
         * because the peer PFCP entity is in a de-associated state.
         */
                    OGS_FSM_TRAN(s, sgwc_pfcp_state_will_associate);
                } else {

        /*
         * If the peer PFCP entity is performing the association,
         * Restoration can be performed immediately.
         */
                    pfcp_restoration(node);
                    node->restoration_required = false;
                    ogs_error("PFCP restoration");
                }
            }
            break;
        case OGS_PFCP_HEARTBEAT_RESPONSE_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_response(node, xact,
                    &message->pfcp_heartbeat_response));
            if (node->restoration_required == true) {
        /*
         * node->t_association that the PFCP entity attempts an association.
         *
         * In this case, even if Remote PFCP entity is restarted,
         * PFCP restoration must be performed after PFCP association.
         *
         * Otherwise, Session related PFCP cannot be initiated
         * because the peer PFCP entity is in a de-associated state.
         */
                if (node->t_association) {
                    OGS_FSM_TRAN(s, sgwc_pfcp_state_will_associate);
                } else {
        /*
         * If the peer PFCP entity is performing the association,
         * Restoration can be performed immediately.
         */
                    pfcp_restoration(node);
                    node->restoration_required = false;
                    ogs_error("PFCP restoration");
                }
            }
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
            ogs_warn("PFCP[REQ] has already been associated %s",
                ogs_sockaddr_to_string_static(node->addr_list));
            ogs_pfcp_cp_handle_association_setup_request(node, xact,
                    &message->pfcp_association_setup_request);
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
            ogs_warn("PFCP[RSP] has already been associated %s",
                ogs_sockaddr_to_string_static(node->addr_list));
            ogs_pfcp_cp_handle_association_setup_response(node, xact,
                    &message->pfcp_association_setup_response);
            break;
        case OGS_PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE:
            ogs_pfcp_cp_handle_association_release_request(node, xact,
                    &message->pfcp_association_release_request);
            ogs_warn("PFCP Association Release Request from %s",
                    ogs_sockaddr_to_string_static(node->addr_list));
            node->restoration_required = true;
            OGS_FSM_TRAN(s, sgwc_pfcp_state_will_associate);
            break;
        case OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE:
            if (!message->h.seid_presence) ogs_error("No SEID");

            if ((xact->create_flags &
                        OGS_PFCP_CREATE_RESTORATION_INDICATION)) {
                ogs_pfcp_session_establishment_response_t *rsp = NULL;
                ogs_pfcp_f_seid_t *up_f_seid = NULL;

                rsp = &message->pfcp_session_establishment_response;
                if (rsp->up_f_seid.presence == 0) {
                    ogs_error("No UP F-SEID");
                    break;
                }
                up_f_seid = rsp->up_f_seid.data;
                ogs_assert(up_f_seid);
                if (!sess) {
                    ogs_error("No session for PFCP Session Establishment "
                            "Response (restoration); "
                            "seid_presence=%d seid=0x%llx local_seid=0x%llx",
                            message->h.seid_presence,
                            (unsigned long long)message->h.seid,
                            (unsigned long long)xact->local_seid);
                    break;
                }
                sess->sgwu_sxa_seid = be64toh(up_f_seid->seid);
            } else {
                /*
                 * The establishment path always buffers a Create Session
                 * Request (S11 CSR, or the CSR synthesized from a Gn Create
                 * PDP Context Request). Anything else means the transaction
                 * or its buffer got crossed (e.g. a stale response matched by
                 * SQN after restart); interpreting it as a CSR reads garbage
                 * union fields and crashes. Treat it as missing.
                 */
                if (e->gtp_message && e->gtp_message->h.type !=
                        OGS_GTP2_CREATE_SESSION_REQUEST_TYPE) {
                    ogs_error("PFCP Session Establishment Response with "
                            "unexpected buffered GTP message type [%d]; "
                            "discarding buffer", e->gtp_message->h.type);
                    e->gtp_message = NULL;
                }
                if (!e->gtp_message) {
                    ogs_gtp_xact_t *s11_xact = NULL;
                    sgwc_ue_t *sgwc_ue = NULL;
                    ogs_pfcp_session_establishment_response_t *rsp =
                        &message->pfcp_session_establishment_response;
                    uint64_t rsp_up_seid = 0;

                    ogs_error("No buffered GTP message for PFCP Session "
                            "Establishment Response (local_seid=0x%llx)",
                            (unsigned long long)xact->local_seid);

                    /*
                     * If the SGW-U accepted the establishment, a user-plane
                     * session now exists. Record its UP F-SEID before any
                     * teardown below so sgwc_sess_purge_upf() can actually
                     * delete it; with no local session at all, purge the raw
                     * SEID directly. Otherwise it leaks on SGW-U (VPP).
                     */
                    if (rsp->cause.presence &&
                            rsp->cause.u8 == OGS_PFCP_CAUSE_REQUEST_ACCEPTED &&
                            rsp->up_f_seid.presence && rsp->up_f_seid.data)
                        rsp_up_seid = be64toh(((ogs_pfcp_f_seid_t *)
                                rsp->up_f_seid.data)->seid);
                    if (sess && rsp_up_seid)
                        sess->sgwu_sxa_seid = rsp_up_seid;

                    /* With no local session, the teardown paths below have
                     * nothing to purge; delete the just-created UP session
                     * by raw SEID no matter whether an S11 answer is due. */
                    if (!sess && rsp_up_seid)
                        sgwc_pfcp_purge_seid_node(node, rsp_up_seid);

                    s11_xact = ogs_gtp_xact_find_by_id(xact->assoc_xact_id);
                    if (sess)
                        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
                    if (s11_xact) {
                        if (sess && sess->gn) {
                            sgwc_gn_send_create_reject(sess, sgwc_ue, s11_xact,
                                    OGS_GTP2_CAUSE_SYSTEM_FAILURE);
                            sess = NULL;
                        } else {
                            sgwc_create_session_reject_and_cleanup(
                                    sess, sgwc_ue, s11_xact,
                                    OGS_GTP2_CAUSE_SYSTEM_FAILURE);
                            sess = NULL;
                        }
                    } else if (sess) {
                        sgwc_sess_abort_create(sess);
                        sess = NULL;
                    }
                    ogs_pfcp_xact_commit(xact);
                    break;
                }
                sgwc_sxa_handle_session_establishment_response(
                    sess, xact, e->gtp_message,
                    &message->pfcp_session_establishment_response,
                    e->pkbuf);
            }
            break;

        case OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE:
            if (!message->h.seid_presence) ogs_error("No SEID");

            if (!xact->modify_flags) {
                sgwc_sxa_handle_unexpected_modification_response(
                        sess, xact,
                        &message->pfcp_session_modification_response);
                break;
            }

            sgwc_sxa_handle_session_modification_response(
                sess, xact, e->gtp_message,
                &message->pfcp_session_modification_response,
                e->pkbuf);
            break;

        case OGS_PFCP_SESSION_DELETION_RESPONSE_TYPE:
            if (!message->h.seid_presence) ogs_error("No SEID");

            if (xact->delete_trigger ==
                    OGS_PFCP_DELETE_TRIGGER_ORPHAN_PURGE) {
                ogs_pfcp_xact_commit(xact);
                break;
            }

            sgwc_sxa_handle_session_deletion_response(
                sess, xact, e->gtp_message,
                &message->pfcp_session_deletion_response);
            break;

        case OGS_PFCP_SESSION_REPORT_REQUEST_TYPE:
            if (!message->h.seid_presence) ogs_error("No SEID");

            sgwc_sxa_handle_session_report_request(
                sess, xact, &message->pfcp_session_report_request);
            break;

        default:
            ogs_error("Not implemented PFCP message type[%d]",
                    message->h.type);
            break;
        }

        break;
    case SGWC_EVT_SXA_TIMER:
        switch(e->timer_id) {
        case SGWC_TIMER_PFCP_NO_HEARTBEAT:
            node = e->pfcp_node;
            ogs_assert(node);

            ogs_assert(OGS_OK ==
                ogs_pfcp_send_heartbeat_request(node, node_timeout));
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    sgwc_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    case SGWC_EVT_SXA_NO_HEARTBEAT:
        ogs_warn("No Heartbeat from SGW-U %s",
                ogs_sockaddr_to_string_static(node->addr_list));
        /* 3GPP TS 23.007 19A: when re-associating, the UP function deletes
         * the existing PFCP association and all associated PFCP sessions
         * upon receiving the new Association Setup Request. The sessions
         * must therefore be re-established with PFCPSEReq-Flags RESTI
         * (TS 29.244 8.2.116) once the association is up again. */
        node->restoration_required = true;
        OGS_FSM_TRAN(s, sgwc_pfcp_state_will_associate);
        break;
    case SGWC_EVT_SXA_REASSOCIATE:
        ogs_warn("PFCP re-association required with SGW-U %s",
                ogs_sockaddr_to_string_static(node->addr_list));
        /* See TS 23.007 19A note above: sessions are deleted on the UP
         * function by the new association; restore them after setup. */
        node->restoration_required = true;
        OGS_FSM_TRAN(s, sgwc_pfcp_state_will_associate);
        break;
    default:
        ogs_error("Unknown event %s", sgwc_event_get_name(e));
        break;
    }
}

void sgwc_pfcp_state_exception(ogs_fsm_t *s, sgwc_event_t *e)
{
    ogs_assert(s);
    ogs_assert(e);

    sgwc_sm_debug(e);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    default:
        ogs_error("Unknown event %s", sgwc_event_get_name(e));
        break;
    }
}

static void pfcp_restoration(ogs_pfcp_node_t *node)
{
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_list_for_each(&sgwc_self()->sgw_ue_list, sgwc_ue) {
        sgwc_sess_t *sess = NULL;
        ogs_assert(sgwc_ue);

        ogs_list_for_each(&sgwc_ue->sess_list, sess) {
            ogs_assert(sess);

            if (node == sess->pfcp_node) {
                ogs_info("UE IMSI[%s] APN[%s]",
                    sgwc_ue->imsi_bcd, sess->session.name);
                if (sgwc_pfcp_send_session_establishment_request(
                        sess, OGS_INVALID_POOL_ID, NULL,
                        OGS_PFCP_CREATE_RESTORATION_INDICATION) != OGS_OK)
                    ogs_warn("PFCP restoration send failed for sess_id[%d]",
                            sess->id);
            }
        }
    }
}

static void node_timeout(ogs_pfcp_xact_t *xact, void *data)
{
    int rv;

    sgwc_event_t *e = NULL;
    uint8_t type;

    ogs_assert(xact);
    type = xact->seq[0].type;

    switch (type) {
    case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
        ogs_assert(data);

        e = sgwc_event_new(SGWC_EVT_SXA_NO_HEARTBEAT);
        e->pfcp_node = data;

        rv = ogs_queue_push(ogs_app()->queue, e);
        if (rv != OGS_OK) {
            ogs_error("ogs_queue_push() failed:%d", (int)rv);
            sgwc_event_free(e);
        }
        break;
    case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
        break;
    default:
        ogs_error("Not implemented [type:%d]", type);
        break;
    }
}
