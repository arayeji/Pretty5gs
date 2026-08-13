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

#include "mme-event.h"
#include "mme-timer.h"
#include "mme-sm.h"
#include "mme-fd-path.h"
#include "emm-handler.h"
#include "esm-build.h"
#include "esm-handler.h"
#include "mme-s11-handler.h"
#include "s1ap-path.h"
#include "nas-path.h"
#include "mme-gtp-path.h"
#include "mme-trace.h"

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __esm_log_domain

/*
 * Late ESM timer / nested FSM entry can outlive the bearer (or its
 * parent sess/mme_ue). Asserting here would abort the MME the same way
 * emm_state_de_registered did — drop the event instead.
 */
#define ESM_FIND_CTX_OR_RETURN(e, bearer, sess, mme_ue) do {             \
    (bearer) = mme_bearer_find_by_id((e)->bearer_id);                   \
    if (!(bearer)) {                                                    \
        ogs_warn("ESM: bearer id=%d gone (event %s)",                   \
                (e)->bearer_id, mme_event_get_name(e));                 \
        return;                                                         \
    }                                                                   \
    (sess) = mme_sess_find_by_id((bearer)->sess_id);                    \
    if (!(sess)) {                                                      \
        ogs_warn("ESM: sess id=%d gone for bearer=%d (event %s)",       \
                (bearer)->sess_id, (bearer)->id,                        \
                mme_event_get_name(e));                                 \
        return;                                                         \
    }                                                                   \
    (mme_ue) = mme_ue_find_by_id((sess)->mme_ue_id);                    \
    if (!(mme_ue)) {                                                    \
        ogs_warn("ESM: mme_ue id=%d gone for bearer=%d (event %s)",     \
                (sess)->mme_ue_id, (bearer)->id,                        \
                mme_event_get_name(e));                                 \
        return;                                                         \
    }                                                                   \
} while (0)

static uint8_t gtp_cause_from_esm(uint8_t esm_cause)
{
    switch (esm_cause) {
    case OGS_NAS_ESM_CAUSE_SEMANTIC_ERROR_IN_THE_TFT_OPERATION:
        return OGS_GTP2_CAUSE_SEMANTIC_ERROR_IN_THE_TFT_OPERATION;
    case OGS_NAS_ESM_CAUSE_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION:
        return OGS_GTP2_CAUSE_SYNTACTIC_ERROR_IN_THE_TFT_OPERATION;
    case OGS_NAS_ESM_CAUSE_SYNTACTICAL_ERROR_IN_PACKET_FILTERS:
        return OGS_GTP2_CAUSE_SYNTACTIC_ERRORS_IN_PACKET_FILTER;
    case OGS_NAS_ESM_CAUSE_SEMANTIC_ERRORS_IN_PACKET_FILTERS:
        return OGS_GTP2_CAUSE_SEMANTIC_ERRORS_IN_PACKET_FILTER;
    default:
        break;
    }

    return OGS_GTP2_CAUSE_SYSTEM_FAILURE;
}

static void esm_handle_bearer_setup_timer(ogs_fsm_t *s,
        mme_ue_t *mme_ue, mme_sess_t *sess, mme_bearer_t *bearer)
{
    int r;
    enb_ue_t *enb_ue = NULL;
    mme_bearer_t *linked_bearer = NULL;
    sgw_ue_t *sgw_ue = NULL;

    ogs_assert(s);
    ogs_assert(mme_ue);
    ogs_assert(sess);
    ogs_assert(bearer);

    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    linked_bearer = mme_linked_bearer(bearer);
    ogs_assert(linked_bearer);

    if (bearer->t_bearer_setup.retry_count >=
            mme_timer_cfg(MME_TIMER_BEARER_SETUP)->max_count) {
        ogs_warn("E-RAB setup retransmission failed "
                "IMSI[%s] EBI[%d]", mme_ue->imsi_bcd, bearer->ebi);

        if (bearer->ebi == linked_bearer->ebi) {
            if (enb_ue && MME_HAVE_SGW_S1U_PATH(sess)) {
                sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
                if (!sgw_ue) {
                    ogs_warn("[%s] bearer setup timeout: sgw_ue gone",
                            mme_ue->imsi_bcd);
                } else if (mme_gtp_send_delete_session_request(
                            enb_ue, sgw_ue, sess,
                            OGS_GTP_DELETE_NO_ACTION) != OGS_OK) {
                    ogs_error("[%s] Delete Session Request failed on "
                            "bearer setup timeout EBI[%d]",
                            mme_ue->imsi_bcd, bearer->ebi);
                }
            }
            OGS_FSM_TRAN(s, esm_state_exception);
        } else {
            if (mme_gtp_send_create_bearer_response(bearer,
                        OGS_GTP2_CAUSE_REQUEST_REJECTED_REASON_NOT_SPECIFIED)
                    != OGS_OK)
                ogs_error("[%s] Create Bearer Response (reject) failed on "
                        "bearer setup timeout EBI[%d]",
                        mme_ue->imsi_bcd, bearer->ebi);
            OGS_FSM_TRAN(s, esm_state_bearer_deactivated);
        }
    } else {
        bearer->t_bearer_setup.retry_count++;
        r = nas_eps_resend_bearer_setup_request(bearer);
        ogs_expect(r == OGS_OK);
    }
}

void esm_state_initial(ogs_fsm_t *s, mme_event_t *e)
{
    ogs_assert(s);

    mme_sm_debug(e);

    OGS_FSM_TRAN(s, &esm_state_inactive);
}

void esm_state_final(ogs_fsm_t *s, mme_event_t *e)
{
    ogs_assert(s);

    mme_sm_debug(e);
}

void esm_state_inactive(ogs_fsm_t *s, mme_event_t *e)
{
    int r, rv;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;
    ogs_nas_eps_message_t *message = NULL;
    ogs_nas_security_header_type_t h;

    ogs_nas_eps_activate_dedicated_eps_bearer_context_reject_t
        *activate_dedicated_eps_bearer_context_reject = NULL;

    ogs_assert(s);
    ogs_assert(e);

    mme_sm_debug(e);

    ESM_FIND_CTX_OR_RETURN(e, bearer, sess, mme_ue);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        CLEAR_BEARER_ALL_TIMERS(bearer);
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    case MME_EVENT_ESM_MESSAGE:
        message = e->nas_message;
        ogs_assert(message);

        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!enb_ue)
            ogs_warn("No eNB-UE context; dropping ESM message(type:%d) "
                    "IMSI[%s] PTI[%d] EBI[%d]",
                    message->esm.h.message_type,
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);

        switch (message->esm.h.message_type) {
        case OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST:
            ogs_debug("PDN Connectivity request");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            rv = esm_handle_pdn_connectivity_request(
                    enb_ue, bearer, &message->esm.pdn_connectivity_request,
                    e->create_action);
            if (rv != OGS_OK) {
                OGS_FSM_TRAN(s, esm_state_exception);
                break;
            }
            break;
        case OGS_NAS_EPS_PDN_DISCONNECT_REQUEST:
            ogs_debug("PDN disconnect request");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            if (MME_HAVE_SGW_S1U_PATH(sess)) {
                sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
                if (!sgw_ue) {
                    ogs_warn("[%s] PDN disconnect: sgw_ue gone",
                            mme_ue->imsi_bcd);
                    OGS_FSM_TRAN(s, esm_state_exception);
                    break;
                }

                if (mme_gtp_send_delete_session_request(enb_ue, sgw_ue, sess,
                            OGS_GTP_DELETE_SEND_DEACTIVATE_BEARER_CONTEXT_REQUEST)
                        != OGS_OK)
                    ogs_error("[%s] Delete Session Request failed on PDN "
                            "disconnect EBI[%d]",
                            mme_ue->imsi_bcd, bearer->ebi);
            } else {
                r = nas_eps_send_deactivate_bearer_context_request(
                        bearer, OGS_NAS_ESM_CAUSE_REGULAR_DEACTIVATION);
                ogs_expect(r == OGS_OK);
            }

            CLEAR_SGW_S1U_PATH(sess);

            OGS_FSM_TRAN(s, esm_state_pdn_will_disconnect);
            break;

        case OGS_NAS_EPS_ESM_INFORMATION_RESPONSE:
            ogs_debug("ESM information response");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);

            CLEAR_BEARER_TIMER(bearer->t3489);

            h.type = e->nas_type;

            if (h.integrity_protected == 0) {
                ogs_error("[%s] No Integrity Protected", mme_ue->imsi_bcd);

                r = nas_eps_send_attach_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED,
                        OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
                ogs_expect(r == OGS_OK);
                r = s1ap_send_ue_context_release_command(enb_ue,
                        S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
                        S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0);
                ogs_expect(r == OGS_OK);
                OGS_FSM_TRAN(s, &esm_state_exception);
                break;
            }

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                ogs_warn("[%s] No Security Context", mme_ue->imsi_bcd);

                r = nas_eps_send_attach_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED,
                        OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
                ogs_expect(r == OGS_OK);
                r = s1ap_send_ue_context_release_command(enb_ue,
                        S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
                        S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0);
                ogs_expect(r == OGS_OK);
                OGS_FSM_TRAN(s, &esm_state_exception);
                break;
            }

            rv = esm_handle_information_response(
                    enb_ue, sess, &message->esm.esm_information_response);
            if (rv != OGS_OK) {
                OGS_FSM_TRAN(s, esm_state_exception);
                break;
            }
            break;
        case OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT:
            ogs_debug("Activate default EPS bearer context accept");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            CLEAR_BEARER_TIMER(bearer->t_bearer_setup);
            /* Check if Initial Context Setup Response or 
             *          E-RAB Setup Response is received */
            if (MME_HAVE_ENB_S1U_PATH(bearer)) {
                ogs_list_init(&mme_ue->bearer_to_modify_list);
                ogs_list_add(&mme_ue->bearer_to_modify_list,
                                &bearer->to_modify_node);
                if (mme_gtp_send_modify_bearer_request(
                            enb_ue, mme_ue, 0, 0) != OGS_OK)
                    ogs_error("[%s] Modify Bearer Request failed on default "
                            "bearer accept EBI[%d]",
                            mme_ue->imsi_bcd, bearer->ebi);
            }

            nas_eps_send_activate_all_dedicated_bearers(bearer);
            OGS_FSM_TRAN(s, esm_state_active);
            break;
        case OGS_NAS_EPS_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT:
            mme_ue_info(mme_ue, NULL, "esm",
                    sess->session ? sess->session->name : NULL,
                    "Dedicated bearer accepted PTI=%d EBI=%d",
                    sess->pti, bearer->ebi);
            CLEAR_BEARER_TIMER(bearer->t_bearer_setup);
            /* Check if Initial Context Setup Response or 
             *          E-RAB Setup Response is received */
            if (MME_HAVE_ENB_S1U_PATH(bearer)) {
                if (mme_gtp_send_create_bearer_response(
                            bearer,
                            OGS_GTP2_CAUSE_REQUEST_ACCEPTED) != OGS_OK)
                    ogs_error("[%s] Create Bearer Response failed on "
                            "dedicated bearer accept EBI[%d]",
                            mme_ue->imsi_bcd, bearer->ebi);
            }

            OGS_FSM_TRAN(s, esm_state_active);
            break;
        case OGS_NAS_EPS_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT:
            activate_dedicated_eps_bearer_context_reject =
                &message->esm.activate_dedicated_eps_bearer_context_reject;
            ogs_assert(activate_dedicated_eps_bearer_context_reject);
            mme_ue_error(mme_ue, NULL, "esm",
                    sess->session ? sess->session->name : NULL,
                    "Dedicated bearer rejected PTI=%d EBI=%d ESM_CAUSE=%d",
                    sess->pti, bearer->ebi,
                    activate_dedicated_eps_bearer_context_reject->esm_cause);
            CLEAR_BEARER_TIMER(bearer->t_bearer_setup);
            if (mme_gtp_send_create_bearer_response(bearer,
                        gtp_cause_from_esm(
                            activate_dedicated_eps_bearer_context_reject->
                                esm_cause)) != OGS_OK)
                ogs_error("[%s] Create Bearer Response failed on dedicated "
                        "bearer reject EBI[%d]",
                        mme_ue->imsi_bcd, bearer->ebi);
            OGS_FSM_TRAN(s, esm_state_bearer_deactivated);
            break;
        case OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT:
            /*
             * TS 24.301 6.4.1.4: the UE rejected the default bearer
             * activation - abort the procedure and tear down the core
             * session; previously this fell into "Unknown message" and
             * the SGW/PGW session leaked until implicit detach.
             */
            mme_ue_error(mme_ue, NULL, "esm",
                    sess->session ? sess->session->name : NULL,
                    "Default bearer rejected PTI=%d EBI=%d ESM_CAUSE=%d",
                    sess->pti, bearer->ebi,
                    message->esm.activate_default_eps_bearer_context_reject.
                        esm_cause);
            CLEAR_BEARER_TIMER(bearer->t_bearer_setup);
            if (MME_HAVE_SGW_S1U_PATH(sess)) {
                sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
                if (!sgw_ue)
                    ogs_warn("[%s] default bearer reject: sgw_ue gone",
                            mme_ue->imsi_bcd);
                else if (mme_gtp_send_delete_session_request(
                            enb_ue, sgw_ue, sess,
                            OGS_GTP_DELETE_NO_ACTION) != OGS_OK)
                    ogs_error("[%s] Delete Session Request failed on default "
                            "bearer reject EBI[%d]",
                            mme_ue->imsi_bcd, bearer->ebi);
            }
            OGS_FSM_TRAN(s, esm_state_exception);
            break;
        default:
            ogs_error("[%s] Unknown/unsupported ESM type[%d] in inactive "
                    "state PTI[%d] EBI[%d] — ignoring "
                    "(garbled NAS or unexpected procedure; no action)",
                    mme_ue->imsi_bcd, message->esm.h.message_type,
                    sess->pti, bearer->ebi);
            break;
        }
        break;
    case MME_EVENT_ESM_TIMER:
        switch (e->timer_id) {
        case MME_TIMER_T3489:
            if (bearer->t3489.retry_count >=
                    mme_timer_cfg(MME_TIMER_T3489)->max_count) {
                ogs_warn("Retransmission of IMSI[%s] failed. "
                        "Stop retransmission", mme_ue->imsi_bcd);
                OGS_FSM_TRAN(&bearer->sm, &esm_state_exception);

                r = nas_eps_send_pdn_connectivity_reject(sess,
                        OGS_NAS_ESM_CAUSE_ESM_INFORMATION_NOT_RECEIVED,
                        e->create_action);
                if (r != OGS_OK)
                    ogs_warn("[%s] PDN connectivity reject send failed "
                            "(no S1?)", mme_ue->imsi_bcd);
            } else {
                bearer->t3489.retry_count++;
                r = nas_eps_send_esm_information_request(bearer);
                if (r != OGS_OK)
                    ogs_warn("[%s] ESM information request retransmit failed "
                            "(no S1?)", mme_ue->imsi_bcd);
            }
            break;
        case MME_TIMER_BEARER_SETUP:
            esm_handle_bearer_setup_timer(s, mme_ue, sess, bearer);
            break;
        case MME_TIMER_NAS_DEACTIVATE_BEARER:
            /*
             * The bearer went back to inactive (e.g. a new PDN
             * Connectivity re-purposed it) while the NAS-Deactivate
             * watchdog was still armed from the aborted deactivation.
             * The procedure is moot - just disarm; previously this
             * fell into "Unknown timer" ERROR spam.
             */
            ogs_debug("[%s] stale NAS-Deactivate watchdog in inactive "
                    "state; disarming (EBI=%d)",
                    mme_ue->imsi_bcd, bearer->ebi);
            CLEAR_BEARER_TIMER(bearer->t_nas_deactivate);
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    mme_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    default:
        ogs_error("Unknown event %s", mme_event_get_name(e));
        break;
    }
}

void esm_state_active(ogs_fsm_t *s, mme_event_t *e)
{
    int r, rv;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;
    ogs_nas_eps_message_t *message = NULL;

    ogs_assert(s);
    ogs_assert(e);

    mme_sm_debug(e);

    ESM_FIND_CTX_OR_RETURN(e, bearer, sess, mme_ue);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    case MME_EVENT_ESM_MESSAGE:
        message = e->nas_message;
        ogs_assert(message);

        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!enb_ue)
            ogs_warn("No eNB-UE context; dropping ESM message(type:%d) "
                    "IMSI[%s] PTI[%d] EBI[%d]",
                    message->esm.h.message_type,
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);

        switch (message->esm.h.message_type) {
        case OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST:
            ogs_debug("PDN Connectivity request");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            rv = esm_handle_pdn_connectivity_request(
                    enb_ue, bearer, &message->esm.pdn_connectivity_request,
                    e->create_action);
            if (rv != OGS_OK) {
                OGS_FSM_TRAN(s, esm_state_exception);
                break;
            }

            OGS_FSM_TRAN(s, esm_state_inactive);
            break;
        case OGS_NAS_EPS_PDN_DISCONNECT_REQUEST:
            ogs_debug("PDN disconnect request");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);

            if (MME_HAVE_SGW_S1U_PATH(sess)) {
                sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
                if (!sgw_ue) {
                    ogs_warn("[%s] PDN disconnect: sgw_ue gone",
                            mme_ue->imsi_bcd);
                    OGS_FSM_TRAN(s, esm_state_exception);
                    break;
                }

                if (mme_gtp_send_delete_session_request(enb_ue, sgw_ue, sess,
                            OGS_GTP_DELETE_SEND_DEACTIVATE_BEARER_CONTEXT_REQUEST)
                        != OGS_OK)
                    ogs_error("[%s] Delete Session Request failed on PDN "
                            "disconnect (active) EBI[%d]",
                            mme_ue->imsi_bcd, bearer->ebi);
            } else {
                r = nas_eps_send_deactivate_bearer_context_request(
                        bearer, OGS_NAS_ESM_CAUSE_REGULAR_DEACTIVATION);
                ogs_expect(r == OGS_OK);
            }

            CLEAR_SGW_S1U_PATH(sess);

            OGS_FSM_TRAN(s, esm_state_pdn_will_disconnect);
            break;

        case OGS_NAS_EPS_MODIFY_EPS_BEARER_CONTEXT_ACCEPT:
            ogs_debug("Modify EPS bearer context accept");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);

            if (mme_gtp_send_update_bearer_response(
                        bearer, OGS_GTP2_CAUSE_REQUEST_ACCEPTED) != OGS_OK)
                ogs_error("[%s] Update Bearer Response failed on modify "
                        "bearer accept EBI[%d]",
                        mme_ue->imsi_bcd, bearer->ebi);
            break;
        case OGS_NAS_EPS_DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT:
            ogs_debug("Deactivate EPS bearer "
                    "context accept");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            CLEAR_BEARER_TIMER(bearer->t_nas_deactivate);
            /* Only answer a network-initiated Delete Bearer Request.
             * UE-initiated PDN disconnect has no pending S11 xact. */
            if (mme_gtp_send_delete_bearer_response(
                    bearer, OGS_GTP2_CAUSE_REQUEST_ACCEPTED) != OGS_OK)
                ogs_error("[%s] Delete Bearer Response not sent EBI[%d]",
                        mme_ue->imsi_bcd, bearer->ebi);
            OGS_FSM_TRAN(s, esm_state_bearer_deactivated);
            break;
        case OGS_NAS_EPS_BEARER_RESOURCE_ALLOCATION_REQUEST:
            ogs_debug("Bearer resource allocation request");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            esm_handle_bearer_resource_allocation_request(
                    enb_ue, bearer, message);
            break;
        case OGS_NAS_EPS_BEARER_RESOURCE_MODIFICATION_REQUEST:
            ogs_debug("Bearer resource modification request");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            esm_handle_bearer_resource_modification_request(
                    enb_ue, bearer, message);
            break;
        case OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT:
        case OGS_NAS_EPS_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT:
            /*
             * Duplicate accept - valid per TS 24.301 6.4.1.5/6.4.2.5:
             * the UE answers every (re)transmitted ACTIVATE ... BEARER
             * CONTEXT REQUEST. When our retransmission crosses the
             * UE's first accept in flight, the second accept arrives
             * after the bearer already went ACTIVE. The procedure was
             * completed by the first accept; just absorb it.
             */
            ogs_debug("Duplicate bearer context accept(type:%d) ignored "
                    "IMSI[%s] PTI[%d] EBI[%d]",
                    message->esm.h.message_type,
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            CLEAR_BEARER_TIMER(bearer->t_bearer_setup);
            break;
        default:
            ogs_error("[%s] Unknown/unsupported ESM type[%d] in active "
                    "state PTI[%d] EBI[%d] — ignoring "
                    "(garbled NAS or unexpected procedure; no action)",
                    mme_ue->imsi_bcd, message->esm.h.message_type,
                    sess->pti, bearer->ebi);
            break;
        }
        break;
    case MME_EVENT_ESM_TIMER:
        switch (e->timer_id) {
        case MME_TIMER_NAS_DEACTIVATE_BEARER:
            if (bearer->t_nas_deactivate.retry_count >=
                    mme_timer_cfg(MME_TIMER_NAS_DEACTIVATE_BEARER)->max_count) {
            /*
             * The UE never answered our DEACTIVATE EPS BEARER CONTEXT
             * REQUEST. Give up and send the Delete Bearer Response to
             * SGW/SMF so the network side can complete the teardown.
             * This unblocks PGW-initiated bearer deactivation (e.g.
             * RADIUS Packet of Disconnect) when the UE is unreachable.
             *
             * We use REQUEST_ACCEPTED so the SMF drives the normal
             * PFCP-session-deletion chain - the bearer IS being
             * deactivated on the core side regardless of what the UE
             * thinks. The UE context will be released by the regular
             * inactivity / implicit-detach mechanisms.
             */
            ogs_warn("[%s] NAS-Deactivate watchdog fired "
                    "(EBI=%d, PTI=%d): UE did not acknowledge "
                    "DEACTIVATE EPS BEARER CONTEXT REQUEST",
                    mme_ue->imsi_bcd, bearer->ebi, sess->pti);

            /*
             * Only synthesize a Delete Bearer Response when the
             * Deactivate procedure was started by a PGW-initiated
             * Delete Bearer Request (i.e. there is a pending GTP
             * transaction on bearer->delete.xact_id). For other
             * code paths (e.g. internal bearer cleanup) we just
             * give up waiting and transition the bearer FSM.
             */
            if (bearer->delete.xact_id >= OGS_MIN_POOL_ID &&
                    bearer->delete.xact_id <= OGS_MAX_POOL_ID) {
                ogs_warn("[%s] sending synthetic Delete Bearer "
                        "Response to SGW/SMF (xact_id=%d) to unblock "
                        "network-initiated teardown",
                        mme_ue->imsi_bcd, (int)bearer->delete.xact_id);
                if (mme_gtp_send_delete_bearer_response(
                        bearer, OGS_GTP2_CAUSE_REQUEST_ACCEPTED) != OGS_OK)
                    ogs_error("[%s] synthetic Delete Bearer Response "
                            "not sent EBI[%d]",
                            mme_ue->imsi_bcd, bearer->ebi);
            }
            OGS_FSM_TRAN(s, esm_state_bearer_deactivated);
            } else {
                bearer->t_nas_deactivate.retry_count++;
                r = nas_eps_resend_deactivate_bearer_context_request(bearer);
                ogs_expect(r == OGS_OK);
            }
            break;
        case MME_TIMER_BEARER_SETUP:
            esm_handle_bearer_setup_timer(s, mme_ue, sess, bearer);
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    mme_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    default:
        ogs_error("Unknown event %s", mme_event_get_name(e));
        break;
    }
}

void esm_state_pdn_will_disconnect(ogs_fsm_t *s, mme_event_t *e)
{
    int rv;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;
    ogs_nas_eps_message_t *message = NULL;

    ogs_assert(s);
    ogs_assert(e);

    mme_sm_debug(e);

    ESM_FIND_CTX_OR_RETURN(e, bearer, sess, mme_ue);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    case MME_EVENT_ESM_MESSAGE:
        message = e->nas_message;
        ogs_assert(message);

        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!enb_ue)
            ogs_warn("No eNB-UE context; dropping ESM message(type:%d) "
                    "IMSI[%s] PTI[%d] EBI[%d]",
                    message->esm.h.message_type,
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);

        switch (message->esm.h.message_type) {
        case OGS_NAS_EPS_DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT:
            ogs_debug("[D] Deactivate EPS bearer "
                    "context accept");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            CLEAR_BEARER_TIMER(bearer->t_nas_deactivate);
            OGS_FSM_TRAN(s, esm_state_pdn_did_disconnect);
            break;
        case OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST:
            ogs_debug("PDN Connectivity request");
            ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            rv = esm_handle_pdn_connectivity_request(
                    enb_ue, bearer, &message->esm.pdn_connectivity_request,
                    e->create_action);
            if (rv != OGS_OK) {
                OGS_FSM_TRAN(s, esm_state_exception);
                break;
            }

            OGS_FSM_TRAN(s, esm_state_inactive);
            break;
        case OGS_NAS_EPS_PDN_DISCONNECT_REQUEST:
            /*
             * TS 24.301 6.5.2: the UE retransmits PDN Disconnect on T3492
             * until it sees the Deactivate EPS Bearer Context Request. The
             * disconnect is already in progress here (Delete Session /
             * NAS-Deactivate in flight), so absorb the duplicate instead of
             * starting a second teardown.
             */
            ogs_debug("Duplicate PDN disconnect request ignored "
                    "IMSI[%s] PTI[%d] EBI[%d]",
                    mme_ue->imsi_bcd, sess->pti, bearer->ebi);
            break;
        default:
            ogs_error("[%s] Unknown/unsupported ESM type[%d] "
                    "PTI[%d] EBI[%d] — ignoring "
                    "(garbled NAS or unexpected procedure; no action)",
                    mme_ue->imsi_bcd, message->esm.h.message_type,
                    sess->pti, bearer->ebi);
            break;
        }
        break;

    case MME_EVENT_ESM_TIMER:
        switch (e->timer_id) {
        case MME_TIMER_NAS_DEACTIVATE_BEARER:
            /*
             * UE never acknowledged NAS Deactivate during UE-initiated
             * PDN Disconnect. The SGW/SMF is already being torn down
             * via the normal Delete Session path, so we don't need to
             * synthesize a Delete Bearer Response here - just move on.
             */
            ogs_warn("[%s] NAS-Deactivate watchdog fired in "
                    "pdn_will_disconnect (EBI=%d): UE did not ack; "
                    "proceeding with local bearer cleanup",
                    mme_ue->imsi_bcd, bearer->ebi);
            OGS_FSM_TRAN(s, esm_state_pdn_did_disconnect);
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    mme_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;

    default:
        ogs_error("Unknown event %s", mme_event_get_name(e));
        break;
    }
}

void esm_state_pdn_did_disconnect(ogs_fsm_t *s, mme_event_t *e)
{
    ogs_assert(e);
    mme_sm_debug(e);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    default:
        /* ESM message for a disconnected PDN - drop it */
        ogs_warn("ESM pdn-did-disconnect: event %s ignored",
                mme_event_get_name(e));
        break;
    }
}

void esm_state_bearer_deactivated(ogs_fsm_t *s, mme_event_t *e)
{
    ogs_assert(e);
    mme_sm_debug(e);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    default:
        /* ESM message for a deactivated bearer - drop it */
        ogs_warn("ESM bearer-deactivated: event %s ignored",
                mme_event_get_name(e));
        break;
    }
}

void esm_state_exception(ogs_fsm_t *s, mme_event_t *e)
{
    mme_bearer_t *bearer = NULL;
    ogs_assert(e);
    mme_sm_debug(e);

    bearer = mme_bearer_find_by_id(e->bearer_id);
    if (!bearer) {
        ogs_warn("ESM exception: bearer id=%d gone (event %s)",
                e->bearer_id, mme_event_get_name(e));
        return;
    }

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        CLEAR_BEARER_ALL_TIMERS(bearer);
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    default:
        /* ESM message for a bearer already in exception (procedure
         * aborted) - drop it; nothing actionable */
        ogs_warn("ESM exception: event %s ignored", mme_event_get_name(e));
        break;
    }
}
