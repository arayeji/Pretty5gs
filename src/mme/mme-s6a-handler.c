/*
 * Copyright (C) 2019-2024 by Sukchan Lee <acetcom@gmail.com>
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

#include "nas-path.h"
#include "s1ap-path.h"
#include "sgsap-path.h"
#include "mme-path.h"
#include "mme-trace.h"
#include "mme-inbound-roam-apn.h"

#include "mme-sm.h"
#include "mme-s6a-handler.h"
#include "mme-fd-path.h"
#include "mme-ambr.h"
#include "mme-pgw-host.h"

/* Unfortunately fd doesn't distinguish
 * between result-code and experimental-result-code.
 *
 * However, e.g. 5004 has different meaning
 * if used in result-code than in experimental-result-code */
static uint8_t emm_cause_from_diameter(
                const uint32_t *dia_err, const uint32_t *dia_exp_err);

static uint8_t mme_ue_session_from_slice_data(mme_ue_t *mme_ue,
    ogs_slice_data_t *slice_data);

uint8_t mme_s6a_handle_aia(
        mme_ue_t *mme_ue, ogs_diam_s6a_message_t *s6a_message)
{
    ogs_diam_s6a_aia_message_t *aia_message = NULL;
    ogs_diam_e_utran_vector_t *e_utran_vector = NULL;

    ogs_assert(mme_ue);
    ogs_assert(s6a_message);
    aia_message = &s6a_message->aia_message;
    ogs_assert(aia_message);
    e_utran_vector = &aia_message->e_utran_vector;
    ogs_assert(e_utran_vector);

    if (s6a_message->result_code != ER_DIAMETER_SUCCESS) {
        ogs_mme_trace_set(
                enb_ue_find_by_id(mme_ue->enb_ue_id), mme_ue, NULL, "s6a");
        ogs_warn("[%s] S6a AIA failed result=%d",
                mme_ue->imsi_bcd, s6a_message->result_code);
        mme_ue_progress(mme_ue, "s6a_aia_fail");
        return emm_cause_from_diameter(s6a_message->err, s6a_message->exp_err);
    }

    mme_ue_progress(mme_ue, "s6a_aia_ok");

    mme_ue->xres_len = e_utran_vector->xres_len;
    memcpy(mme_ue->xres, e_utran_vector->xres, mme_ue->xres_len);
    memcpy(mme_ue->kasme, e_utran_vector->kasme, OGS_SHA256_DIGEST_SIZE);
    memcpy(mme_ue->rand, e_utran_vector->rand, OGS_RAND_LEN);
    memcpy(mme_ue->autn, e_utran_vector->autn, OGS_AUTN_LEN);

    CLEAR_MME_UE_TIMER(mme_ue->t3460);

    if (mme_ue->nas_eps.mme.ksi < (OGS_NAS_KSI_NO_KEY_IS_AVAILABLE - 1))
        mme_ue->nas_eps.mme.ksi++;
    else
        mme_ue->nas_eps.mme.ksi = 0;

    mme_ue->nas_eps.ue.ksi = mme_ue->nas_eps.mme.ksi;

    return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;
}

uint8_t mme_s6a_handle_ula(
        mme_ue_t *mme_ue, ogs_diam_s6a_message_t *s6a_message)
{
    ogs_diam_s6a_ula_message_t *ula_message = NULL;
    ogs_subscription_data_t *subscription_data = NULL;
    ogs_slice_data_t *slice_data = NULL;
    int r, rv, num_of_session;

    ogs_assert(mme_ue);
    ogs_assert(s6a_message);
    ula_message = &s6a_message->ula_message;
    ogs_assert(ula_message);
    subscription_data = &ula_message->subscription_data;
    ogs_assert(subscription_data);

    if (s6a_message->result_code != ER_DIAMETER_SUCCESS) {
        /* Per-subscriber HSS reject (5420 unknown-EPS-subscription,
         * 5004 roaming-not-allowed, ...) - normal outcome for roamers
         * and unprovisioned SIMs, not an MME error. */
        ogs_warn("[%s] S6a ULA failed result=%d",
                mme_ue->imsi_bcd, s6a_message->result_code);
        mme_ue_progress(mme_ue, "s6a_ula_fail");
        return emm_cause_from_diameter(s6a_message->err, s6a_message->exp_err);
    }

    mme_ue_progress(mme_ue, "s6a_ula_ok");

    ogs_assert(subscription_data->num_of_slice == 1);
    slice_data = &subscription_data->slice[0];

    mme_pgw_host_resolve_pending_sessions(slice_data);

    if (ula_message->subdatamask & OGS_DIAM_S6A_SUBDATA_SUB_STATUS) {
        mme_ue->subscriber_status = subscription_data->subscriber_status;
        mme_ue->subscriber_status_presence = true;
        if (mme_ue->subscriber_status !=
                OGS_SUBSCRIBER_STATUS_SERVICE_GRANTED) {
            ogs_error("Subscriber-Status not SERVICE_GRANTED [%u]",
                    mme_ue->subscriber_status);
            return OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED;
        }
    }

    if (ula_message->subdatamask & OGS_DIAM_S6A_SUBDATA_OP_DET_BARRING) {
        mme_ue->operator_determined_barring =
            subscription_data->operator_determined_barring;
        mme_ue->operator_determined_barring_presence = true;
        if (mme_ue->operator_determined_barring &
                OGS_OP_DET_BARRING_ALL_PS_BARRED) {
            ogs_error("Operator Determined Barring: all PS barred");
            return OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED;
        }
    }

    if (ula_message->subdatamask & OGS_DIAM_S6A_SUBDATA_ARD) {
        mme_ue->access_restriction_data =
            subscription_data->access_restriction_data;
        mme_ue->access_restriction_data_presence = true;
        if (mme_ue->access_restriction_data &
                OGS_ACCESS_RESTRICTION_WB_E_UTRAN_NOT_ALLOWED) {
            ogs_error("Access-Restriction-Data: E-UTRAN not allowed");
            return OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED;
        }
    }

    if (subscription_data->ics_indicator_presence) {
        mme_ue->ics_indicator = subscription_data->ics_indicator;
        mme_ue->ics_indicator_presence = true;
    }

    mme_ue->subscribed_rau_tau_timer =
        subscription_data->subscribed_rau_tau_timer;
    mme_ue->maximum_apn_restriction = OGS_GTP2_APN_NO_RESTRICTION;

    memcpy(&mme_ue->ambr, &subscription_data->ambr, sizeof(ogs_bitrate_t));
    mme_ambr_apply_config(&mme_ue->ambr);

    mme_session_remove_all(mme_ue);

    num_of_session = mme_ue_session_from_slice_data(mme_ue, slice_data);
    if (num_of_session == 0) {
        ogs_warn("[%s] No usable session from HSS subscription "
                "(APN configs:%d, all filtered or invalid) - "
                "rejecting with severe network failure",
                mme_ue->imsi_bcd, slice_data->num_of_session);
        return OGS_NAS_EMM_CAUSE_SEVERE_NETWORK_FAILURE;
    }
    mme_ue->num_of_session = num_of_session;

    mme_ue->context_identifier = slice_data->context_identifier;

    if (mme_ue->nas_eps.type == MME_EPS_TYPE_ATTACH_REQUEST) {
        rv = nas_eps_send_emm_to_esm(mme_ue,
                &mme_ue->pdn_connectivity_request);
        if (rv != OGS_OK) {
            ogs_error("nas_eps_send_emm_to_esm() failed");
            return OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED;
        }
    } else if (mme_ue->nas_eps.type == MME_EPS_TYPE_TAU_REQUEST) {
        if (!SESSION_CONTEXT_IS_AVAILABLE(mme_ue)) {
            /*
             * Identified/authenticated after foreign-GUTI TAU, but no SGW
             * session (S10 context transfer not available). #10 drives the
             * UE to Attach and build a fresh PDN context.
             */
            ogs_warn("No PDN Connection after TAU Identity/Auth : UE[%s] - "
                    "Implicitly detached", mme_ue->imsi_bcd);
            return OGS_NAS_EMM_CAUSE_IMPLICITLY_DETACHED;
        }

        if (!ACTIVE_EPS_BEARERS_IS_AVAIABLE(mme_ue)) {
            ogs_warn("No active EPS bearers : IMSI[%s]", mme_ue->imsi_bcd);
            return OGS_NAS_EMM_CAUSE_NO_EPS_BEARER_CONTEXT_ACTIVATED;
        }

        /* Determine S1AP procedure and store it for reuse */
        mme_ue->tracking_area_update_accept_proc =
            S1AP_ProcedureCode_id_InitialContextSetup;

        /* Update CSMAP from Tracking area update request */
        mme_ue->csmap = mme_csmap_find_for_ue(mme_ue);
        if (mme_ue->csmap &&
            mme_ue->network_access_mode ==
                OGS_NETWORK_ACCESS_MODE_PACKET_AND_CIRCUIT &&
            (mme_ue->nas_eps.update.value ==
             OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING ||
             mme_ue->nas_eps.update.value ==
             OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING_WITH_IMSI_ATTACH)) {

            if (sgsap_send_location_update_request(mme_ue) != OGS_OK) {
                /*
                 * SGs/VLR association down or send failed. Do not abort the
                 * MME (this was ogs_assert()). Return "CS domain not
                 * available"; the caller (OGS_DIAM_S6A_CMD_CODE_UPDATE_LOCATION
                 * in mme-sm.c) sends a TAU reject and releases the context.
                 */
                ogs_error("[%s] Combined TAU(ULA): SGsAP Location-Update not "
                        "sent (VLR/SGs unavailable)", mme_ue->imsi_bcd);
                return OGS_NAS_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE;
            }

        } else {
            ogs_info("[%s] TAU accept(Diameter ULA)", mme_ue->imsi_bcd);
            r = nas_eps_send_tau_accept(mme_ue,
                    mme_ue->tracking_area_update_accept_proc);
            ogs_expect(r == OGS_OK);
        }
    } else {
        ogs_error("Invalid Type[%d]", mme_ue->nas_eps.type);
        return OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED;
    }

    return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;
}

uint8_t mme_s6a_handle_pua(
        mme_ue_t *mme_ue, ogs_diam_s6a_message_t *s6a_message)
{
    ogs_diam_s6a_pua_message_t *pua_message = NULL;

    ogs_assert(mme_ue);
    ogs_assert(s6a_message);
    pua_message = &s6a_message->pua_message;
    ogs_assert(pua_message);

    if (s6a_message->result_code != ER_DIAMETER_SUCCESS) {
        ogs_error("Purge UE failed for IMSI[%s] [%d]", mme_ue->imsi_bcd,
            s6a_message->result_code);
        mme_ue_remove(mme_ue);
        return OGS_ERROR;
    }

    if (pua_message->pua_flags & OGS_DIAM_S6A_PUA_FLAGS_FREEZE_MTMSI)
        ogs_debug("Freeze M-TMSI requested but not implemented.");

    mme_ue_remove(mme_ue);

    return OGS_OK;
}

uint8_t mme_s6a_handle_idr(
        mme_ue_t *mme_ue, ogs_diam_s6a_message_t *s6a_message)
{
    ogs_diam_s6a_idr_message_t *idr_message = NULL;
    ogs_subscription_data_t *subscription_data = NULL;
    ogs_slice_data_t *slice_data = NULL;
    int num_of_session;

    ogs_assert(mme_ue);
    ogs_assert(s6a_message);
    idr_message = &s6a_message->idr_message;
    ogs_assert(idr_message);
    subscription_data = &idr_message->subscription_data;
    ogs_assert(subscription_data);

    if (idr_message->subdatamask & OGS_DIAM_S6A_SUBDATA_UEAMBR) {
        memcpy(&mme_ue->ambr, &subscription_data->ambr, sizeof(ogs_bitrate_t));
        mme_ambr_apply_config(&mme_ue->ambr);
    }

    if (idr_message->subdatamask & OGS_DIAM_S6A_SUBDATA_APN_CONFIG) {
        ogs_assert(subscription_data->num_of_slice == 1);
        slice_data = &subscription_data->slice[0];

        mme_pgw_host_resolve_pending_sessions(slice_data);

        if (slice_data->all_apn_config_inc ==
                OGS_ALL_APN_CONFIGURATIONS_INCLUDED) {
            mme_session_remove_all(mme_ue);
            num_of_session = mme_ue_session_from_slice_data(mme_ue, slice_data);
            if (num_of_session == 0) {
                ogs_warn("[%s] IDR: no usable session from HSS "
                        "subscription (APN configs:%d)",
                        mme_ue->imsi_bcd, slice_data->num_of_session);
                return OGS_ERROR;
            }
            mme_ue->num_of_session = num_of_session;
        } else {
            ogs_error ("[%d] Partial APN-Configuration Not Supported in IDR.",
                        slice_data->all_apn_config_inc);
            return OGS_ERROR;
        }

        mme_ue->context_identifier = slice_data->context_identifier;
    }

    /*
     * T-ADS UE Reachability (URRP-MME), 3GPP TS 23.272 / TS 29.272.
     *
     * The HSS arms URRP-MME with an S6a IDR carrying the UE-Reachability
     * IDR-Flag when an IMS Application Server (Kamailio S-CSCF/TAS) needs to
     * know when an unregistered/idle UE becomes reachable for terminating
     * access domain selection.
     *
     *  - UE already ECM-CONNECTED -> report reachability immediately (NOR).
     *  - UE ECM-IDLE -> page the UE (TS 23.401) and report once it answers
     *    (handled in mme_send_after_paging()).
     */
    if (idr_message->idr_flags & OGS_DIAM_S6A_IDR_FLAGS_UE_REACHABILITY) {
        if (ECM_CONNECTED(mme_ue)) {
            ogs_info("[%s] T-ADS: URRP-MME armed; UE already ECM-CONNECTED, "
                    "reporting reachability now", mme_ue->imsi_bcd);
            mme_ue->urrp_mme = false;
            mme_s6a_send_nor(mme_ue,
                    OGS_DIAM_S6A_NOR_FLAGS_UE_REACHABLE_FROM_MME);
        } else {
            mme_ue->urrp_mme = true;
            if (!MME_PAGING_ONGOING(mme_ue)) {
                int r;
                ogs_info("[%s] T-ADS: URRP-MME armed; UE ECM-IDLE, paging "
                        "for UE reachability", mme_ue->imsi_bcd);
                MME_STORE_PAGING_INFO(mme_ue,
                        MME_PAGING_TYPE_UE_REACHABILITY, NULL);
                r = s1ap_send_paging(mme_ue, S1AP_CNDomain_ps);
                ogs_expect(r == OGS_OK);
            } else {
                ogs_info("[%s] T-ADS: URRP-MME armed; paging already ongoing "
                        "[type=%d], will report on connect",
                        mme_ue->imsi_bcd, mme_ue->paging.type);
            }
        }
    }

    return OGS_OK;
}

void mme_s6a_handle_clr(mme_ue_t *mme_ue, ogs_diam_s6a_message_t *s6a_message)
{
    int r;
    ogs_diam_s6a_clr_message_t *clr_message = NULL;
    ogs_assert(mme_ue);
    ogs_assert(s6a_message);
    clr_message = &s6a_message->clr_message;
    ogs_assert(clr_message);

    if (!mme_ue) {
        ogs_warn("UE(mme-ue) context has already been removed");
        return;
    }

    /*
     * This causes issues in this scenario:
     * 1. UE attaches
     * 2. UE detaches (Airplane Mode)
     * 3. Cancel Location is triggered by HSS
     *
     * If Cancel Locations are performed, UE(mme-ue) context must be removed.
     */
    if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_de_registered)) {
        ogs_warn("UE has already been de-registered");
        mme_ue_remove(mme_ue);
        return;
    }

    /*
     * HSS sends Cancel-Location (MME-Update) to the previous registration when
     * it receives ULR for the same subscriber. On re-attach at this MME the
     * CLR targets the same mme_ue context that is still in attach/TAU.
     *
     * Applying implicit detach here overwrites nas_eps.type with
     * DETACH_REQUEST_TO_UE and tears down the session that attach is creating.
     * Combined attach then crashes in sgsap_handle_location_update_accept when
     * SGs Location Update Accept arrives after create_session_rsp_ok.
     *
     * The in-flight attach/TAU supersedes the old registration; ignore CLR.
     * (Cancel-Location-Answer was already sent in mme-fd-path.c.)
     */
    if (clr_message->cancellation_type == OGS_DIAM_S6A_CT_MME_UPDATE_PROCEDURE ||
        clr_message->cancellation_type == OGS_DIAM_S6A_CT_SGSN_UPDATE_PROCEDURE) {
        if (mme_ue->nas_eps.type == MME_EPS_TYPE_ATTACH_REQUEST ||
            mme_ue->nas_eps.type == MME_EPS_TYPE_TAU_REQUEST) {
            ogs_info("[%s] Ignore CLR(MME-Update) during attach/TAU",
                    mme_ue->imsi_bcd);
            return;
        }
    }

    /* Set EPS Detach */
    memset(&mme_ue->nas_eps.detach, 0, sizeof(ogs_nas_detach_type_t));

    if (clr_message->clr_flags & OGS_DIAM_S6A_CLR_FLAGS_REATTACH_REQUIRED)
        mme_ue->nas_eps.detach.value =
            OGS_NAS_DETACH_TYPE_TO_UE_RE_ATTACH_REQUIRED;
    else
        mme_ue->nas_eps.detach.value =
            OGS_NAS_DETACH_TYPE_TO_UE_RE_ATTACH_NOT_REQUIRED;

    /* 1. MME initiated detach request to the UE.
     *    (nas_eps.type = MME_EPS_TYPE_DETACH_REQUEST_TO_UE)
     * 2. If UE is IDLE, Paging sent to the UE
     * 3. If UE is wake-up, UE will send Server Request.
     *    (nas_eps.type = MME_EPS_TYPE_SERVICE_REQUEST)
     *
     * So, we will lose the MME_EPS_TYPE_DETACH_REQUEST_TO_UE.
     *
     * We need more variable(detach_type)
     * to keep Detach-Type whether UE-initiated or MME-initiaed.  */
    mme_ue->nas_eps.type = MME_EPS_TYPE_DETACH_REQUEST_TO_UE;

    ogs_debug("    OGS_NAS_EPS TYPE[%d]", mme_ue->nas_eps.type);

    switch (clr_message->cancellation_type) {
    case OGS_DIAM_S6A_CT_SUBSCRIPTION_WITHDRAWAL:
        mme_ue->detach_type = MME_DETACH_TYPE_HSS_EXPLICIT;

        /*
         * Before sending Detach-Request,
         * we need to check whether UE is IDLE or not.
         */
        if (ECM_IDLE(mme_ue)) {
            MME_STORE_PAGING_INFO(mme_ue,
                MME_PAGING_TYPE_DETACH_TO_UE, NULL);
            r = s1ap_send_paging(mme_ue, S1AP_CNDomain_ps);
            ogs_expect(r == OGS_OK);
        } else {
            MME_CLEAR_PAGING_INFO(mme_ue);
            r = nas_eps_send_detach_request(mme_ue);
            ogs_expect(r == OGS_OK);
            if (MME_CURRENT_P_TMSI_IS_AVAILABLE(mme_ue)) {
                if (sgsap_send_detach_indication(mme_ue) != OGS_OK) {
                    enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
                    /* VLR/SGs down: continue the EPS-side detach so
                     * the context is not parked forever. */
                    ogs_error("sgsap_send_detach_indication() failed - "
                            "proceeding with EPS detach");
                    if (enb_ue)
                        mme_send_delete_session_or_detach(enb_ue, mme_ue);
                    else
                        ogs_warn("ENB-S1 Context has already been removed");
                }
            } else {
                enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
                if (enb_ue)
                    mme_send_delete_session_or_detach(enb_ue, mme_ue);
                else
                    ogs_warn("ENB-S1 Context has already been removed");
            }
        }
        break;
    case OGS_DIAM_S6A_CT_MME_UPDATE_PROCEDURE:
    case OGS_DIAM_S6A_CT_SGSN_UPDATE_PROCEDURE:
        mme_ue->detach_type = MME_DETACH_TYPE_HSS_IMPLICIT;

        /* 3GPP TS 23.401 D.3.5.5 8), 3GPP TS 23.060 6.9.1.2.2 8):
         * "When the timer described in step 2 is running, the MM and PDP/EPS
         * Bearer Contexts and any affected S-GW resources are removed when the
         * timer expires and the SGSN received a Cancel Location".
         */
        if (mme_ue->gn.t_gn_holding->running) {
            ogs_debug("Gn Holding Timer is running, delay removing UE resources");
            break;
        }

        /*
         * There is no need to send NAS or S1AP message to the UE.
         * So, we don't have to check whether UE is IDLE or not.
         */
        if (MME_CURRENT_P_TMSI_IS_AVAILABLE(mme_ue)) {
            if (sgsap_send_detach_indication(mme_ue) != OGS_OK) {
                enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
                /* VLR/SGs down: continue the EPS-side detach so the
                 * context is not parked forever. */
                ogs_error("sgsap_send_detach_indication() failed - "
                        "proceeding with EPS detach");
                if (enb_ue)
                    mme_send_delete_session_or_detach(enb_ue, mme_ue);
                else
                    ogs_warn("ENB-S1 Context has already been removed");
            }
        } else {
            enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
            if (enb_ue)
                mme_send_delete_session_or_detach(enb_ue, mme_ue);
            else
                ogs_warn("ENB-S1 Context has already been removed");
        }
        break;
    default:
        ogs_error("Unsupported Cancellation-Type [%d]",
            clr_message->cancellation_type);
        break;
    }
}

static uint8_t mme_ue_session_from_slice_data(mme_ue_t *mme_ue,
    ogs_slice_data_t *slice_data)
{
    int i, dst = 0;
    bool default_present = false;

    for (i = 0; i < slice_data->num_of_session; i++) {
        ogs_session_t *src = &slice_data->session[i];

        if (dst >= OGS_MAX_NUM_OF_SESS) {
            ogs_warn("Ignore max session count overflow [%d>=%d]",
                    slice_data->num_of_session, OGS_MAX_NUM_OF_SESS);
            break;
        }

        /*
         * Keep all HSS APNs in the subscription. inbound_roam allowed_apn
         * is enforced only when the UE supplies a non-empty APN IE
         * (PDN Connectivity / ESM Information). Absent/empty APN uses the
         * S6a default and must not have that default stripped here.
         */

        if (src->name) {
            mme_ue->session[dst].name = ogs_strdup(src->name);
            ogs_assert(mme_ue->session[dst].name);
        }

        mme_ue->session[dst].context_identifier = src->context_identifier;
        if (src->context_identifier == slice_data->context_identifier)
            default_present = true;

        if (src->session_type == OGS_PDU_SESSION_TYPE_IPV4 ||
            src->session_type == OGS_PDU_SESSION_TYPE_IPV6 ||
            src->session_type == OGS_PDU_SESSION_TYPE_IPV4V6) {
            mme_ue->session[dst].session_type = src->session_type;
        } else {
            ogs_error("Invalid PDN_TYPE[%d]", src->session_type);
            if (mme_ue->session[dst].name)
                ogs_free(mme_ue->session[dst].name);
            break;
        }
        memcpy(&mme_ue->session[dst].ue_ip, &src->ue_ip,
                sizeof(mme_ue->session[dst].ue_ip));

        memcpy(&mme_ue->session[dst].qos, &src->qos,
                sizeof(mme_ue->session[dst].qos));
        memcpy(&mme_ue->session[dst].ambr, &src->ambr,
                sizeof(mme_ue->session[dst].ambr));

        memcpy(&mme_ue->session[dst].smf_ip, &src->smf_ip,
                sizeof(mme_ue->session[dst].smf_ip));

        memcpy(&mme_ue->session[dst].charging_characteristics,
                &src->charging_characteristics,
                sizeof(mme_ue->session[dst].charging_characteristics));
        mme_ue->session[dst].charging_characteristics_presence =
            src->charging_characteristics_presence;

        mme_ue->session[dst].vplmn_dynamic_address_allowed =
            src->vplmn_dynamic_address_allowed;
        mme_ue->session[dst].pdn_gw_allocation_type =
            src->pdn_gw_allocation_type;

        dst++;
    }

    if (dst > 0 && !default_present)
        slice_data->context_identifier =
                mme_ue->session[0].context_identifier;

    return dst;
}

/* 3GPP TS 29.272 Annex A; Table A.1:
 * Mapping from S6a error codes to NAS Cause Codes */
static uint8_t emm_cause_from_diameter(
                const uint32_t *dia_err, const uint32_t *dia_exp_err)
{
    if (dia_exp_err) {
        switch (*dia_exp_err) {
        case OGS_DIAM_S6A_ERROR_USER_UNKNOWN:                   /* 5001 */
            return OGS_NAS_EMM_CAUSE_EPS_SERVICES_AND_NON_EPS_SERVICES_NOT_ALLOWED;
        case OGS_DIAM_S6A_ERROR_UNKNOWN_EPS_SUBSCRIPTION:       /* 5420 */
            /* FIXME: Error diagnostic? */
            return OGS_NAS_EMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA;
        case OGS_DIAM_S6A_ERROR_RAT_NOT_ALLOWED:                /* 5421 */
            return OGS_NAS_EMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA;
        case OGS_DIAM_S6A_ERROR_ROAMING_NOT_ALLOWED:            /* 5004 */
            return OGS_NAS_EMM_CAUSE_PLMN_NOT_ALLOWED;
            /* return OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED_IN_THIS_PLMN;
             * (ODB_HPLMN_APN) */
            /* return OGS_NAS_EMM_CAUSE_ESM_FAILURE; (ODB_ALL_APN) */
        case OGS_DIAM_S6A_AUTHENTICATION_DATA_UNAVAILABLE:      /* 4181 */
            return OGS_NAS_EMM_CAUSE_NETWORK_FAILURE;
        }
    }
    if (dia_err) {
        switch (*dia_err) {
        case ER_DIAMETER_AUTHORIZATION_REJECTED:                /* 5003 */
        case ER_DIAMETER_UNABLE_TO_DELIVER:                     /* 3002 */
        case ER_DIAMETER_REALM_NOT_SERVED:                      /* 3003 */
            return OGS_NAS_EMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA;
        case ER_DIAMETER_UNABLE_TO_COMPLY:                      /* 5012 */
        case ER_DIAMETER_INVALID_AVP_VALUE:                     /* 5004 */
        case ER_DIAMETER_AVP_UNSUPPORTED:                       /* 5001 */
        case ER_DIAMETER_MISSING_AVP:                           /* 5005 */
        case ER_DIAMETER_RESOURCES_EXCEEDED:                    /* 5006 */
        case ER_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES:             /* 5009 */
            return OGS_NAS_EMM_CAUSE_NETWORK_FAILURE;
        }
    }

    ogs_error("Unexpected Diameter Result Code %d/%d, defaulting to severe "
              "network failure",
              dia_err ? *dia_err : -1, dia_exp_err ? *dia_exp_err : -1);
    return OGS_NAS_EMM_CAUSE_SEVERE_NETWORK_FAILURE;
}
