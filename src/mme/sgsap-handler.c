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

#include "sgsap-types.h"
#include "sgsap-build.h"
#include "sgsap-path.h"
#include "sgsap-handler.h"

#include "mme-sm.h"
#include "mme-context.h"
#include "mme-path.h"
#include "mme-trace.h"
#include "nas-path.h"
#include "s1ap-path.h"

void sgsap_handle_location_update_accept(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf)
{
    int r;
    ogs_tlv_t *root = NULL, *iter = NULL;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;

    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    ogs_nas_mobile_identity_imsi_t *nas_mobile_identity_imsi = NULL;
    int nas_mobile_identity_imsi_len = 0;
    ogs_nas_lai_t *lai = NULL;
    ogs_nas_mobile_identity_tmsi_t *nas_mobile_identity_tmsi = NULL;

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    ogs_debug("[SGSAP] LOCATION-UPDATE-ACCEPT");

    ogs_pkbuf_pull(pkbuf, 1);

    root = ogs_tlv_parse_block(pkbuf->len, pkbuf->data, OGS_TLV_MODE_T1_L1);
    if (!root) {
        ogs_error("ogs_tlv_parse_block() failed");
        goto error;
    }

    iter = root;
    while (iter) {
        switch (iter->type) {
        case SGSAP_IE_IMSI_TYPE:
            nas_mobile_identity_imsi = iter->value;
            nas_mobile_identity_imsi_len = iter->length;
            break;
        case SGSAP_IE_LAI_TYPE:
            lai = iter->value;
            break;
        case SGSAP_IE_MOBILE_IDENTITY_TYPE:
            nas_mobile_identity_tmsi = iter->value;
            break;
        default:
            ogs_warn("Invalid Type [%d]", iter->type);
            break;
        }
        iter = iter->next;
    }

    ogs_tlv_free_all(root);

    if (!nas_mobile_identity_imsi || !lai) {
        ogs_error("!nas_mobile_identity_imsi || !lai");
        goto error;
    }
    if (!SGSAP_IMSI_LEN_OK(nas_mobile_identity_imsi_len)) {
        ogs_error("Invalid IMSI len [%d]", nas_mobile_identity_imsi_len);
        goto error;
    }

    if (nas_mobile_identity_imsi->type == OGS_NAS_MOBILE_IDENTITY_IMSI) {
        ogs_nas_eps_imsi_to_bcd(nas_mobile_identity_imsi,
                nas_mobile_identity_imsi_len, imsi_bcd);
        mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
    } else {
        ogs_error("nas_mobile_identity_imsi->type == "
                "OGS_NAS_MOBILE_IDENTITY_IMSI");
        goto error;
    }

    if (!mme_ue) {
        ogs_error("!mme_ue");
        goto error;
    }

    /*
     * Late / duplicate LU Accept after Ts6-1, Service Request, or S1
     * release must not drive Attach/TAU Accept again.
     */
    if (!mme_ue->sgs_lu_pending) {
        ogs_warn("[%s] Ignoring stale SGsAP Location-Update-Accept "
                "(EPS-Type[%d])",
                mme_ue->imsi_bcd, mme_ue->nas_eps.type);
        return;
    }

    mme_sgs_ts6_1_timer_stop(mme_ue);
    mme_ue->sgs_cs_unavailable = false;

    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!enb_ue) {
        ogs_warn("[%s] SGsAP LU Accept: S1 context already removed",
                mme_ue->imsi_bcd);
        return;
    }

    ogs_info("[%s] SGSAP: Location-Update-Accept", mme_ue->imsi_bcd);
    if (lai) {
        ogs_debug("    LAI[PLMN_ID:%06x,LAC:%d]",
                    ogs_plmn_id_hexdump(&lai->nas_plmn_id), lai->lac);
    }

    if (nas_mobile_identity_tmsi) {
        if (nas_mobile_identity_tmsi->type == OGS_NAS_MOBILE_IDENTITY_TMSI) {
            mme_ue_set_p_tmsi(mme_ue, nas_mobile_identity_tmsi);
        } else {
            ogs_error("Not supported Identity type[%d]",
                    nas_mobile_identity_tmsi->type);
            goto error;
        }
        ogs_debug("    P-TMSI[0x%08x]", mme_ue->next.p_tmsi);
    }

    if (mme_ue->nas_eps.type == MME_EPS_TYPE_ATTACH_REQUEST) {
        mme_ue_progress(mme_ue, "sgsap_lu_accept");
        r = nas_eps_send_attach_accept(mme_ue);
        if (r != OGS_OK)
            mme_send_delete_session_after_attach_accept_fail(enb_ue, mme_ue);
        ogs_expect(r == OGS_OK);
    } else if (mme_ue->nas_eps.type == MME_EPS_TYPE_TAU_REQUEST) {
        if (mme_ue->nas_eps.update.active_flag) {

    /*
     * TS33.401
     * 7 Security procedures between UE and EPS access network elements
     * 7.2 Handling of user-related keys in E-UTRAN
     * 7.2.7 Key handling for the TAU procedure when registered in E-UTRAN
     *
     * If the "active flag" is set in the TAU request message or
     * the MME chooses to establish radio bearers when there is pending downlink
     * UP data or pending downlink signalling, radio bearers will be established
     * as part of the TAU procedure and a KeNB derivation is necessary.
     */
            ogs_kdf_kenb(mme_ue->kasme, mme_ue->ul_count.i32,
                    mme_ue->kenb);
            ogs_kdf_nh_enb(mme_ue->kasme, mme_ue->kenb, mme_ue->nh);
            mme_ue->nhcc = 1;

            ogs_info("[%s] KDF update(active_flag=1)", mme_ue->imsi_bcd);
        }

        /* check BCS regardless of active_flag */
        if (mme_ue->tracking_area_update_request_presencemask &
            OGS_NAS_EPS_TRACKING_AREA_UPDATE_REQUEST_EPS_BEARER_CONTEXT_STATUS_PRESENT) {
            ogs_info("[%s] LU accept + TAU accept(active_flag=%d, BCS)",
                mme_ue->imsi_bcd,
                mme_ue->nas_eps.update.active_flag);
            mme_send_delete_session_or_tau_accept(enb_ue, mme_ue);
        } else {
            ogs_info("[%s] LU accept + TAU accept(active_flag=%d, No BCS)",
                mme_ue->imsi_bcd,
                mme_ue->nas_eps.update.active_flag);
            mme_send_tau_accept_and_check_release(enb_ue, mme_ue);
        }
    } else {
        ogs_warn("[%s] SGsAP LU Accept ignored: unexpected EPS-Type[%d]",
                mme_ue->imsi_bcd, mme_ue->nas_eps.type);
    }

    return;

error:
    /* Clang scan-build SA:
     * NULL pointer dereference: mme_ue=NULL if root=NULL. */
    if (!mme_ue) {
        ogs_error("!mme_ue");
        return;
    }
    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!enb_ue) {
        ogs_warn("ENB-S1 Context has already been removed");
        return;
    }

    if (mme_ue->nas_eps.type == MME_EPS_TYPE_ATTACH_REQUEST) {
        r = nas_eps_send_attach_reject(
                enb_ue, mme_ue,
                OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
        ogs_expect(r == OGS_OK);
    } else if (mme_ue->nas_eps.type == MME_EPS_TYPE_TAU_REQUEST) {
        r = nas_eps_send_tau_reject(
                enb_ue, mme_ue,
                OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
        ogs_expect(r == OGS_OK);
    } else {
        ogs_error("[%s] Invalid EPS-Type[%d]",
                mme_ue->imsi_bcd, mme_ue->nas_eps.type);
    }
    mme_send_delete_session_or_mme_ue_context_release(enb_ue, mme_ue);
}

void sgsap_handle_location_update_reject(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf)
{
    ogs_tlv_t *root = NULL, *iter = NULL;
    mme_ue_t *mme_ue = NULL;

    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    ogs_nas_mobile_identity_imsi_t *nas_mobile_identity_imsi = NULL;
    int nas_mobile_identity_imsi_len = 0;
    ogs_nas_emm_cause_t emm_cause = 0;
    ogs_nas_lai_t *lai = NULL;

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    ogs_warn("[SGSAP] LOCATION-UPDATE-REJECT");

    ogs_pkbuf_pull(pkbuf, 1);

    root = ogs_tlv_parse_block(pkbuf->len, pkbuf->data, OGS_TLV_MODE_T1_L1);
    if (!root) {
        ogs_error("ogs_tlv_parse_block() failed");
        goto error;
    }

    iter = root;
    while (iter) {
        switch (iter->type) {
        case SGSAP_IE_IMSI_TYPE:
            nas_mobile_identity_imsi = iter->value;
            nas_mobile_identity_imsi_len = iter->length;
            break;
        case SGSAP_IE_LAI_TYPE:
            lai = iter->value;
            break;
        case SGSAP_IE_REJECT_CAUSE_TYPE:
            emm_cause = *((uint8_t*)(iter->value));
            break;
        default:
            ogs_warn("Invalid Type [%d]", iter->type);
            break;
        }
        iter = iter->next;
    }

    ogs_tlv_free_all(root);

    if (!nas_mobile_identity_imsi || !emm_cause) {
        ogs_error("!nas_mobile_identity_imsi || !emm_cause");
        goto error;
    }
    if (!SGSAP_IMSI_LEN_OK(nas_mobile_identity_imsi_len)) {
        ogs_error("Invalid IMSI len [%d]", nas_mobile_identity_imsi_len);
        goto error;
    }

    if (nas_mobile_identity_imsi->type == OGS_NAS_MOBILE_IDENTITY_IMSI) {
        ogs_nas_eps_imsi_to_bcd(nas_mobile_identity_imsi,
                nas_mobile_identity_imsi_len, imsi_bcd);
        mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
    } else {
        ogs_error("nas_mobile_identity_imsi->type == "
                    "OGS_NAS_MOBILE_IDENTITY_IMSI");
        goto error;
    }

    if (!mme_ue) {
        /* VLR LU-Reject after MME already dropped the UE — expected. */
        ogs_warn("[SGSAP] LOCATION-UPDATE-REJECT: no UE context IMSI[%s]",
                imsi_bcd);
        return;
    }

    if (!mme_ue->sgs_lu_pending) {
        ogs_warn("[%s] Ignoring stale SGsAP Location-Update-Reject "
                "(Cause:%d EPS-Type[%d])",
                mme_ue->imsi_bcd, emm_cause, mme_ue->nas_eps.type);
        return;
    }

    ogs_info("[%s] SGSAP: Location-Update-Reject [Cause:%d]",
            mme_ue->imsi_bcd, emm_cause);
    if (lai) {
        ogs_debug("    LAI[PLMN_ID:%06x,LAC:%d]",
                    ogs_plmn_id_hexdump(&lai->nas_plmn_id), lai->lac);
    }

    /* Continue Attach/TAU: fake_csfb → Combined; else EPS-only + #18 */
    mme_sgs_continue_without_cs(mme_ue, "sgsap_lu_reject");
    return;

error:
    ogs_error("Error processing SGsAP LU REJECT");
    return;
}

void sgsap_handle_alert_request(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf)
{
    ogs_tlv_t *root = NULL, *iter = NULL;
    mme_ue_t *mme_ue = NULL;
    uint8_t sgs_cause = SGSAP_SGS_CAUSE_IMSI_UNKNOWN;

    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1] = {0, };

    ogs_nas_mobile_identity_imsi_t *nas_mobile_identity_imsi = NULL;
    int nas_mobile_identity_imsi_len = 0;

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    ogs_warn("[SGSAP] Rx ALERT-REQUEST");

    ogs_pkbuf_pull(pkbuf, 1);

    root = ogs_tlv_parse_block(pkbuf->len, pkbuf->data, OGS_TLV_MODE_T1_L1);
    if (!root) {
        ogs_error("ogs_tlv_parse_block() failed");
        sgs_cause = SGSAP_SGS_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE;
        goto alert_reject;
    }

    iter = root;
    while (iter) {
        switch (iter->type) {
        case SGSAP_IE_IMSI_TYPE:
            nas_mobile_identity_imsi = iter->value;
            nas_mobile_identity_imsi_len = iter->length;
            break;
        default:
            ogs_warn("Invalid Type [%d]", iter->type);
            break;
        }
        iter = iter->next;
    }

    ogs_tlv_free_all(root);

    if (!nas_mobile_identity_imsi) {
        ogs_error("No IMSI");
        sgs_cause = SGSAP_SGS_CAUSE_MISSING_MANDATORY_IE;
        goto alert_reject;
    }
    if (!SGSAP_IMSI_LEN_OK(nas_mobile_identity_imsi_len)) {
        ogs_error("Invalid IMSI len [%d]", nas_mobile_identity_imsi_len);
        sgs_cause = SGSAP_SGS_CAUSE_INVALID_MANDATORY_IE;
        goto alert_reject;
    }

    if (nas_mobile_identity_imsi->type != OGS_NAS_MOBILE_IDENTITY_IMSI) {
        ogs_error("nas_mobile_identity_imsi->type == "
                    "OGS_NAS_MOBILE_IDENTITY_IMSI");
        sgs_cause = SGSAP_SGS_CAUSE_INVALID_MANDATORY_IE;
        goto alert_reject;
    }

    ogs_nas_eps_imsi_to_bcd(nas_mobile_identity_imsi,
                            nas_mobile_identity_imsi_len, imsi_bcd);
    mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);

    if (!mme_ue) {
       /* ALERT for an IMSI we no longer hold — reply IMSI unknown. */
       ogs_warn("[SGSAP] ALERT-REQUEST: no UE context IMSI[%s]", imsi_bcd);
       sgs_cause = SGSAP_SGS_CAUSE_IMSI_UNKNOWN;
       goto alert_reject;
    }

    /* TODO: Set NEAF flag in UE */

    ogs_warn("[SGSAP] Tx ALERT-ACK");

    sgsap_send_to_vlr_with_sid(
        vlr,
        sgsap_build_alert_ack(mme_ue),
        0);
    return;

alert_reject:
    ogs_debug("[SGSAP] Tx ALERT-REJECT");
    ogs_debug("    IMSI[%s]", imsi_bcd);

    sgsap_send_to_vlr_with_sid(
        vlr,
        sgsap_build_alert_reject(
            nas_mobile_identity_imsi, nas_mobile_identity_imsi_len,
            sgs_cause),
        0);
    return;
}

void sgsap_handle_detach_ack(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf)
{
    ogs_tlv_t *root = NULL, *iter = NULL;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;

    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    uint8_t type = 0;
    ogs_nas_mobile_identity_imsi_t *nas_mobile_identity_imsi = NULL;
    int nas_mobile_identity_imsi_len = 0;

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    type = *(unsigned char *)(pkbuf->data);
    if (type == SGSAP_EPS_DETACH_ACK)
        ogs_debug("[SGSAP] EPS-DETACH-ACK");
    else if (type == SGSAP_IMSI_DETACH_ACK)
        ogs_debug("[SGSAP] IMSI-DETACH-ACK");
    else {
        ogs_error("Unknown type [%d]", type);
        return;
    }

    ogs_pkbuf_pull(pkbuf, 1);

    root = ogs_tlv_parse_block(pkbuf->len, pkbuf->data, OGS_TLV_MODE_T1_L1);
    if (!root) {
        ogs_error("ogs_tlv_parse_block() failed");
        return;
    }

    iter = root;
    while (iter) {
        switch (iter->type) {
        case SGSAP_IE_IMSI_TYPE:
            nas_mobile_identity_imsi = iter->value;
            nas_mobile_identity_imsi_len = iter->length;
            break;
        default:
            ogs_warn("Invalid Type [%d]", iter->type);
            break;
        }
        iter = iter->next;
    }

    ogs_tlv_free_all(root);

    if (!nas_mobile_identity_imsi) {
        ogs_error("No IMSI");
        return;
    }
    if (!SGSAP_IMSI_LEN_OK(nas_mobile_identity_imsi_len)) {
        ogs_error("Invalid IMSI len [%d]", nas_mobile_identity_imsi_len);
        return;
    }

    if (nas_mobile_identity_imsi->type == OGS_NAS_MOBILE_IDENTITY_IMSI) {
        ogs_nas_eps_imsi_to_bcd(nas_mobile_identity_imsi,
                nas_mobile_identity_imsi_len, imsi_bcd);
        mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
    } else {
        ogs_error("Unknown type [%d]", nas_mobile_identity_imsi->type);
        return;
    }

    if (!mme_ue) {
        /*
         * DETACH-ACK after MME already removed the UE (local detach
         * finished first). Harmless — nothing left to clear.
         */
        ogs_warn("[SGSAP] %s: no UE context IMSI[%s] "
                "(late ACK after local detach)",
                type == SGSAP_EPS_DETACH_ACK ? "EPS-DETACH-ACK" :
                type == SGSAP_IMSI_DETACH_ACK ? "IMSI-DETACH-ACK" : "DETACH-ACK",
                imsi_bcd);
        return;
    }

    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    /*
     * DETACH-ACK can race with local cleanup that already cleared
     * detach_type. Default to implicit so we never abort the MME.
     */
    if (mme_ue->detach_type == 0) {
        ogs_warn("[%s] SGsAP DETACH-ACK with unset detach_type; "
                "using MME implicit detach", mme_ue->imsi_bcd);
        mme_ue->detach_type = MME_DETACH_TYPE_MME_IMPLICIT;
    }

    /*
     * S1 may already be gone (CLEAR_S1_CONTEXT before SGs indication).
     * Still Delete Session if PDN remains — skipping DSR here was an
     * SGW/PGW leak. If detach already started DSR, sessions/xacts show
     * that and we skip the duplicate.
     */
    if (ogs_list_empty(&mme_ue->sess_list) ||
            MME_SESSION_RELEASE_PENDING(mme_ue) ||
            mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) > 0)
        return;

    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!enb_ue)
        ogs_warn("[%s] SGsAP DETACH-ACK: no S1 context - Delete Session anyway",
                mme_ue->imsi_bcd);
    mme_send_delete_session_or_detach(enb_ue, mme_ue);
}

void sgsap_handle_paging_request(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf)
{
    int r;
    ogs_tlv_t *root = NULL, *iter = NULL;
    mme_ue_t *mme_ue = NULL;
    uint8_t sgs_cause = SGSAP_SGS_CAUSE_IMSI_UNKNOWN;

    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1] = { 0, };

    ogs_nas_mobile_identity_imsi_t *nas_mobile_identity_imsi = NULL;
    int nas_mobile_identity_imsi_len = 0;
    ogs_nas_lai_t *lai = NULL;
    char vlr_name[SGSAP_IE_VLR_NAME_LEN] = { 0, };
    uint8_t *service_indicator = NULL;

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    ogs_debug("[SGSAP] PAGING-REQUEST");

    ogs_pkbuf_pull(pkbuf, 1);

    root = ogs_tlv_parse_block(pkbuf->len, pkbuf->data, OGS_TLV_MODE_T1_L1);
    if (!root) {
        ogs_error("ogs_tlv_parse_block() failed");
        return;
    }

    iter = root;
    while (iter) {
        switch (iter->type) {
        case SGSAP_IE_IMSI_TYPE:
            nas_mobile_identity_imsi = iter->value;
            nas_mobile_identity_imsi_len = iter->length;
            break;
        case SGSAP_IE_VLR_NAME_TYPE:
            if (ogs_fqdn_parse(vlr_name, iter->value,
                ogs_min(iter->length, SGSAP_IE_VLR_NAME_LEN)) <= 0) {
                ogs_error("Invalid VLR-Name");
                sgs_cause = SGSAP_SGS_CAUSE_INVALID_MANDATORY_IE;
                goto paging_reject;
            }
            break;
        case SGSAP_IE_LAI_TYPE:
            lai = iter->value;
            break;
        case SGSAP_IE_SERVICE_INDICATOR_TYPE:
            service_indicator = iter->value;
            break;
        default:
            ogs_warn("Invalid Type [%d]", iter->type);
            break;
        }
        iter = iter->next;
    }

    ogs_tlv_free_all(root);

    if (!nas_mobile_identity_imsi) {
        ogs_error("No IMSI");
        sgs_cause = SGSAP_SGS_CAUSE_MISSING_MANDATORY_IE;
        goto paging_reject;
    }
    if (!SGSAP_IMSI_LEN_OK(nas_mobile_identity_imsi_len)) {
        ogs_error("Invalid IMSI len [%d]", nas_mobile_identity_imsi_len);
        sgs_cause = SGSAP_SGS_CAUSE_INVALID_MANDATORY_IE;
        goto paging_reject;
    }

    if (!service_indicator) {
        ogs_error("No Service indicator");
        sgs_cause = SGSAP_SGS_CAUSE_MISSING_MANDATORY_IE;
        goto paging_reject;
    }

    if (nas_mobile_identity_imsi->type == OGS_NAS_MOBILE_IDENTITY_IMSI) {

        ogs_nas_eps_imsi_to_bcd(nas_mobile_identity_imsi,
                nas_mobile_identity_imsi_len, imsi_bcd);
        mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
    } else {
        ogs_error("Unknown type [%d]", nas_mobile_identity_imsi->type);
            sgs_cause = SGSAP_SGS_CAUSE_INVALID_MANDATORY_IE;
            goto paging_reject;
    }

    if (!mme_ue) {
        sgs_cause = SGSAP_SGS_CAUSE_IMSI_UNKNOWN;
        goto paging_reject;
    }

    switch (*service_indicator) {
    case SGSAP_CS_CALL_SERVICE_INDICATOR:
    case SGSAP_SMS_SERVICE_INDICATOR:
        mme_ue->service_indicator = *service_indicator;
        break;
    default:
        /* 3GPP TS 29.118 9.4.17: Other vals "shall not be sent in this version
         * of the protocol. If received, shall be treated as '00000001'" */
        mme_ue->service_indicator = SGSAP_CS_CALL_SERVICE_INDICATOR;
        break;
    }

    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
    ogs_debug("    VLR_NAME[%s]", vlr_name);
    ogs_debug("    SERVICE_INDICATOR[%d]", mme_ue->service_indicator);

    if (lai) {
        ogs_debug("    LAI[PLMN_ID:%06x,LAC:%d]",
                    ogs_plmn_id_hexdump(&lai->nas_plmn_id), lai->lac);
    }

    /*
     * Treat as idle when ECM-IDLE, when there is no S1, when an S1
     * release is already in flight, or when the eNB SCTP is down.
     * SGsAP Paging can race UEContextReleaseComplete on the main queue
     * (common with mme.workers / separate S1AP vs SGs sockets): treating
     * that UE as CONNECTED skipped S1AP Paging and left the VLR with no
     * Service-Request / Paging-Reject (MSC retries forever).
     */
    {
        enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        mme_enb_t *enb = NULL;
        bool release_pending = enb_ue &&
            enb_ue->ue_ctx_rel_action != S1AP_UE_CTX_REL_INVALID_ACTION;
        bool s1_live = false;
        bool page_as_idle;

        /*
         * SGs paging is IMSI-addressed, so do NOT require a *confirmed*
         * (current) P-TMSI here: the MSC typically pages for a pending MT
         * SMS right after LU-Accept, before the UE has sent Attach/TAU
         * Complete — at that point the reallocated P-TMSI is still in
         * 'next'. Gating on MME_CURRENT_P_TMSI_IS_AVAILABLE (via the
         * CS_CALL/SMS_SERVICE_INDICATOR macros) bounced every such page
         * with the bogus cause 13 "MT CSFB call rejected by user".
         * Accept the association with either a current or a next P-TMSI.
         */
        bool sgs_assoc = MME_SGSAP_IS_CONNECTED(mme_ue) &&
            (mme_ue->current.p_tmsi || mme_ue->next.p_tmsi);

        if (enb_ue)
            enb = mme_enb_find_by_id(enb_ue->enb_id);
        s1_live = enb_ue && enb && enb->sctp.sock &&
            enb->sctp.sock->fd != INVALID_SOCKET;

        page_as_idle = ECM_IDLE(mme_ue) || !enb_ue || release_pending ||
            !s1_live;

        if (!sgs_assoc) {
            ogs_warn("[%s] SGsAP Paging-Request (%s): no SGs association "
                    "(SGs %sconnected, P-TMSI cur=0x%x next=0x%x) — "
                    "Paging-Reject",
                    mme_ue->imsi_bcd,
                    mme_ue->service_indicator ==
                        SGSAP_SMS_SERVICE_INDICATOR ?  "SMS" : "CS",
                    MME_SGSAP_IS_CONNECTED(mme_ue) ? "" : "not ",
                    (unsigned)mme_ue->current.p_tmsi,
                    (unsigned)mme_ue->next.p_tmsi);
            sgs_cause = SGSAP_SGS_CAUSE_IMSI_DETACHED_NON_EPS;
            goto paging_reject;
        }

        if (page_as_idle) {
            /*
             * New SGs-triggered page: drop any stale T3413 state so
             * first-wave / retry accounting starts clean.
             */
            CLEAR_MME_UE_TIMER(mme_ue->t3413);

            if (mme_ue->service_indicator == SGSAP_CS_CALL_SERVICE_INDICATOR) {
                /* UE will respond Extended Service Request in CS CNDomain*/
                MME_STORE_PAGING_INFO(mme_ue,
                    MME_PAGING_TYPE_CS_CALL_SERVICE, NULL);
                ogs_info("[%s] SGsAP Paging-Request (CS): S1AP paging",
                        mme_ue->imsi_bcd);
                r = s1ap_send_paging(mme_ue, S1AP_CNDomain_cs);
            } else {
                /* SMS: UE will respond Service Request in PS CNDomain */
                MME_STORE_PAGING_INFO(mme_ue,
                    MME_PAGING_TYPE_SMS_SERVICE, NULL);
                ogs_info("[%s] SGsAP Paging-Request (SMS): S1AP paging",
                        mme_ue->imsi_bcd);
                r = s1ap_send_paging(mme_ue, S1AP_CNDomain_ps);
            }

            if (r != OGS_OK) {
                ogs_warn("[%s] SGsAP Paging-Request: S1AP paging failed "
                        "(%d) — Paging-Reject to VLR",
                        mme_ue->imsi_bcd, r);
                MME_CLEAR_PAGING_INFO(mme_ue);
                sgs_cause = SGSAP_SGS_CAUSE_UE_UNREACHABLE;
                goto paging_reject;
            }
        } else {
            MME_CLEAR_PAGING_INFO(mme_ue);
            if (mme_ue->service_indicator == SGSAP_CS_CALL_SERVICE_INDICATOR) {
                ogs_info("[%s] SGsAP Paging-Request (CS): UE connected, "
                        "CS Service Notification", mme_ue->imsi_bcd);
                r = nas_eps_send_cs_service_notification(mme_ue);
                ogs_expect(r == OGS_OK);
            } else {
                ogs_info("[%s] SGsAP Paging-Request (SMS): UE connected, "
                        "SGsAP Service-Request", mme_ue->imsi_bcd);
                if (sgsap_send_service_request(
                        mme_ue, SGSAP_EMM_CONNECTED_MODE) != OGS_OK) {
                    /*
                     * VLR/CSMAP/SGs send failed while we still believe
                     * the UE is CONNECTED — fall back to S1 paging so
                     * the MSC is not left without any response path.
                     */
                    ogs_error("[%s] SGsAP Service-Request not sent "
                            "(VLR/SGs/CSMAP unavailable) — "
                            "falling back to S1AP paging",
                            mme_ue->imsi_bcd);
                    CLEAR_MME_UE_TIMER(mme_ue->t3413);
                    MME_STORE_PAGING_INFO(mme_ue,
                            MME_PAGING_TYPE_SMS_SERVICE, NULL);
                    r = s1ap_send_paging(mme_ue, S1AP_CNDomain_ps);
                    if (r != OGS_OK) {
                        MME_CLEAR_PAGING_INFO(mme_ue);
                        sgs_cause = SGSAP_SGS_CAUSE_UE_UNREACHABLE;
                        goto paging_reject;
                    }
                }
            }
        }
    }

    return;

paging_reject:
    ogs_info("[SGSAP] PAGING-REJECT IMSI[%s] cause[%d]",
            imsi_bcd[0] ? imsi_bcd : "-", sgs_cause);

    sgsap_send_to_vlr_with_sid(
        vlr,
        sgsap_build_paging_reject(
            nas_mobile_identity_imsi, nas_mobile_identity_imsi_len,
            sgs_cause),
        0);
}

void sgsap_handle_downlink_unitdata(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf)
{
    int r;
    ogs_tlv_t *root = NULL, *iter = NULL;
    mme_ue_t *mme_ue = NULL;

    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    ogs_nas_mobile_identity_imsi_t *nas_mobile_identity_imsi = NULL;
    int nas_mobile_identity_imsi_len = 0;
    uint8_t *nas_message_container_buffer = NULL;
    uint8_t nas_message_container_length = 0;

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    ogs_debug("[SGSAP] DOWNLINK-UNITDATA");

    ogs_pkbuf_pull(pkbuf, 1);

    root = ogs_tlv_parse_block(pkbuf->len, pkbuf->data, OGS_TLV_MODE_T1_L1);
    if (!root) {
        ogs_error("ogs_tlv_parse_block() failed");
        return;
    }

    iter = root;
    while (iter) {
        switch (iter->type) {
        case SGSAP_IE_IMSI_TYPE:
            nas_mobile_identity_imsi = iter->value;
            nas_mobile_identity_imsi_len = iter->length;
            break;
        case SGSAP_IE_NAS_MESSAGE_CONTAINER_TYPE:
            nas_message_container_buffer = iter->value;
            nas_message_container_length = iter->length;
            break;
        default:
            ogs_warn("Invalid Type [%d]", iter->type);
            break;
        }
        iter = iter->next;
    }

    ogs_tlv_free_all(root);

    if (!nas_mobile_identity_imsi ||
            !SGSAP_IMSI_LEN_OK(nas_mobile_identity_imsi_len)) {
        ogs_error("Invalid IMSI (len=%d)", nas_mobile_identity_imsi_len);
        return;
    }
    if (!nas_message_container_buffer || !nas_message_container_length) {
        ogs_error("No NAS message container");
        return;
    }

    if (nas_mobile_identity_imsi->type == OGS_NAS_MOBILE_IDENTITY_IMSI) {

        ogs_nas_eps_imsi_to_bcd(nas_mobile_identity_imsi,
                nas_mobile_identity_imsi_len, imsi_bcd);
        mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
    } else {
        ogs_error("Unknown mobile identity type [%d]",
                nas_mobile_identity_imsi->type);
        return;
    }

    if (!mme_ue) {
        /* DOWNLINK-UNITDATA for an IMSI already gone — drop. */
        ogs_warn("[SGSAP] DOWNLINK-UNITDATA: no UE context IMSI[%s]",
                imsi_bcd);
        return;
    }

    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
    ogs_log_hexdump(OGS_LOG_DEBUG,
            nas_message_container_buffer,
            nas_message_container_length);

    r = nas_eps_send_downlink_nas_transport(mme_ue,
            nas_message_container_buffer, nas_message_container_length);
    ogs_expect(r == OGS_OK);
}

void sgsap_handle_reset_indication(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf)
{
    ogs_debug("[SGSAP] RESET-INDICATION");

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    if (sgsap_send_reset_ack(vlr) != OGS_OK)
        ogs_error("sgsap_send_reset_ack() failed");
}

void sgsap_handle_release_request(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf)
{
    ogs_tlv_t *root = NULL, *iter = NULL;
    mme_ue_t *mme_ue = NULL;

    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    ogs_nas_mobile_identity_imsi_t *nas_mobile_identity_imsi = NULL;
    int nas_mobile_identity_imsi_len = 0;

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    ogs_debug("[SGSAP] RELEASE-REQUEST");

    ogs_pkbuf_pull(pkbuf, 1);

    root = ogs_tlv_parse_block(pkbuf->len, pkbuf->data, OGS_TLV_MODE_T1_L1);
    if (!root) {
        ogs_error("ogs_tlv_parse_block() failed");
        return;
    }

    iter = root;
    while (iter) {
        switch (iter->type) {
        case SGSAP_IE_IMSI_TYPE:
            nas_mobile_identity_imsi = iter->value;
            nas_mobile_identity_imsi_len = iter->length;
            break;
        default:
            ogs_warn("Invalid Type [%d]", iter->type);
            break;
        }
        iter = iter->next;
    }

    ogs_tlv_free_all(root);

    if (!nas_mobile_identity_imsi) {
        ogs_error("No IMSI");
        return;
    }
    if (!SGSAP_IMSI_LEN_OK(nas_mobile_identity_imsi_len)) {
        ogs_error("Invalid IMSI len [%d]", nas_mobile_identity_imsi_len);
        return;
    }

    if (nas_mobile_identity_imsi->type == OGS_NAS_MOBILE_IDENTITY_IMSI) {

        ogs_nas_eps_imsi_to_bcd(nas_mobile_identity_imsi,
                nas_mobile_identity_imsi_len, imsi_bcd);
        mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
    } else {
        ogs_error("Unknown type [%d]", nas_mobile_identity_imsi->type);
        return;
    }

    if (mme_ue)
        ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
    else
        ogs_warn("Unknown IMSI[%s]", imsi_bcd);

}

void sgsap_handle_mm_information_request(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf)
{
    ogs_tlv_t *root = NULL, *iter = NULL;
    mme_ue_t *mme_ue = NULL;

    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    ogs_nas_mobile_identity_imsi_t *nas_mobile_identity_imsi = NULL;
    int nas_mobile_identity_imsi_len = 0;

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    ogs_debug("[SGSAP] MM-INFORMATION-REQUEST(DISCARD by OPTION2)");

    ogs_pkbuf_pull(pkbuf, 1);

    root = ogs_tlv_parse_block(pkbuf->len, pkbuf->data, OGS_TLV_MODE_T1_L1);
    if (!root) {
        ogs_error("ogs_tlv_parse_block() failed");
        return;
    }

    iter = root;
    while (iter) {
        switch (iter->type) {
        case SGSAP_IE_IMSI_TYPE:
            nas_mobile_identity_imsi = iter->value;
            nas_mobile_identity_imsi_len = iter->length;
            break;
        case SGSAP_IE_MM_INFORMATION_TYPE:
            /* TODO */
            break;
        default:
            ogs_warn("Invalid Type [%d]", iter->type);
            break;
        }
        iter = iter->next;
    }

    ogs_tlv_free_all(root);

    if (!nas_mobile_identity_imsi) {
        ogs_error("No IMSI");
        return;
    }
    if (!SGSAP_IMSI_LEN_OK(nas_mobile_identity_imsi_len)) {
        ogs_error("Invalid IMSI len [%d]", nas_mobile_identity_imsi_len);
        return;
    }

    if (nas_mobile_identity_imsi->type == OGS_NAS_MOBILE_IDENTITY_IMSI) {

        ogs_nas_eps_imsi_to_bcd(nas_mobile_identity_imsi,
                nas_mobile_identity_imsi_len, imsi_bcd);
        mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
    } else {
        ogs_error("Unknown type [%d]", nas_mobile_identity_imsi->type);
        return;
    }

    if (mme_ue)
        ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
    else
        ogs_warn("Unknown IMSI[%s]", imsi_bcd);
}
