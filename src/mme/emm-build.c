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

#include "nas-security.h"
#include "emm-build.h"
#include "mme-sm.h"
#include "mme-path.h"
#include "eplmn-config.h"
#include "mme-roam-access.h"

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __emm_log_domain

/*
 * fake_csfb: advertise Combined Attach/TAU result when CS/SGs is not
 * available (no real VLR registration).
 *
 * fake_csfb_lai: optionally also synthesize LAI + P-TMSI. When false,
 * still return Combined — only omit the fake LAI/P-TMSI IEs.
 */
static bool emm_fake_csfb_enabled(void)
{
    return ogs_global_conf()->parameter.fake_csfb == true;
}

static bool emm_fake_csfb_lai_enabled(void)
{
    return emm_fake_csfb_enabled() &&
           ogs_global_conf()->parameter.fake_csfb_lai == true;
}

/* Combined result without a real SGs/VLR registration. */
static bool emm_can_fake_combined(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    return emm_fake_csfb_enabled() &&
           mme_ue->network_access_mode !=
                OGS_NETWORK_ACCESS_MODE_ONLY_PACKET;
}

/* Synthetic LAI + P-TMSI (subset of fake_csfb). */
static bool emm_can_fake_lai_ptmsi(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    return emm_fake_csfb_lai_enabled() &&
           mme_ue->network_access_mode !=
                OGS_NETWORK_ACCESS_MODE_ONLY_PACKET;
}

/* use_openair keeps both quirks on for backward compatibility. */
static bool emm_openair_short_enfs(void)
{
    return ogs_global_conf()->parameter.use_openair == true ||
           ogs_global_conf()->parameter.openair_short_enfs == true;
}

static bool emm_openair_omit_hashmme(void)
{
    return ogs_global_conf()->parameter.use_openair == true ||
           ogs_global_conf()->parameter.openair_omit_hashmme == true;
}

static mme_p_tmsi_t emm_fake_csfb_ptmsi(mme_ue_t *mme_ue)
{
    mme_p_tmsi_t ptmsi = INVALID_P_TMSI;

    ogs_assert(mme_ue);

    if (mme_ue->next.p_tmsi != INVALID_P_TMSI)
        return mme_ue->next.p_tmsi;
    if (mme_ue->current.p_tmsi != INVALID_P_TMSI)
        return mme_ue->current.p_tmsi;
    if (MME_NEXT_GUTI_IS_AVAILABLE(mme_ue))
        ptmsi = mme_ue->next.guti.m_tmsi;
    else if (MME_CURRENT_GUTI_IS_AVAILABLE(mme_ue))
        ptmsi = mme_ue->current.guti.m_tmsi;
    else if (mme_ue->mme_s11_teid)
        ptmsi = mme_ue->mme_s11_teid;

    if (ptmsi == INVALID_P_TMSI)
        ptmsi = 0xc0000001;

    return ptmsi;
}

/* Prefer a configured LAI whose PLMN matches the serving TAI PLMN. */
static mme_csmap_t *emm_csmap_find_lai_by_serving_plmn(mme_ue_t *mme_ue)
{
    mme_csmap_t *csmap = NULL;
    ogs_nas_plmn_id_t serving;

    ogs_assert(mme_ue);

    ogs_nas_from_plmn_id(&serving, &mme_ue->tai.plmn_id);
    ogs_list_for_each(&mme_self()->csmap_list, csmap) {
        if (memcmp(&csmap->lai.nas_plmn_id, &serving, sizeof(serving)) == 0)
            return csmap;
    }

    return NULL;
}

static void emm_fill_fake_csfb_lai_ms_identity(
        mme_ue_t *mme_ue,
        ogs_nas_location_area_identification_t *lai,
        ogs_nas_mobile_identity_t *ms_identity)
{
    mme_csmap_t *csmap = NULL;
    ogs_nas_mobile_identity_tmsi_t *tmsi = NULL;
    mme_p_tmsi_t ptmsi;
    const char *lai_src = NULL;

    ogs_assert(mme_ue);
    ogs_assert(lai);
    ogs_assert(ms_identity);

    tmsi = &ms_identity->tmsi;
    csmap = mme_ue->csmap;
    if (!csmap)
        csmap = mme_csmap_find_for_ue(mme_ue);
    if (!csmap)
        csmap = emm_csmap_find_lai_by_serving_plmn(mme_ue);

    if (csmap) {
        mme_ue->csmap = csmap;
        lai->nas_plmn_id = csmap->lai.nas_plmn_id;
        lai->lac = csmap->lai.lac;
        lai_src = "csmap";
    } else {
        /* No LA map: non-broadcast-style LAI from serving PLMN + TAC. */
        ogs_nas_from_plmn_id(&lai->nas_plmn_id, &mme_ue->tai.plmn_id);
        lai->lac = mme_ue->tai.tac ? mme_ue->tai.tac : 1;
        lai_src = "serving TAI";
    }

    ptmsi = emm_fake_csfb_ptmsi(mme_ue);
    mme_ue->next.p_tmsi = ptmsi;
    mme_ue->current.p_tmsi = ptmsi;

    ms_identity->length = 5;
    tmsi->spare = 0xf;
    tmsi->odd_even = 0;
    tmsi->type = OGS_NAS_MOBILE_IDENTITY_TMSI;
    tmsi->tmsi = ptmsi;

    ogs_info("[%s] fake_csfb_lai: LAI[PLMN:%06x,LAC:%d] "
            "P-TMSI[0x%08x] (%s)",
            mme_ue->imsi_bcd,
            ogs_plmn_id_hexdump(&lai->nas_plmn_id), lai->lac, ptmsi,
            lai_src);
}

static int emm_tai_list_build_for_accept(
        ogs_nas_tracking_area_identity_list_t *target,
        mme_ue_t *mme_ue, int served_tai_index)
{
    ogs_assert(target);
    ogs_assert(mme_ue);
    ogs_assert(served_tai_index >= 0 &&
            served_tai_index < OGS_MAX_NUM_OF_SUPPORTED_TA);

    if (mme_self()->attach_accept.tai_list_serving_only) {
        ogs_debug("    TAI list: serving_only (TAC:%d)", mme_ue->tai.tac);
        return ogs_nas_tai_list_build_serving_only(target, &mme_ue->tai);
    }

    /*
     * Default (tai_list_in_accept: all): full mme.tai lists with no serving-TAI
     * reordering, matching upstream Open5GS Attach/TAU Accept encoding.
     */
    return ogs_nas_tai_list_build(target,
            mme_self()->served_tai[served_tai_index].list0,
            &mme_self()->served_tai[served_tai_index].list1,
            &mme_self()->served_tai[served_tai_index].list2,
            NULL);
}

ogs_pkbuf_t *emm_build_attach_accept(
        mme_ue_t *mme_ue, ogs_pkbuf_t *esmbuf)
{
    ogs_nas_eps_message_t message;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_nas_eps_attach_accept_t *attach_accept = &message.emm.attach_accept;
    ogs_nas_eps_attach_result_t *eps_attach_result =
        &attach_accept->eps_attach_result;
    ogs_nas_gprs_timer_t *t3412_value = &attach_accept->t3412_value;
    ogs_nas_gprs_timer_t *t3402_value = &attach_accept->t3402_value;
    ogs_nas_gprs_timer_t *t3423_value = &attach_accept->t3423_value;
    int rv, served_tai_index = 0;
    ogs_nas_eps_mobile_identity_t *nas_guti = &attach_accept->guti;
    ogs_nas_eps_network_feature_support_t *eps_network_feature_support =
        &attach_accept->eps_network_feature_support;
    ogs_nas_location_area_identification_t *lai =
        &attach_accept->location_area_identification;
    ogs_nas_mobile_identity_t *ms_identity = &attach_accept->ms_identity;
    ogs_nas_mobile_identity_tmsi_t *tmsi = &ms_identity->tmsi;;
    ogs_nas_emergency_number_list_t *emerg_numbers =
        &attach_accept->emergency_number_list;

    ogs_assert(mme_ue);
    ogs_assert(esmbuf);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
       OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_ATTACH_ACCEPT;

    /* Set EPS Attach Accept Type
     *
     * BEFORE: set attach accept EPS_ATTACH_TYPE from requested EPS_ATTACH_TYPE
     *   request EPS_ONLY_ATTACH[1] > serve EPS_ONLY_ATTACH[1]
     *   request COMBINED_EPS_IMSI_ATTACH[2] > serve COMBINED_EPS_IMSI_ATTACH[2]
     *   request EPS_EMERGENCY_ATTACH[3] > serve EPS_EMERGENCY_ATTACH[3]
     *
     *   ==> eps_attach_result->result = mme_ue->nas_eps.attach.value;
     *
     * NOW: set attach accept EPS_ATTACH_TYPE from HSS "Network-Access-Mode"
     *
     *   HSS IMSI[x] Network-Access-Mode[2]  > serve EPS_ONLY_ATTACH[1]
     *
     *   HSS IMSI[x] Network-Access-Mode[0] && request EPS_ONLY_ATTACH[1]
     *       > serve EPS_ONLY_ATTACH[1]
     *
     *   HSS IMSI[x] Network-Access-Mode[0] &&
     *   request COMBINED_EPS_IMSI_ATTACH[2]
     *       > serve COMBINED_EPS_IMSI_ATTACH[2]
     *
     * EXCEPTIONS:
     *   request EPS_EMERGENCY_ATTACH[3] > serve EPS_EMERGENCY_ATTACH[3]
     *   HSS IMSI[x] Network-Access-Mode[invalid] > serve as requested
     */

    if (mme_ue->network_access_mode == OGS_NETWORK_ACCESS_MODE_ONLY_PACKET) {
        /*
         * HSS NAM = packet-only → always EPS Attach.
         * fake_csfb must not override this subscriber restriction
         * (TS 23.401 / TS 29.272 Network-Access-Mode). Combined request
         * then gets EMM cause 18 below.
         */
        eps_attach_result->result = OGS_NAS_ATTACH_TYPE_EPS_ATTACH;
    } else if (mme_ue->nas_eps.attach.value ==
                OGS_NAS_ATTACH_TYPE_COMBINED_EPS_IMSI_ATTACH &&
            (mme_ue->sgs_cs_unavailable ||
             ogs_global_conf()->parameter.ignore_sgs == true ||
             mme_ue->csmap == NULL)) {
        /*
         * Combined requested but CS cannot be registered via SGs.
         * fake_csfb → still Combined (LAI/P-TMSI only if fake_csfb_lai).
         * Otherwise EPS-only + EMM cause 18.
         */
        if (emm_can_fake_combined(mme_ue))
            eps_attach_result->result =
                OGS_NAS_ATTACH_TYPE_COMBINED_EPS_IMSI_ATTACH;
        else
            eps_attach_result->result = OGS_NAS_ATTACH_TYPE_EPS_ATTACH;
    } else {
        eps_attach_result->result = mme_ue->nas_eps.attach.value;
    }

    /*
     * Real Combined needs a VLR P-TMSI. fake_csfb may keep Combined
     * without one (with or without synthetic LAI/P-TMSI).
     */
    if (eps_attach_result->result ==
            OGS_NAS_ATTACH_TYPE_COMBINED_EPS_IMSI_ATTACH &&
        !MME_NEXT_P_TMSI_IS_AVAILABLE(mme_ue) &&
        !emm_can_fake_combined(mme_ue)) {
        eps_attach_result->result = OGS_NAS_ATTACH_TYPE_EPS_ATTACH;
    }

    if (mme_ue->nas_eps.attach.value != eps_attach_result->result) {
        /* print warning if difference in requested/served EPS_ATTACH_TYPE */
        switch (mme_ue->nas_eps.attach.value){
            case OGS_NAS_ATTACH_TYPE_EPS_ATTACH:
                ogs_warn("  Requested EPS_ATTACH_TYPE[1, EPS_ATTACH]");
                break;
            case OGS_NAS_ATTACH_TYPE_COMBINED_EPS_IMSI_ATTACH:
                ogs_warn("  Requested EPS_ATTACH_TYPE[2, "
                            "COMBINED_EPS_IMSI_ATTACH]");
                break;
            case OGS_NAS_ATTACH_TYPE_EPS_EMERGENCY_ATTACH:
                ogs_warn("  Requested EPS_ATTACH_TYPE[3, "
                            "EPS_EMERGENCY_ATTACH]");
                break;
        }
        switch (eps_attach_result->result) {
            case OGS_NAS_ATTACH_TYPE_EPS_ATTACH:
                ogs_warn("  Permitted EPS_ATTACH_TYPE[1, EPS_ATTACH]");
                break;
            case OGS_NAS_ATTACH_TYPE_COMBINED_EPS_IMSI_ATTACH:
                ogs_warn("  Permitted EPS_ATTACH_TYPE[2, "
                            "COMBINED_EPS_IMSI_ATTACH]");
                break;
            case OGS_NAS_ATTACH_TYPE_EPS_EMERGENCY_ATTACH:
                ogs_warn("  Permitted EPS_ATTACH_TYPE[3, "
                            "EPS_EMERGENCY_ATTACH]");
                break;
        }

        if ((mme_ue->nas_eps.attach.value ==
                OGS_NAS_ATTACH_TYPE_COMBINED_EPS_IMSI_ATTACH) &&
            (eps_attach_result->result == OGS_NAS_ATTACH_TYPE_EPS_ATTACH)) {
            attach_accept->presencemask |=
                OGS_NAS_EPS_ATTACH_ACCEPT_EMM_CAUSE_PRESENT;
            attach_accept->emm_cause =
                OGS_NAS_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE;
        }
    } else {
        switch (eps_attach_result->result) {
            case OGS_NAS_ATTACH_TYPE_EPS_ATTACH:
                ogs_debug("    EPS_ATTACH_TYPE[1, EPS_ATTACH]");
                break;
            case OGS_NAS_ATTACH_TYPE_COMBINED_EPS_IMSI_ATTACH:
                ogs_debug("    EPS_ATTACH_TYPE[2, COMBINED_EPS_IMSI_ATTACH]");
                break;
            case OGS_NAS_ATTACH_TYPE_EPS_EMERGENCY_ATTACH:
                ogs_debug("    EPS_ATTACH_TYPE[3, EPS_EMERGENCY_ATTACH]");
                break;
        }
    }

    /* Set T3412 : Mandatory in Open5GS */
    ogs_assert(mme_self()->time.t3412.value);
    rv = ogs_nas_gprs_timer_from_sec(
            t3412_value, mme_self()->time.t3412.value);
    ogs_assert(rv == OGS_OK);

    ogs_debug("    TAI[PLMN_ID:%06x,TAC:%d]",
            ogs_plmn_id_hexdump(&mme_ue->tai.plmn_id),
            mme_ue->tai.tac);
    ogs_debug("    E_CGI[PLMN_ID:%06x,CELL_ID:0x%x]",
            ogs_plmn_id_hexdump(&mme_ue->e_cgi.plmn_id),
            mme_ue->e_cgi.cell_id);
    served_tai_index = mme_find_served_tai(&mme_ue->tai);
    ogs_debug("    SERVED_TAI_INDEX[%d]", served_tai_index);
    ogs_assert(served_tai_index >= 0 &&
            served_tai_index < OGS_MAX_NUM_OF_SUPPORTED_TA);
    ogs_assert(OGS_OK ==
        emm_tai_list_build_for_accept(
            &attach_accept->tai_list, mme_ue, served_tai_index));

    attach_accept->esm_message_container.buffer = esmbuf->data;
    attach_accept->esm_message_container.length = esmbuf->len;

    if (MME_NEXT_GUTI_IS_AVAILABLE(mme_ue)) {
        attach_accept->presencemask |= OGS_NAS_EPS_ATTACH_ACCEPT_GUTI_PRESENT;

        ogs_debug("    [%s]    GUTI[G:%d,C:%d,M_TMSI:0x%x]",
                mme_ue->imsi_bcd,
                mme_ue->next.guti.mme_gid, mme_ue->next.guti.mme_code,
                mme_ue->next.guti.m_tmsi);
        nas_guti->length = sizeof(ogs_nas_eps_mobile_identity_guti_t);
        nas_guti->guti.odd_even = OGS_NAS_MOBILE_IDENTITY_EVEN;
        nas_guti->guti.type = OGS_NAS_EPS_MOBILE_IDENTITY_GUTI;
        nas_guti->guti.nas_plmn_id = mme_ue->next.guti.nas_plmn_id;
        nas_guti->guti.mme_gid = mme_ue->next.guti.mme_gid;
        nas_guti->guti.mme_code = mme_ue->next.guti.mme_code;
        nas_guti->guti.m_tmsi = mme_ue->next.guti.m_tmsi;
    }

    /* Set T3402 */
    if (mme_self()->attach_accept.t3402 &&
            mme_self()->time.t3402.value) {
        rv = ogs_nas_gprs_timer_from_sec(
                t3402_value, mme_self()->time.t3402.value);
        ogs_assert(rv == OGS_OK);
        attach_accept->presencemask |=
            OGS_NAS_EPS_ATTACH_ACCEPT_T3402_VALUE_PRESENT;
    }

    /* Set T3423 */
    if (mme_self()->time.t3423.value) {
        rv = ogs_nas_gprs_timer_from_sec(
                t3423_value, mme_self()->time.t3423.value);
        ogs_assert(rv == OGS_OK);
        attach_accept->presencemask |=
            OGS_NAS_EPS_ATTACH_ACCEPT_T3423_VALUE_PRESENT;
    }

    /* Set emergency number(s) */
    if (!ogs_list_empty(&mme_self()->emerg_list)) {
        mme_emerg_t *emerg;
        ogs_nas_emergency_number_item_t *item;
        int len, o = 0;
        ogs_list_for_each(&mme_self()->emerg_list, emerg) {
            len = (strlen(emerg->digits) + 1) >> 1;
            if (o + 2 + len > OGS_NAS_MAX_EMERGENCY_NUMBER_LIST_LEN) {
                ogs_debug("    Too many list EMERG_NUM_LIST items.");
                break;
            }
            ogs_debug("    EMERG_NUM_LIST[CAT:0x%02x,DIGITS:%s]",
                    emerg->categories, emerg->digits);
            item = (ogs_nas_emergency_number_item_t *)(emerg_numbers->buffer + o);
            item->service_category = emerg->categories;
            ogs_bcd_to_buffer(emerg->digits, item->digits, &len);
            item->length = 1 + len;
            o += 2 + len;
        }
        attach_accept->presencemask |=
            OGS_NAS_EPS_ATTACH_ACCEPT_EMERGENCY_NUMBER_LIST_PRESENT;
        emerg_numbers->length = o;
    }

    attach_accept->presencemask |=
        OGS_NAS_EPS_ATTACH_ACCEPT_EPS_NETWORK_FEATURE_SUPPORT_PRESENT;
    if (emm_openair_short_enfs() == false) {
        eps_network_feature_support->length = 2;
    } else {
        eps_network_feature_support->length = 1;
    }
    eps_network_feature_support->ims_voice_over_ps_session_in_s1_mode =
        mme_self()->attach_accept.ims_voice_over_ps ? 1 : 0;
    eps_network_feature_support->extended_protocol_configuration_options = 1;
    if (mme_self()->emergency.dnn)
        eps_network_feature_support->emergency_bearer_services_in_s1_mode = 1;

    if (MME_NEXT_P_TMSI_IS_AVAILABLE(mme_ue)) {
        ogs_assert(mme_ue->csmap);
        ogs_assert(mme_ue->next.p_tmsi);

        attach_accept->presencemask |=
            OGS_NAS_EPS_ATTACH_ACCEPT_LOCATION_AREA_IDENTIFICATION_PRESENT;
        lai->nas_plmn_id = mme_ue->csmap->lai.nas_plmn_id;
        lai->lac = mme_ue->csmap->lai.lac;
        ogs_debug("    LAI[PLMN_ID:%06x,LAC:%d]",
                ogs_plmn_id_hexdump(&lai->nas_plmn_id), lai->lac);

        attach_accept->presencemask |=
            OGS_NAS_EPS_ATTACH_ACCEPT_MS_IDENTITY_PRESENT;
        ms_identity->length = 5;
        tmsi->spare = 0xf;
        tmsi->odd_even = 0;
        tmsi->type = OGS_NAS_MOBILE_IDENTITY_TMSI;
        tmsi->tmsi = mme_ue->next.p_tmsi;
        ogs_debug("    P-TMSI: 0x%08x", tmsi->tmsi);
    } else if (eps_attach_result->result ==
                OGS_NAS_ATTACH_TYPE_COMBINED_EPS_IMSI_ATTACH &&
            emm_can_fake_lai_ptmsi(mme_ue)) {
        attach_accept->presencemask |=
            OGS_NAS_EPS_ATTACH_ACCEPT_LOCATION_AREA_IDENTIFICATION_PRESENT;
        attach_accept->presencemask |=
            OGS_NAS_EPS_ATTACH_ACCEPT_MS_IDENTITY_PRESENT;
        emm_fill_fake_csfb_lai_ms_identity(mme_ue, lai, ms_identity);
    }

    /*
     * TS 24.301 5.5.1.3.4.2: if the UE requested SMS only, Additional
     * update result shall be "SMS only".
     */
    if (eps_attach_result->result ==
            OGS_NAS_ATTACH_TYPE_COMBINED_EPS_IMSI_ATTACH &&
        mme_ue->nas_eps.sms_only) {
        attach_accept->presencemask |=
            OGS_NAS_EPS_ATTACH_ACCEPT_ADDITIONAL_UPDATE_RESULT_PRESENT;
        attach_accept->additional_update_result.
            additional_update_result_value =
                OGS_NAS_ADDITIONAL_UPDATE_RESULT_SMS_ONLY;
        ogs_info("[%s] Attach Accept Additional update result: SMS only",
                mme_ue->imsi_bcd);
    }

    if (mme_self()->attach_accept.equivalent_plmn &&
            mme_self()->num_of_eplmn && MME_UE_HAVE_IMSI(mme_ue) &&
            (!mme_self()->attach_accept.equivalent_plmn_access_control_tac ||
             mme_access_control_eplmn_tac_allowed(mme_ue))) {
        int num_eplmn = mme_eplmn_count_for_imsi(mme_ue->imsi_bcd,
                mme_self()->attach_accept.equivalent_plmn_serving_only,
                mme_self()->num_of_eplmn, mme_self()->eplmn);

        ogs_assert(mme_eplmn_build_nas_list_for_imsi(
                    &attach_accept->equivalent_plmns, mme_ue->imsi_bcd,
                    mme_self()->attach_accept.equivalent_plmn_serving_only,
                    mme_self()->num_of_eplmn, mme_self()->eplmn) == OGS_OK);
        attach_accept->presencemask |=
            OGS_NAS_EPS_ATTACH_ACCEPT_EQUIVALENT_PLMNS_PRESENT;
        ogs_debug("    Equivalent PLMNs[%d/%d] included in Attach Accept "
                "(IMSI[%s] serving_only:%d ac_tac:%d)",
                num_eplmn, mme_self()->num_of_eplmn,
                mme_ue->imsi_bcd,
                mme_self()->attach_accept.equivalent_plmn_serving_only,
                mme_self()->attach_accept.equivalent_plmn_access_control_tac);
    } else if (mme_self()->attach_accept.equivalent_plmn &&
            mme_self()->attach_accept.equivalent_plmn_access_control_tac &&
            MME_UE_HAVE_IMSI(mme_ue) &&
            !mme_access_control_eplmn_tac_allowed(mme_ue)) {
        ogs_debug("    Equivalent PLMNs omitted (access_control TAC) "
                "IMSI[%s] TAC[%u]",
                mme_ue->imsi_bcd, mme_ue->tai.tac);
    }

    pkbuf = nas_eps_security_encode(mme_ue, &message);
    ogs_pkbuf_free(esmbuf);

    return pkbuf;
}

ogs_pkbuf_t *emm_build_attach_reject(mme_ue_t *mme_ue,
        ogs_nas_emm_cause_t emm_cause, ogs_pkbuf_t *esmbuf)
{
    ogs_nas_eps_message_t message;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_nas_eps_attach_reject_t *attach_reject = &message.emm.attach_reject;

    memset(&message, 0, sizeof(message));

    /* Same rationale as emm_build_tau_reject: integrity-protect the
     * reject when the security context is valid (post-SMC) so the UE
     * honours the EMM cause instead of abnormal-case retrying. */
    if (SECURITY_CONTEXT_IS_VALID(mme_ue)) {
        message.h.security_header_type =
            OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
        message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    }

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_ATTACH_REJECT;

    attach_reject->emm_cause = emm_cause;

    if (mme_t3346_should_include(emm_cause)) {
        if (ogs_nas_gprs_timer_from_sec(&attach_reject->t3346_value.t,
                    mme_self()->time.t3346.value) == OGS_OK) {
            attach_reject->t3346_value.length = 1;
            attach_reject->presencemask |=
                OGS_NAS_EPS_ATTACH_REJECT_T3346_VALUE_PRESENT;
        } else {
            ogs_error("Invalid T3346 value [%ld]",
                    (long)mme_self()->time.t3346.value);
        }
    }

    if (esmbuf) {
        attach_reject->presencemask |=
            OGS_NAS_EPS_ATTACH_REJECT_ESM_MESSAGE_CONTAINER_PRESENT;
        attach_reject->esm_message_container.buffer = esmbuf->data;
        attach_reject->esm_message_container.length = esmbuf->len;
    }

    if (SECURITY_CONTEXT_IS_VALID(mme_ue))
        pkbuf = nas_eps_security_encode(mme_ue, &message);
    else
        pkbuf = ogs_nas_eps_plain_encode(&message);
    if (esmbuf)
        ogs_pkbuf_free(esmbuf);

    return pkbuf;
}

ogs_pkbuf_t *emm_build_identity_request(mme_ue_t *mme_ue)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_identity_request_t *identity_request =
        &message.emm.identity_request;

    ogs_assert(mme_ue);

    memset(&message, 0, sizeof(message));
    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_IDENTITY_REQUEST;

    /* Request IMSI */
    ogs_debug("    Identity Type 2 : IMSI");
    identity_request->identity_type.type = OGS_NAS_IDENTITY_TYPE_2_IMSI;

    return ogs_nas_eps_plain_encode(&message);
}

ogs_pkbuf_t *emm_build_authentication_request(mme_ue_t *mme_ue)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_authentication_request_t *authentication_request =
        &message.emm.authentication_request;

    ogs_assert(mme_ue);

    memset(&message, 0, sizeof(message));
    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_AUTHENTICATION_REQUEST;

    authentication_request->nas_key_set_identifierasme.tsc =
        mme_ue->nas_eps.mme.tsc;
    authentication_request->nas_key_set_identifierasme.value =
        mme_ue->nas_eps.mme.ksi;
    memcpy(authentication_request->authentication_parameter_rand.rand,
            mme_ue->rand, OGS_RAND_LEN);
    memcpy(authentication_request->authentication_parameter_autn.autn,
            mme_ue->autn, OGS_AUTN_LEN);
    authentication_request->authentication_parameter_autn.length =
            OGS_AUTN_LEN;

    return ogs_nas_eps_plain_encode(&message);
}

ogs_pkbuf_t *emm_build_authentication_reject(void)
{
    ogs_nas_eps_message_t message;

    memset(&message, 0, sizeof(message));

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_AUTHENTICATION_REJECT;

    return ogs_nas_eps_plain_encode(&message);
}

ogs_pkbuf_t *emm_build_security_mode_command(mme_ue_t *mme_ue)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_security_mode_command_t *security_mode_command =
        &message.emm.security_mode_command;
    ogs_nas_security_algorithms_t *selected_nas_security_algorithms =
        &security_mode_command->selected_nas_security_algorithms;
    ogs_nas_key_set_identifier_t *nas_key_set_identifier =
        &security_mode_command->nas_key_set_identifier;
    ogs_nas_ue_security_capability_t *replayed_ue_security_capabilities =
        &security_mode_command->replayed_ue_security_capabilities;
    ogs_nas_imeisv_request_t *imeisv_request =
        &security_mode_command->imeisv_request;
    ogs_nas_hashmme_t *hashmme = &security_mode_command->hashmme;
    ogs_nas_ue_additional_security_capability_t
        *replayed_ue_additional_security_capability =
            &security_mode_command->replayed_ue_additional_security_capability;

    ogs_assert(mme_ue);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
       OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_SECURITY_MODE_COMMAND;

    selected_nas_security_algorithms->type_of_integrity_protection_algorithm =
        mme_ue->selected_int_algorithm;
    selected_nas_security_algorithms->type_of_ciphering_algorithm =
        mme_ue->selected_enc_algorithm;

    nas_key_set_identifier->tsc = mme_ue->nas_eps.mme.tsc;
    nas_key_set_identifier->value = mme_ue->nas_eps.mme.ksi;

    replayed_ue_security_capabilities->eea = mme_ue->ue_network_capability.eea;
    replayed_ue_security_capabilities->eia = mme_ue->ue_network_capability.eia;
    replayed_ue_security_capabilities->uea = mme_ue->ue_network_capability.uea;
    replayed_ue_security_capabilities->uia =
        mme_ue->ue_network_capability.uia & 0x7f;
    replayed_ue_security_capabilities->gea =
        (mme_ue->ms_network_capability.gea1 << 6) |
        mme_ue->ms_network_capability.extended_gea;

    replayed_ue_security_capabilities->length =
        sizeof(replayed_ue_security_capabilities->eea) +
        sizeof(replayed_ue_security_capabilities->eia);
    if (replayed_ue_security_capabilities->uea ||
        replayed_ue_security_capabilities->uia)
        replayed_ue_security_capabilities->length =
            sizeof(replayed_ue_security_capabilities->eea) +
            sizeof(replayed_ue_security_capabilities->eia) +
            sizeof(replayed_ue_security_capabilities->uea) +
            sizeof(replayed_ue_security_capabilities->uia);
    if (replayed_ue_security_capabilities->gea)
        replayed_ue_security_capabilities->length =
            sizeof(replayed_ue_security_capabilities->eea) +
            sizeof(replayed_ue_security_capabilities->eia) +
            sizeof(replayed_ue_security_capabilities->uea) +
            sizeof(replayed_ue_security_capabilities->uia) +
            sizeof(replayed_ue_security_capabilities->gea);
    ogs_debug("    Replayed UE SEC[LEN:%d EEA:0x%x EIA:0x%x UEA:0x%x "
            "UIA:0x%x GEA:0x%x]",
            replayed_ue_security_capabilities->length,
            replayed_ue_security_capabilities->eea,
            replayed_ue_security_capabilities->eia,
            replayed_ue_security_capabilities->uea,
            replayed_ue_security_capabilities->uia,
            replayed_ue_security_capabilities->gea);
    ogs_debug("    Selected[Integrity:0x%x Encrypt:0x%x]",
            mme_ue->selected_int_algorithm, mme_ue->selected_enc_algorithm);

    security_mode_command->presencemask |=
        OGS_NAS_EPS_SECURITY_MODE_COMMAND_IMEISV_REQUEST_PRESENT;
    imeisv_request->type = OGS_NAS_IMEISV_TYPE;
    imeisv_request->value = OGS_NAS_IMEISV_REQUESTED;

    if (mme_ue->nonceue) {
        security_mode_command->presencemask |=
            OGS_NAS_EPS_SECURITY_MODE_COMMAND_REPLAYED_NONCEUE_PRESENT;
            security_mode_command->replayed_nonceue = mme_ue->nonceue;
    }

    if (mme_ue->noncemme) {
        security_mode_command->presencemask |=
            OGS_NAS_EPS_SECURITY_MODE_COMMAND_NONCEMME_PRESENT;
            security_mode_command->noncemme = mme_ue->noncemme;
    }

    /*
     * TS24.301
     * 5.4.3.2 NAS security mode control initiation by the network
     *
     * If, during an ongoing attach or tracking area updating procedure,
     * the MME is initiating a SECURITY MODE COMMAND (i.e. after receiving
     * the ATTACH REQUEST or TRACKING AREA UPDATE REQUEST message,
     * but before sending a response to that message) and the ATTACH REQUEST
     * or TRACKING AREA UPDATE REQUEST message is received without integrity
     * protection or does not successfully pass the integrity check at the MME,
     * the MME shall calculate the HASH MME of the entire plain ATTACH REQUEST
     * or TRACKING AREA UPDATE REQUEST message as described
     * in 3GPP TS 33.401 [19] and shall include the HASH MME
     * in the SECURITY MODE COMMAND message
     *
     * However, Openair UE does not support HashMME. For user convenience,
     * omit HashMME via openair_omit_hashmme (or use_openair umbrella).
     * Prefer openair_short_enfs alone when only ENFS length is needed —
     * omitting HashMME weakens bidding-down protection (TS 33.401).
     */
    if (emm_openair_omit_hashmme() == false) {
        security_mode_command->presencemask |=
            OGS_NAS_EPS_SECURITY_MODE_COMMAND_HASHMME_PRESENT;
        hashmme->length = OGS_HASH_MME_LEN;
        memcpy(hashmme->value, mme_ue->hash_mme, hashmme->length);
    }

    if (mme_ue->ue_additional_security_capability.length) {
        security_mode_command->presencemask |=
            OGS_NAS_EPS_SECURITY_MODE_COMMAND_REPLAYED_UE_ADDITIONAL_SECURITY_CAPABILITY_PRESENT;
        memcpy(replayed_ue_additional_security_capability,
                &mme_ue->ue_additional_security_capability,
                sizeof(mme_ue->ue_additional_security_capability));
    }

    ogs_assert(mme_ue->selected_int_algorithm !=
            OGS_NAS_SECURITY_ALGORITHMS_EIA0);

    ogs_kdf_nas_eps(OGS_KDF_NAS_INT_ALG, mme_ue->selected_int_algorithm,
            mme_ue->kasme, mme_ue->knas_int);
    ogs_kdf_nas_eps(OGS_KDF_NAS_ENC_ALG, mme_ue->selected_enc_algorithm,
            mme_ue->kasme, mme_ue->knas_enc);

    return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *emm_build_detach_request(mme_ue_t *mme_ue)
{
    ogs_nas_eps_message_t message;

    ogs_assert(mme_ue);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
        OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_DETACH_REQUEST;

    message.emm.detach_request_to_ue.detach_type.value =
        mme_ue->nas_eps.detach.value;

    return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *emm_build_detach_accept(mme_ue_t *mme_ue)
{
    ogs_nas_eps_message_t message;

    ogs_assert(mme_ue);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
        OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_DETACH_ACCEPT;

    return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *emm_build_tau_accept(mme_ue_t *mme_ue)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_tracking_area_update_accept_t *tau_accept =
        &message.emm.tracking_area_update_accept;
    ogs_nas_eps_mobile_identity_t *nas_guti = &tau_accept->guti;
    ogs_nas_location_area_identification_t *lai =
        &tau_accept->location_area_identification;
    ogs_nas_mobile_identity_t *ms_identity = &tau_accept->ms_identity;
    ogs_nas_mobile_identity_tmsi_t *tmsi = &ms_identity->tmsi;;
    ogs_nas_gprs_timer_t *t3412_value = &tau_accept->t3412_value;
    ogs_nas_gprs_timer_t *t3402_value = &tau_accept->t3402_value;
    ogs_nas_gprs_timer_t *t3423_value = &tau_accept->t3423_value;
    int rv, served_tai_index = 0;

    mme_sess_t *sess = NULL;

    ogs_assert(mme_ue);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
        OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT;

    if (mme_ue->network_access_mode != OGS_NETWORK_ACCESS_MODE_ONLY_PACKET &&
        (mme_ue->nas_eps.update.value ==
            OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING ||
         mme_ue->nas_eps.update.value ==
            OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING_WITH_IMSI_ATTACH) &&
        (MME_NEXT_P_TMSI_IS_AVAILABLE(mme_ue) ||
         emm_can_fake_combined(mme_ue))) {
        tau_accept->eps_update_result.result =
            OGS_NAS_EPS_UPDATE_RESULT_COMBINED_TA_LA_UPDATED;
    } else {
        /*
         * TA-updated only: no real VLR P-TMSI, fake_csfb off, or
         * HSS NAM = packet-only (fake_csfb must not override NAM).
         */
        tau_accept->eps_update_result.result =
            OGS_NAS_EPS_UPDATE_RESULT_TA_UPDATED;
        if ((mme_ue->nas_eps.update.value ==
                OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING ||
             mme_ue->nas_eps.update.value ==
                OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING_WITH_IMSI_ATTACH)) {
            tau_accept->presencemask |=
                OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_EMM_CAUSE_PRESENT;
            tau_accept->emm_cause =
                OGS_NAS_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE;
        }
    }

    if (mme_self()->time.t3412.value) {
        rv = ogs_nas_gprs_timer_from_sec(
                t3412_value, mme_self()->time.t3412.value);
        ogs_assert(rv == OGS_OK);
        tau_accept->presencemask |=
            OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_T3412_VALUE_PRESENT ;
    }

    if (MME_NEXT_GUTI_IS_AVAILABLE(mme_ue)) {
        tau_accept->presencemask |=
            OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_GUTI_PRESENT;

        ogs_debug("[%s]    GUTI[G:%d,C:%d,M_TMSI:0x%x]",
                mme_ue->imsi_bcd,
                mme_ue->next.guti.mme_gid, mme_ue->next.guti.mme_code,
                mme_ue->next.guti.m_tmsi);
        nas_guti->length = sizeof(ogs_nas_eps_mobile_identity_guti_t);
        nas_guti->guti.odd_even = OGS_NAS_MOBILE_IDENTITY_EVEN;
        nas_guti->guti.type = OGS_NAS_EPS_MOBILE_IDENTITY_GUTI;
        nas_guti->guti.nas_plmn_id = mme_ue->next.guti.nas_plmn_id;
        nas_guti->guti.mme_gid = mme_ue->next.guti.mme_gid;
        nas_guti->guti.mme_code = mme_ue->next.guti.mme_code;
        nas_guti->guti.m_tmsi = mme_ue->next.guti.m_tmsi;
    }

    /* Set TAI */
    tau_accept->presencemask |=
        OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_TAI_LIST_PRESENT;

    ogs_debug("    TAI[PLMN_ID:%06x,TAC:%d]",
            ogs_plmn_id_hexdump(&mme_ue->tai.plmn_id),
            mme_ue->tai.tac);
    ogs_debug("    E_CGI[PLMN_ID:%06x,CELL_ID:0x%x]",
            ogs_plmn_id_hexdump(&mme_ue->e_cgi.plmn_id),
            mme_ue->e_cgi.cell_id);
    served_tai_index = mme_find_served_tai(&mme_ue->tai);
    ogs_debug("    SERVED_TAI_INDEX[%d]", served_tai_index);
    ogs_assert(served_tai_index >= 0 &&
            served_tai_index < OGS_MAX_NUM_OF_SUPPORTED_TA);
    ogs_assert(OGS_OK ==
        emm_tai_list_build_for_accept(
            &tau_accept->tai_list, mme_ue, served_tai_index));

    /* Set EPS bearer context status */
    tau_accept->presencemask |=
        OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_EPS_BEARER_CONTEXT_STATUS_PRESENT;
    tau_accept->eps_bearer_context_status.length = 2;
    sess = mme_sess_first(mme_ue);
    while (sess) {
        mme_bearer_t *bearer = mme_bearer_first(sess);
        while (bearer) {
            switch (bearer->ebi) {
            case 5: tau_accept->eps_bearer_context_status.ebi5 = 1; break;
            case 6: tau_accept->eps_bearer_context_status.ebi6 = 1; break;
            case 7: tau_accept->eps_bearer_context_status.ebi7 = 1; break;
            case 8: tau_accept->eps_bearer_context_status.ebi8 = 1; break;
            case 9: tau_accept->eps_bearer_context_status.ebi9 = 1; break;
            case 10: tau_accept->eps_bearer_context_status.ebi10 = 1; break;
            case 11: tau_accept->eps_bearer_context_status.ebi11 = 1; break;
            case 12: tau_accept->eps_bearer_context_status.ebi12 = 1; break;
            case 13: tau_accept->eps_bearer_context_status.ebi13 = 1; break;
            case 14: tau_accept->eps_bearer_context_status.ebi14 = 1; break;
            case 15: tau_accept->eps_bearer_context_status.ebi15 = 1; break;
            default: break;
            }

            bearer = mme_bearer_next(bearer);
        }
        sess = mme_sess_next(sess);
    }

    /* Location Area Identification & MS Identity */
    if (MME_NEXT_P_TMSI_IS_AVAILABLE(mme_ue)) {
        ogs_assert(mme_ue->csmap);
        ogs_assert(mme_ue->next.p_tmsi);

        tau_accept->presencemask |= OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_LOCATION_AREA_IDENTIFICATION_PRESENT;
        lai->nas_plmn_id = mme_ue->csmap->lai.nas_plmn_id;
        lai->lac = mme_ue->csmap->lai.lac;
        ogs_debug("    LAI[PLMN_ID:%06x,LAC:%d]",
                ogs_plmn_id_hexdump(&lai->nas_plmn_id), lai->lac);

        tau_accept->presencemask |=
            OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_MS_IDENTITY_PRESENT;
        ms_identity->length = 5;
        tmsi->spare = 0xf;
        tmsi->odd_even = 0;
        tmsi->type = OGS_NAS_MOBILE_IDENTITY_TMSI;
        tmsi->tmsi = mme_ue->next.p_tmsi;
        ogs_debug("    P-TMSI: 0x%08x", tmsi->tmsi);
    } else if (tau_accept->eps_update_result.result ==
                OGS_NAS_EPS_UPDATE_RESULT_COMBINED_TA_LA_UPDATED &&
            emm_can_fake_lai_ptmsi(mme_ue)) {
        tau_accept->presencemask |=
            OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_LOCATION_AREA_IDENTIFICATION_PRESENT;
        tau_accept->presencemask |=
            OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_MS_IDENTITY_PRESENT;
        emm_fill_fake_csfb_lai_ms_identity(mme_ue, lai, ms_identity);
    }

    if (tau_accept->eps_update_result.result ==
            OGS_NAS_EPS_UPDATE_RESULT_COMBINED_TA_LA_UPDATED &&
        mme_ue->nas_eps.sms_only) {
        tau_accept->presencemask |=
            OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_ADDITIONAL_UPDATE_RESULT_PRESENT;
        tau_accept->additional_update_result.
            additional_update_result_value =
                OGS_NAS_ADDITIONAL_UPDATE_RESULT_SMS_ONLY;
        ogs_info("[%s] TAU Accept Additional update result: SMS only",
                mme_ue->imsi_bcd);
    }

    /* Set T3402 */
    if (mme_self()->attach_accept.t3402 &&
            mme_self()->time.t3402.value) {
        rv = ogs_nas_gprs_timer_from_sec(
                t3402_value, mme_self()->time.t3402.value);
        ogs_assert(rv == OGS_OK);
        tau_accept->presencemask |=
            OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_T3402_VALUE_PRESENT;
    }

    /* Set T3423 */
    if (mme_self()->time.t3423.value) {
        rv = ogs_nas_gprs_timer_from_sec(
                t3423_value, mme_self()->time.t3423.value);
        ogs_assert(rv == OGS_OK);
        tau_accept->presencemask |=
            OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_T3423_VALUE_PRESENT;
    }

    /* Set EPS network feature support */
    tau_accept->presencemask |=
        OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_EPS_NETWORK_FEATURE_SUPPORT_PRESENT;
    if (emm_openair_short_enfs() == false) {
        tau_accept->eps_network_feature_support.length = 2;
    } else {
        tau_accept->eps_network_feature_support.length = 1;
    }
    tau_accept->eps_network_feature_support.
        ims_voice_over_ps_session_in_s1_mode =
        mme_self()->attach_accept.ims_voice_over_ps ? 1 : 0;
    tau_accept->eps_network_feature_support.
        extended_protocol_configuration_options = 1;

    if (mme_self()->attach_accept.equivalent_plmn &&
            mme_self()->num_of_eplmn && MME_UE_HAVE_IMSI(mme_ue) &&
            (!mme_self()->attach_accept.equivalent_plmn_access_control_tac ||
             mme_access_control_eplmn_tac_allowed(mme_ue))) {
        int num_eplmn = mme_eplmn_count_for_imsi(mme_ue->imsi_bcd,
                mme_self()->attach_accept.equivalent_plmn_serving_only,
                mme_self()->num_of_eplmn, mme_self()->eplmn);

        ogs_assert(mme_eplmn_build_nas_list_for_imsi(
                    &tau_accept->equivalent_plmns, mme_ue->imsi_bcd,
                    mme_self()->attach_accept.equivalent_plmn_serving_only,
                    mme_self()->num_of_eplmn, mme_self()->eplmn) == OGS_OK);
        tau_accept->presencemask |=
            OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT_EQUIVALENT_PLMNS_PRESENT;
        ogs_debug("    Equivalent PLMNs[%d/%d] included in TAU Accept "
                "(IMSI[%s] serving_only:%d ac_tac:%d)",
                num_eplmn, mme_self()->num_of_eplmn,
                mme_ue->imsi_bcd,
                mme_self()->attach_accept.equivalent_plmn_serving_only,
                mme_self()->attach_accept.equivalent_plmn_access_control_tac);
    } else if (mme_self()->attach_accept.equivalent_plmn &&
            mme_self()->attach_accept.equivalent_plmn_access_control_tac &&
            MME_UE_HAVE_IMSI(mme_ue) &&
            !mme_access_control_eplmn_tac_allowed(mme_ue)) {
        ogs_debug("    Equivalent PLMNs omitted (access_control TAC) "
                "IMSI[%s] TAC[%u]",
                mme_ue->imsi_bcd, mme_ue->tai.tac);
    }

    return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *emm_build_tau_reject(
        ogs_nas_emm_cause_t emm_cause, mme_ue_t *mme_ue)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_tracking_area_update_reject_t *tau_reject =
        &message.emm.tracking_area_update_reject;

    ogs_debug("    Cause[%d]", emm_cause);

    memset(&message, 0, sizeof(message));

    /*
     * TS 24.301 5.5.3.2.5: a TAU REJECT with cause #9/#10 that is not
     * integrity protected does NOT make the UE delete its GUTI and
     * re-attach; the UE treats it as an abnormal case and just retries
     * TAU on T3411 (observed as a 10s reject loop for inbound UEs
     * without S10 context). Send it protected whenever the current EPS
     * security context is valid (i.e. after a successful SMC).
     */
    if (SECURITY_CONTEXT_IS_VALID(mme_ue)) {
        message.h.security_header_type =
            OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
        message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    }

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_TRACKING_AREA_UPDATE_REJECT;

    tau_reject->emm_cause = emm_cause;

    if (mme_t3346_should_include(emm_cause)) {
        if (ogs_nas_gprs_timer_from_sec(&tau_reject->t3346_value.t,
                    mme_self()->time.t3346.value) == OGS_OK) {
            tau_reject->t3346_value.length = 1;
            tau_reject->presencemask |=
                OGS_NAS_EPS_TRACKING_AREA_UPDATE_REJECT_T3346_VALUE_PRESENT;
        } else {
            ogs_error("Invalid T3346 value [%ld]",
                    (long)mme_self()->time.t3346.value);
        }
    }

    if (SECURITY_CONTEXT_IS_VALID(mme_ue))
        return nas_eps_security_encode(mme_ue, &message);

    return ogs_nas_eps_plain_encode(&message);
}

ogs_pkbuf_t *emm_build_service_reject(
        ogs_nas_emm_cause_t emm_cause, mme_ue_t *mme_ue)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_service_reject_t *service_reject = &message.emm.service_reject;

    memset(&message, 0, sizeof(message));

    /* Same rationale as emm_build_tau_reject: protect when possible so
     * the UE acts on the cause instead of applying abnormal-case retry. */
    if (SECURITY_CONTEXT_IS_VALID(mme_ue)) {
        message.h.security_header_type =
            OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
        message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    }

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_SERVICE_REJECT;

    service_reject->emm_cause = emm_cause;

    if (mme_t3346_should_include(emm_cause)) {
        if (ogs_nas_gprs_timer_from_sec(&service_reject->t3346_value.t,
                    mme_self()->time.t3346.value) == OGS_OK) {
            service_reject->t3346_value.length = 1;
            service_reject->presencemask |=
                OGS_NAS_EPS_SERVICE_REJECT_T3346_VALUE_PRESENT;
        } else {
            ogs_error("Invalid T3346 value [%ld]",
                    (long)mme_self()->time.t3346.value);
        }
    }

    if (SECURITY_CONTEXT_IS_VALID(mme_ue))
        return nas_eps_security_encode(mme_ue, &message);

    return ogs_nas_eps_plain_encode(&message);
}

ogs_pkbuf_t *emm_build_cs_service_notification(mme_ue_t *mme_ue)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_cs_service_notification_t *cs_service_notification =
        &message.emm.cs_service_notification;
    ogs_nas_paging_identity_t *paging_identity =
        &cs_service_notification->paging_identity;

    ogs_assert(mme_ue);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
        OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_CS_SERVICE_NOTIFICATION;

    /* FIXME : Does it right to use TMSI */
    paging_identity->identity = OGS_NAS_PAGING_IDENTITY_TMSI;
    ogs_debug("    Paging Identity[%d]", paging_identity->identity);

    /* FIXME : What optional filed should be included in this message? */

    return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *emm_build_downlink_nas_transport(
        mme_ue_t *mme_ue, uint8_t *buffer, uint8_t length)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_downlink_nas_transport_t *downlink_nas_transport =
        &message.emm.downlink_nas_transport;
    ogs_nas_eps_message_container_t *nas_message_container =
        &downlink_nas_transport->nas_message_container;

    ogs_assert(mme_ue);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
        OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;

    message.emm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.emm.h.message_type = OGS_NAS_EPS_DOWNLINK_NAS_TRANSPORT;

    nas_message_container->length = length;
    memcpy(nas_message_container->buffer, buffer, length);

    return nas_eps_security_encode(mme_ue, &message);
}
