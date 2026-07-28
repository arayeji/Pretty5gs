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

#include "mme-event.h"
#include "mme-timer.h"
#include "mme-trace.h"

#include "s1ap-path.h"
#include "nas-path.h"
#include "mme-fd-path.h"
#include "mme-gtp-path.h"
#include "sgsap-types.h"
#include "sgsap-path.h"

#include "mme-s11-build.h"
#include "s1ap-build.h"
#include "s1ap-handler.h"

#include "mme-path.h"
#include "mme-sm.h"
#include "mme-workers.h"
#include "metrics.h"

static enb_ue_t *s1ap_find_enb_ue_by_message_ue_ids(
        mme_enb_t *enb,
        S1AP_MME_UE_S1AP_ID_t *mme_ue_s1ap_id,
        S1AP_ENB_UE_S1AP_ID_t *enb_ue_s1ap_id)
{
    enb_ue_t *enb_ue = NULL;

    ogs_assert(enb);

    if (enb_ue_s1ap_id)
        enb_ue = enb_ue_find_by_enb_ue_s1ap_id(enb, *enb_ue_s1ap_id);

    if (!enb_ue && mme_ue_s1ap_id)
        enb_ue = enb_ue_find_by_mme_ue_s1ap_id(*mme_ue_s1ap_id);

    if (!enb_ue)
        return NULL;

    if (mme_ue_s1ap_id && *mme_ue_s1ap_id &&
            enb_ue->mme_ue_s1ap_id != (uint32_t)*mme_ue_s1ap_id)
        return NULL;

    if (enb_ue_s1ap_id && *enb_ue_s1ap_id &&
            enb_ue->enb_ue_s1ap_id != (uint32_t)*enb_ue_s1ap_id)
        return NULL;

    return enb_ue;
}

static bool maximum_number_of_enbs_is_reached(void)
{
    /*
     * Use the cached enb_list count instead of walking the list:
     * this function used to be called on every S1 Setup Request
     * and was O(n) over all attached eNBs. With pool exhaustion
     * driving reconnect storms (see mme_enb_add() comment), the
     * quadratic cost saturated the main loop and starved the
     * /metrics HTTP worker (empty body / connection reset).
     *
     * We now compare against the total enb_list size rather than
     * only those with state.s1_setup_success set; the original
     * intent was to bound MME memory, and the underlying pool is
     * sized to global.max.peer*2 so this is the correct guard.
     */
    return mme_self()->num_of_enbs >= (int)ogs_global_conf()->max.peer;
}

static bool enb_plmn_id_is_foreign(mme_enb_t *enb)
{
    int i, j, k;

    for (i = 0; i < mme_self()->num_of_served_gummei; i++) {
        for (j = 0; j < mme_self()->served_gummei[i].num_of_plmn_id; j++) {
            for (k = 0; k < enb->num_of_supported_ta_list; k++) {
                if (memcmp(&mme_self()->served_gummei[i].plmn_id[j],
                            &enb->supported_ta_list[k].plmn_id,
                            OGS_PLMN_ID_LEN) == 0)
                    return false;
            }
        }
    }

    return true;
}

static bool served_tai_is_found(mme_enb_t *enb)
{
    int i;
    int served_tai_index;

    for (i = 0; i < enb->num_of_supported_ta_list; i++) {
        served_tai_index = mme_find_served_tai(&enb->supported_ta_list[i]);
        if (served_tai_index >= 0 &&
                served_tai_index < OGS_MAX_NUM_OF_SUPPORTED_TA) {
            ogs_debug("    SERVED_TAI_INDEX[%d]", served_tai_index);
            return true;
        }
    }

    return false;
}

/*
 * Print the TAIs the eNB advertised in its S1 Setup / eNB
 * Configuration Update, plus the TAIs we have configured in
 * mme.tai. Operators routinely hit "Cannot find Served TAI" with
 * nothing in the log explaining *which* TAI was missing; this
 * makes the mismatch obvious; enable [mme] DEBUG to see the dump.
 * Called from the warn-path only, so this iteration is not on the hot path.
 */
static void log_tai_mismatch_diagnostic(mme_enb_t *enb)
{
    int i, j, k;

    ogs_debug("    eNB advertised %d TAI(s):", enb->num_of_supported_ta_list);
    for (i = 0; i < enb->num_of_supported_ta_list; i++) {
        ogs_eps_tai_t *t = &enb->supported_ta_list[i];
        ogs_debug("        [%d] MCC=%03d MNC=%0*d TAC=%u (0x%04x)",
                i,
                ogs_plmn_id_mcc(&t->plmn_id),
                ogs_plmn_id_mnc_len(&t->plmn_id),
                ogs_plmn_id_mnc(&t->plmn_id),
                t->tac, t->tac);
    }

    ogs_debug("    MME 'mme.tai' is configured with %d entry/entries:",
            mme_self()->num_of_served_tai);
    for (i = 0; i < mme_self()->num_of_served_tai; i++) {
        ogs_eps_tai0_list_t *list0 = mme_self()->served_tai[i].list0;
        ogs_eps_tai1_list_t *list1 = &mme_self()->served_tai[i].list1;
        ogs_eps_tai2_list_t *list2 = &mme_self()->served_tai[i].list2;

        if (list0) {
            for (j = 0; j < (int)ogs_app_max_eps_tai0_partial_list() &&
                    list0->tai[j].num; j++) {
                for (k = 0; k < list0->tai[j].num; k++) {
                    ogs_debug("        [%d] (list0) MCC=%03d MNC=%0*d TAC=%u "
                            "(0x%04x)",
                            i,
                            ogs_plmn_id_mcc(&list0->tai[j].plmn_id),
                            ogs_plmn_id_mnc_len(&list0->tai[j].plmn_id),
                            ogs_plmn_id_mnc(&list0->tai[j].plmn_id),
                            list0->tai[j].tac[k], list0->tai[j].tac[k]);
                }
            }
        }
        for (j = 0; list1->tai[j].num; j++) {
            ogs_debug("        [%d] (list1) MCC=%03d MNC=%0*d "
                    "TAC=%u..%u (0x%04x..0x%04x)",
                    i,
                    ogs_plmn_id_mcc(&list1->tai[j].plmn_id),
                    ogs_plmn_id_mnc_len(&list1->tai[j].plmn_id),
                    ogs_plmn_id_mnc(&list1->tai[j].plmn_id),
                    list1->tai[j].tac,
                    list1->tai[j].tac + list1->tai[j].num - 1,
                    list1->tai[j].tac,
                    list1->tai[j].tac + list1->tai[j].num - 1);
        }
        for (j = 0; j < list2->num; j++) {
            ogs_debug("        [%d] (list2) MCC=%03d MNC=%0*d TAC=%u (0x%04x)",
                    i,
                    ogs_plmn_id_mcc(&list2->tai[j].plmn_id),
                    ogs_plmn_id_mnc_len(&list2->tai[j].plmn_id),
                    ogs_plmn_id_mnc(&list2->tai[j].plmn_id),
                    list2->tai[j].tac, list2->tai[j].tac);
        }
    }
}

void s1ap_handle_s1_setup_request(mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, j, r;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_S1SetupRequest_t *S1SetupRequest = NULL;

    S1AP_S1SetupRequestIEs_t *ie = NULL;
    S1AP_Global_ENB_ID_t *Global_ENB_ID = NULL;
    S1AP_SupportedTAs_t *SupportedTAs = NULL;
    S1AP_PagingDRX_t *PagingDRX = NULL;

    uint32_t enb_id;
    S1AP_Cause_PR group = S1AP_Cause_PR_NOTHING;
    long cause = 0;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    S1SetupRequest = &initiatingMessage->value.choice.S1SetupRequest;
    ogs_assert(S1SetupRequest);

    ogs_debug("S1SetupRequest");

    for (i = 0; i < S1SetupRequest->protocolIEs.list.count; i++) {
        ie = S1SetupRequest->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_Global_ENB_ID:
            Global_ENB_ID = &ie->value.choice.Global_ENB_ID;
            break;
        case S1AP_ProtocolIE_ID_id_SupportedTAs:
            SupportedTAs = &ie->value.choice.SupportedTAs;
            break;
        case S1AP_ProtocolIE_ID_id_DefaultPagingDRX:
            PagingDRX = &ie->value.choice.PagingDRX;
            break;
        default:
            break;
        }
    }

    if (!Global_ENB_ID) {
        ogs_error("No Global_ENB_ID");
        group = S1AP_Cause_PR_misc;
        cause = S1AP_CauseProtocol_semantic_error;

        r = s1ap_send_s1_setup_failure(enb, group, cause);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (Global_ENB_ID->pLMNidentity.size != sizeof(enb->plmn_id)) {
        ogs_error("Invalid PLMNIdentity size = %d (expected %d)",
                (int)Global_ENB_ID->pLMNidentity.size,
                (int)sizeof(enb->plmn_id));
        group = S1AP_Cause_PR_misc;
        cause = S1AP_CauseProtocol_semantic_error;

        r = s1ap_send_s1_setup_failure(enb, group, cause);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!SupportedTAs) {
        ogs_error("No SupportedTAs");
        group = S1AP_Cause_PR_misc;
        cause = S1AP_CauseProtocol_semantic_error;

        r = s1ap_send_s1_setup_failure(enb, group, cause);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_s1ap_ENB_ID_to_uint32(&Global_ENB_ID->eNB_ID, &enb_id);
    ogs_debug("    IP[%s] ENB_ID[%d]", OGS_ADDR(enb->sctp.addr, buf), enb_id);

    mme_enb_set_enb_id(enb, enb_id);

    memcpy(&enb->plmn_id,
            Global_ENB_ID->pLMNidentity.buf, sizeof(enb->plmn_id));
    ogs_debug("    PLMN_ID[MCC:%d MNC:%d]",
            ogs_plmn_id_mcc(&enb->plmn_id), ogs_plmn_id_mnc(&enb->plmn_id));

    if (PagingDRX)
        ogs_debug("    PagingDRX[%ld]", *PagingDRX);

    /*
     * First broadcast PLMN in the first SupportedTAs item — used to
     * order ServedGUMMEIs in the S1 Setup Response.
     */
    enb->supported_ta_plmn_present = false;
    if (SupportedTAs->list.count > 0) {
        S1AP_SupportedTAs_Item_t *first_ta =
            (S1AP_SupportedTAs_Item_t *)SupportedTAs->list.array[0];
        ogs_assert(first_ta);

        if (first_ta->broadcastPLMNs.list.count > 0) {
            S1AP_PLMNidentity_t *pLMNidentity =
                (S1AP_PLMNidentity_t *)
                first_ta->broadcastPLMNs.list.array[0];
            ogs_assert(pLMNidentity);

            if (pLMNidentity->size == sizeof(ogs_plmn_id_t)) {
                memcpy(&enb->supported_ta_plmn, pLMNidentity->buf,
                        sizeof(enb->supported_ta_plmn));
                enb->supported_ta_plmn_present = true;
                ogs_debug("    SupportedTAs PLMN_ID[MCC:%d MNC:%d]",
                        ogs_plmn_id_mcc(&enb->supported_ta_plmn),
                        ogs_plmn_id_mnc(&enb->supported_ta_plmn));
            }
        }
    }

    /*
     * Parse Supported TA into a LOCAL list, then publish it under the
     * ctx lock. Shard workers walk supported_ta_list on every paging
     * (s1ap_send_paging), so rebuilding it in place — count zeroed
     * first, entries filled one by one — let a concurrent page see an
     * empty or half-written list and skip the eNB (missed MT
     * call/SMS). Publishing atomically also keeps a malformed S1 Setup
     * from destroying the TA list the eNB is currently serving.
     */
    {
    ogs_eps_tai_t new_ta_list[OGS_MAX_NUM_OF_SUPPORTED_TA];
    int new_ta_count = 0;

    memset(new_ta_list, 0, sizeof(new_ta_list));

    for (i = 0;
            i < SupportedTAs->list.count &&
            new_ta_count < OGS_MAX_NUM_OF_SUPPORTED_TA;
            i++) {
        S1AP_SupportedTAs_Item_t *SupportedTAs_Item = NULL;
        S1AP_TAC_t *tAC = NULL;

        SupportedTAs_Item =
            (S1AP_SupportedTAs_Item_t *)SupportedTAs->list.array[i];
        ogs_assert(SupportedTAs_Item);
        tAC = &SupportedTAs_Item->tAC;
        ogs_assert(tAC);

        for (j = 0; j < SupportedTAs_Item->broadcastPLMNs.list.count; j++) {
            S1AP_PLMNidentity_t *pLMNidentity = NULL;
            pLMNidentity = (S1AP_PLMNidentity_t *)
                SupportedTAs_Item->broadcastPLMNs.list.array[j];
            ogs_assert(pLMNidentity);

            if (new_ta_count >= (int)OGS_ARRAY_SIZE(new_ta_list)) {
                ogs_error("OVERFLOW ENB->num_of_supported_ta_list "
                        "[%d:%d:%d]",
                        new_ta_count,
                        OGS_MAX_NUM_OF_SUPPORTED_TA,
                        (int)OGS_ARRAY_SIZE(new_ta_list));
                break;
            }

            if (tAC->size != sizeof(uint16_t)) {
                ogs_error("Invalid tAC size = %d (expected %d)",
                        (int)tAC->size, (int)sizeof(uint16_t));
                group = S1AP_Cause_PR_misc;
                cause = S1AP_CauseProtocol_semantic_error;

                r = s1ap_send_s1_setup_failure(enb, group, cause);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            if (pLMNidentity->size != sizeof(ogs_plmn_id_t)) {
                ogs_error("Invalid pLMNidentity size = %d (expected %d)",
                        (int)pLMNidentity->size, (int)sizeof(ogs_plmn_id_t));
                group = S1AP_Cause_PR_misc;
                cause = S1AP_CauseProtocol_semantic_error;

                r = s1ap_send_s1_setup_failure(enb, group, cause);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            memcpy(&new_ta_list[new_ta_count].tac,
                    tAC->buf, sizeof(uint16_t));
            new_ta_list[new_ta_count].tac =
                be16toh(new_ta_list[new_ta_count].tac);
            memcpy(&new_ta_list[new_ta_count].plmn_id,
                    pLMNidentity->buf, sizeof(ogs_plmn_id_t));
            ogs_debug("    PLMN_ID[MCC:%d MNC:%d] TAC[%d]",
                ogs_plmn_id_mcc(&new_ta_list[new_ta_count].plmn_id),
                ogs_plmn_id_mnc(&new_ta_list[new_ta_count].plmn_id),
                new_ta_list[new_ta_count].tac);
            new_ta_count++;
        }
    }

    /* publish atomically for the paging readers */
    mme_ctx_lock();
    memcpy(enb->supported_ta_list, new_ta_list, sizeof(new_ta_list));
    enb->num_of_supported_ta_list = new_ta_count;
    mme_ctx_unlock();
    }

    if (maximum_number_of_enbs_is_reached()) {
        ogs_warn("S1-Setup failure:");
        ogs_warn("    Maximum number of eNBs reached");
        group = S1AP_Cause_PR_misc;
        cause = S1AP_CauseMisc_unspecified;

        r = s1ap_send_s1_setup_failure(enb, group, cause);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    /*
     * TS36.413
     * Section 8.7.3.4 Abnormal Conditions
     *
     * If the eNB initiates the procedure by sending a S1 SETUP REQUEST
     * message including the PLMN Identity IEs and none of the PLMNs
     * provided by the eNB is identified by the MME, then the MME shall
     * reject the eNB S1 Setup Request procedure with the appropriate cause
     * value, e.g., “Unknown PLMN”.
     */
    if (enb_plmn_id_is_foreign(enb)) {
        ogs_warn("S1-Setup failure:");
        ogs_warn("    Global-ENB-ID PLMN-ID is foreign");
        group = S1AP_Cause_PR_misc;
        cause = S1AP_CauseMisc_unknown_PLMN;

        r = s1ap_send_s1_setup_failure(enb, group, cause);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!served_tai_is_found(enb)) {
        ogs_warn("S1-Setup failure:");
        ogs_warn("    Cannot find Served TAI. Check 'mme.tai' configuration");
        log_tai_mismatch_diagnostic(enb);
        group = S1AP_Cause_PR_misc;
        cause = S1AP_CauseMisc_unknown_PLMN;

        r = s1ap_send_s1_setup_failure(enb, group, cause);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    enb->state.s1_setup_success = true;
    r = s1ap_send_s1_setup_response(enb);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);
}

void s1ap_handle_enb_configuration_update(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    int i, j, r;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_ENBConfigurationUpdate_t *ENBConfigurationUpdate = NULL;

    S1AP_ENBConfigurationUpdateIEs_t *ie = NULL;
    S1AP_SupportedTAs_t *SupportedTAs = NULL;
    S1AP_PagingDRX_t *PagingDRX = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    ENBConfigurationUpdate =
        &initiatingMessage->value.choice.ENBConfigurationUpdate;
    ogs_assert(ENBConfigurationUpdate);

    ogs_debug("ENBConfigurationUpdate");

    for (i = 0; i < ENBConfigurationUpdate->protocolIEs.list.count; i++) {
        ie = ENBConfigurationUpdate->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_SupportedTAs:
            SupportedTAs = &ie->value.choice.SupportedTAs;
            break;
        case S1AP_ProtocolIE_ID_id_DefaultPagingDRX:
            PagingDRX = &ie->value.choice.PagingDRX;
            break;
        default:
            break;
        }
    }

    /* Parse Supported TA */
    if (SupportedTAs) {
        S1AP_Cause_PR group = S1AP_Cause_PR_NOTHING;
        long cause = 0;

        /* Local build + atomic publish: see the S1 Setup handler. */
        ogs_eps_tai_t new_ta_list[OGS_MAX_NUM_OF_SUPPORTED_TA];
        int new_ta_count = 0;

        memset(new_ta_list, 0, sizeof(new_ta_list));

        for (i = 0;
                i < SupportedTAs->list.count &&
                new_ta_count < OGS_MAX_NUM_OF_SUPPORTED_TA;
                i++) {
            S1AP_SupportedTAs_Item_t *SupportedTAs_Item = NULL;
            S1AP_TAC_t *tAC = NULL;

            SupportedTAs_Item =
                (S1AP_SupportedTAs_Item_t *)SupportedTAs->list.array[i];
            ogs_assert(SupportedTAs_Item);
            tAC = &SupportedTAs_Item->tAC;
            ogs_assert(tAC);

            for (j = 0; j < SupportedTAs_Item->broadcastPLMNs.list.count; j++) {
                S1AP_PLMNidentity_t *pLMNidentity = NULL;
                pLMNidentity = (S1AP_PLMNidentity_t *)
                    SupportedTAs_Item->broadcastPLMNs.list.array[j];
                ogs_assert(pLMNidentity);

                if (new_ta_count >= (int)OGS_ARRAY_SIZE(new_ta_list)) {
                    ogs_error("OVERFLOW ENB->num_of_supported_ta_list "
                            "[%d:%d:%d]",
                            new_ta_count,
                            OGS_MAX_NUM_OF_SUPPORTED_TA,
                            (int)OGS_ARRAY_SIZE(new_ta_list));
                    break;
                }

                if (tAC->size != sizeof(uint16_t)) {
                    ogs_error("Invalid tAC size = %d (expected %d)",
                            (int)tAC->size, (int)sizeof(uint16_t));
                    group = S1AP_Cause_PR_misc;
                    cause = S1AP_CauseProtocol_semantic_error;

                    r = s1ap_send_s1_setup_failure(enb, group, cause);
                    ogs_expect(r == OGS_OK);
                    ogs_assert(r != OGS_ERROR);
                    return;
                }

                if (pLMNidentity->size != sizeof(ogs_plmn_id_t)) {
                    ogs_error("Invalid pLMNidentity size = %d (expected %d)",
                            (int)pLMNidentity->size,
                            (int)sizeof(ogs_plmn_id_t));
                    group = S1AP_Cause_PR_misc;
                    cause = S1AP_CauseProtocol_semantic_error;

                    r = s1ap_send_s1_setup_failure(enb, group, cause);
                    ogs_expect(r == OGS_OK);
                    ogs_assert(r != OGS_ERROR);
                    return;
                }

                memcpy(&new_ta_list[new_ta_count].tac,
                        tAC->buf, sizeof(uint16_t));
                new_ta_list[new_ta_count].tac =
                    be16toh(new_ta_list[new_ta_count].tac);
                memcpy(&new_ta_list[new_ta_count].plmn_id,
                        pLMNidentity->buf, sizeof(ogs_plmn_id_t));
                ogs_debug("    PLMN_ID[MCC:%d MNC:%d] TAC[%d]",
                    ogs_plmn_id_mcc(&new_ta_list[new_ta_count].plmn_id),
                    ogs_plmn_id_mnc(&new_ta_list[new_ta_count].plmn_id),
                    new_ta_list[new_ta_count].tac);
                new_ta_count++;
            }
        }

        /* publish atomically for the paging readers */
        mme_ctx_lock();
        memcpy(enb->supported_ta_list, new_ta_list, sizeof(new_ta_list));
        enb->num_of_supported_ta_list = new_ta_count;
        mme_ctx_unlock();

        /*
         * TS36.413
         * Section 8.7.3.4 Abnormal Conditions
         *
         * If the eNB initiates the procedure by sending a S1 SETUP REQUEST
         * message including the PLMN Identity IEs and none of the PLMNs
         * provided by the eNB is identified by the MME, then the MME shall
         * reject the eNB S1 Setup Request procedure with the appropriate cause
         * value, e.g., “Unknown PLMN”.
         */
        if (enb_plmn_id_is_foreign(enb)) {
            ogs_warn("S1-Setup failure:");
            ogs_warn("    Global-ENB-ID PLMN-ID is foreign");
            group = S1AP_Cause_PR_misc;
            cause = S1AP_CauseMisc_unknown_PLMN;

            r = s1ap_send_enb_configuration_update_failure(enb, group, cause);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        if (!served_tai_is_found(enb)) {
            ogs_warn("S1-Setup failure:");
            ogs_warn("    Cannot find Served TAI. "
                    "Check 'mme.tai' configuration");
            log_tai_mismatch_diagnostic(enb);
            group = S1AP_Cause_PR_misc;
            cause = S1AP_CauseMisc_unknown_PLMN;

            r = s1ap_send_enb_configuration_update_failure(enb, group, cause);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
    }

    if (PagingDRX)
        ogs_debug("    PagingDRX[%ld]", *PagingDRX);

    r = s1ap_send_enb_configuration_update_ack(enb);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);
}

void s1ap_handle_initial_ue_message(mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    int i, r;
    char buf[OGS_ADDRSTRLEN];

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_InitialUEMessage_t *InitialUEMessage = NULL;

    S1AP_InitialUEMessage_IEs_t *ie = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_NAS_PDU_t *NAS_PDU = NULL;
    S1AP_TAI_t *TAI = NULL;
    S1AP_EUTRAN_CGI_t *EUTRAN_CGI = NULL;
    S1AP_S_TMSI_t *S_TMSI = NULL;

    S1AP_PLMNidentity_t *pLMNidentity = NULL;
    S1AP_TAC_t *tAC = NULL;
    S1AP_CellIdentity_t *cell_ID = NULL;

    enb_ue_t *enb_ue = NULL;
    mme_ue_t *mme_ue_from_stmsi = NULL;
    bool enb_ue_new = false;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    InitialUEMessage = &initiatingMessage->value.choice.InitialUEMessage;
    ogs_assert(InitialUEMessage);

    for (i = 0; i < InitialUEMessage->protocolIEs.list.count; i++) {
        ie = InitialUEMessage->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_NAS_PDU:
            NAS_PDU = &ie->value.choice.NAS_PDU;
            break;
        case S1AP_ProtocolIE_ID_id_TAI:
            TAI = &ie->value.choice.TAI;
            break;
        case S1AP_ProtocolIE_ID_id_EUTRAN_CGI:
            EUTRAN_CGI = &ie->value.choice.EUTRAN_CGI;
            break;
        case S1AP_ProtocolIE_ID_id_S_TMSI:
            S_TMSI = &ie->value.choice.S_TMSI;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!ENB_UE_S1AP_ID) {
        ogs_error("No ENB_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (*ENB_UE_S1AP_ID > 0x00ffffff) {
        ogs_error("Invalid ENB_UE_S1AP_ID [%lx]", *ENB_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    enb_ue = enb_ue_find_by_enb_ue_s1ap_id(enb, *ENB_UE_S1AP_ID);
    if (!enb_ue) {
        enb_ue = enb_ue_add(enb, *ENB_UE_S1AP_ID);
        if (enb_ue == NULL) {
            r = s1ap_send_error_indication(enb, NULL, NULL,
                    S1AP_Cause_PR_misc,
                    S1AP_CauseMisc_control_processing_overload);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
        enb_ue_new = true;

        /* Find MME_UE if S_TMSI included */
        if (S_TMSI) {
            served_gummei_t *served_gummei = &mme_self()->served_gummei[0];
            ogs_nas_eps_guti_t nas_guti;
            memset(&nas_guti, 0, sizeof(ogs_nas_eps_guti_t));

            /* Use the first configured plmn_id and mme group id */
            ogs_nas_from_plmn_id(&nas_guti.nas_plmn_id,
                    &served_gummei->plmn_id[0]);
            nas_guti.mme_gid = served_gummei->mme_gid[0];

            /* size must be 1 */
            if (S_TMSI->mMEC.size != 1) {
                ogs_error("Invalid S_TMSI->mMEC.size = %d (expected 1)",
                        (int)S_TMSI->mMEC.size);
                r = s1ap_send_error_indication1(
                        enb_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                if (enb_ue_new) enb_ue_remove(enb_ue);
                return;
            }
            memcpy(&nas_guti.mme_code, S_TMSI->mMEC.buf, S_TMSI->mMEC.size);
            /* size must be 4 */
            if (S_TMSI->m_TMSI.size != 4) {
                ogs_error("Invalid S_TMSI->m_TMSI.size = %d (expected 4)",
                        (int)S_TMSI->m_TMSI.size);
                r = s1ap_send_error_indication1(
                        enb_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                if (enb_ue_new) enb_ue_remove(enb_ue);
                return;
            }
            memcpy(&nas_guti.m_tmsi, S_TMSI->m_TMSI.buf, S_TMSI->m_TMSI.size);
            nas_guti.m_tmsi = be32toh(nas_guti.m_tmsi);

            mme_ue_from_stmsi = mme_ue_find_by_guti(&nas_guti);
            if (!mme_ue_from_stmsi) {
                ogs_mme_trace_set(enb_ue, NULL, NULL, "initial-ue");
                OGS_TLOG_DEBUG("Unknown UE by S_TMSI[G:%d,C:%d,M_TMSI:0x%x]",
                        nas_guti.mme_gid, nas_guti.mme_code, nas_guti.m_tmsi);
            } else if (!mme_ue_is_valid_for_s1(mme_ue_from_stmsi)) {
                ogs_warn("Stale MME-UE for S_TMSI[G:%d,C:%d,M_TMSI:0x%x] "
                        "(mid-teardown) - treating as unknown UE",
                        nas_guti.mme_gid, nas_guti.mme_code, nas_guti.m_tmsi);
                mme_ue_from_stmsi = NULL;
                ogs_mme_trace_set(enb_ue, NULL, NULL, "initial-ue");
            } else {
                ogs_debug("    S_TMSI[G:%d,C:%d,M_TMSI:0x%x] IMSI:[%s]",
                        mme_ue_from_stmsi->current.guti.mme_gid,
                        mme_ue_from_stmsi->current.guti.mme_code,
                        mme_ue_from_stmsi->current.guti.m_tmsi,
                        MME_UE_HAVE_IMSI(mme_ue_from_stmsi)
                            ? mme_ue_from_stmsi->imsi_bcd : "Unknown");

                /* If NAS(mme_ue_t) has already been associated with
                 * older S1(enb_ue_t) context */
                if (ECM_CONNECTED(mme_ue_from_stmsi)) {
    /*
     * Issue #2786
     *
     * In cases where the UE sends an Integrity Un-Protected Attach
     * Request or Service Request, there is an issue of sending
     * a UEContextReleaseCommand for the OLD ENB Context.
     *
     * For example, if the UE switchs off and power-on after
     * the first connection, the EPC sends a UEContextReleaseCommand.
     *
     * However, since there is no ENB context for this on the eNB,
     * the eNB does not send a UEContextReleaseComplete,
     * so the deletion of the ENB Context does not function properly.
     *
     * To solve this problem, the EPC has been modified to implicitly
     * delete the ENB Context instead of sending a UEContextReleaseCommand.
     */
                    HOLDING_S1_CONTEXT(mme_ue_from_stmsi);
                }
                enb_ue_associate_mme_ue(enb_ue, mme_ue_from_stmsi);
                ogs_debug("Mobile Reachable timer stopped for IMSI[%s]",
                    mme_ue_from_stmsi->imsi_bcd);
                CLEAR_MME_UE_TIMER(mme_ue_from_stmsi->t_mobile_reachable);
            }
        }
    } else {
        mme_ue_t *mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
        ogs_error("Known UE ENB_UE_S1AP_ID[%d] [%p:%p]",
                (int)*ENB_UE_S1AP_ID, enb_ue, mme_ue);
        if (mme_ue) {
            ogs_error("    S_TMSI[G:%d,C:%d,M_TMSI:0x%x] IMSI:[%s]",
                mme_ue->current.guti.mme_gid,
                mme_ue->current.guti.mme_code,
                mme_ue->current.guti.m_tmsi,
                MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "Unknown");
        }
    }

    {
        mme_ue_t *mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);

        ogs_mme_trace_set(enb_ue, mme_ue, NULL, "initial-ue");
        OGS_TLOG_DEBUG("InitialUEMessage");
    }

    if (!NAS_PDU) {
        ogs_error("No NAS_PDU");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        if (enb_ue_new) enb_ue_remove(enb_ue);
        return;
    }

    if (!TAI) {
        ogs_error("No TAI");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        if (enb_ue_new) enb_ue_remove(enb_ue);
        return;
    }

    if (!EUTRAN_CGI) {
        ogs_error("No EUTRAN_CGI");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        if (enb_ue_new) enb_ue_remove(enb_ue);
        return;
    }

    pLMNidentity = &TAI->pLMNidentity;
    if (pLMNidentity->size != sizeof(enb_ue->saved.tai.plmn_id)) {
        ogs_error("Invalid pLMNidentity->size = %d (expected %d)",
                (int)pLMNidentity->size,
                (int)sizeof(enb_ue->saved.tai.plmn_id));
        r = s1ap_send_error_indication1(
                enb_ue,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        if (enb_ue_new) enb_ue_remove(enb_ue);
        return;
    }
    tAC = &TAI->tAC;
    if (tAC->size != sizeof(enb_ue->saved.tai.tac)) {
        ogs_error("Invalid tAC->size = %d (expected %d)",
                (int)tAC->size, (int)sizeof(enb_ue->saved.tai.tac));
        r = s1ap_send_error_indication1(
                enb_ue,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        if (enb_ue_new) enb_ue_remove(enb_ue);
        return;
    }
    memcpy(&enb_ue->saved.tai.plmn_id, pLMNidentity->buf,
            sizeof(enb_ue->saved.tai.plmn_id));
    memcpy(&enb_ue->saved.tai.tac, tAC->buf, sizeof(enb_ue->saved.tai.tac));
    enb_ue->saved.tai.tac = be16toh(enb_ue->saved.tai.tac);

    pLMNidentity = &EUTRAN_CGI->pLMNidentity;
    if (pLMNidentity->size != sizeof(enb_ue->saved.e_cgi.plmn_id)) {
        ogs_error("Invalid pLMNidentity->size = %d (expected %d)",
                (int)pLMNidentity->size,
                (int)sizeof(enb_ue->saved.e_cgi.plmn_id));
        r = s1ap_send_error_indication1(
                enb_ue,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        if (enb_ue_new) enb_ue_remove(enb_ue);
        return;
    }
    cell_ID = &EUTRAN_CGI->cell_ID;
    if (cell_ID->size != sizeof(enb_ue->saved.e_cgi.cell_id)) {
        ogs_error("Invalid cell_ID->size = %d (expected %d)",
                (int)cell_ID->size,
                (int)sizeof(enb_ue->saved.e_cgi.cell_id));
        r = s1ap_send_error_indication1(
                enb_ue,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        if (enb_ue_new) enb_ue_remove(enb_ue);
        return;
    }

    memcpy(&enb_ue->saved.e_cgi.plmn_id, pLMNidentity->buf,
            sizeof(enb_ue->saved.e_cgi.plmn_id));
    memcpy(&enb_ue->saved.e_cgi.cell_id, cell_ID->buf,
            sizeof(enb_ue->saved.e_cgi.cell_id));
    enb_ue->saved.e_cgi.cell_id = (be32toh(enb_ue->saved.e_cgi.cell_id) >> 4);

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d] TAC[%d] CellID[0x%x]",
        enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id,
        enb_ue->saved.tai.tac, enb_ue->saved.e_cgi.cell_id);

    ogs_expect(OGS_OK == s1ap_send_to_nas(
                enb_ue, S1AP_ProcedureCode_id_initialUEMessage, NAS_PDU));
}

void s1ap_handle_uplink_nas_transport(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_UplinkNASTransport_t *UplinkNASTransport = NULL;

    S1AP_UplinkNASTransport_IEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_NAS_PDU_t *NAS_PDU = NULL;
    S1AP_EUTRAN_CGI_t *EUTRAN_CGI = NULL;
    S1AP_TAI_t *TAI = NULL;

    S1AP_PLMNidentity_t *pLMNidentity = NULL;
    S1AP_TAC_t *tAC = NULL;
    S1AP_CellIdentity_t *cell_ID = NULL;

    enb_ue_t *enb_ue = NULL;
    mme_ue_t *mme_ue = NULL;

    ogs_eps_tai_t tai;
    int served_tai_index = 0;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    UplinkNASTransport = &initiatingMessage->value.choice.UplinkNASTransport;
    ogs_assert(UplinkNASTransport);

    ogs_debug("UplinkNASTransport");

    for (i = 0; i < UplinkNASTransport->protocolIEs.list.count; i++) {
        ie = UplinkNASTransport->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_NAS_PDU:
            NAS_PDU = &ie->value.choice.NAS_PDU;
            break;
        case S1AP_ProtocolIE_ID_id_EUTRAN_CGI:
            EUTRAN_CGI = &ie->value.choice.EUTRAN_CGI;
            break;
        case S1AP_ProtocolIE_ID_id_TAI:
            TAI = &ie->value.choice.TAI;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    enb_ue = s1ap_find_enb_ue_by_message_ue_ids(
            enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("%s: Failed to find eNB UE by S1AP UE IDs", __func__);
        return;
    }

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    /*
     * Stale S1 context. Dominant trigger: HOLDING_S1_CONTEXT parks the
     * old enb_ue (ue_ctx_rel_action + t_s1_holding) when a newer S1
     * arrives for the same NAS UE; the held enb_ue stays until Implicit
     * S1 release / CLEAR_S1_CONTEXT (per TS 23.401 §5.3.4.4).
     *
     * If the eNB sends a stale UplinkNASTransport on the held IDs during
     * that window, send UEContextReleaseCommand here so the eNB can
     * promptly release its end of the stale RAN context. We do NOT
     * forward the held NAS message to the NAS layer - the UE has
     * abandoned this radio link, and replaying an old NAS message
     * through the EMM state machine could re-associate the held enb_ue
     * with the live mme_ue and cause responses to be sent on the wrong
     * S1 connection. The t_s1_holding timer guarantees local cleanup
     * even if the eNB does not respond.
     *
     * Mirrors the AMF NGAP handling in ngap_handle_uplink_nas_transport().
     */
    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (!mme_ue) {
        ogs_warn("UplinkNASTransport on stale S1 context "
                "[MME_UE_S1AP_ID:%d] - sending UEContextReleaseCommand",
                enb_ue->mme_ue_s1ap_id);
        r = s1ap_send_ue_context_release_command(
                enb_ue, S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unspecified,
                S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!NAS_PDU) {
        ogs_error("No NAS_PDU");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!EUTRAN_CGI) {
        ogs_error("No EUTRAN_CGI");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!TAI) {
        ogs_error("No TAI");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    pLMNidentity = &TAI->pLMNidentity;
    if (pLMNidentity->size != sizeof(tai.plmn_id)) {
        ogs_error("Invalid pLMNidentity->size = %d (expected %d)",
                (int)pLMNidentity->size,
                (int)sizeof(tai.plmn_id));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    tAC = &TAI->tAC;
    if (tAC->size != sizeof(tai.tac)) {
        ogs_error("Invalid tAC->size = %d (expected %d)",
                (int)tAC->size, (int)sizeof(tai.tac));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    memcpy(&tai.plmn_id, pLMNidentity->buf, sizeof(tai.plmn_id));
    memcpy(&tai.tac, tAC->buf, sizeof(tai.tac));
    tai.tac = be16toh(tai.tac);

    /* Check TAI */
    served_tai_index = mme_find_served_tai(&tai);
    if (served_tai_index < 0) {
        ogs_error("Cannot find Served TAI[PLMN_ID:%06x,TAC:%d]",
            ogs_plmn_id_hexdump(&tai.plmn_id), tai.tac);
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_message_not_compatible_with_receiver_state);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    ogs_debug("    SERVED_TAI_INDEX[%d]", served_tai_index);

    pLMNidentity = &EUTRAN_CGI->pLMNidentity;
    if (pLMNidentity->size != sizeof(enb_ue->saved.e_cgi.plmn_id)) {
        ogs_error("Invalid pLMNidentity->size = %d (expected %d)",
                (int)pLMNidentity->size,
                (int)sizeof(enb_ue->saved.e_cgi.plmn_id));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    cell_ID = &EUTRAN_CGI->cell_ID;
    if (cell_ID->size != sizeof(enb_ue->saved.e_cgi.cell_id)) {
        ogs_error("Invalid cell_ID->size = %d (expected %d)",
                (int)cell_ID->size,
                (int)sizeof(enb_ue->saved.e_cgi.cell_id));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    memcpy(&enb_ue->saved.e_cgi.plmn_id, pLMNidentity->buf,
            sizeof(enb_ue->saved.e_cgi.plmn_id));
    memcpy(&enb_ue->saved.e_cgi.cell_id, cell_ID->buf,
            sizeof(enb_ue->saved.e_cgi.cell_id));
    enb_ue->saved.e_cgi.cell_id = (be32toh(enb_ue->saved.e_cgi.cell_id) >> 4);

    pLMNidentity = &TAI->pLMNidentity;
    if (pLMNidentity->size != sizeof(enb_ue->saved.tai.plmn_id)) {
        ogs_error("Invalid pLMNidentity->size = %d (expected %d)",
                (int)pLMNidentity->size,
                (int)sizeof(enb_ue->saved.tai.plmn_id));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    tAC = &TAI->tAC;
    if (tAC->size != sizeof(enb_ue->saved.tai.tac)) {
        ogs_error("Invalid tAC->size = %d (expected %d)",
                (int)tAC->size, (int)sizeof(enb_ue->saved.tai.tac));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    memcpy(&enb_ue->saved.tai.plmn_id, pLMNidentity->buf,
            sizeof(enb_ue->saved.tai.plmn_id));
    memcpy(&enb_ue->saved.tai.tac, tAC->buf, sizeof(enb_ue->saved.tai.tac));
    enb_ue->saved.tai.tac = be16toh(enb_ue->saved.tai.tac);

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d] TAC[%d] CellID[0x%x]",
        enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id,
        enb_ue->saved.tai.tac, enb_ue->saved.e_cgi.cell_id);

    /* Copy Stream-No/TAI/ECGI from enb_ue (mme_ue checked at function entry).
     * With mme.workers the owner shard applies the snapshot instead
     * (mme-sm.c); main must not write shard-owned mme_ue fields. */
    if (!mme_workers_active()) {
        memcpy(&mme_ue->tai, &enb_ue->saved.tai, sizeof(ogs_eps_tai_t));
        memcpy(&mme_ue->e_cgi, &enb_ue->saved.e_cgi, sizeof(ogs_e_cgi_t));
        mme_ue->ue_location_timestamp = ogs_time_now();
    }

    ogs_expect(OGS_OK == s1ap_send_to_nas(
                enb_ue, S1AP_ProcedureCode_id_uplinkNASTransport, NAS_PDU));
}

void s1ap_handle_ue_capability_info_indication(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_UECapabilityInfoIndication_t *UECapabilityInfoIndication = NULL;

    S1AP_UECapabilityInfoIndicationIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_UERadioCapability_t *UERadioCapability = NULL;

    enb_ue_t *enb_ue = NULL;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    UECapabilityInfoIndication =
        &initiatingMessage->value.choice.UECapabilityInfoIndication;
    ogs_assert(UECapabilityInfoIndication);

    ogs_debug("UECapabilityInfoIndication");

    for (i = 0; i < UECapabilityInfoIndication->protocolIEs.list.count; i++) {
        ie = UECapabilityInfoIndication->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_UERadioCapability:
            UERadioCapability = &ie->value.choice.UERadioCapability;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    enb_ue = s1ap_find_enb_ue_by_message_ue_ids(
            enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("%s: Failed to find eNB UE by S1AP UE IDs", __func__);
        return;
    }

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (mme_ue) {
        /*
         * UERadioCapability is mandatory per S1AP, but a malformed or
         * partial UECapabilityInfoIndication (seen in production right
         * after eNB SCTP timeouts) can arrive without it, leaving the
         * pointer NULL. It is only cached for later handover use, so a
         * missing IE must warn-and-skip, never abort the whole MME.
         */
        if (UERadioCapability)
            OGS_ASN_STORE_DATA(&mme_ue->ueRadioCapability, UERadioCapability);
        else
            ogs_warn("UECapabilityInfoIndication without UERadioCapability "
                    "IE [eNB:%d ENB_UE_S1AP_ID:%d]",
                    enb->enb_id, enb_ue->enb_ue_s1ap_id);
    }
}

void s1ap_handle_initial_context_setup_response(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    int i, r, rv;
    char buf[OGS_ADDRSTRLEN];

    S1AP_SuccessfulOutcome_t *successfulOutcome = NULL;
    S1AP_InitialContextSetupResponse_t *InitialContextSetupResponse = NULL;

    S1AP_InitialContextSetupResponseIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_E_RABSetupListCtxtSURes_t *E_RABSetupListCtxtSURes = NULL;

    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    successfulOutcome = message->choice.successfulOutcome;
    ogs_assert(successfulOutcome);
    InitialContextSetupResponse =
        &successfulOutcome->value.choice.InitialContextSetupResponse;
    ogs_assert(InitialContextSetupResponse);

    ogs_debug("InitialContextSetupResponse");

    for (i = 0; i < InitialContextSetupResponse->protocolIEs.list.count; i++) {
        ie = InitialContextSetupResponse->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_E_RABSetupListCtxtSURes:
            E_RABSetupListCtxtSURes =
                &ie->value.choice.E_RABSetupListCtxtSURes;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    enb_ue = s1ap_find_enb_ue_by_message_ue_ids(
            enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("%s: Failed to find eNB UE by S1AP UE IDs", __func__);
        return;
    }

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (!mme_ue) {
        /*
         * Stale S1 context - see s1ap_handle_uplink_nas_transport()
         * for the rationale. Send UEContextReleaseCommand so the eNB
         * cleans up its end of the stale RAN context.
         */
        ogs_warn("InitialContextSetupResponse on stale S1 context "
                "[MME_UE_S1AP_ID:%d] - sending UEContextReleaseCommand",
                enb_ue->mme_ue_s1ap_id);
        r = s1ap_send_ue_context_release_command(
                enb_ue, S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unspecified,
                S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    /*
     * Snapshot the E-RAB Setup items out of the ASN.1 message on main
     * (the decoded PDU is freed after dispatch), then run the tail —
     * bearer enb_s1u_teid/ip writes, bearer_to_modify_list, the S11
     * Modify Bearer send and the paging check — on the UE owner shard.
     * All of that state is shard-owned (TSAN: main ICS-Response paging
     * read vs owner-shard Create-Bearer-Request paging write).
     */
    {
        mme_ics_rsp_tail_t *tail = NULL;
        ogs_pkbuf_t *tailbuf = NULL;
        int count = E_RABSetupListCtxtSURes ?
            E_RABSetupListCtxtSURes->list.count : 0;

        tailbuf = ogs_pkbuf_alloc(NULL, sizeof(mme_ics_rsp_tail_t) +
                count * sizeof(mme_ics_rsp_erab_t));
        ogs_assert(tailbuf);
        ogs_pkbuf_put(tailbuf, sizeof(mme_ics_rsp_tail_t) +
                count * sizeof(mme_ics_rsp_erab_t));
        tail = (mme_ics_rsp_tail_t *)tailbuf->data;
        memset(tail, 0, tailbuf->len);
        tail->erab_present = (E_RABSetupListCtxtSURes != NULL);

        for (i = 0; i < count; i++) {
            S1AP_E_RABSetupItemCtxtSUResIEs_t *item = NULL;
            S1AP_E_RABSetupItemCtxtSURes_t *e_rab = NULL;
            mme_ics_rsp_erab_t *erab = &tail->erab[tail->num_of_erab];

            item = (S1AP_E_RABSetupItemCtxtSUResIEs_t *)
                E_RABSetupListCtxtSURes->list.array[i];
            if (!item) {
                ogs_error("No S1AP_E_RABSetupItemCtxtSUResIEs_t");
                r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                ogs_pkbuf_free(tailbuf);
                return;
            }

            e_rab = &item->value.choice.E_RABSetupItemCtxtSURes;
            if (!e_rab) {
                ogs_error("No E_RABSetupItemCtxtSURes");
                r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                ogs_pkbuf_free(tailbuf);
                return;
            }

            if (e_rab->gTP_TEID.size != sizeof(erab->enb_s1u_teid)) {
                ogs_error("Invalid e_rab->gTP_TEID.size = %d (expected %d)",
                        (int)e_rab->gTP_TEID.size,
                        (int)sizeof(erab->enb_s1u_teid));
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                ogs_pkbuf_free(tailbuf);
                return;
            }
            erab->ebi = e_rab->e_RAB_ID;
            memcpy(&erab->enb_s1u_teid, e_rab->gTP_TEID.buf,
                    sizeof(erab->enb_s1u_teid));
            erab->enb_s1u_teid = be32toh(erab->enb_s1u_teid);

            rv = ogs_asn_BIT_STRING_to_ip(
                    &e_rab->transportLayerAddress, &erab->enb_s1u_ip);
            if (rv != OGS_OK) {
                ogs_error("No transportLayerAddress [%d]",
                        (int)e_rab->e_RAB_ID);
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_abstract_syntax_error_falsely_constructed_message);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                ogs_pkbuf_free(tailbuf);
                return;
            }

            ogs_log_hexdump(OGS_LOG_DEBUG,
                    e_rab->transportLayerAddress.buf,
                    e_rab->transportLayerAddress.size);

            tail->num_of_erab++;
        }

        if (mme_workers_active()) {
            /* takes ownership of tailbuf on success only */
            if (mme_worker_post_ho_tail(
                        MME_HO_TAIL_ICS_RSP, enb_ue->id,
                        mme_ue, tailbuf) == OGS_OK)
                return;

            /*
             * Dropping the tail means Modify Bearer Request is never
             * sent and the SGW keeps forwarding DL to the previous
             * (dead) eNB TEID until the next paging cycle. Run inline
             * on main instead: a rare cross-shard access beats a
             * black-holed session.
             */
            ogs_warn("[%s] InitialContextSetupResponse tail post failed; "
                    "running inline", mme_ue->imsi_bcd);
        }

        s1ap_initial_context_setup_response_complete(enb_ue, mme_ue, tail);
        ogs_pkbuf_free(tailbuf);
    }
}

/*
 * Tail of InitialContextSetupResponse handling. With mme.workers this
 * runs on the UE owner shard (MME_EVENT_S1AP_HO_TAIL / ICS_RSP);
 * workers off, it is called directly by the handler above.
 */
void s1ap_initial_context_setup_response_complete(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue, mme_ics_rsp_tail_t *tail)
{
    int i, r;

    ogs_assert(enb_ue);
    ogs_assert(mme_ue);
    ogs_assert(tail);

    if (tail->erab_present) {
        int uli_presence = 0;

        ogs_list_init(&mme_ue->bearer_to_modify_list);

        for (i = 0; i < tail->num_of_erab; i++) {
            mme_ics_rsp_erab_t *erab = &tail->erab[i];
            mme_bearer_t *bearer = NULL;

            bearer = mme_bearer_find_by_ue_ebi(mme_ue, erab->ebi);
            if (!bearer) {
                ogs_error("No Bearer [%d]", (int)erab->ebi);
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_radioNetwork,
                        S1AP_CauseRadioNetwork_unknown_E_RAB_ID);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            bearer->enb_s1u_teid = erab->enb_s1u_teid;
            memcpy(&bearer->enb_s1u_ip, &erab->enb_s1u_ip,
                    sizeof(bearer->enb_s1u_ip));

            ogs_debug("UE[%s] EBI[%d] Update enb_s1u_teid = 0x%x",
                    mme_ue->imsi_bcd, bearer->ebi, bearer->enb_s1u_teid);
            ogs_debug("    IPv4(%d): 0x%x",
                    bearer->enb_s1u_ip.ipv4, bearer->enb_s1u_ip.addr);
            ogs_debug("    IPv6(%d):", bearer->enb_s1u_ip.ipv6);
            ogs_log_hexdump(OGS_LOG_DEBUG,
                    bearer->enb_s1u_ip.addr6, OGS_IPV6_LEN);

            if (!bearer->sgw_s1u_teid) {
                /*
                 * The SGW never created (or already deleted) this bearer.
                 * Including it would make the SGW-C reject the whole
                 * Modify Bearer Request with Context Not Found, so the
                 * *other* bearers keep the previous eNB TEID and downlink
                 * black-holes for the entire UE.
                 */
                ogs_warn("UE[%s] EBI[%d] has no SGW S1-U TEID in "
                        "InitialContextSetupResponse: excluded from "
                        "Modify Bearer Request",
                        mme_ue->imsi_bcd, bearer->ebi);
            } else if (OGS_FSM_CHECK(&bearer->sm, esm_state_active)) {
                ogs_debug("    NAS_EPS Type[%d]", mme_ue->nas_eps.type);
                if (mme_ue->nas_eps.type != MME_EPS_TYPE_ATTACH_REQUEST) {
                    ogs_debug("    ### ULI PRESENT ###");
                    uli_presence = 1;
                }
                if (ogs_list_exists(
                            &mme_ue->bearer_to_modify_list,
                            &bearer->to_modify_node) == false)
                    ogs_list_add(
                            &mme_ue->bearer_to_modify_list,
                            &bearer->to_modify_node);
                else
                    ogs_warn("Bearer [%d] Duplicated", (int)erab->ebi);
            } else {
                /*
                 * TEID stored but Modify Bearer skipped: the SGW keeps
                 * the previous eNB TEID for this bearer. Surface it —
                 * a stale-TEID DL black hole starts exactly here.
                 */
                ogs_warn("UE[%s] EBI[%d] ESM inactive in "
                        "InitialContextSetupResponse: Modify Bearer "
                        "skipped, SGW keeps previous eNB TEID",
                        mme_ue->imsi_bcd, bearer->ebi);
            }
        }

        if (ogs_list_count(&mme_ue->bearer_to_modify_list)) {
            if (mme_ue->nas_eps.type == MME_EPS_TYPE_SERVICE_REQUEST)
                mme_ue_service_progress(mme_ue, enb_ue, "ics_rsp");

            if (mme_gtp_send_modify_bearer_request(
                    enb_ue, mme_ue, uli_presence, 0) != OGS_OK) {
                if (mme_ue->nas_eps.type == MME_EPS_TYPE_SERVICE_REQUEST)
                    mme_ue_service_progress(mme_ue, enb_ue, "mbr_req_fail");
            }
        } else if (mme_ue->nas_eps.type == MME_EPS_TYPE_SERVICE_REQUEST) {
            mme_ue_service_error(mme_ue, enb_ue,
                    "InitialContextSetupResponse: no bearer to modify");
            mme_ue_service_progress(mme_ue, enb_ue, "ics_rsp_no_bearer");
        }
    }

    if (MME_PAGING_ONGOING(mme_ue))
        mme_send_after_paging(mme_ue, false);
}

void s1ap_handle_initial_context_setup_failure(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_UnsuccessfulOutcome_t *unsuccessfulOutcome = NULL;
    S1AP_InitialContextSetupFailure_t *InitialContextSetupFailure = NULL;

    S1AP_InitialContextSetupFailureIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_Cause_t *Cause = NULL;

    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    unsuccessfulOutcome = message->choice.unsuccessfulOutcome;
    ogs_assert(unsuccessfulOutcome);
    InitialContextSetupFailure =
        &unsuccessfulOutcome->value.choice.InitialContextSetupFailure;
    ogs_assert(InitialContextSetupFailure);

    ogs_debug("InitialContextSetupFailure");

    for (i = 0; i < InitialContextSetupFailure->protocolIEs.list.count; i++) {
        ie = InitialContextSetupFailure->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_Cause:
            Cause = &ie->value.choice.Cause;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    enb_ue = s1ap_find_enb_ue_by_message_ue_ids(
            enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("%s: Failed to find eNB UE by S1AP UE IDs", __func__);
        return;
    }

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    if (!Cause) {
        ogs_error("No Cause");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    {
        mme_sess_t *sess = mme_ue ? mme_sess_first(mme_ue) : NULL;
        const char *apn = (sess && sess->session) ? sess->session->name : NULL;

        s1ap_log_ue_failure(enb_ue, mme_ue, NULL, apn, "attach-fail",
                "InitialContextSetupFailure", Cause);
    }

    if (mme_ue) {
        if (mme_ue->nas_eps.type == MME_EPS_TYPE_SERVICE_REQUEST)
            mme_ue_service_progress(mme_ue, enb_ue, "ics_fail");

        /*
         * if T3450 is running, Attach complete will be sent.
         * So, we need to clear all the timer at this point.
         */
        CLEAR_SERVICE_INDICATOR(mme_ue);
        CLEAR_MME_UE_ALL_TIMERS(mme_ue);
    }

    enb_ue->relcause.group = S1AP_Cause_PR_nas;
    enb_ue->relcause.cause = S1AP_CauseNas_normal_release;

    /*
     * 19.2.2.3 in Spec 36.300
     *
     * In case of failure, eNB and MME behaviours are not mandated.
     *
     * Both implicit release (local release at each node) and
     * explicit release (MME-initiated UE Context Release procedure)
     * may in principle be adopted. The eNB should ensure
     * that no hanging resources remain at the eNB.
     */
    mme_send_release_access_bearer_or_ue_context_release(enb_ue);
}

void s1ap_handle_ue_context_modification_response(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_SuccessfulOutcome_t *successfulOutcome = NULL;
    S1AP_UEContextModificationResponse_t *UEContextModificationResponse = NULL;

    S1AP_UEContextModificationResponseIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;

    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    successfulOutcome = message->choice.successfulOutcome;
    ogs_assert(successfulOutcome);
    UEContextModificationResponse =
        &successfulOutcome->value.choice.UEContextModificationResponse;
    ogs_assert(UEContextModificationResponse);

    ogs_debug("UEContextModificationResponse");

    for (i = 0;
            i < UEContextModificationResponse->protocolIEs.list.count; i++) {
        ie = UEContextModificationResponse->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    enb_ue = s1ap_find_enb_ue_by_message_ue_ids(
            enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("%s: Failed to find eNB UE by S1AP UE IDs", __func__);
        return;
    }

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (!mme_ue) {
        /*
         * Stale S1 context - see s1ap_handle_uplink_nas_transport()
         * for the rationale. Send UEContextReleaseCommand so the eNB
         * cleans up its end of the stale RAN context.
         */
        ogs_warn("UEContextModificationResponse on stale S1 context "
                "[MME_UE_S1AP_ID:%d] - sending UEContextReleaseCommand",
                enb_ue->mme_ue_s1ap_id);
        r = s1ap_send_ue_context_release_command(
                enb_ue, S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unspecified,
                S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    CLEAR_SERVICE_INDICATOR(mme_ue);
}

void s1ap_handle_ue_context_modification_failure(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_UnsuccessfulOutcome_t *unsuccessfulOutcome = NULL;
    S1AP_UEContextModificationFailure_t *UEContextModificationFailure = NULL;

    S1AP_UEContextModificationFailureIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_Cause_t *Cause = NULL;

    enb_ue_t *enb_ue = NULL;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    unsuccessfulOutcome = message->choice.unsuccessfulOutcome;
    ogs_assert(unsuccessfulOutcome);
    UEContextModificationFailure =
        &unsuccessfulOutcome->value.choice.UEContextModificationFailure;
    ogs_assert(UEContextModificationFailure);

    ogs_warn("UEContextModificationFailure");

    for (i = 0; i < UEContextModificationFailure->protocolIEs.list.count; i++) {
        ie = UEContextModificationFailure->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_Cause:
            Cause = &ie->value.choice.Cause;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    enb_ue = s1ap_find_enb_ue_by_message_ue_ids(
            enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("%s: Failed to find eNB UE by S1AP UE IDs", __func__);
        return;
    }

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    if (!Cause) {
        ogs_error("No Cause");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_debug("    Cause[Group:%d Cause:%d]",
            Cause->present, (int)Cause->choice.radioNetwork);

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (!mme_ue) {
        /*
         * Stale S1 context - see s1ap_handle_uplink_nas_transport()
         * for the rationale. Send UEContextReleaseCommand so the eNB
         * cleans up its end of the stale RAN context.
         */
        ogs_warn("UEContextModificationFailure on stale S1 context "
                "[MME_UE_S1AP_ID:%d] - sending UEContextReleaseCommand",
                enb_ue->mme_ue_s1ap_id);
        r = s1ap_send_ue_context_release_command(
                enb_ue, S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unspecified,
                S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    CLEAR_SERVICE_INDICATOR(mme_ue);
}


void s1ap_handle_e_rab_setup_response(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    int i, r, rv;
    char buf[OGS_ADDRSTRLEN];

    S1AP_SuccessfulOutcome_t *successfulOutcome = NULL;
    S1AP_E_RABSetupResponse_t *E_RABSetupResponse = NULL;

    S1AP_E_RABSetupResponseIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_E_RABSetupListBearerSURes_t *E_RABSetupListBearerSURes = NULL;
    S1AP_E_RABList_t *E_RABFailedToSetupListBearerSURes = NULL;
    S1AP_CriticalityDiagnostics_t *CriticalityDiagnostics = NULL;

    enb_ue_t *enb_ue = NULL;
    mme_ue_t *mme_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;

    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;
    mme_bearer_t *linked_bearer = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    successfulOutcome = message->choice.successfulOutcome;
    ogs_assert(successfulOutcome);
    E_RABSetupResponse = &successfulOutcome->value.choice.E_RABSetupResponse;
    ogs_assert(E_RABSetupResponse);

    ogs_debug("E-RABSetupResponse");

    for (i = 0; i < E_RABSetupResponse->protocolIEs.list.count; i++) {
        ie = E_RABSetupResponse->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_E_RABSetupListBearerSURes:
            E_RABSetupListBearerSURes =
                &ie->value.choice.E_RABSetupListBearerSURes;
            break;
        case S1AP_ProtocolIE_ID_id_E_RABFailedToSetupListBearerSURes:
            E_RABFailedToSetupListBearerSURes =
                &ie->value.choice.E_RABList;
            break;
        case S1AP_ProtocolIE_ID_id_CriticalityDiagnostics:
            CriticalityDiagnostics =
                &ie->value.choice.CriticalityDiagnostics;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    enb_ue = s1ap_find_enb_ue_by_message_ue_ids(
            enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("%s: Failed to find eNB UE by S1AP UE IDs", __func__);
        return;
    }

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
        enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (!mme_ue) {
        /*
         * Stale S1 context - see s1ap_handle_uplink_nas_transport()
         * for the rationale. Send UEContextReleaseCommand so the eNB
         * cleans up its end of the stale RAN context.
         */
        ogs_warn("E-RABSetupResponse on stale S1 context "
                "[MME_UE_S1AP_ID:%d] - sending UEContextReleaseCommand",
                enb_ue->mme_ue_s1ap_id);
        r = s1ap_send_ue_context_release_command(
                enb_ue, S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unspecified,
                S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (E_RABSetupListBearerSURes) {
        for (i = 0; i < E_RABSetupListBearerSURes->list.count; i++) {
            S1AP_E_RABSetupItemBearerSUResIEs_t *item = NULL;
            S1AP_E_RABSetupItemBearerSURes_t *e_rab = NULL;

            item = (S1AP_E_RABSetupItemBearerSUResIEs_t *)
                E_RABSetupListBearerSURes->list.array[i];
            if (!item) {
                ogs_error("No S1AP_E_RABSetupItemBearerSUResIEs_t");
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            e_rab = &item->value.choice.E_RABSetupItemBearerSURes;
            if (!e_rab) {
                ogs_error("No E_RABSetupItemBearerSURes");
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            bearer = mme_bearer_find_by_ue_ebi(mme_ue, e_rab->e_RAB_ID);
            if (!bearer) {
                ogs_error("No Bearer [%d]", (int)e_rab->e_RAB_ID);
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_radioNetwork,
                        S1AP_CauseRadioNetwork_unknown_E_RAB_ID);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            if (e_rab->gTP_TEID.size != sizeof(bearer->enb_s1u_teid)) {
                ogs_error("Invalid e_rab->gTP_TEID.size = %d (expected %d)",
                        (int)e_rab->gTP_TEID.size,
                        (int)sizeof(bearer->enb_s1u_teid));
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }
            memcpy(&bearer->enb_s1u_teid, e_rab->gTP_TEID.buf,
                    sizeof(bearer->enb_s1u_teid));
            bearer->enb_s1u_teid = be32toh(bearer->enb_s1u_teid);

            ogs_debug("UE[%s] EBI[%d] Update enb_s1u_teid = 0x%x",
                    mme_ue->imsi_bcd, bearer->ebi, bearer->enb_s1u_teid);

            rv = ogs_asn_BIT_STRING_to_ip(
                    &e_rab->transportLayerAddress, &bearer->enb_s1u_ip);
            if (rv != OGS_OK) {
                ogs_error("No transportLayerAddress [%d]",
                        (int)e_rab->e_RAB_ID);
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_abstract_syntax_error_falsely_constructed_message);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            ogs_log_hexdump(OGS_LOG_DEBUG,
                    e_rab->transportLayerAddress.buf,
                    e_rab->transportLayerAddress.size);
            ogs_debug("    IPv4(%d): 0x%x",
                    bearer->enb_s1u_ip.ipv4, bearer->enb_s1u_ip.addr);
            ogs_debug("    IPv6(%d):", bearer->enb_s1u_ip.ipv6);
            ogs_log_hexdump(OGS_LOG_DEBUG,
                    bearer->enb_s1u_ip.addr6, OGS_IPV6_LEN);

            CLEAR_BEARER_TIMER(bearer->t_bearer_setup);

            if (OGS_FSM_CHECK(&bearer->sm, esm_state_active)) {
                linked_bearer = mme_linked_bearer(bearer);
                ogs_assert(linked_bearer);
                ogs_debug("    Linked-EBI[%d]", linked_bearer->ebi);

                if (bearer->ebi == linked_bearer->ebi) {
                    ogs_list_init(&mme_ue->bearer_to_modify_list);
                    ogs_list_add(&mme_ue->bearer_to_modify_list,
                                    &bearer->to_modify_node);
                    if (mme_gtp_send_modify_bearer_request(
                                enb_ue, mme_ue, 0, 0) != OGS_OK)
                        ogs_error("[%s] Modify Bearer Request failed "
                                "after E-RAB setup EBI[%d]",
                                mme_ue->imsi_bcd, bearer->ebi);
                } else {
                    if (mme_gtp_send_create_bearer_response(
                                bearer,
                                OGS_GTP2_CAUSE_REQUEST_ACCEPTED) != OGS_OK)
                        ogs_error("[%s] Create Bearer Response failed EBI[%d]",
                                mme_ue->imsi_bcd, bearer->ebi);
                }
            }
        }
    }

    if (E_RABFailedToSetupListBearerSURes) {
        for (i = 0; i < E_RABFailedToSetupListBearerSURes->list.count; i++) {
            S1AP_E_RABItemIEs_t *item = NULL;
            S1AP_E_RABItem_t *e_rab = NULL;

            item = (S1AP_E_RABItemIEs_t *)
                E_RABFailedToSetupListBearerSURes->list.array[i];

            if (!item) {
                ogs_error("No S1AP_E_RABItemIEs_t");
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            e_rab = &item->value.choice.E_RABItem;

            bearer = mme_bearer_find_by_ue_ebi(mme_ue, e_rab->e_RAB_ID);
            if (!bearer) {
                ogs_error("No Bearer [%d]", (int)e_rab->e_RAB_ID);
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_radioNetwork,
                        S1AP_CauseRadioNetwork_unknown_E_RAB_ID);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            {
                mme_sess_t *sess = mme_sess_find_by_id(bearer->sess_id);
                const char *apn = (sess && sess->session) ? sess->session->name : NULL;

                s1ap_log_ue_failure(enb_ue, mme_ue, bearer, apn, "attach-fail",
                        "E-RAB setup failed", &e_rab->cause);
            }

            CLEAR_BEARER_TIMER(bearer->t_bearer_setup);

            linked_bearer = mme_linked_bearer(bearer);
            ogs_assert(linked_bearer);
            ogs_debug("    Linked-EBI[%d]", linked_bearer->ebi);

            if (bearer->ebi == linked_bearer->ebi) {
                sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
                ogs_assert(sgw_ue);

                sess = mme_sess_find_by_id(bearer->sess_id);
                ogs_assert(sess);

                /* Radio failure cleanup:
                 * delete session without E-RAB release procedure */
                if (mme_gtp_send_delete_session_request(enb_ue, sgw_ue, sess,
                            OGS_GTP_DELETE_NO_ACTION) != OGS_OK)
                    ogs_error("[%s] Delete Session Request failed EBI[%d]",
                            mme_ue->imsi_bcd, bearer->ebi);
                else
                    ogs_warn("Delete Session Request");
            } else {
                if (mme_gtp_send_create_bearer_response(bearer,
                            OGS_GTP2_CAUSE_REQUEST_REJECTED_REASON_NOT_SPECIFIED)
                        != OGS_OK)
                    ogs_error("[%s] Create Bearer Response (reject) failed "
                            "EBI[%d]", mme_ue->imsi_bcd, bearer->ebi);
                mme_bearer_remove(bearer);
            }
        }
    }

    if (CriticalityDiagnostics) {
        ogs_debug("CriticalityDiagnostics");
        S1AP_ProcedureCode_t *procedureCode =
            CriticalityDiagnostics->procedureCode;
        S1AP_TriggeringMessage_t *triggeringMessage =
            CriticalityDiagnostics->triggeringMessage;
        S1AP_Criticality_t *procedureCriticality =
            CriticalityDiagnostics->procedureCriticality;
        if (procedureCode)
            ogs_debug("procedureCode: %lld", (long long)*procedureCode);
        if (triggeringMessage)
            ogs_debug("triggeringMessage: %lld", (long long)*triggeringMessage);
        if (procedureCriticality)
            ogs_debug("procedureCriticality: %lld",
                    (long long)*procedureCriticality);
    }
}

void s1ap_handle_ue_context_release_request(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_UEContextReleaseRequest_t *UEContextReleaseRequest = NULL;

    S1AP_UEContextReleaseRequest_IEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_Cause_t *Cause = NULL;

    enb_ue_t *enb_ue = NULL;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    UEContextReleaseRequest =
        &initiatingMessage->value.choice.UEContextReleaseRequest;
    ogs_assert(UEContextReleaseRequest);

    ogs_debug("UEContextReleaseRequest");

    for (i = 0; i < UEContextReleaseRequest->protocolIEs.list.count; i++) {
        ie = UEContextReleaseRequest->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_Cause:
            Cause = &ie->value.choice.Cause;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!ENB_UE_S1AP_ID) {
        ogs_error("No ENB_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (*ENB_UE_S1AP_ID > 0x00ffffff) {
        ogs_error("Invalid ENB_UE_S1AP_ID [%lx]", *ENB_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!MME_UE_S1AP_ID) {
        ogs_error("No MME_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    enb_ue = enb_ue_find_by_mme_ue_s1ap_id(*MME_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("No ENB UE Context : MME_UE_S1AP_ID[%d]",
                (int)*MME_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb,
                MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (enb_ue->enb_id != enb->id) {
        ogs_error("MME_UE_S1AP_ID[%lld] does not belong to this eNB "
                "[UE:eNB-ID:%llu, Message:eNB-ID:%llu]",
                (long long)*MME_UE_S1AP_ID,
                (unsigned long long)enb_ue->enb_id,
                (unsigned long long)enb->id);
        r = s1ap_send_error_indication(enb,
                MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (enb_ue->enb_ue_s1ap_id != *ENB_UE_S1AP_ID) {
        ogs_error("Invalid ENB_UE_S1AP_ID[%lld] for "
                "MME_UE_S1AP_ID[%lld] [expected:%u]",
                (long long)*ENB_UE_S1AP_ID,
                (long long)*MME_UE_S1AP_ID,
                enb_ue->enb_ue_s1ap_id);
        r = s1ap_send_error_indication(enb,
                MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    if (!Cause) {
        ogs_error("No Cause");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_debug("    Cause[Group:%d Cause:%d]",
            Cause->present, (int)Cause->choice.radioNetwork);

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (mme_ue) {
        mme_sess_t *sess = mme_sess_first(mme_ue);
        const char *apn = (sess && sess->session) ? sess->session->name : NULL;

        s1ap_log_ue_failure(enb_ue, mme_ue, NULL, apn, "attach-fail",
                "UEContextReleaseRequest", Cause);
    }

    switch (Cause->present) {
    case S1AP_Cause_PR_radioNetwork:
    case S1AP_Cause_PR_transport:
    case S1AP_Cause_PR_protocol:
    case S1AP_Cause_PR_misc:
        break;
    case S1AP_Cause_PR_nas:
        ogs_warn("NAS-Cause[%d]", (int)Cause->choice.nas);
        break;
    default:
        ogs_error("Invalid cause group[%d]", Cause->present);
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    enb_ue->relcause.group = Cause->present;
    enb_ue->relcause.cause = (int)Cause->choice.radioNetwork;
    mme_send_release_access_bearer_or_ue_context_release(enb_ue);
}

void s1ap_handle_ue_context_release_complete(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_SuccessfulOutcome_t *successfulOutcome = NULL;
    S1AP_UEContextReleaseComplete_t *UEContextReleaseComplete = NULL;

    S1AP_UEContextReleaseComplete_IEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;

    enb_ue_t *enb_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    successfulOutcome = message->choice.successfulOutcome;
    ogs_assert(successfulOutcome);
    UEContextReleaseComplete =
        &successfulOutcome->value.choice.UEContextReleaseComplete;
    ogs_assert(UEContextReleaseComplete);

    ogs_debug("UEContextReleaseComplete");

    for (i = 0; i < UEContextReleaseComplete->protocolIEs.list.count; i++) {
        ie = UEContextReleaseComplete->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!ENB_UE_S1AP_ID) {
        ogs_error("No ENB_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (*ENB_UE_S1AP_ID > 0x00ffffff) {
        ogs_error("Invalid ENB_UE_S1AP_ID [%lx]", *ENB_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!MME_UE_S1AP_ID) {
        ogs_error("No MME_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    enb_ue = enb_ue_find_by_mme_ue_s1ap_id(*MME_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("No ENB UE Context : MME_UE_S1AP_ID[%d]",
                (int)*MME_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb,
                MME_UE_S1AP_ID, NULL,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (enb_ue->enb_id != enb->id) {
        ogs_error("MME_UE_S1AP_ID[%lld] does not belong to this eNB "
                "[UE:eNB-ID:%llu, Message:eNB-ID:%llu]",
                (long long)*MME_UE_S1AP_ID,
                (unsigned long long)enb_ue->enb_id,
                (unsigned long long)enb->id);
        r = s1ap_send_error_indication(enb,
                MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    s1ap_handle_ue_context_release_action(enb_ue);
}

void s1ap_handle_ue_context_release_action(enb_ue_t *enb_ue)
{
    mme_ue_t *mme_ue = NULL;
    int rel_action;
    int rel_flags = 0;
    ogs_pool_id_t old_enb_ue_id;

    if (!enb_ue) {
        ogs_warn("S1 context has already been removed");
        return;
    }

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    ogs_mme_trace_set(enb_ue, mme_ue, NULL, "s1-release");
    OGS_TLOG_INFO("UE Context Release [Action:%d]", enb_ue->ue_ctx_rel_action);
    if (mme_ue)
        ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    rel_action = enb_ue->ue_ctx_rel_action;
    old_enb_ue_id = enb_ue->id;

    /*
     * Split: the eNB-side bookkeeping (HO peer unlink, enb_ue_remove)
     * runs here on main — enb_ue and the per-eNB list/hash are
     * main-owned. Everything that touches shard-owned mme_ue state
     * (mobile-reachable timer, will-remove, mme_ue_remove, indirect
     * tunnel teardown, paging) is the tail, which runs on the UE owner
     * shard when mme.workers is active. Running mme_ue_remove here on
     * main while the owner shard was mid-event was the "Assertion
     * 'sess'/'sgw_ue' failed" production crash loop.
     */
    switch (rel_action) {
    case S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE:
        ogs_debug("    Action: S1 context remove");
        enb_ue_remove(enb_ue);
        break;
    case S1AP_UE_CTX_REL_S1_REMOVE_AND_UNLINK:
        ogs_debug("    Action: S1 normal release");
        if (!mme_ue)
            mme_ran_error(mme_enb_find_by_id(enb_ue->enb_id), enb_ue, NULL,
                    "s1ap", NULL, "No UE(mme-ue) context");
        enb_ue_remove(enb_ue);
        break;
    case S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE:
        ogs_debug("    Action: UE context remove");
        enb_ue_remove(enb_ue);
        if (!mme_ue)
            ogs_error("No UE(mme-ue) context");
        break;
    case S1AP_UE_CTX_REL_S1_HANDOVER_COMPLETE:
    case S1AP_UE_CTX_REL_S1_HANDOVER_CANCEL:
    case S1AP_UE_CTX_REL_S1_HANDOVER_FAILURE:
        if (rel_action == S1AP_UE_CTX_REL_S1_HANDOVER_COMPLETE)
            ogs_debug("    Action: S1 handover complete");
        else if (rel_action == S1AP_UE_CTX_REL_S1_HANDOVER_CANCEL)
            ogs_warn("    Action: S1 handover cancel");
        else
            ogs_warn("    Action: S1 handover failure");

        if (enb_ue_source_deassociate_target(enb_ue))
            rel_flags |= MME_UE_REL_F_HO_PEER_GONE;
        enb_ue_remove(enb_ue);
        if (!mme_ue)
            ogs_error("No UE(mme-ue) context");
        break;
    case S1AP_UE_CTX_REL_S1_PAGING:
        ogs_debug("    Action: S1 paging");
        if (!mme_ue)
            ogs_error("No UE(mme-ue) context");
        enb_ue_remove(enb_ue);
        break;
    default:
        /*
         * No release procedure was ever recorded for this S1 context
         * (UEContextReleaseComplete without a Command, or t_s1_holding
         * firing on a context that never got an action). Leaving the
         * enb_ue alive here leaked it permanently - t_s1_holding is
         * one-shot, so nothing would ever reclaim the context and the
         * enb_ue pool (sized to global max.ue) slowly filled up until
         * no new UE could connect. Reclaim it now.
         */
        ogs_error("Invalid Action[%d] - removing orphaned S1 context "
                "ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
                rel_action,
                enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);
        enb_ue_remove(enb_ue);
        break;
    }

    if (!mme_ue)
        return;

    if (mme_workers_active() &&
            mme_worker_post_ue_rel_tail(
                rel_action, old_enb_ue_id, mme_ue, rel_flags) == OGS_OK)
        return;

    /* workers off, main owns the UE, or the post failed: run inline */
    s1ap_ue_context_release_tail(mme_ue, rel_action, old_enb_ue_id, rel_flags);
}

/*
 * mme_ue-side of UE Context Release Complete. Runs on the UE owner
 * shard when mme.workers is active (MME_HO_TAIL_UE_REL), inline on
 * main otherwise. old_enb_ue_id names the enb_ue main already removed:
 * use it only to detect stale links, never resolve it.
 */
void s1ap_ue_context_release_tail(mme_ue_t *mme_ue, int rel_action,
        ogs_pool_id_t old_enb_ue_id, int rel_flags)
{
    int r;
    enb_ue_t *target_ue = NULL;
    bool ho_peer_gone = (rel_flags & MME_UE_REL_F_HO_PEER_GONE);

    ogs_assert(mme_ue);

    /* Drop the reverse links to the removed S1 context. */
    if (mme_ue->enb_ue_holding_id == old_enb_ue_id)
        mme_ue->enb_ue_holding_id = OGS_INVALID_POOL_ID;
    if (mme_ue->enb_ue_id == old_enb_ue_id)
        mme_ue->enb_ue_id = OGS_INVALID_POOL_ID;

    /*
     * An assert occurs when a NAS message retransmission occurs.
     *
     * Because there is no `enb_ue` context.
     *
     * All timers must be stopped to prevent retransmission of
     * NAS messages towards the removed S1 context.
     */
    mme_mobile_reachable_start(mme_ue);

    switch (rel_action) {
    case S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE:
        /*
         * Normal S1 release keeps a REGISTERED UE with live session(s)
         * on mme_ue_list (ECM-IDLE). Any context with no ESM session
         * after S1 is gone is a stale stub and must not linger.
         *
         * BUT only when this was the UE's last S1 context. On an
         * immediate re-attach the UE is already mid-attach on a NEW
         * enb_ue (no ESM session yet, AIR in flight) while the OLD
         * held context is being released here; reclaiming the mme_ue
         * at that point kills the ongoing attach (auth-test: the
         * Authentication Request is never sent and the UE wedges).
         */
        if (ogs_list_empty(&mme_ue->sess_list) &&
                !MME_SESSION_RELEASE_PENDING(mme_ue) &&
                !mme_ue->ue_context_will_remove &&
                enb_ue_find_by_id(mme_ue->enb_ue_id) == NULL)
            mme_ue_enter_ue_context_will_remove(mme_ue);
        break;
    case S1AP_UE_CTX_REL_S1_REMOVE_AND_UNLINK:
        break;
    case S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE:
        mme_ue_remove(mme_ue);
        break;
    case S1AP_UE_CTX_REL_S1_HANDOVER_COMPLETE:
    case S1AP_UE_CTX_REL_S1_HANDOVER_CANCEL:
        target_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!target_ue) {
            mme_ue_warn(mme_ue, NULL, "s1ap", NULL,
                    "No UE(target-enb-ue) context%s",
                    ho_peer_gone ?
                        " (HO peer already released)" : "");
            return;
        }
        if (ho_peer_gone)
            mme_ue_warn(mme_ue, target_ue, "s1ap", NULL,
                    "HO peer S1 context already released");

        if (mme_ue_have_indirect_tunnel(mme_ue) == true) {
            if (mme_gtp_send_delete_indirect_data_forwarding_tunnel_request(
                        target_ue, mme_ue,
                        rel_action == S1AP_UE_CTX_REL_S1_HANDOVER_COMPLETE ?
                            OGS_GTP_DELETE_INDIRECT_HANDOVER_COMPLETE :
                            OGS_GTP_DELETE_INDIRECT_HANDOVER_CANCEL) != OGS_OK)
                ogs_error("[%s] Delete Indirect Data Forwarding Tunnel "
                        "Request failed", mme_ue->imsi_bcd);
        } else {
            ogs_warn("Check your eNodeB");
            ogs_warn("  No INDIRECT TUNNEL");
            ogs_warn("  Packet could be dropped during S1-Handover");
            mme_ue_clear_indirect_tunnel(mme_ue);

            if (rel_action == S1AP_UE_CTX_REL_S1_HANDOVER_CANCEL) {
                target_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
                if (!target_ue) {
                    ogs_warn("No S1 context");
                    return;
                }
                r = s1ap_send_handover_cancel_ack(target_ue);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
            }
        }
        break;
    case S1AP_UE_CTX_REL_S1_HANDOVER_FAILURE:
        if (ho_peer_gone)
            ogs_warn("HO peer S1 context already released "
                    "during failure cleanup");
        if (mme_ue_have_indirect_tunnel(mme_ue) == true) {
            ogs_error("Check your eNodeB");
            ogs_error("  We found INDIRECT TUNNEL in HandoverFailure");
            mme_ue_clear_indirect_tunnel(mme_ue);
        }
        break;
    case S1AP_UE_CTX_REL_S1_PAGING:
        r = s1ap_send_paging(mme_ue, S1AP_CNDomain_ps);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        break;
    default:
        break;
    }
}

void s1ap_handle_e_rab_release_indication(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;
    int num_of_released = 0, num_of_radio_left = 0;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_E_RABReleaseIndication_t *E_RABReleaseIndication = NULL;

    S1AP_E_RABReleaseIndicationIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_E_RABList_t *E_RABReleasedList = NULL;

    enb_ue_t *enb_ue = NULL;
    mme_ue_t *mme_ue = NULL;
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    E_RABReleaseIndication =
        &initiatingMessage->value.choice.E_RABReleaseIndication;
    ogs_assert(E_RABReleaseIndication);

    for (i = 0; i < E_RABReleaseIndication->protocolIEs.list.count; i++) {
        ie = E_RABReleaseIndication->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_E_RABReleasedList:
            E_RABReleasedList = &ie->value.choice.E_RABList;
            break;
        default:
            break;
        }
    }

    ogs_debug("E-RABReleaseIndication IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    enb_ue = s1ap_find_enb_ue_by_message_ue_ids(
            enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("%s: Failed to find eNB UE by S1AP UE IDs", __func__);
        return;
    }

    if (!E_RABReleasedList) {
        ogs_error("No E-RABReleasedList");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (!mme_ue) {
        ogs_warn("E-RABReleaseIndication on stale S1 context "
                "[MME_UE_S1AP_ID:%d] - sending UEContextReleaseCommand",
                enb_ue->mme_ue_s1ap_id);
        r = s1ap_send_ue_context_release_command(
                enb_ue, S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unspecified,
                S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    for (i = 0; i < E_RABReleasedList->list.count; i++) {
        S1AP_E_RABItemIEs_t *item = NULL;
        S1AP_E_RABItem_t *e_rab = NULL;

        item = (S1AP_E_RABItemIEs_t *)E_RABReleasedList->list.array[i];
        if (!item)
            continue;

        e_rab = &item->value.choice.E_RABItem;

        bearer = mme_bearer_find_by_ue_ebi(mme_ue, (uint8_t)e_rab->e_RAB_ID);
        if (!bearer) {
            ogs_warn("[%s] E-RABReleaseIndication for unknown E-RAB[%d]",
                    mme_ue->imsi_bcd, (int)e_rab->e_RAB_ID);
            continue;
        }

        /*
         * The eNB has already torn down the radio bearer. Drop our copy of
         * the eNB S1-U TEID: keeping it makes the next Modify Bearer
         * Request program the SGW-U FAR with a dead TEID, which black-holes
         * downlink for the whole UE until it detaches.
         */
        ogs_info("[%s] E-RAB[%d] released by eNB (cause %d:%ld)",
                mme_ue->imsi_bcd, (int)e_rab->e_RAB_ID,
                e_rab->cause.present,
                e_rab->cause.present == S1AP_Cause_PR_radioNetwork ?
                    e_rab->cause.choice.radioNetwork : 0);
        CLEAR_ENB_S1U_PATH(bearer);
        num_of_released++;
    }

    if (!num_of_released)
        return;

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        mme_bearer_t *b = NULL;
        ogs_list_for_each(&sess->bearer_list, b) {
            if (MME_HAVE_ENB_S1U_PATH(b))
                num_of_radio_left++;
        }
    }

    /*
     * Every E-RAB is gone but the S1 context is still up: ask the SGW to
     * release the access bearers so downlink data is buffered and triggers
     * paging instead of being forwarded to an eNB that no longer has a
     * radio bearer for this UE.
     */
    if (num_of_radio_left == 0 && ECM_CONNECTED(mme_ue)) {
        ogs_info("[%s] all E-RABs released by eNB; "
                "sending Release Access Bearers Request", mme_ue->imsi_bcd);
        if (mme_gtp_send_release_access_bearers_request(
                enb_ue->id, mme_ue,
                OGS_GTP_RELEASE_SEND_UE_CONTEXT_RELEASE_COMMAND) != OGS_OK)
            ogs_error("[%s] Release Access Bearers Request not sent after "
                    "E-RABReleaseIndication", mme_ue->imsi_bcd);
    }
}

void s1ap_handle_e_rab_modification_indication(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r, rv;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_E_RABModificationIndication_t *E_RABModificationIndication = NULL;

    S1AP_E_RABModificationIndicationIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_E_RABToBeModifiedListBearerModInd_t
        *E_RABToBeModifiedListBearerModInd = NULL;

    enb_ue_t *enb_ue = NULL;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    E_RABModificationIndication = &initiatingMessage->value.choice.E_RABModificationIndication;
    ogs_assert(E_RABModificationIndication);

    ogs_info("E_RABModificationIndication");

    for (i = 0; i < E_RABModificationIndication->protocolIEs.list.count; i++) {
        ie = E_RABModificationIndication->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_E_RABToBeModifiedListBearerModInd:
            E_RABToBeModifiedListBearerModInd =
                &ie->value.choice.E_RABToBeModifiedListBearerModInd;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    enb_ue = s1ap_find_enb_ue_by_message_ue_ids(
            enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_warn("%s: Failed to find eNB UE by S1AP UE IDs", __func__);
        return;
    }

    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    if (!E_RABToBeModifiedListBearerModInd) {
        ogs_error("No E_RABToBeModifiedListBearerModInd");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (!mme_ue) {
        /*
         * Stale S1 context - see s1ap_handle_uplink_nas_transport()
         * for the rationale. Send UEContextReleaseCommand so the eNB
         * cleans up its end of the stale RAN context.
         */
        ogs_warn("E-RABModificationIndication on stale S1 context "
                "[MME_UE_S1AP_ID:%d] - sending UEContextReleaseCommand",
                enb_ue->mme_ue_s1ap_id);
        r = s1ap_send_ue_context_release_command(
                enb_ue, S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unspecified,
                S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_list_init(&mme_ue->bearer_to_modify_list);

    for (i = 0; i < E_RABToBeModifiedListBearerModInd->list.count; i++) {
        S1AP_E_RABToBeModifiedItemBearerModIndIEs_t *item = NULL;
        S1AP_E_RABToBeModifiedItemBearerModInd_t *e_rab = NULL;

        mme_bearer_t *bearer = NULL;

        item = (S1AP_E_RABToBeModifiedItemBearerModIndIEs_t *)
                E_RABToBeModifiedListBearerModInd->list.array[i];
        if (!item) {
            ogs_error("No S1AP_E_RABToBeModifiedItemBearerModIndIEs_t");
            r = s1ap_send_error_indication2(mme_ue,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        e_rab = &item->value.choice.E_RABToBeModifiedItemBearerModInd;
        if (!e_rab) {
            ogs_error("No E_RABToBeModifiedItemBearerModInd");
            r = s1ap_send_error_indication2(mme_ue,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        bearer = mme_bearer_find_by_ue_ebi(mme_ue, e_rab->e_RAB_ID);
        if (!bearer) {
            ogs_error("No Bearer [%d]", (int)e_rab->e_RAB_ID);
            r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_radioNetwork,
                    S1AP_CauseRadioNetwork_unknown_E_RAB_ID);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        if (e_rab->dL_GTP_TEID.size != sizeof(bearer->enb_s1u_teid)) {
            ogs_error("Invalid e_rab->dL_GTP_TEID.size = %d (expected %d)",
                    (int)e_rab->dL_GTP_TEID.size,
                    (int)sizeof(bearer->enb_s1u_teid));
            r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_protocol,
                    S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
        memcpy(&bearer->enb_s1u_teid, e_rab->dL_GTP_TEID.buf,
                sizeof(bearer->enb_s1u_teid));
        bearer->enb_s1u_teid = be32toh(bearer->enb_s1u_teid);

        ogs_debug("UE[%s] EBI[%d] Update enb_s1u_teid = 0x%x",
                mme_ue->imsi_bcd, bearer->ebi, bearer->enb_s1u_teid);

        rv = ogs_asn_BIT_STRING_to_ip(
                &e_rab->transportLayerAddress, &bearer->enb_s1u_ip);
        if (rv != OGS_OK) {
            ogs_error("No transportLayerAddress [%d]",
                    (int)e_rab->e_RAB_ID);
            r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_protocol,
                    S1AP_CauseProtocol_abstract_syntax_error_falsely_constructed_message);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        ogs_log_hexdump(OGS_LOG_DEBUG,
                e_rab->transportLayerAddress.buf,
                e_rab->transportLayerAddress.size);
        ogs_debug("    IPv4(%d): 0x%x",
                bearer->enb_s1u_ip.ipv4, bearer->enb_s1u_ip.addr);
        ogs_debug("    IPv6(%d):", bearer->enb_s1u_ip.ipv6);
        ogs_log_hexdump(OGS_LOG_DEBUG,
                bearer->enb_s1u_ip.addr6, OGS_IPV6_LEN);

        if (!bearer->sgw_s1u_teid)
            ogs_warn("UE[%s] EBI[%d] has no SGW S1-U TEID in "
                    "E-RAB Modification Indication: excluded from "
                    "Modify Bearer Request", mme_ue->imsi_bcd, bearer->ebi);
        else if (ogs_list_exists(
                    &mme_ue->bearer_to_modify_list,
                    &bearer->to_modify_node) == false)
            ogs_list_add(
                    &mme_ue->bearer_to_modify_list, &bearer->to_modify_node);
        else
            ogs_warn("Bearer [%d] Duplicated", (int)e_rab->e_RAB_ID);
    }

    if (ogs_list_count(&mme_ue->bearer_to_modify_list)) {
        if (mme_gtp_send_modify_bearer_request(enb_ue, mme_ue, 0,
                    OGS_GTP_MODIFY_IN_E_RAB_MODIFICATION) != OGS_OK)
            ogs_error("[%s] Modify Bearer Request failed in "
                    "E-RAB Modification Indication", mme_ue->imsi_bcd);
    }
}

void s1ap_handle_enb_direct_information_transfer(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_ENBDirectInformationTransfer_t *ENBDirectInformationTransfer = NULL;

    S1AP_ENBDirectInformationTransferIEs_t *ie = NULL;
    S1AP_Inter_SystemInformationTransferType_t *Inter_SystemInformationTransferType = NULL;

    S1AP_RIMTransfer_t *RIMTransfer = NULL;
    S1AP_RIMInformation_t *RIMInformation = NULL;
    S1AP_RIMRoutingAddress_t *RIMRoutingAddress = NULL;
    struct S1AP_GERAN_Cell_ID *geran_cell_id = NULL;
    ogs_plmn_id_t plmn_id;
    ogs_nas_rai_t rai;
    uint16_t cell_id;
    int i, r;
    mme_sgsn_t *sgsn = NULL;

    ogs_assert(enb);
    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    ENBDirectInformationTransfer = &initiatingMessage->value.choice.ENBDirectInformationTransfer;
    ogs_assert(ENBDirectInformationTransfer);

    ogs_info("Rx eNB DIRECT INFORMATION TRANSFER");

    for (i = 0; i < ENBDirectInformationTransfer->protocolIEs.list.count; i++) {
        ie = ENBDirectInformationTransfer->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_Inter_SystemInformationTransferTypeEDT:
            Inter_SystemInformationTransferType = &ie->value.choice.Inter_SystemInformationTransferType;
            break;
        default:
            break;
        }
    }

    /* Clang scan-build SA: NULL pointer dereference: Inter_SystemInformationTransferType=NULL if above
     * protocolIEs.list.count=0 in loop. */
    if (!Inter_SystemInformationTransferType) {
        ogs_warn("No Inter_SystemInformationTransferType");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }


    RIMTransfer = Inter_SystemInformationTransferType->choice.rIMTransfer;

    RIMInformation = &RIMTransfer->rIMInformation;
    RIMRoutingAddress = RIMTransfer->rIMRoutingAddress; /* optional */

    if (!RIMRoutingAddress) {
        ogs_warn("Rx eNB DIRECT INFORMATION TRANSFER without RIM Routing Address IE!");
        goto forward_to_default_sgsn;
    }

    switch (RIMRoutingAddress->present) {
    case S1AP_RIMRoutingAddress_PR_gERAN_Cell_ID:
        geran_cell_id = RIMRoutingAddress->choice.gERAN_Cell_ID;
        if (!geran_cell_id) {
            ogs_error("No gERAN_Cell_ID");
            r = s1ap_send_error_indication(enb, NULL, NULL,
                    S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
        if (geran_cell_id->lAI.pLMNidentity.size != sizeof(plmn_id)) {
            ogs_error("Invalid geran_cell_id->lAI.pLMNidentity.size = %d "
                    "(expected %d)",
                    (int)geran_cell_id->lAI.pLMNidentity.size,
                    (int)sizeof(plmn_id));
            r = s1ap_send_error_indication(enb, NULL, NULL,
                    S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
        if (geran_cell_id->lAI.lAC.size != sizeof(uint16_t)) {
            ogs_error("Invalid geran_cell_id->lAI.lAC.size = %d "
                    "(expected %d)",
                    (int)geran_cell_id->lAI.lAC.size,
                    (int)sizeof(uint16_t));
            r = s1ap_send_error_indication(enb, NULL, NULL,
                    S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
        if (geran_cell_id->cI.size != sizeof(uint16_t)) {
            ogs_error("Invalid geran_cell_id->cI.size = %d "
                    "(expected %d)",
                    (int)geran_cell_id->cI.size,
                    (int)sizeof(uint16_t));
            r = s1ap_send_error_indication(enb, NULL, NULL,
                    S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
        memcpy(&plmn_id, geran_cell_id->lAI.pLMNidentity.buf, sizeof(plmn_id));
        ogs_nas_from_plmn_id(&rai.lai.nas_plmn_id, &plmn_id);
        memcpy(&rai.lai.lac, geran_cell_id->lAI.lAC.buf, sizeof(uint16_t));
        rai.lai.lac = be16toh(rai.lai.lac);
        rai.rac = *geran_cell_id->rAC.buf;
        memcpy(&cell_id, geran_cell_id->cI.buf, sizeof(uint16_t));
        cell_id = be16toh(cell_id);
            ogs_debug("    RAI[MCC:%u MNC:%u LAC:%u RAC:%u] CI[%u]",
                      ogs_plmn_id_mcc(&plmn_id), ogs_plmn_id_mnc(&plmn_id),
                      rai.lai.lac, rai.rac, cell_id);
        sgsn = mme_sgsn_find_by_routing_address(&rai, cell_id);
        if (sgsn) {
            mme_gtp1_send_ran_information_relay(
                sgsn, RIMInformation->buf, RIMInformation->size,
            &rai, cell_id);
        } else {
            ogs_warn("No SGSN to forward RIM message! RAI[MCC:%u MNC:%u LAC:%u RAC:%u] CI[%u]",
                      ogs_plmn_id_mcc(&plmn_id), ogs_plmn_id_mnc(&plmn_id),
                      rai.lai.lac, rai.rac, cell_id);
        }
        break;
    case S1AP_RIMRoutingAddress_PR_targetRNC_ID:
        ogs_warn("Rx empty RIM Routing Address 'RNC_ID' not implemented!");
        break;
    case S1AP_RIMRoutingAddress_PR_eHRPD_Sector_ID:
        ogs_warn("Rx empty RIM Routing Address 'eHRPD_Sector_ID' not implemented!");
        break;
    case S1AP_RIMRoutingAddress_PR_NOTHING:
        ogs_warn("Rx empty RIM Routing Address!");
        goto forward_to_default_sgsn;
    default:
        ogs_warn("Rx unknown RIM Routing Address type %u!", RIMRoutingAddress->present);
        break;
    }

    return;

forward_to_default_sgsn:
    sgsn = mme_sgsn_find_by_default_routing_address();
    if (!sgsn)
        return;
    mme_gtp1_send_ran_information_relay(
        sgsn, RIMInformation->buf, RIMInformation->size,
        NULL, 0);
}

void s1ap_handle_path_switch_request(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    int i, r, rv;
    char buf[OGS_ADDRSTRLEN];

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_PathSwitchRequest_t *PathSwitchRequest = NULL;

    S1AP_PathSwitchRequestIEs_t *ie = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_E_RABToBeSwitchedDLList_t *E_RABToBeSwitchedDLList = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_EUTRAN_CGI_t *EUTRAN_CGI = NULL;
    S1AP_TAI_t *TAI = NULL;
    S1AP_UESecurityCapabilities_t *UESecurityCapabilities = NULL;

    S1AP_PLMNidentity_t *pLMNidentity = NULL;
    S1AP_CellIdentity_t *cell_ID = NULL;
    S1AP_TAC_t *tAC = NULL;
    S1AP_EncryptionAlgorithms_t    *encryptionAlgorithms = NULL;
    S1AP_IntegrityProtectionAlgorithms_t *integrityProtectionAlgorithms = NULL;
    uint16_t eea = 0, eia = 0;
    uint8_t received_eea = 0, received_eia = 0;
    bool ue_security_capability_mismatch = false;

    enb_ue_t *enb_ue = NULL;
    mme_ue_t *mme_ue = NULL;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_eps_tai_t tai;
    int served_tai_index = 0;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    PathSwitchRequest = &initiatingMessage->value.choice.PathSwitchRequest;
    ogs_assert(PathSwitchRequest);

    ogs_info("PathSwitchRequest");

    for (i = 0; i < PathSwitchRequest->protocolIEs.list.count; i++) {
        ie = PathSwitchRequest->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_E_RABToBeSwitchedDLList:
            E_RABToBeSwitchedDLList =
                &ie->value.choice.E_RABToBeSwitchedDLList;
            break;
        case S1AP_ProtocolIE_ID_id_SourceMME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_EUTRAN_CGI:
            EUTRAN_CGI = &ie->value.choice.EUTRAN_CGI;
            break;
        case S1AP_ProtocolIE_ID_id_TAI:
            TAI = &ie->value.choice.TAI;
            break;
        case S1AP_ProtocolIE_ID_id_UESecurityCapabilities:
            UESecurityCapabilities = &ie->value.choice.UESecurityCapabilities;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!ENB_UE_S1AP_ID) {
        ogs_error("No ENB_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (*ENB_UE_S1AP_ID > 0x00ffffff) {
        ogs_error("Invalid ENB_UE_S1AP_ID [%lx]", *ENB_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!MME_UE_S1AP_ID) {
        ogs_error("No MME_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    enb_ue = enb_ue_find_by_mme_ue_s1ap_id(*MME_UE_S1AP_ID);
    if (!enb_ue) {
        ogs_error("Cannot find UE from sourceMME-UE-S1AP-ID[%d] and eNB[%s:%d]",
                (int)*MME_UE_S1AP_ID,
                OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

        s1apbuf = s1ap_build_path_switch_failure(
                *ENB_UE_S1AP_ID, *MME_UE_S1AP_ID,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        if (!s1apbuf) {
            ogs_error("s1ap_build_path_switch_failure() failed");
            return;
        }

        r = s1ap_send_to_enb(enb, s1apbuf, S1AP_NON_UE_SIGNALLING);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_debug("    OLD ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    if (!EUTRAN_CGI) {
        ogs_error("No EUTRAN_CGI");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!TAI) {
        ogs_error("No TAI");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    pLMNidentity = &TAI->pLMNidentity;
    if (pLMNidentity->size != sizeof(tai.plmn_id)) {
        ogs_error("Invalid pLMNidentity->size = %d (expected %d)",
                (int)pLMNidentity->size,
                (int)sizeof(tai.plmn_id));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    tAC = &TAI->tAC;
    if (tAC->size != sizeof(tai.tac)) {
        ogs_error("Invalid tAC->size = %d (expected %d)",
                (int)tAC->size, (int)sizeof(tai.tac));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    memcpy(&tai.plmn_id, pLMNidentity->buf, sizeof(tai.plmn_id));
    memcpy(&tai.tac, tAC->buf, sizeof(tai.tac));
    tai.tac = be16toh(tai.tac);

    /* Check TAI */
    served_tai_index = mme_find_served_tai(&tai);
    if (served_tai_index < 0) {
        ogs_error("Cannot find Served TAI[PLMN_ID:%06x,TAC:%d]",
            ogs_plmn_id_hexdump(&tai.plmn_id), tai.tac);
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_message_not_compatible_with_receiver_state);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    ogs_debug("    SERVED_TAI_INDEX[%d]", served_tai_index);

    if (!E_RABToBeSwitchedDLList) {
        ogs_error("No E_RABToBeSwitchedDLList");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (!mme_ue) {
        ogs_error("No UE(mme-ue) context");
        return;
    }

    mme_metrics_ho_attempt(mme_ue, "path_switch");

    mme_ue->send_ue_security_capability_in_path_switch_ack = false;

    if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
        ogs_error("No Security Context");
        mme_metrics_ho_fail(mme_ue, "path_switch",
                s1ap_cause_group_name(S1AP_Cause_PR_nas),
                S1AP_CauseNas_authentication_failure);
        s1apbuf = s1ap_build_path_switch_failure(
                *ENB_UE_S1AP_ID, *MME_UE_S1AP_ID,
                S1AP_Cause_PR_nas, S1AP_CauseNas_authentication_failure);
        if (!s1apbuf) {
            ogs_error("s1ap_build_path_switch_failure() failed");
            return;
        }

        r = s1ap_send_to_enb_ue(enb_ue, s1apbuf);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_debug("    OLD TAI[PLMN_ID:%06x,TAC:%d]",
            ogs_plmn_id_hexdump(&mme_ue->tai.plmn_id),
            mme_ue->tai.tac);
    ogs_debug("    OLD E_CGI[PLMN_ID:%06x,CELL_ID:0x%x]",
            ogs_plmn_id_hexdump(&mme_ue->e_cgi.plmn_id),
            mme_ue->e_cgi.cell_id);

    /* Update ENB-UE-S1AP-ID */
    enb_ue->enb_ue_s1ap_id = *ENB_UE_S1AP_ID;

    /* Change enb_ue to the NEW eNB */
    enb_ue_switch_to_enb(enb_ue, enb);

    ogs_debug("    NEW ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    pLMNidentity = &TAI->pLMNidentity;
    if (pLMNidentity->size != sizeof(enb_ue->saved.tai.plmn_id)) {
        ogs_error("Invalid pLMNidentity->size = %d (expected %d)",
                (int)pLMNidentity->size,
                (int)sizeof(enb_ue->saved.tai.plmn_id));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    tAC = &TAI->tAC;
    if (tAC->size != sizeof(enb_ue->saved.tai.tac)) {
        ogs_error("Invalid tAC->size = %d (expected %d)",
                (int)tAC->size, (int)sizeof(enb_ue->saved.tai.tac));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    pLMNidentity = &EUTRAN_CGI->pLMNidentity;
    if (pLMNidentity->size != sizeof(enb_ue->saved.e_cgi.plmn_id)) {
        ogs_error("Invalid pLMNidentity->size = %d (expected %d)",
                (int)pLMNidentity->size,
                (int)sizeof(enb_ue->saved.e_cgi.plmn_id));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    cell_ID = &EUTRAN_CGI->cell_ID;
    if (cell_ID->size != sizeof(enb_ue->saved.e_cgi.cell_id)) {
        ogs_error("Invalid cell_ID->size = %d (expected %d)",
                (int)cell_ID->size,
                (int)sizeof(enb_ue->saved.e_cgi.cell_id));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    encryptionAlgorithms =
        &UESecurityCapabilities->encryptionAlgorithms;
    integrityProtectionAlgorithms =
        &UESecurityCapabilities->integrityProtectionAlgorithms;

    if (encryptionAlgorithms->size != sizeof(eea)) {
        ogs_error("Invalid encryptionAlgorithms->size = %d (expected %d)",
                (int)encryptionAlgorithms->size,
                (int)sizeof(eea));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_message_not_compatible_with_receiver_state);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    /*
     * The MME shall verify that the UE security capabilities received
     * from the target eNB are the same as the UE security capabilities
     * locally stored in the MME.
     *
     * If there is a mismatch, the MME shall send its locally stored
     * UE security capabilities to the target eNB in the
     * Path Switch Request Acknowledge message.
     *
     * Therefore, do not overwrite mme_ue->ue_network_capability
     * with the value received in PathSwitchRequest.
     */
    memcpy(&eea, encryptionAlgorithms->buf, sizeof(eea));
    eea = be16toh(eea);
    received_eea = eea >> 9;

    if (integrityProtectionAlgorithms->size != sizeof(eia)) {
        ogs_error("Invalid integrityProtectionAlgorithms->size = %d "
                "(expected %d)",
                (int)integrityProtectionAlgorithms->size,
                (int)sizeof(eia));
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_message_not_compatible_with_receiver_state);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    memcpy(&eia, integrityProtectionAlgorithms->buf, sizeof(eia));
    eia = be16toh(eia);
    received_eia = eia >> 9;

    if (received_eea != (mme_ue->ue_network_capability.eea & 0x7f) ||
        received_eia != (mme_ue->ue_network_capability.eia & 0x7f)) {
        ue_security_capability_mismatch = true;
    }

    /* Update ENB-UE-S1AP-ID */
    enb_ue->enb_ue_s1ap_id = *ENB_UE_S1AP_ID;

    /* Change enb_ue to the NEW eNB after mandatory IE validation */
    enb_ue_switch_to_enb(enb_ue, enb);

    ogs_info("    NEW ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    pLMNidentity = &TAI->pLMNidentity;
    memcpy(&enb_ue->saved.tai.plmn_id, pLMNidentity->buf,
            sizeof(enb_ue->saved.tai.plmn_id));
    tAC = &TAI->tAC;
    memcpy(&enb_ue->saved.tai.tac, tAC->buf, sizeof(enb_ue->saved.tai.tac));
    enb_ue->saved.tai.tac = be16toh(enb_ue->saved.tai.tac);

    pLMNidentity = &EUTRAN_CGI->pLMNidentity;
    memcpy(&enb_ue->saved.e_cgi.plmn_id, pLMNidentity->buf,
            sizeof(enb_ue->saved.e_cgi.plmn_id));
    cell_ID = &EUTRAN_CGI->cell_ID;
    memcpy(&enb_ue->saved.e_cgi.cell_id, cell_ID->buf,
            sizeof(enb_ue->saved.e_cgi.cell_id));
    enb_ue->saved.e_cgi.cell_id = (be32toh(enb_ue->saved.e_cgi.cell_id) >> 4);

    ogs_debug("    TAI[PLMN_ID:%06x,TAC:%d]",
            ogs_plmn_id_hexdump(&enb_ue->saved.tai.plmn_id),
            enb_ue->saved.tai.tac);
    ogs_debug("    E_CGI[PLMN_ID:%06x,CELL_ID:0x%x]",
            ogs_plmn_id_hexdump(&enb_ue->saved.e_cgi.plmn_id),
            enb_ue->saved.e_cgi.cell_id);

    /*
     * Stream-No/TAI/ECGI are applied to mme_ue in
     * s1ap_path_switch_request_complete(): on the owner shard when
     * mme.workers is active (main must not write shard-owned fields),
     * directly at the end of this handler otherwise.
     */

    /*
     * Path Switch Request (TS 23.401) puts the UE in ECM-CONNECTED at the
     * target eNB. Re-associate the S1 context — mme_ue->enb_ue_id is often
     * invalid after S1 release while the UE was idle before X2 HO.
     */
    enb_ue_associate_mme_ue(enb_ue, mme_ue);

    if (ue_security_capability_mismatch) {
        mme_ue->send_ue_security_capability_in_path_switch_ack = true;

        ogs_warn("[%s] UE Security Capability mismatch in "
                "PathSwitchRequest",
                MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "Unknown");
        ogs_warn("    Stored  EEA[0x%x] EIA[0x%x]",
                mme_ue->ue_network_capability.eea,
                mme_ue->ue_network_capability.eia);
        ogs_warn("    Received EEA[0x%x] EIA[0x%x]",
                received_eea, received_eia);
    }

    ogs_list_init(&mme_ue->bearer_to_modify_list);

    for (i = 0; i < E_RABToBeSwitchedDLList->list.count; i++) {
        S1AP_E_RABToBeSwitchedDLItemIEs_t *item = NULL;
        S1AP_E_RABToBeSwitchedDLItem_t *e_rab = NULL;

        mme_bearer_t *bearer = NULL;

        item = (S1AP_E_RABToBeSwitchedDLItemIEs_t *)
            E_RABToBeSwitchedDLList->list.array[i];
        if (!item) {
            ogs_error("No S1AP_E_RABToBeSwitchedDLItemIEs_t");
            r = s1ap_send_error_indication2(mme_ue,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        e_rab = &item->value.choice.E_RABToBeSwitchedDLItem;
        if (!e_rab) {
            ogs_error("No E_RABToBeSwitchedDLItem");
            r = s1ap_send_error_indication2(mme_ue,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        bearer = mme_bearer_find_by_ue_ebi(mme_ue, e_rab->e_RAB_ID);
        if (!bearer) {
            ogs_error("No Bearer [%d]", (int)e_rab->e_RAB_ID);
            r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_radioNetwork,
                    S1AP_CauseRadioNetwork_unknown_E_RAB_ID);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        if (e_rab->gTP_TEID.size != sizeof(bearer->enb_s1u_teid)) {
            ogs_error("Invalid e_rab->gTP_TEID.size = %d (expected %d)",
                    (int)e_rab->gTP_TEID.size,
                    (int)sizeof(bearer->enb_s1u_teid));
            r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_protocol,
                    S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
        memcpy(&bearer->enb_s1u_teid, e_rab->gTP_TEID.buf,
                sizeof(bearer->enb_s1u_teid));
        bearer->enb_s1u_teid = be32toh(bearer->enb_s1u_teid);

        ogs_debug("UE[%s] EBI[%d] Update enb_s1u_teid = 0x%x",
                mme_ue->imsi_bcd, bearer->ebi, bearer->enb_s1u_teid);

        rv = ogs_asn_BIT_STRING_to_ip(
                &e_rab->transportLayerAddress, &bearer->enb_s1u_ip);
        if (rv != OGS_OK) {
            ogs_error("No transportLayerAddress [%d]",
                    (int)e_rab->e_RAB_ID);
            r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_protocol,
                    S1AP_CauseProtocol_abstract_syntax_error_falsely_constructed_message);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        ogs_log_hexdump(OGS_LOG_DEBUG,
                e_rab->transportLayerAddress.buf,
                e_rab->transportLayerAddress.size);
        ogs_debug("    IPv4(%d): 0x%x",
                bearer->enb_s1u_ip.ipv4, bearer->enb_s1u_ip.addr);
        ogs_debug("    IPv6(%d):", bearer->enb_s1u_ip.ipv6);
        ogs_log_hexdump(OGS_LOG_DEBUG,
                bearer->enb_s1u_ip.addr6, OGS_IPV6_LEN);

        if (!bearer->sgw_s1u_teid)
            ogs_warn("UE[%s] EBI[%d] has no SGW S1-U TEID in "
                    "Path Switch Request: excluded from "
                    "Modify Bearer Request", mme_ue->imsi_bcd, bearer->ebi);
        else if (ogs_list_exists(
                    &mme_ue->bearer_to_modify_list,
                    &bearer->to_modify_node) == false)
            ogs_list_add(
                    &mme_ue->bearer_to_modify_list, &bearer->to_modify_node);
        else
            ogs_warn("Bearer [%d] Duplicated", (int)e_rab->e_RAB_ID);
    }

    /*
     * With mme.workers the tail (location, NH chain, S11 sends) runs
     * on the UE's owner shard: main must not write shard-owned mme_ue
     * fields, the Modify Bearer ULI must carry the NEW location, and
     * the GTP xact must live in the shard the S11 response routes to.
     * Everything written above (enb_ue, bearer TEIDs, to_modify list)
     * happens-before the tail via the worker queue.
     */
    if (mme_workers_active()) {
        if (mme_worker_post_ho_tail(
                    MME_HO_TAIL_PATH_SWITCH, enb_ue->id,
                    mme_ue, NULL) == OGS_OK)
            return;
        /* Dropped tail = no Modify Bearer = stale eNB TEID at the SGW.
         * Fall back to running the tail inline on main. */
        ogs_warn("[%s] PathSwitchRequest tail post failed; running inline",
                mme_ue->imsi_bcd);
    }

    s1ap_path_switch_request_complete(enb_ue, mme_ue);
}

/*
 * Path Switch Request tail. Runs on the UE owner thread: the main
 * thread when workers are off, the owner shard (MME_EVENT_S1AP_HO_TAIL)
 * when mme.workers is active.
 */
void s1ap_path_switch_request_complete(enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    sgw_relocation_e relocation;

    ogs_assert(enb_ue);
    ogs_assert(mme_ue);

    /* Copy Stream-No/TAI/ECGI from enb_ue */
    mme_ue->enb_ostream_id = enb_ue->enb_ostream_id;
    memcpy(&mme_ue->tai, &enb_ue->saved.tai, sizeof(ogs_eps_tai_t));
    memcpy(&mme_ue->e_cgi, &enb_ue->saved.e_cgi, sizeof(ogs_e_cgi_t));
    mme_ue->ue_location_timestamp = ogs_time_now();

    /*
     * Update Security Context (NextHop)
     *
     * Defer NH/NCC derivation until every E-RAB in the PathSwitchRequest
     * has been validated. An unknown E-RAB ID (or malformed GTP-TEID /
     * transportLayerAddress) returns an ErrorIndication in the loop above;
     * advancing the NextHop chain before that point would desynchronize
     * the {NH, NCC} with the eNB with no rollback (TS 33.401 7.2.8).
     */
    mme_ue->nhcc++;
    ogs_kdf_nh_enb(mme_ue->kasme, mme_ue->nh, mme_ue->nh);

    relocation = sgw_ue_check_if_relocated(mme_ue, enb_ue);
    if (relocation == SGW_WITHOUT_RELOCATION) {
        if (ogs_list_count(&mme_ue->bearer_to_modify_list)) {
            if (mme_gtp_send_modify_bearer_request(enb_ue, mme_ue, 1,
                        OGS_GTP_MODIFY_IN_PATH_SWITCH_REQUEST) != OGS_OK)
                ogs_error("[%s] Modify Bearer Request failed in "
                        "Path Switch Request", mme_ue->imsi_bcd);
        }
    } else if (relocation == SGW_WITH_RELOCATION) {
        mme_sess_t *sess = NULL;

        ogs_list_for_each(&mme_ue->sess_list, sess) {
            GTP_COUNTER_INCREMENT(
                mme_ue, GTP_COUNTER_CREATE_SESSION_BY_PATH_SWITCH);

            if (mme_gtp_send_create_session_request(enb_ue, sess,
                        OGS_GTP_CREATE_IN_PATH_SWITCH_REQUEST) != OGS_OK)
                ogs_error("[%s] Create Session Request failed in "
                        "Path Switch Request", mme_ue->imsi_bcd);
        }
    } else if (relocation == SGW_HAS_ALREADY_BEEN_RELOCATED) {
        ogs_error("SGW has already been relocated");
    }
}

void s1ap_handle_enb_configuration_transfer(
        mme_enb_t *enb, ogs_s1ap_message_t *message, ogs_pkbuf_t *pkbuf)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_ENBConfigurationTransfer_t *ENBConfigurationTransfer = NULL;

    S1AP_ENBConfigurationTransferIEs_t *ie = NULL;
    S1AP_SONConfigurationTransfer_t *SONConfigurationTransfer = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    ENBConfigurationTransfer =
        &initiatingMessage->value.choice.ENBConfigurationTransfer;
    ogs_assert(ENBConfigurationTransfer);

    ogs_debug("ENBConfigurationTransfer");
    for (i = 0; i < ENBConfigurationTransfer->protocolIEs.list.count; i++) {
        ie = ENBConfigurationTransfer->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_SONConfigurationTransferECT:
            SONConfigurationTransfer =
                &ie->value.choice.SONConfigurationTransfer;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (SONConfigurationTransfer) {
        S1AP_TargeteNB_ID_t *targeteNB_ID =
            &SONConfigurationTransfer->targeteNB_ID;
        S1AP_SourceeNB_ID_t *sourceeNB_ID =
            &SONConfigurationTransfer->sourceeNB_ID;

        mme_enb_t *target_enb = NULL;
        uint32_t source_enb_id, target_enb_id;
        uint16_t source_tac, target_tac;

        ogs_s1ap_ENB_ID_to_uint32(
                &sourceeNB_ID->global_ENB_ID.eNB_ID, &source_enb_id);
        ogs_s1ap_ENB_ID_to_uint32(
                &targeteNB_ID->global_ENB_ID.eNB_ID, &target_enb_id);

        if (sourceeNB_ID->selected_TAI.tAC.size != sizeof(source_tac)) {
            ogs_error("Invalid sourceeNB_ID->selected_TAI.tAC.size = %d "
                    "(expected %d)",
                    (int)sourceeNB_ID->selected_TAI.tAC.size,
                    (int)sizeof(source_tac));
            r = s1ap_send_error_indication(enb, NULL, NULL,
                    S1AP_Cause_PR_radioNetwork,
                    S1AP_CauseRadioNetwork_unknown_targetID);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
        if (targeteNB_ID->selected_TAI.tAC.size != sizeof(target_tac)) {
            ogs_error("Invalid targeteNB_ID->selected_TAI.tAC.size = %d "
                    "(expected %d)",
                    (int)targeteNB_ID->selected_TAI.tAC.size,
                    (int)sizeof(target_tac));
            r = s1ap_send_error_indication(enb, NULL, NULL,
                    S1AP_Cause_PR_radioNetwork,
                    S1AP_CauseRadioNetwork_unknown_targetID);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
        memcpy(&source_tac, sourceeNB_ID->selected_TAI.tAC.buf,
                sizeof(source_tac));
        source_tac = be16toh(source_tac);
        memcpy(&target_tac, targeteNB_ID->selected_TAI.tAC.buf,
                sizeof(target_tac));
        target_tac = be16toh(target_tac);

        ogs_debug("    Source : ENB_ID[%s:%d], TAC[%d]",
                sourceeNB_ID->global_ENB_ID.eNB_ID.present ==
                    S1AP_ENB_ID_PR_homeENB_ID ? "Home" :
                sourceeNB_ID->global_ENB_ID.eNB_ID.present ==
                    S1AP_ENB_ID_PR_macroENB_ID ? "Macro" : "Others",
                source_enb_id, source_tac);
        ogs_debug("    Target : ENB_ID[%s:%d], TAC[%d]",
                targeteNB_ID->global_ENB_ID.eNB_ID.present ==
                    S1AP_ENB_ID_PR_homeENB_ID ? "Home" :
                targeteNB_ID->global_ENB_ID.eNB_ID.present ==
                    S1AP_ENB_ID_PR_macroENB_ID ? "Macro" : "Others",
                target_enb_id, target_tac);

        target_enb = mme_enb_find_by_enb_id(target_enb_id);
        if (target_enb == NULL) {
            ogs_debug("eNB configuration transfer : "
                        "cannot find target eNB-id[0x%x]", target_enb_id);
            r = s1ap_send_error_indication(enb, NULL, NULL,
                    S1AP_Cause_PR_radioNetwork,
                    S1AP_CauseRadioNetwork_unknown_targetID);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        r = s1ap_send_mme_configuration_transfer(
                target_enb, SONConfigurationTransfer);
        ogs_expect(r == OGS_OK);
        /* ogs_asn_copy_ie() could be failed from received packet.
         * So we should not use ogs_assert(r != OGS_ERROR).*/
    }
}

static void s1ap_handle_handover_required_intralte(enb_ue_t *source_ue,
                S1AP_Cause_t *Cause, S1AP_TargetID_t *TargetID,
                S1AP_Source_ToTarget_TransparentContainer_t *Source_ToTarget_TransparentContainer)
{
    mme_enb_t *target_enb = NULL;
    uint32_t target_enb_id = 0;
    S1AP_ENB_ID_PR target_enb_id_pr = S1AP_ENB_ID_PR_NOTHING;
    mme_ue_t *mme_ue = NULL;
    int r;

    ogs_assert(source_ue);
    ogs_assert(Cause);
    ogs_assert(TargetID);
    ogs_assert(Source_ToTarget_TransparentContainer);

    mme_ue = mme_ue_find_by_id(source_ue->mme_ue_id);
    if (!mme_ue) {
        ogs_error("No UE(mme-ue) context");
        return;
    }

    /*
     * TS 32.410 / 36.413: HO preparation attempt when Handover Required
     * is accepted for a known UE (before any preparation failure).
     */
    mme_metrics_ho_attempt(mme_ue, "intralte");

    switch (TargetID->present) {
    case S1AP_TargetID_PR_targeteNB_ID:
        target_enb_id_pr =
            TargetID->choice.targeteNB_ID->global_ENB_ID.eNB_ID.present;
        ogs_s1ap_ENB_ID_to_uint32(
            &TargetID->choice.targeteNB_ID->global_ENB_ID.eNB_ID,
            &target_enb_id);
        break;
    default:
        ogs_error("Not implemented(%d)", TargetID->present);
        r = s1ap_send_handover_preparation_failure(source_ue,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    target_enb = mme_enb_find_by_enb_id(target_enb_id);

    /*
     * Tolerate the common macro/home eNB-ID encoding mismatch: a
     * 28-bit home eNB ID is the 20-bit macro eNB ID shifted left by
     * 8 bits (with the cell part appended). Some eNB vendors encode
     * the target in Handover Required with a different choice than
     * the target eNB used in its own S1 Setup Request, so the direct
     * lookup misses even though the eNB is attached to this MME.
     */
    if (target_enb == NULL) {
        if (target_enb_id_pr == S1AP_ENB_ID_PR_homeENB_ID) {
            target_enb = mme_enb_find_by_enb_id(target_enb_id >> 8);
            if (target_enb)
                ogs_info("Handover required : target eNB-id[0x%x] matched "
                        "as macro id[0x%x] (home->macro fallback)",
                        target_enb_id, target_enb_id >> 8);
        } else if (target_enb_id_pr == S1AP_ENB_ID_PR_macroENB_ID) {
            uint32_t low;
            for (low = 0; low < 0x100 && target_enb == NULL; low++)
                target_enb = mme_enb_find_by_enb_id(
                        (target_enb_id << 8) | low);
            if (target_enb)
                ogs_info("Handover required : target eNB-id[0x%x] matched "
                        "as home id[0x%x] (macro->home fallback)",
                        target_enb_id, (target_enb_id << 8) | (low - 1));
        }
    }

    if (target_enb == NULL) {
        ogs_warn("Handover required : cannot find target eNB-id[0x%x] "
                "(%s) IMSI[%s]",
                target_enb_id,
                target_enb_id_pr == S1AP_ENB_ID_PR_homeENB_ID ? "Home" :
                target_enb_id_pr == S1AP_ENB_ID_PR_macroENB_ID ? "Macro" :
                "Other",
                mme_ue->imsi_bcd);
        r = s1ap_send_handover_preparation_failure(source_ue,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_targetID);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
        ogs_error("No Security Context");
        r = s1ap_send_handover_preparation_failure(source_ue,
                S1AP_Cause_PR_nas, S1AP_CauseNas_authentication_failure);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!SESSION_CONTEXT_IS_AVAILABLE(mme_ue)) {
        ogs_error("No Session Context : IMSI[%s]", mme_ue->imsi_bcd);
        r = s1ap_send_handover_preparation_failure(source_ue,
                S1AP_Cause_PR_nas, S1AP_CauseNas_authentication_failure);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!ACTIVE_EPS_BEARERS_IS_AVAIABLE(mme_ue)) {
        ogs_error("No active EPS bearers : IMSI[%s]", mme_ue->imsi_bcd);
        r = s1ap_send_handover_preparation_failure(source_ue,
                S1AP_Cause_PR_nas, S1AP_CauseNas_authentication_failure);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    source_ue->handover_type = S1AP_HandoverType_intralte;

    mme_ue->nhcc++;
    ogs_kdf_nh_enb(mme_ue->kasme, mme_ue->nh, mme_ue->nh);

    r = s1ap_send_handover_request(
            source_ue, target_enb, &source_ue->handover_type, Cause,
            Source_ToTarget_TransparentContainer);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);
}

void s1ap_handle_handover_required(mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_HandoverRequired_t *HandoverRequired = NULL;

    S1AP_HandoverRequiredIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_HandoverType_t *HandoverType = NULL;
    S1AP_Cause_t *Cause = NULL;
    S1AP_TargetID_t *TargetID = NULL;
    S1AP_Source_ToTarget_TransparentContainer_t
        *Source_ToTarget_TransparentContainer = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    HandoverRequired = &initiatingMessage->value.choice.HandoverRequired;
    ogs_assert(HandoverRequired);

    enb_ue_t *source_ue = NULL;

    ogs_debug("HandoverRequired");
    for (i = 0; i < HandoverRequired->protocolIEs.list.count; i++) {
        ie = HandoverRequired->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_HandoverType:
            HandoverType = &ie->value.choice.HandoverType;
            break;
        case S1AP_ProtocolIE_ID_id_Cause:
            Cause = &ie->value.choice.Cause;
            break;
        case S1AP_ProtocolIE_ID_id_TargetID:
            TargetID = &ie->value.choice.TargetID;
            break;
        case S1AP_ProtocolIE_ID_id_Source_ToTarget_TransparentContainer:
            Source_ToTarget_TransparentContainer =
                &ie->value.choice.Source_ToTarget_TransparentContainer;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!ENB_UE_S1AP_ID) {
        ogs_error("No ENB_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (*ENB_UE_S1AP_ID > 0x00ffffff) {
        ogs_error("Invalid ENB_UE_S1AP_ID [%lx]", *ENB_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!MME_UE_S1AP_ID) {
        ogs_error("No MME_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    source_ue = enb_ue_find_by_mme_ue_s1ap_id(*MME_UE_S1AP_ID);
    if (!source_ue) {
        ogs_error("No eNB UE Context : MME_UE_S1AP_ID[%lld]",
                (long long)*MME_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, NULL,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_debug("    Source : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            source_ue->enb_ue_s1ap_id, source_ue->mme_ue_s1ap_id);

    if (!HandoverType) {
        ogs_error("No HandoverType");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!Cause) {
        ogs_error("No Cause");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!TargetID) {
        ogs_error("No TargetID");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!Source_ToTarget_TransparentContainer) {
        ogs_error("No Source_ToTarget_TransparentContainer");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    switch (*HandoverType) {
    case S1AP_HandoverType_intralte:
        s1ap_handle_handover_required_intralte(source_ue, Cause, TargetID, Source_ToTarget_TransparentContainer);
        break;
    case S1AP_HandoverType_ltetoutran:
    case S1AP_HandoverType_ltetogeran:
    case S1AP_HandoverType_utrantolte:
    case S1AP_HandoverType_gerantolte:
    case S1AP_HandoverType_eps_to_5gs:
    case S1AP_HandoverType_fivegs_to_eps:
    default: /* Enumeration is extensible */
        /*
         * Refuse with radioNetwork/ho-target-not-allowed, NOT
         * protocol/semantic-error: the message is well-formed, we just
         * don't support the target RAT. This cause lets the eNB
         * blacklist the handover target and fall back to release with
         * redirection instead of retrying the preparation.
         */
        ogs_warn("Rx Handover Required HandoverType=%ld not supported; "
                "replying Handover Preparation Failure "
                "(ho-target-not-allowed) ENB_UE_S1AP_ID[%d]",
                *HandoverType, source_ue->enb_ue_s1ap_id);
        r = s1ap_send_handover_preparation_failure(source_ue,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_ho_target_not_allowed);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        break;
    }
}

void s1ap_handle_handover_request_ack(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    int i, r, rv;
    char buf[OGS_ADDRSTRLEN];

    S1AP_SuccessfulOutcome_t *successfulOutcome = NULL;
    S1AP_HandoverRequestAcknowledge_t *HandoverRequestAcknowledge = NULL;

    S1AP_HandoverRequestAcknowledgeIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_E_RABAdmittedList_t *E_RABAdmittedList = NULL;
    S1AP_Target_ToSource_TransparentContainer_t
        *Target_ToSource_TransparentContainer = NULL;

    enb_ue_t *source_ue = NULL;
    enb_ue_t *target_ue = NULL;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    successfulOutcome = message->choice.successfulOutcome;
    ogs_assert(successfulOutcome);
    HandoverRequestAcknowledge =
        &successfulOutcome->value.choice.HandoverRequestAcknowledge;
    ogs_assert(HandoverRequestAcknowledge);

    ogs_debug("HandoverRequestAcknowledge");
    for (i = 0; i < HandoverRequestAcknowledge->protocolIEs.list.count; i++) {
        ie = HandoverRequestAcknowledge->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_E_RABAdmittedList:
            E_RABAdmittedList = &ie->value.choice.E_RABAdmittedList;
            break;
        case S1AP_ProtocolIE_ID_id_Target_ToSource_TransparentContainer:
            Target_ToSource_TransparentContainer =
                &ie->value.choice.Target_ToSource_TransparentContainer;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!ENB_UE_S1AP_ID) {
        ogs_error("No ENB_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (*ENB_UE_S1AP_ID > 0x00ffffff) {
        ogs_error("Invalid ENB_UE_S1AP_ID [%lx]", *ENB_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!MME_UE_S1AP_ID) {
        ogs_error("No MME_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    target_ue = enb_ue_find_by_mme_ue_s1ap_id(*MME_UE_S1AP_ID);
    if (!target_ue) {
        ogs_error("No eNB UE Context : MME_UE_S1AP_ID[%lld]",
                (long long)*MME_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, NULL,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!E_RABAdmittedList) {
        ogs_error("No E_RABAdmittedList");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!Target_ToSource_TransparentContainer) {
        ogs_error("No Target_ToSource_TransparentContainer");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    source_ue = enb_ue_find_by_id(target_ue->source_ue_id);
    if (!source_ue) {
        ogs_error("No Source UE");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    mme_ue = mme_ue_find_by_id(source_ue->mme_ue_id);
    if (!mme_ue) {
        ogs_error("No UE(mme-ue) context");
        return;
    }

    ogs_debug("    Source : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            source_ue->enb_ue_s1ap_id, source_ue->mme_ue_s1ap_id);
    ogs_debug("    Target : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            target_ue->enb_ue_s1ap_id, target_ue->mme_ue_s1ap_id);

    target_ue->enb_ue_s1ap_id = *ENB_UE_S1AP_ID;

    for (i = 0; i < E_RABAdmittedList->list.count; i++) {
        S1AP_E_RABAdmittedItemIEs_t *item = NULL;
        S1AP_E_RABAdmittedItem_t *e_rab = NULL;

        mme_bearer_t *bearer = NULL;

        item = (S1AP_E_RABAdmittedItemIEs_t *)E_RABAdmittedList->list.array[i];
        if (!item) {
            ogs_error("No S1AP_E_RABAdmittedItemIEs_t");
            r = s1ap_send_error_indication2(mme_ue,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        e_rab = &item->value.choice.E_RABAdmittedItem;
        if (!e_rab) {
            ogs_error("No E_RABAdmittedItem");
            r = s1ap_send_error_indication2(mme_ue,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        bearer = mme_bearer_find_by_ue_ebi(mme_ue, e_rab->e_RAB_ID);
        if (!bearer) {
            ogs_error("No Bearer [%d]", (int)e_rab->e_RAB_ID);
            r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_radioNetwork,
                    S1AP_CauseRadioNetwork_unknown_E_RAB_ID);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        if (e_rab->gTP_TEID.size != sizeof(bearer->enb_s1u_teid)) {
            ogs_error("Invalid e_rab->gTP_TEID.size = %d (expected %d)",
                    (int)e_rab->gTP_TEID.size,
                    (int)sizeof(bearer->enb_s1u_teid));
            r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_protocol,
                    S1AP_CauseProtocol_semantic_error);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }
        memcpy(&bearer->target_s1u_teid, e_rab->gTP_TEID.buf,
                sizeof(bearer->target_s1u_teid));
        bearer->target_s1u_teid = be32toh(bearer->target_s1u_teid);

        ogs_debug("UE[%s] EBI[%d] Update target_s1u_teid = 0x%x",
                mme_ue->imsi_bcd, bearer->ebi, bearer->target_s1u_teid);

        rv = ogs_asn_BIT_STRING_to_ip(
                &e_rab->transportLayerAddress, &bearer->target_s1u_ip);
        if (rv != OGS_OK) {
            ogs_error("No transportLayerAddress [%d]",
                    (int)e_rab->e_RAB_ID);
            r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_protocol,
                    S1AP_CauseProtocol_abstract_syntax_error_falsely_constructed_message);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return;
        }

        ogs_log_hexdump(OGS_LOG_DEBUG,
                e_rab->transportLayerAddress.buf,
                e_rab->transportLayerAddress.size);
        ogs_debug("    IPv4(%d): 0x%x",
                bearer->target_s1u_ip.ipv4, bearer->target_s1u_ip.addr);
        ogs_debug("    IPv6(%d):", bearer->target_s1u_ip.ipv6);
        ogs_log_hexdump(OGS_LOG_DEBUG,
                bearer->target_s1u_ip.addr6, OGS_IPV6_LEN);

        if (e_rab->dL_transportLayerAddress && e_rab->dL_gTP_TEID) {
            if (e_rab->dL_gTP_TEID->size != sizeof(bearer->enb_dl_teid)) {
                ogs_error("Invalid e_rab->dL_gTP_TEID.size = %d (expected %d)",
                        (int)e_rab->dL_gTP_TEID->size,
                        (int)sizeof(bearer->enb_dl_teid));
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }
            memcpy(&bearer->enb_dl_teid, e_rab->dL_gTP_TEID->buf,
                    sizeof(bearer->enb_dl_teid));
            bearer->enb_dl_teid = be32toh(bearer->enb_dl_teid);

            ogs_debug("UE[%s] EBI[%d] Update enb_dl_teid = 0x%x",
                    mme_ue->imsi_bcd, bearer->ebi, bearer->enb_dl_teid);

            rv = ogs_asn_BIT_STRING_to_ip(
                    e_rab->dL_transportLayerAddress, &bearer->enb_dl_ip);
            if (rv != OGS_OK) {
                ogs_error("No dL_transportLayerAddress [%d]",
                        (int)e_rab->e_RAB_ID);
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_abstract_syntax_error_falsely_constructed_message);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            ogs_log_hexdump(OGS_LOG_DEBUG,
                    e_rab->dL_transportLayerAddress->buf,
                    e_rab->dL_transportLayerAddress->size);
            ogs_debug("    IPv4(%d): 0x%x",
                    bearer->enb_dl_ip.ipv4, bearer->enb_dl_ip.addr);
            ogs_debug("    IPv6(%d):", bearer->enb_dl_ip.ipv6);
            ogs_log_hexdump(OGS_LOG_DEBUG,
                    bearer->enb_dl_ip.addr6, OGS_IPV6_LEN);
        }

        if (e_rab->uL_TransportLayerAddress && e_rab->uL_GTP_TEID) {
            if (e_rab->uL_GTP_TEID->size != sizeof(bearer->enb_ul_teid)) {
                ogs_error("Invalid e_rab->uL_GTP_TEID.size = %d (expected %d)",
                        (int)e_rab->uL_GTP_TEID->size,
                        (int)sizeof(bearer->enb_ul_teid));
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }
            memcpy(&bearer->enb_ul_teid, e_rab->uL_GTP_TEID->buf,
                    sizeof(bearer->enb_ul_teid));
            bearer->enb_ul_teid = be32toh(bearer->enb_ul_teid);
            rv = ogs_asn_BIT_STRING_to_ip(
                    e_rab->uL_TransportLayerAddress, &bearer->enb_ul_ip);
            if (rv != OGS_OK) {
                ogs_error("No uL_transportLayerAddress [%d]",
                        (int)e_rab->e_RAB_ID);
                r = s1ap_send_error_indication2(mme_ue,
                        S1AP_Cause_PR_protocol,
                        S1AP_CauseProtocol_abstract_syntax_error_falsely_constructed_message);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                return;
            }

            ogs_log_hexdump(OGS_LOG_DEBUG,
                    e_rab->uL_TransportLayerAddress->buf,
                    e_rab->uL_TransportLayerAddress->size);
            ogs_debug("    IPv4(%d): 0x%x",
                    bearer->enb_ul_ip.ipv4, bearer->enb_ul_ip.addr);
            ogs_debug("    IPv6(%d):", bearer->enb_ul_ip.ipv6);
            ogs_log_hexdump(OGS_LOG_DEBUG,
                    bearer->enb_ul_ip.addr6, OGS_IPV6_LEN);
        }
    }

    OGS_ASN_STORE_DATA(&mme_ue->container,
            Target_ToSource_TransparentContainer);

    if (mme_ue_have_indirect_tunnel(mme_ue) == true &&
            mme_gtp_send_create_indirect_data_forwarding_tunnel_request(
                source_ue, mme_ue) == OGS_OK)
        return;

    /*
     * No indirect tunnel, or the S11 request could not be sent. Proceed with
     * the handover anyway: packets in flight may be lost, but stalling here
     * would leave the UE without a Handover Command at all.
     */
    if (mme_ue_have_indirect_tunnel(mme_ue) == true)
        ogs_error("[%s] Create Indirect Data Forwarding Tunnel Request "
                "failed; sending Handover Command without it",
                mme_ue->imsi_bcd);

    r = s1ap_send_handover_command(source_ue);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);
}

void s1ap_handle_handover_failure(mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_UnsuccessfulOutcome_t *unsuccessfulOutcome = NULL;
    S1AP_HandoverFailure_t *HandoverFailure = NULL;

    S1AP_HandoverFailureIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_Cause_t *Cause = NULL;

    enb_ue_t *target_ue = NULL;
    enb_ue_t *source_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    unsuccessfulOutcome = message->choice.unsuccessfulOutcome;
    ogs_assert(unsuccessfulOutcome);
    HandoverFailure = &unsuccessfulOutcome->value.choice.HandoverFailure;
    ogs_assert(HandoverFailure);

    ogs_debug("HandoverFailure");
    for (i = 0; i < HandoverFailure->protocolIEs.list.count; i++) {
        ie = HandoverFailure->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_Cause:
            Cause = &ie->value.choice.Cause;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!MME_UE_S1AP_ID) {
        ogs_error("No MME_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    target_ue = enb_ue_find_by_mme_ue_s1ap_id(*MME_UE_S1AP_ID);
    if (!target_ue) {
        ogs_error("No eNB UE Context : MME_UE_S1AP_ID[%lld]",
                (long long)*MME_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, NULL,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!Cause) {
        ogs_error("No Cause");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    source_ue = enb_ue_find_by_id(target_ue->source_ue_id);
    if (!source_ue) {
        ogs_error("No Source UE");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_debug("    Source : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            source_ue->enb_ue_s1ap_id, source_ue->mme_ue_s1ap_id);
    ogs_debug("    Target : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            target_ue->enb_ue_s1ap_id, target_ue->mme_ue_s1ap_id);

    r = s1ap_send_handover_preparation_failure_from_cause(source_ue, Cause);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    r = s1ap_send_ue_context_release_command(
        target_ue, S1AP_Cause_PR_radioNetwork,
        S1AP_CauseRadioNetwork_ho_failure_in_target_EPC_eNB_or_target_system,
        S1AP_UE_CTX_REL_S1_HANDOVER_FAILURE, 0);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);
}

void s1ap_handle_handover_cancel(mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_HandoverCancel_t *HandoverCancel = NULL;

    S1AP_HandoverCancelIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_Cause_t *Cause = NULL;

    enb_ue_t *source_ue = NULL;
    enb_ue_t *target_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    HandoverCancel = &initiatingMessage->value.choice.HandoverCancel;
    ogs_assert(HandoverCancel);

    ogs_debug("HandoverCancel");
    for (i = 0; i < HandoverCancel->protocolIEs.list.count; i++) {
        ie = HandoverCancel->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_Cause:
            Cause = &ie->value.choice.Cause;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!ENB_UE_S1AP_ID) {
        ogs_error("No ENB_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (*ENB_UE_S1AP_ID > 0x00ffffff) {
        ogs_error("Invalid ENB_UE_S1AP_ID [%lx]", *ENB_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!MME_UE_S1AP_ID) {
        ogs_error("No MME_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    source_ue = enb_ue_find_by_mme_ue_s1ap_id(*MME_UE_S1AP_ID);
    if (!source_ue) {
        ogs_error("No eNB UE Context : MME_UE_S1AP_ID[%lld]",
                (long long)*MME_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, NULL,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!Cause) {
        ogs_error("No Cause");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    target_ue = enb_ue_find_by_id(source_ue->target_ue_id);
    if (!target_ue) {
        mme_ran_error(enb, source_ue,
                mme_ue_find_by_id(source_ue->mme_ue_id),
                "s1ap", NULL, "No Target UE");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_debug("    Source : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            source_ue->enb_ue_s1ap_id, source_ue->mme_ue_s1ap_id);
    ogs_debug("    Target : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            target_ue->enb_ue_s1ap_id, target_ue->mme_ue_s1ap_id);

    r = s1ap_send_ue_context_release_command(
            target_ue, S1AP_Cause_PR_radioNetwork,
            S1AP_CauseRadioNetwork_handover_cancelled,
            S1AP_UE_CTX_REL_S1_HANDOVER_CANCEL, 0);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    ogs_debug("Handover Cancel : UE[eNB-UE-S1AP-ID(%d)] --> eNB[%s:%d]",
            source_ue->enb_ue_s1ap_id,
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);
}

void s1ap_handle_enb_status_transfer(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_ENBStatusTransfer_t *ENBStatusTransfer = NULL;

    S1AP_ENBStatusTransferIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_ENB_StatusTransfer_TransparentContainer_t
        *ENB_StatusTransfer_TransparentContainer = NULL;

    enb_ue_t *source_ue = NULL, *target_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    ENBStatusTransfer = &initiatingMessage->value.choice.ENBStatusTransfer;
    ogs_assert(ENBStatusTransfer);

    ogs_debug("ENBStatusTransfer");
    for (i = 0; i < ENBStatusTransfer->protocolIEs.list.count; i++) {
        ie = ENBStatusTransfer->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_StatusTransfer_TransparentContainer:
            ENB_StatusTransfer_TransparentContainer =
                &ie->value.choice.ENB_StatusTransfer_TransparentContainer;
            break;
        default:
            break;
        }
    }
    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!ENB_UE_S1AP_ID) {
        ogs_error("No ENB_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (*ENB_UE_S1AP_ID > 0x00ffffff) {

        /*
         * The test code is using this problem,
         * so we use WARN here instead of ERROR.
         */
        ogs_warn("Invalid ENB_UE_S1AP_ID [%lx]", *ENB_UE_S1AP_ID);

        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!MME_UE_S1AP_ID) {
        ogs_error("No MME_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    source_ue = enb_ue_find_by_mme_ue_s1ap_id(*MME_UE_S1AP_ID);
    if (!source_ue) {
        ogs_error("No eNB UE Context : MME_UE_S1AP_ID[%lld]",
                (long long)*MME_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, NULL,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!ENB_StatusTransfer_TransparentContainer) {
        ogs_error("No ENB_StatusTransfer_TransparentContainer");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    target_ue = enb_ue_find_by_id(source_ue->target_ue_id);
    if (!target_ue) {
        mme_ran_error(enb, source_ue,
                mme_ue_find_by_id(source_ue->mme_ue_id),
                "s1ap", NULL, "No Target UE");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_debug("    Source : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            source_ue->enb_ue_s1ap_id, source_ue->mme_ue_s1ap_id);
    ogs_debug("    Target : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            target_ue->enb_ue_s1ap_id, target_ue->mme_ue_s1ap_id);

    r = s1ap_send_mme_status_transfer(target_ue,
            ENB_StatusTransfer_TransparentContainer);
    ogs_expect(r == OGS_OK);
    /* ogs_asn_copy_ie() could be failed from received packet.
     * So we should not use ogs_assert(r != OGS_ERROR).*/
}

void s1ap_handle_handover_notification(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_HandoverNotify_t *HandoverNotify = NULL;

    S1AP_HandoverNotifyIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_EUTRAN_CGI_t *EUTRAN_CGI = NULL;
    S1AP_TAI_t *TAI = NULL;

    S1AP_PLMNidentity_t *pLMNidentity = NULL;
    S1AP_CellIdentity_t *cell_ID = NULL;
    S1AP_TAC_t *tAC = NULL;

    enb_ue_t *source_ue = NULL;
    enb_ue_t *target_ue = NULL;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    HandoverNotify = &initiatingMessage->value.choice.HandoverNotify;
    ogs_assert(HandoverNotify);

    ogs_debug("HandoverNotify");
    for (i = 0; i < HandoverNotify->protocolIEs.list.count; i++) {
        ie = HandoverNotify->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_EUTRAN_CGI:
            EUTRAN_CGI = &ie->value.choice.EUTRAN_CGI;
            break;
        case S1AP_ProtocolIE_ID_id_TAI:
            TAI = &ie->value.choice.TAI;
            break;
        default:
            break;
        }
    }
    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!ENB_UE_S1AP_ID) {
        ogs_error("No ENB_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (*ENB_UE_S1AP_ID > 0x00ffffff) {
        ogs_error("Invalid ENB_UE_S1AP_ID [%lx]", *ENB_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!MME_UE_S1AP_ID) {
        ogs_error("No MME_UE_S1AP_ID");
        r = s1ap_send_error_indication(enb, NULL, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    target_ue = enb_ue_find_by_mme_ue_s1ap_id(*MME_UE_S1AP_ID);
    if (!target_ue) {
        ogs_error("No eNB UE Context : MME_UE_S1AP_ID[%lld]",
                (long long)*MME_UE_S1AP_ID);
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, NULL,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_unknown_mme_ue_s1ap_id);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!EUTRAN_CGI) {
        ogs_error("No EUTRAN_CGI");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    if (!TAI) {
        ogs_error("No TAI");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    source_ue = enb_ue_find_by_id(target_ue->source_ue_id);
    if (!source_ue) {
        ogs_error("No Source UE");
        r = s1ap_send_error_indication(enb, MME_UE_S1AP_ID, ENB_UE_S1AP_ID,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    mme_ue = mme_ue_find_by_id(source_ue->mme_ue_id);
    if (!mme_ue) {
        ogs_error("No UE(mme-ue) context");
        return;
    }

    mme_metrics_ho_success(mme_ue, "intralte");

    ogs_debug("    Source : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            source_ue->enb_ue_s1ap_id, source_ue->mme_ue_s1ap_id);
    ogs_debug("    Target : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            target_ue->enb_ue_s1ap_id, target_ue->mme_ue_s1ap_id);

    enb_ue_associate_mme_ue(target_ue, mme_ue);
    ogs_debug("Mobile Reachable timer stopped for IMSI[%s]", mme_ue->imsi_bcd);
    CLEAR_MME_UE_TIMER(mme_ue->t_mobile_reachable);

    pLMNidentity = &TAI->pLMNidentity;
    if (pLMNidentity->size != sizeof(target_ue->saved.tai.plmn_id)) {
        ogs_error("Invalid pLMNidentity->size = %d (expected %d)",
                (int)pLMNidentity->size,
                (int)sizeof(target_ue->saved.tai.plmn_id));
        r = s1ap_send_error_indication2(
                mme_ue,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    tAC = &TAI->tAC;
    if (tAC->size != sizeof(target_ue->saved.tai.tac)) {
        ogs_error("Invalid tAC->size = %d (expected %d)",
                (int)tAC->size, (int)sizeof(target_ue->saved.tai.tac));
        r = s1ap_send_error_indication2(
                mme_ue,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    memcpy(&target_ue->saved.tai.plmn_id, pLMNidentity->buf,
            sizeof(target_ue->saved.tai.plmn_id));
    memcpy(&target_ue->saved.tai.tac,
            tAC->buf, sizeof(target_ue->saved.tai.tac));
    target_ue->saved.tai.tac = be16toh(target_ue->saved.tai.tac);

    pLMNidentity = &EUTRAN_CGI->pLMNidentity;
    if (pLMNidentity->size != sizeof(target_ue->saved.e_cgi.plmn_id)) {
        ogs_error("Invalid pLMNidentity->size = %d (expected %d)",
                (int)pLMNidentity->size,
                (int)sizeof(target_ue->saved.e_cgi.plmn_id));
        r = s1ap_send_error_indication2(
                mme_ue,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    cell_ID = &EUTRAN_CGI->cell_ID;
    if (cell_ID->size != sizeof(target_ue->saved.e_cgi.cell_id)) {
        ogs_error("Invalid cell_ID->size = %d (expected %d)",
                (int)cell_ID->size,
                (int)sizeof(target_ue->saved.e_cgi.cell_id));
        r = s1ap_send_error_indication1(
                target_ue,
                S1AP_Cause_PR_protocol,
                S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }
    memcpy(&target_ue->saved.e_cgi.plmn_id, pLMNidentity->buf,
            sizeof(target_ue->saved.e_cgi.plmn_id));
    memcpy(&target_ue->saved.e_cgi.cell_id, cell_ID->buf,
            sizeof(target_ue->saved.e_cgi.cell_id));
    target_ue->saved.e_cgi.cell_id =
        (be32toh(target_ue->saved.e_cgi.cell_id) >> 4);

    ogs_debug("    OLD TAI[PLMN_ID:%06x,TAC:%d]",
            ogs_plmn_id_hexdump(&mme_ue->tai.plmn_id),
            mme_ue->tai.tac);
    ogs_debug("    OLD E_CGI[PLMN_ID:%06x,CELL_ID:0x%x]",
            ogs_plmn_id_hexdump(&mme_ue->e_cgi.plmn_id),
            mme_ue->e_cgi.cell_id);
    ogs_debug("    TAI[PLMN_ID:%06x,TAC:%d]",
            ogs_plmn_id_hexdump(&target_ue->saved.tai.plmn_id),
            target_ue->saved.tai.tac);
    ogs_debug("    E_CGI[PLMN_ID:%06x,CELL_ID:0x%x]",
            ogs_plmn_id_hexdump(&target_ue->saved.e_cgi.plmn_id),
            target_ue->saved.e_cgi.cell_id);

    /*
     * With mme.workers the tail (location, source release, S11 Modify
     * Bearer) runs on the UE's owner shard — see
     * s1ap_handle_path_switch_request for the rationale.
     */
    if (mme_workers_active()) {
        if (mme_worker_post_ho_tail(
                    MME_HO_TAIL_HANDOVER_NOTIFY, target_ue->id,
                    mme_ue, NULL) == OGS_OK)
            return;
        /* Dropped tail = no Modify Bearer = stale eNB TEID at the SGW.
         * Fall back to running the tail inline on main. */
        ogs_warn("[%s] HandoverNotify tail post failed; running inline",
                mme_ue->imsi_bcd);
    }

    s1ap_handover_notify_complete(target_ue, mme_ue);
}

/*
 * Handover Notify tail. Runs on the UE owner thread: the main thread
 * when workers are off, the owner shard (MME_EVENT_S1AP_HO_TAIL) when
 * mme.workers is active.
 */
void s1ap_handover_notify_complete(enb_ue_t *target_ue, mme_ue_t *mme_ue)
{
    int r;
    enb_ue_t *source_ue = NULL;
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;

    ogs_assert(target_ue);
    ogs_assert(mme_ue);

    /* Copy Stream-No/TAI/ECGI from enb_ue */
    mme_ue->enb_ostream_id = target_ue->enb_ostream_id;
    memcpy(&mme_ue->tai, &target_ue->saved.tai, sizeof(ogs_eps_tai_t));
    memcpy(&mme_ue->e_cgi, &target_ue->saved.e_cgi, sizeof(ogs_e_cgi_t));
    mme_ue->ue_location_timestamp = ogs_time_now();

    /* Source may already be gone if the deferred tail lost a race with
     * source-side release; the handover itself proceeds regardless. */
    source_ue = enb_ue_find_by_id(target_ue->source_ue_id);
    if (source_ue) {
        r = s1ap_send_ue_context_release_command(source_ue,
                S1AP_Cause_PR_radioNetwork,
                S1AP_CauseRadioNetwork_successful_handover,
                S1AP_UE_CTX_REL_S1_HANDOVER_COMPLETE,
                ogs_local_conf()->time.handover.duration);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
    } else {
        ogs_warn("[%s] HandoverNotify tail: source UE already released",
                mme_ue->imsi_bcd);
    }

    ogs_list_init(&mme_ue->bearer_to_modify_list);

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            if (bearer->target_s1u_ip.ipv4 || bearer->target_s1u_ip.ipv6) {
                bearer->enb_s1u_teid = bearer->target_s1u_teid;
                ogs_debug("UE[%s] EBI[%d] Update enb_s1u_teid = 0x%x",
                        mme_ue->imsi_bcd, bearer->ebi, bearer->enb_s1u_teid);

                memcpy(&bearer->enb_s1u_ip, &bearer->target_s1u_ip,
                        sizeof(ogs_ip_t));

                ogs_debug("    IPv4(%d): 0x%x",
                        bearer->enb_s1u_ip.ipv4, bearer->enb_s1u_ip.addr);
                ogs_debug("    IPv6(%d):", bearer->enb_s1u_ip.ipv6);
                ogs_log_hexdump(OGS_LOG_DEBUG,
                        bearer->enb_s1u_ip.addr6, OGS_IPV6_LEN);

                if (!bearer->sgw_s1u_teid) {
                    ogs_warn("UE[%s] EBI[%d] has no SGW S1-U TEID after "
                            "Handover Notify: excluded from "
                            "Modify Bearer Request",
                            mme_ue->imsi_bcd, bearer->ebi);
                    continue;
                }

                ogs_list_add(
                        &mme_ue->bearer_to_modify_list,
                        &bearer->to_modify_node);
            }
        }
    }

    if (ogs_list_count(&mme_ue->bearer_to_modify_list)) {
        if (mme_gtp_send_modify_bearer_request(
                    target_ue, mme_ue, 1, 0) != OGS_OK)
            ogs_error("[%s] Modify Bearer Request failed after "
                    "Handover Notify", mme_ue->imsi_bcd);
    }
}

void s1ap_handle_s1_reset(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];
    int i, r;

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_Reset_t *Reset = NULL;

    S1AP_ResetIEs_t *ie = NULL;
    S1AP_Cause_t *Cause = NULL;
    S1AP_ResetType_t *ResetType = NULL;
    S1AP_UE_associatedLogicalS1_ConnectionListRes_t *partOfS1_Interface = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    initiatingMessage = message->choice.initiatingMessage;
    ogs_assert(initiatingMessage);
    Reset = &initiatingMessage->value.choice.Reset;
    ogs_assert(Reset);

    ogs_warn("Reset");

    for (i = 0; i < Reset->protocolIEs.list.count; i++) {
        ie = Reset->protocolIEs.list.array[i];
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_Cause:
            Cause = &ie->value.choice.Cause;
            break;
        case S1AP_ProtocolIE_ID_id_ResetType:
            ResetType = &ie->value.choice.ResetType;
            break;
        default:
            break;
        }
    }

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

    if (!Cause) {
        ogs_error("No Cause");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    ogs_warn("    Cause[Group:%d Cause:%d]",
            Cause->present, (int)Cause->choice.radioNetwork);

    if (!ResetType) {
        ogs_error("No ResetType");
        r = s1ap_send_error_indication(enb, NULL, NULL,
                S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return;
    }

    switch (ResetType->present) {
    case S1AP_ResetType_PR_s1_Interface:
        ogs_warn("    S1AP_ResetType_PR_s1_Interface");

        /*
         * Throttle Reset retransmissions. eNBs re-send Reset until they
         * receive the ack, and the ack is only sent once every UE on
         * the eNB is released. Re-running the mass release for every
         * retransmission re-walked the whole enb_ue_list and re-sent a
         * Release Access Bearers Request per UE - with tens of
         * thousands of UEs this pegged the main thread at 100% under
         * mme_ctx_lock and made the MME unresponsive (perf: 56% of
         * cycles in s1ap_handle_s1_reset / ogs_list_next).
         */
        {
            bool release_in_progress = false;
            ogs_time_t now = ogs_time_now();

            mme_ctx_lock();
            if (enb->last_reset_all &&
                    now - enb->last_reset_all < ogs_time_from_sec(10))
                release_in_progress = true;
            else
                enb->last_reset_all = now;
            mme_ctx_unlock();

            if (release_in_progress)
                ogs_warn("S1 Reset (all) retransmission within 10s - "
                        "release already in progress "
                        "(eNB[%u], %d UEs remaining)",
                        enb->enb_id, enb->num_enb_ues);
            else
                mme_gtp_send_release_all_ue_in_enb(enb,
                        OGS_GTP_RELEASE_S1_CONTEXT_REMOVE_BY_RESET_ALL);
        }

        /*
         * TS36.413
         * 8.7.1.2.1 Reset Procedure Initiated from the MME
         *
         * The eNB does not need to wait for the release of radio resources
         * to be completed before returning the RESET ACKNOWLEDGE message.
         *
         * 8.7.1.2.2 Reset Procedure Initiated from the E-UTRAN
         * After the MME has released all assigned S1 resources and
         * the UE S1AP IDs for all indicated UE associations which can be used
         * for new UE-associated logical S1-connections over the S1 interface,
         * the MME shall respond with the RESET ACKNOWLEDGE message.
         *
         * num_enb_ues replaces ogs_list_count(): O(1) instead of O(n).
         */
        if (enb->num_enb_ues == 0) {
            mme_ctx_lock();
            enb->last_reset_all = 0;
            mme_ctx_unlock();
            r = s1ap_send_s1_reset_ack(enb, NULL);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
        }

        break;

    case S1AP_ResetType_PR_partOfS1_Interface:
        ogs_warn("    S1AP_ResetType_PR_partOfS1_Interface");

        partOfS1_Interface = ResetType->choice.partOfS1_Interface;
        ogs_assert(partOfS1_Interface);

        /* enb->s1_reset_ack is taken (take-and-null) by whichever
         * thread finishes the last partial-reset UE — main here or a
         * UE owner shard in the Release Access Bearers response path —
         * so every store/take must be under the ctx lock. */
        mme_ctx_lock();
        if (enb->s1_reset_ack)
            ogs_pkbuf_free(enb->s1_reset_ack);

        enb->s1_reset_ack = ogs_s1ap_build_s1_reset_ack(partOfS1_Interface);
        mme_ctx_unlock();
        if (!enb->s1_reset_ack) {
            ogs_error("ogs_s1ap_build_s1_reset_ack() failed");
            return;
        }

        for (i = 0; i < partOfS1_Interface->list.count; i++) {
            S1AP_UE_associatedLogicalS1_ConnectionItemRes_t *ie2 = NULL;
            S1AP_UE_associatedLogicalS1_ConnectionItem_t *item = NULL;

            enb_ue_t *enb_ue = NULL;
            mme_ue_t *mme_ue = NULL;

            ie2 = (S1AP_UE_associatedLogicalS1_ConnectionItemRes_t *)
                partOfS1_Interface->list.array[i];
            if (!ie2) {
                ogs_error("No S1AP_UE_associatedLogicalS1_ConnectionItemRes_t");
                continue;
            }

            item = &ie2->value.choice.UE_associatedLogicalS1_ConnectionItem;
            if (!item) {
                ogs_error("No UE_associatedLogicalS1_ConnectionItem");
                continue;
            }

            if (item->mME_UE_S1AP_ID)
                enb_ue = enb_ue_find_by_mme_ue_s1ap_id( *item->mME_UE_S1AP_ID);
            else if (item->eNB_UE_S1AP_ID)
                enb_ue = enb_ue_find_by_enb_ue_s1ap_id(enb,
                        *item->eNB_UE_S1AP_ID);

            if (enb_ue == NULL) {
                /* Already released on the MME side before the eNB's
                 * partial S1 Reset arrived - benign race, TS 36.413
                 * just wants the connection listed in the RESET ACK. */
                ogs_warn("S1 Reset for unknown S1 context, already "
                    "released (MME_UE_S1AP_ID[%d] ENB_UE_S1AP_ID[%d])",
                    item->mME_UE_S1AP_ID ? (int)*item->mME_UE_S1AP_ID : -1,
                    item->eNB_UE_S1AP_ID ? (int)*item->eNB_UE_S1AP_ID : -1);
                continue;
            }

            ogs_warn("    MME_UE_S1AP_ID[%d] ENB_UE_S1AP_ID[%d]",
                    item->mME_UE_S1AP_ID ? (int)*item->mME_UE_S1AP_ID : -1,
                    item->eNB_UE_S1AP_ID ? (int)*item->eNB_UE_S1AP_ID : -1);

            /*
             * ENB_UE Context where PartOfS1_interface was requested.
             * Flag + per-eNB pending counter are kept in sync under
             * the ctx lock; enb_ue_remove() decrements the counter.
             * An already-flagged context means this Reset is a
             * retransmission for a release that is still in flight -
             * don't send another Release Access Bearers Request.
             */
            {
                bool already_flagged;

                mme_ctx_lock();
                already_flagged = enb_ue->part_of_s1_reset_requested;
                if (!already_flagged) {
                    enb_ue->part_of_s1_reset_requested = true;
                    enb->num_part_reset_pending++;
                }
                mme_ctx_unlock();

                if (already_flagged)
                    continue;
            }

            mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
            if (mme_ue) {
                if (mme_gtp_send_release_access_bearers_request(enb_ue->id,
                        mme_ue,
                        OGS_GTP_RELEASE_S1_CONTEXT_REMOVE_BY_RESET_PARTIAL)
                        != OGS_OK) {
                    ogs_error("[%s] Release Access Bearers failed "
                            "(partial S1 reset)", mme_ue->imsi_bcd);
                    /*
                     * The release will never complete, so the flagged
                     * context would wedge the RESET ACK forever (the
                     * eNB then retransmits Reset indefinitely). Drop
                     * the S1 context now; enb_ue_remove() clears the
                     * flag and the pending counter.
                     */
                    enb_ue_deassociate_mme_ue(enb_ue, mme_ue);
                    enb_ue_remove(enb_ue);
                }
            } else {
                enb_ue_remove(enb_ue);
            }
        }

        /*
         * TS36.413
         * 8.7.1.2.1 Reset Procedure Initiated from the MME
         *
         * The eNB does not need to wait for the release of radio resources
         * to be completed before returning the RESET ACKNOWLEDGE message.
         *
         * 8.7.1.2.2 Reset Procedure Initiated from the E-UTRAN
         * After the MME has released all assigned S1 resources and
         * the UE S1AP IDs for all indicated UE associations which can be used
         * for new UE-associated logical S1-connections over the S1 interface,
         * the MME shall respond with the RESET ACKNOWLEDGE message.
         */
        {
            ogs_pkbuf_t *reset_ack = NULL;
            bool reset_remains = false;

            /*
             * Check + take-and-null atomically: with mme.workers the
             * Release Access Bearers response path runs the same
             * completion check on UE owner shards. Whoever wins the
             * take sends the ack exactly once; the buffer is enqueued
             * to the S1AP IO thread, so a double take double-freed the
             * pkbuf inside io_sock_flush (talloc bad-magic abort).
             *
             * num_part_reset_pending replaces the whole-list scan:
             * O(1) instead of O(n) under the global ctx lock.
             */
            mme_ctx_lock();
            reset_remains = (enb->num_part_reset_pending > 0);
            if (!reset_remains) {
                reset_ack = enb->s1_reset_ack;
                enb->s1_reset_ack = NULL;
            }
            mme_ctx_unlock();

            if (reset_remains)
                return;

            /* All ENB_UE context
             * where PartOfS1_interface was requested
             * REMOVED */
            if (!reset_ack) {
                ogs_warn("No S1 Reset Ack buffer (eNB[%u], already sent?)",
                        enb->enb_id);
                break;
            }
            r = s1ap_send_to_enb(enb, reset_ack, S1AP_NON_UE_SIGNALLING);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
        }
        break;
    default:
        ogs_warn("Invalid ResetType[%d]", ResetType->present);
        break;
    }
}

void s1ap_handle_write_replace_warning_response(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];

    S1AP_SuccessfulOutcome_t *successfulOutcome = NULL;
    S1AP_WriteReplaceWarningResponse_t *WriteReplaceWarningResponse = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    successfulOutcome = message->choice.successfulOutcome;
    ogs_assert(successfulOutcome);
    WriteReplaceWarningResponse =
        &successfulOutcome->value.choice.WriteReplaceWarningResponse;
    ogs_assert(WriteReplaceWarningResponse);

    ogs_debug("WriteReplaceWarningResponse");

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);

}

void s1ap_handle_kill_response(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    char buf[OGS_ADDRSTRLEN];

    S1AP_SuccessfulOutcome_t *successfulOutcome = NULL;
    S1AP_KillResponse_t *KillResponse = NULL;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    ogs_assert(message);
    successfulOutcome = message->choice.successfulOutcome;
    ogs_assert(successfulOutcome);
    KillResponse =
        &successfulOutcome->value.choice.KillResponse;
    ogs_assert(KillResponse);

    ogs_debug("KillResponse");

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->sctp.addr, buf), enb->enb_id);
}
