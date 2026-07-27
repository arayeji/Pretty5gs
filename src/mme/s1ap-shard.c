/*
 * Copyright (C) 2026 by Ahmad Raeiji <ahmad.rayeji@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
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

/*
 * Stage C — UE-scoped S1AP dispatch on the owner shard.
 *
 * Today every S1AP PDU funnels through the main thread even when the
 * work is entirely UE-scoped and the UE lives on a shard worker
 * (mme.workers). The MME_UE_S1AP_ID already carries the owner shard in
 * its top OGS_WORKER_ID_BITS (mme_shard_compose at enb_ue_add), so for
 * the high-volume UE procedures the RX worker can compute the owner
 * with pure arithmetic and post the decoded PDU straight to that
 * shard's queue.
 *
 * Whitelist (phase 1) — handlers verified UE-scoped, no eNB lifecycle:
 *
 *   initiatingMessage:  UplinkNASTransport, UECapabilityInfoIndication
 *   successfulOutcome:  InitialContextSetupResponse,
 *                       UEContextModificationResponse, E-RABSetupResponse
 *
 * Everything else (S1Setup, Reset, InitialUEMessage, release, handover,
 * paging, failures) stays on main. Ordering: any routed message is
 * causally later than the InitialUEMessage that created the enb_ue
 * (the UE only talks after the MME answered), so the shard never sees
 * a UE before main created it.
 *
 * Fallback contract: whenever the fast-path preconditions fail
 * (unknown UE id, eNB gone, socket mismatch after reconnect, S1 setup
 * not complete) the event is re-posted to the MAIN queue untouched, so
 * stale/edge cases take exactly the legacy path (error indications,
 * stale-context release, etc.).
 */

#include "ogs-sctp.h"
#include "ogs-s1ap.h"

#include "mme-context.h"
#include "mme-event.h"
#include "mme-workers.h"
#include "s1ap-path.h"
#include "s1ap-handler.h"
#include "s1ap-shard.h"

bool s1ap_stage_c_active(void)
{
    return mme_self()->stage_c && mme_workers_active();
}

/*
 * Extract MME_UE_S1AP_ID from a whitelisted PDU. Returns false when the
 * procedure is not whitelisted or the IE is absent.
 */
#define stagec_scan_ies(container, IES_T, PR_MME, out) \
    do { \
        int i_; \
        for (i_ = 0; i_ < (container)->protocolIEs.list.count; i_++) { \
            IES_T *ie_ = (IES_T *)(container)->protocolIEs.list.array[i_]; \
            if (ie_ && ie_->id == S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID && \
                    ie_->value.present == PR_MME) { \
                *(out) = (uint32_t)ie_->value.choice.MME_UE_S1AP_ID; \
                return true; \
            } \
        } \
        return false; \
    } while (0)

static bool stagec_extract_mme_ue_id(
        ogs_s1ap_message_t *pdu, uint32_t *mme_ue_s1ap_id)
{
    ogs_assert(pdu);
    ogs_assert(mme_ue_s1ap_id);

    switch (pdu->present) {
    case S1AP_S1AP_PDU_PR_initiatingMessage:
    {
        S1AP_InitiatingMessage_t *im = pdu->choice.initiatingMessage;

        if (!im)
            return false;

        switch (im->procedureCode) {
        case S1AP_ProcedureCode_id_uplinkNASTransport:
            stagec_scan_ies(&im->value.choice.UplinkNASTransport,
                    S1AP_UplinkNASTransport_IEs_t,
                    S1AP_UplinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID,
                    mme_ue_s1ap_id);
        case S1AP_ProcedureCode_id_UECapabilityInfoIndication:
            stagec_scan_ies(&im->value.choice.UECapabilityInfoIndication,
                    S1AP_UECapabilityInfoIndicationIEs_t,
                    S1AP_UECapabilityInfoIndicationIEs__value_PR_MME_UE_S1AP_ID,
                    mme_ue_s1ap_id);
        default:
            return false;
        }
    }
    case S1AP_S1AP_PDU_PR_successfulOutcome:
    {
        S1AP_SuccessfulOutcome_t *so = pdu->choice.successfulOutcome;

        if (!so)
            return false;

        switch (so->procedureCode) {
        case S1AP_ProcedureCode_id_InitialContextSetup:
            stagec_scan_ies(&so->value.choice.InitialContextSetupResponse,
                    S1AP_InitialContextSetupResponseIEs_t,
                    S1AP_InitialContextSetupResponseIEs__value_PR_MME_UE_S1AP_ID,
                    mme_ue_s1ap_id);
        case S1AP_ProcedureCode_id_UEContextModification:
            stagec_scan_ies(&so->value.choice.UEContextModificationResponse,
                    S1AP_UEContextModificationResponseIEs_t,
                    S1AP_UEContextModificationResponseIEs__value_PR_MME_UE_S1AP_ID,
                    mme_ue_s1ap_id);
        case S1AP_ProcedureCode_id_E_RABSetup:
            stagec_scan_ies(&so->value.choice.E_RABSetupResponse,
                    S1AP_E_RABSetupResponseIEs_t,
                    S1AP_E_RABSetupResponseIEs__value_PR_MME_UE_S1AP_ID,
                    mme_ue_s1ap_id);
        default:
            return false;
        }
    }
    default:
        return false;
    }
}

int s1ap_shard_classify_wid(ogs_s1ap_message_t *pdu)
{
    uint32_t mme_ue_s1ap_id = 0;
    int wid;

    if (!s1ap_stage_c_active())
        return -1;

    if (!stagec_extract_mme_ue_id(pdu, &mme_ue_s1ap_id))
        return -1;

    wid = mme_shard_from_ue_s1ap_id(mme_ue_s1ap_id);
    if (wid < 0 || wid >= mme_workers_count())
        return -1;    /* main-owned or forged shard prefix */

    return wid;
}

static void stagec_event_cleanup(mme_event_t *e)
{
    if (e->s1ap_rx_decoded && e->s1ap_message) {
        ogs_s1ap_free(e->s1ap_message);
        ogs_free(e->s1ap_message);
        e->s1ap_message = NULL;
        e->s1ap_rx_decoded = false;
    }
    if (e->pkbuf) {
        ogs_pkbuf_free(e->pkbuf);
        e->pkbuf = NULL;
    }
    if (e->addr) {
        ogs_free(e->addr);
        e->addr = NULL;
    }
}

/*
 * Re-post the untouched event to main so legacy edge handling runs.
 * Returns true on success — the event then belongs to main and MUST
 * NOT be touched again by the caller. On failure the payload is freed
 * and the (empty) event stays with the caller.
 */
static bool stagec_bounce_to_main(mme_event_t *e)
{
    int rv;

    rv = ogs_queue_trypush(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("stage-c: main-queue fallback failed (%d); "
                "dropping S1AP PDU", (int)rv);
        stagec_event_cleanup(e);
        return false;
    }
    ogs_pollset_notify(ogs_app()->pollset);
    return true;
}

void s1ap_shard_push_decoded(int wid, void *sock, ogs_sockaddr_t *addr,
        ogs_pkbuf_t *pkbuf, ogs_s1ap_message_t *pdu)
{
    mme_event_t *e = NULL;
    ogs_worker_t *worker;
    int rv;

    ogs_assert(sock);
    ogs_assert(pkbuf);
    ogs_assert(pdu);

    e = mme_event_new(MME_EVENT_S1AP_MESSAGE);
    ogs_assert(e);
    e->sock = sock;
    e->addr = addr;
    e->pkbuf = pkbuf;
    e->s1ap_message = pdu;
    e->s1ap_rx_decoded = true;

    worker = mme_worker_by_id(wid);
    rv = worker ? ogs_worker_post(worker, e) : OGS_ERROR;
    if (rv != OGS_OK) {
        /* shard queue full / gone: legacy path via main, never block */
        if (!stagec_bounce_to_main(e))
            mme_event_free(e);
    }
}

bool s1ap_shard_handle(mme_event_t *e)
{
    ogs_s1ap_message_t *pdu = NULL;
    uint32_t mme_ue_s1ap_id = 0;
    enb_ue_t *enb_ue = NULL;
    mme_enb_t *enb = NULL;

    S1AP_InitiatingMessage_t *im = NULL;
    S1AP_SuccessfulOutcome_t *so = NULL;

    ogs_assert(e);
    pdu = e->s1ap_message;
    ogs_assert(pdu);
    ogs_assert(e->s1ap_rx_decoded);

    /*
     * Resolve the owner-side context. All finds take mme_ctx_lock
     * internally (pool-id / hash lookups); the returned pointers follow
     * the same lifetime rules as every other shard-side S1AP tail
     * (HO_TAIL, EMM handlers): main frees eNB/enb_ue only under the
     * ctx lock, and stale ids resolve to NULL.
     */
    if (!stagec_extract_mme_ue_id(pdu, &mme_ue_s1ap_id)) {
        /* should be impossible: RX classified this PDU */
        ogs_error("stage-c: unclassifiable PDU on shard — to main");
        return !stagec_bounce_to_main(e);
    }

    enb_ue = enb_ue_find_by_mme_ue_s1ap_id(mme_ue_s1ap_id);
    if (enb_ue)
        enb = mme_enb_find_by_id(enb_ue->enb_id);

    if (!enb_ue || !enb ||
            enb->sctp.sock != e->sock ||
            !__atomic_load_n(&enb->state.s1_setup_success,
                    __ATOMIC_ACQUIRE)) {
        /*
         * Unknown/stale UE id, eNB torn down or replaced by a fast
         * reconnect, or a PDU racing S1 Setup: main handles these with
         * its addr-based lookup exactly as before Stage C.
         */
        return !stagec_bounce_to_main(e);
    }

    e->enb_id = enb->id;

    switch (pdu->present) {
    case S1AP_S1AP_PDU_PR_initiatingMessage:
        im = pdu->choice.initiatingMessage;
        ogs_assert(im);
        switch (im->procedureCode) {
        case S1AP_ProcedureCode_id_uplinkNASTransport:
            s1ap_handle_uplink_nas_transport(enb, pdu);
            break;
        case S1AP_ProcedureCode_id_UECapabilityInfoIndication:
            s1ap_handle_ue_capability_info_indication(enb, pdu);
            break;
        default:
            ogs_error("stage-c: unexpected initiating proc %d",
                    (int)im->procedureCode);
            break;
        }
        break;
    case S1AP_S1AP_PDU_PR_successfulOutcome:
        so = pdu->choice.successfulOutcome;
        ogs_assert(so);
        switch (so->procedureCode) {
        case S1AP_ProcedureCode_id_InitialContextSetup:
            s1ap_handle_initial_context_setup_response(enb, pdu);
            break;
        case S1AP_ProcedureCode_id_UEContextModification:
            s1ap_handle_ue_context_modification_response(enb, pdu);
            break;
        case S1AP_ProcedureCode_id_E_RABSetup:
            s1ap_handle_e_rab_setup_response(enb, pdu);
            break;
        default:
            ogs_error("stage-c: unexpected successful proc %d",
                    (int)so->procedureCode);
            break;
        }
        break;
    default:
        ogs_error("stage-c: unexpected PDU present %d", pdu->present);
        break;
    }

    stagec_event_cleanup(e);
    return true;
}
