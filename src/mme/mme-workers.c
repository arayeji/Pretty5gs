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

#include "ogs-gtp.h"

#include "mme-context.h"
#include "mme-event.h"
#include "mme-sm.h"
#include "mme-workers.h"
#include "sgsap-types.h"

static ogs_worker_t *mme_workers[OGS_MAX_WORKERS];
static int mme_worker_count = 0;

static OGS_THREAD_LOCAL ogs_fsm_t worker_fsm;

int mme_workers_count(void)
{
    return mme_worker_count;
}

bool mme_workers_active(void)
{
    return mme_worker_count > 0;
}

ogs_worker_t *mme_worker_by_id(int wid)
{
    if (wid < 0 || wid >= mme_worker_count)
        return NULL;
    return mme_workers[wid];
}

uint32_t mme_shard_compose(uint32_t raw, int shard_id)
{
    if (!ogs_worker_shards_active())
        return raw;

    ogs_assert(shard_id >= 0 && shard_id < OGS_MAX_WORKERS);
    ogs_assert(raw < (1u << (32 - OGS_WORKER_ID_BITS)));

    return ((uint32_t)shard_id << (32 - OGS_WORKER_ID_BITS)) | raw;
}

int mme_shard_from_teid(uint32_t teid)
{
    int shard;

    if (!mme_workers_active())
        return -1;

    shard = (int)((teid >> (32 - OGS_WORKER_ID_BITS)) &
            ((1u << OGS_WORKER_ID_BITS) - 1));
    return shard - 1;
}

int mme_shard_from_ue_s1ap_id(uint32_t mme_ue_s1ap_id)
{
    return mme_shard_from_teid(mme_ue_s1ap_id);
}

int mme_shard_from_imsi_bcd(const char *imsi_bcd)
{
    unsigned h = 5381;
    const char *p;

    ogs_assert(imsi_bcd);
    ogs_assert(mme_worker_count > 0);

    for (p = imsi_bcd; *p; p++)
        h = ((h << 5) + h) + (unsigned char)*p;

    return (int)(h % (unsigned)mme_worker_count);
}

int mme_gtpv2_peek_imsi_bcd(ogs_pkbuf_t *pkbuf, char *bcd, size_t bcd_size)
{
    ogs_gtp2_header_t *h;
    uint8_t *p, *end;
    int hdr_len;

    ogs_assert(pkbuf);
    ogs_assert(bcd);
    ogs_assert(bcd_size > 0);

    bcd[0] = '\0';

    if (pkbuf->len < 8)
        return OGS_ERROR;

    h = (ogs_gtp2_header_t *)pkbuf->data;
    hdr_len = h->teid_presence ? OGS_GTPV2C_HEADER_LEN : 8;
    if (pkbuf->len < (size_t)hdr_len)
        return OGS_ERROR;

    p = (uint8_t *)pkbuf->data + hdr_len;
    end = (uint8_t *)pkbuf->data + pkbuf->len;

    while (p + 4 <= end) {
        uint8_t type = p[0];
        uint16_t len = ((uint16_t)p[1] << 8) | p[2];
        uint8_t instance = p[3] & 0x0f;
        uint8_t *val = p + 4;

        if (val + len > end)
            break;

        if (type == OGS_GTP2_IMSI_TYPE && instance == 0 && len > 0) {
            if (len > OGS_MAX_IMSI_LEN)
                len = OGS_MAX_IMSI_LEN;
            ogs_buffer_to_bcd(val, len, bcd);
            return OGS_OK;
        }

        p = val + len;
    }

    return OGS_ERROR;
}

int mme_shard_from_mme_ue_id(ogs_pool_id_t mme_ue_id)
{
    mme_ue_t *mme_ue;

    if (!mme_workers_active())
        return -1;
    if (mme_ue_id < OGS_MIN_POOL_ID || mme_ue_id > OGS_MAX_POOL_ID)
        return -1;

    mme_ue = mme_ue_find_by_id(mme_ue_id);
    if (!mme_ue)
        return -1;

    return mme_shard_from_teid(mme_ue->mme_s11_teid);
}

int mme_shard_from_enb_ue_id(ogs_pool_id_t enb_ue_id)
{
    enb_ue_t *enb_ue;
    mme_ue_t *mme_ue;

    if (!mme_workers_active())
        return -1;
    if (enb_ue_id < OGS_MIN_POOL_ID || enb_ue_id > OGS_MAX_POOL_ID)
        return -1;

    enb_ue = enb_ue_find_by_id(enb_ue_id);
    if (!enb_ue)
        return -1;

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (mme_ue)
        return mme_shard_from_teid(mme_ue->mme_s11_teid);

    return mme_shard_from_ue_s1ap_id(enb_ue->mme_ue_s1ap_id);
}

ogs_timer_mgr_t *mme_ue_timer_mgr_for_wid(int wid)
{
    ogs_worker_t *w;

    if (!mme_workers_active() || wid < 0)
        return ogs_app()->timer_mgr;

    w = mme_worker_by_id(wid);
    if (!w)
        return ogs_app()->timer_mgr;

    return w->timer_mgr;
}

static void mme_event_discard_payload(mme_event_t *e)
{
    ogs_assert(e);

    if (e->addr) {
        ogs_free(e->addr);
        e->addr = NULL;
    }
    if (e->pkbuf) {
        ogs_pkbuf_free(e->pkbuf);
        e->pkbuf = NULL;
    }
    if (e->s6a_message) {
        ogs_subscription_data_free(
                &e->s6a_message->idr_message.subscription_data);
        ogs_subscription_data_free(
                &e->s6a_message->ula_message.subscription_data);
        ogs_free(e->s6a_message);
        e->s6a_message = NULL;
    }
    /* e->nas_message is typically stack memory in mme-sm — never free */
}

int mme_event_push_to_worker(int wid, mme_event_t *e)
{
    ogs_worker_t *worker;
    int rv;

    ogs_assert(e);

    worker = mme_worker_by_id(wid);
    if (!worker) {
        ogs_error("mme_event_push_to_worker: bad wid %d", wid);
        mme_event_discard_payload(e);
        mme_event_free(e);
        return OGS_ERROR;
    }

    rv = ogs_worker_post(worker, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_worker_post(wid=%d) failed [%d]", wid, rv);
        mme_event_discard_payload(e);
        mme_event_free(e);
    }
    return rv;
}

static int mme_event_resolve_wid(mme_event_t *e)
{
    int wid = -1;

    ogs_assert(e);

    switch (e->id) {
    case MME_EVENT_EMM_MESSAGE:
    case MME_EVENT_EMM_TIMER:
        wid = mme_shard_from_mme_ue_id(e->mme_ue_id);
        if (wid < 0)
            wid = mme_shard_from_enb_ue_id(e->enb_ue_id);
        break;

    case MME_EVENT_ESM_MESSAGE:
    case MME_EVENT_ESM_TIMER:
        if (e->bearer_id >= OGS_MIN_POOL_ID &&
                e->bearer_id <= OGS_MAX_POOL_ID) {
            mme_bearer_t *bearer = mme_bearer_find_by_id(e->bearer_id);
            if (bearer)
                wid = mme_shard_from_mme_ue_id(bearer->mme_ue_id);
        }
        if (wid < 0)
            wid = mme_shard_from_mme_ue_id(e->mme_ue_id);
        if (wid < 0)
            wid = mme_shard_from_enb_ue_id(e->enb_ue_id);
        break;

    case MME_EVENT_S11_MESSAGE:
        if (e->pkbuf && e->pkbuf->len >= 8) {
            ogs_gtp2_header_t *h = (ogs_gtp2_header_t *)e->pkbuf->data;
            /*
             * Replies to OUR requests must reach the thread holding
             * the xact (xid partition carries the creator shard).
             * S1AP-driven sends — Release Access Bearers, Delete
             * Session on S1 release/reset — create their xact on MAIN
             * while the UE TEID names a worker; TEID routing would
             * strand those responses and every such request would
             * retransmit + time out ("GTP timeout ... SGW" storms).
             */
            int reply_shard = ogs_gtp2_rx_reply_shard(
                    e->pkbuf->data, e->pkbuf->len);
            if (reply_shard >= 0 && reply_shard - 1 < mme_worker_count)
                return reply_shard - 1;    /* 0 = main -> wid -1 */

            if (h->teid_presence && h->teid) {
                wid = mme_shard_from_teid(be32toh(h->teid));
            } else {
                char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
                if (mme_gtpv2_peek_imsi_bcd(e->pkbuf, imsi_bcd,
                        sizeof(imsi_bcd)) == OGS_OK)
                    wid = mme_shard_from_imsi_bcd(imsi_bcd);
            }
        }
        if (wid < 0)
            wid = mme_shard_from_mme_ue_id(e->mme_ue_id);
        break;

    case MME_EVENT_S11_TIMER:
        if (e->sgw_ue_id >= OGS_MIN_POOL_ID &&
                e->sgw_ue_id <= OGS_MAX_POOL_ID) {
            sgw_ue_t *sgw_ue = sgw_ue_find_by_id(e->sgw_ue_id);
            if (sgw_ue)
                wid = mme_shard_from_mme_ue_id(sgw_ue->mme_ue_id);
        }
        if (wid < 0)
            wid = mme_shard_from_mme_ue_id(e->mme_ue_id);
        break;

    case MME_EVENT_S6A_MESSAGE:
    case MME_EVENT_S6A_TIMER:
        wid = mme_shard_from_mme_ue_id(e->mme_ue_id);
        if (wid < 0)
            wid = mme_shard_from_enb_ue_id(e->enb_ue_id);
        break;

    case MME_EVENT_ADMIN_DETACH_UE:
    case MME_EVENT_ADMIN_PAGE_UE:
    case MME_EVENT_ADMIN_PURGE_UE:
    case MME_EVENT_S1AP_HO_TAIL:
    case MME_EVENT_GN_TIMER:
        wid = mme_shard_from_mme_ue_id(e->mme_ue_id);
        break;

    case MME_EVENT_GN_MESSAGE:
        /*
         * GTPv1-C header: TEID at octets 4-7. The Gn handlers mutate
         * mme_ue (context transfer, gn xact ids), so TEID-addressed
         * messages must reach the owner. TEID 0 (SGSN Context Request
         * addressed by RAI+P-TMSI) stays on main: the target UE is in
         * its SGSN-resident phase with no concurrent shard activity.
         */
        if (e->pkbuf && e->pkbuf->len >= 8) {
            uint32_t gn_teid;
            memcpy(&gn_teid, (uint8_t *)e->pkbuf->data + 4, 4);
            gn_teid = be32toh(gn_teid);
            if (gn_teid) {
                mme_ue_t *gn_ue = mme_ue_find_by_gn_local_teid(gn_teid);
                if (gn_ue)
                    wid = mme_shard_from_teid(gn_ue->mme_s11_teid);
            }
        }
        break;

    default:
        break;
    }

    if (wid >= mme_worker_count)
        wid = wid % mme_worker_count;

    return wid;
}

int mme_event_push_to_ue_owner(mme_event_t *e)
{
    int wid;
    int rv;

    ogs_assert(e);

    if (!mme_workers_active()) {
        rv = mme_queue_push_main(e);
        if (rv != OGS_OK) {
            ogs_error("event id=%d dropped on main queue:%d",
                    (int)e->id, (int)rv);
            mme_event_discard_payload(e);
            mme_event_free(e);
            return OGS_ERROR;
        }
        return OGS_OK;
    }

    wid = mme_event_resolve_wid(e);
    if (wid < 0) {
        /* Owner not known yet (e.g. first attach before mme_ue): main. */
        rv = mme_queue_push_main(e);
        if (rv != OGS_OK) {
            ogs_error("unowned event id=%d dropped on main queue:%d",
                    (int)e->id, (int)rv);
            mme_event_discard_payload(e);
            mme_event_free(e);
            return OGS_ERROR;
        }
        return OGS_OK;
    }

    return mme_event_push_to_worker(wid, e);
}

/*
 * On failure the CALLER retains ownership of pkbuf: the S1AP handlers
 * fall back to running the HO tail inline (a dropped tail black-holes
 * DL until the next paging cycle — the SGW keeps forwarding to the
 * previous eNB TEID because Modify Bearer is never sent).
 */
int mme_worker_post_ho_tail(int kind, ogs_pool_id_t enb_ue_id,
        mme_ue_t *mme_ue, ogs_pkbuf_t *pkbuf)
{
    int owner, rv;
    ogs_worker_t *worker;
    mme_event_t *e;

    ogs_assert(mme_ue);
    ogs_assert(mme_workers_active());

    owner = mme_shard_from_teid(mme_ue->mme_s11_teid);
    if (owner < 0) {
        ogs_error("mme_worker_post_ho_tail: no owner for mme_ue [%s]",
                mme_ue->imsi_bcd);
        return OGS_ERROR;
    }

    worker = mme_worker_by_id(owner);
    if (!worker) {
        ogs_error("mme_worker_post_ho_tail: bad wid %d", owner);
        return OGS_ERROR;
    }

    e = mme_event_new(MME_EVENT_S1AP_HO_TAIL);
    if (!e) {
        ogs_error("mme_worker_post_ho_tail: mme_event_new() failed");
        return OGS_ERROR;
    }
    e->ho_kind = kind;
    e->enb_ue_id = enb_ue_id;
    e->mme_ue_id = mme_ue->id;
    e->pkbuf = pkbuf;

    rv = ogs_worker_post(worker, e);
    if (rv != OGS_OK) {
        ogs_error("mme_worker_post_ho_tail: ogs_worker_post(wid=%d) "
                "failed [%d]", owner, rv);
        /* not enqueued: we still own e; pkbuf stays with the caller */
        e->pkbuf = NULL;
        mme_event_free(e);
        return OGS_ERROR;
    }
    return OGS_OK;
}

int mme_worker_post_ue_rel_tail(int rel_action, ogs_pool_id_t old_enb_ue_id,
        mme_ue_t *mme_ue, int rel_flags)
{
    int owner;
    mme_event_t *e;

    ogs_assert(mme_ue);
    ogs_assert(mme_workers_active());

    owner = mme_shard_from_teid(mme_ue->mme_s11_teid);
    if (owner < 0) {
        /* Main IS the owner (shard 0): caller runs the tail inline. */
        return OGS_ERROR;
    }

    e = mme_event_new(MME_EVENT_S1AP_HO_TAIL);
    if (!e) {
        ogs_error("mme_worker_post_ue_rel_tail: mme_event_new() failed");
        return OGS_ERROR;
    }
    e->ho_kind = MME_HO_TAIL_UE_REL;
    e->enb_ue_id = old_enb_ue_id;   /* already removed; comparison only */
    e->mme_ue_id = mme_ue->id;
    e->rel_action = rel_action;
    e->rel_flags = rel_flags;

    /* frees e on failure */
    return mme_event_push_to_worker(owner, e);
}

int mme_sgsap_peek_owner(ogs_pkbuf_t *pkbuf)
{
    uint8_t type;
    uint8_t *p, *end;

    if (!mme_workers_active())
        return -1;
    if (!pkbuf || pkbuf->len < 1)
        return -1;

    type = *(uint8_t *)pkbuf->data;
    switch (type) {
    case SGSAP_LOCATION_UPDATE_ACCEPT:
    case SGSAP_LOCATION_UPDATE_REJECT:
    case SGSAP_ALERT_REQUEST:
    case SGSAP_EPS_DETACH_ACK:
    case SGSAP_IMSI_DETACH_ACK:
    case SGSAP_PAGING_REQUEST:
    case SGSAP_DOWNLINK_UNITDATA:
    case SGSAP_RELEASE_REQUEST:
    case SGSAP_MM_INFORMATION_REQUEST:
        break;              /* UE-addressed: route by the IMSI IE */
    default:
        return -1;          /* RESET / STATUS / unknown: main */
    }

    /* SGsAP TLVs: 1-byte tag, 1-byte length (TS 29.118 clause 9) */
    p = (uint8_t *)pkbuf->data + 1;
    end = (uint8_t *)pkbuf->data + pkbuf->len;
    while (p + 2 <= end) {
        uint8_t tag = p[0];
        uint8_t len = p[1];
        uint8_t *val = p + 2;

        if (val + len > end)
            break;

        if (tag == SGSAP_IE_IMSI_TYPE) {
            char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
            mme_ue_t *mme_ue;

            if (len < 4 || len > SGSAP_IE_IMSI_LEN)
                return -1;

            ogs_nas_eps_imsi_to_bcd(
                    (ogs_nas_mobile_identity_imsi_t *)val, len, imsi_bcd);
            mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
            if (!mme_ue)
                return -1;
            return mme_shard_from_teid(mme_ue->mme_s11_teid);
        }

        p = val + len;
    }

    return -1;
}

int mme_worker_post_sgsap(int wid, mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf)
{
    mme_event_t *ne;

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    ne = mme_event_new(MME_EVENT_SGSAP_MESSAGE);
    if (!ne) {
        ogs_error("mme_worker_post_sgsap: mme_event_new() failed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    ne->vlr = vlr;
    ne->pkbuf = pkbuf;

    /* frees ne and pkbuf on failure */
    return mme_event_push_to_worker(wid, ne);
}

int mme_worker_post_rel_ab(int action, ogs_pool_id_t enb_ue_id,
        mme_ue_t *mme_ue)
{
    int owner, self;
    mme_event_t *e;

    ogs_assert(mme_ue);
    ogs_assert(mme_workers_active());

    owner = mme_shard_from_teid(mme_ue->mme_s11_teid);
    /* ogs_worker_self_id(): 0=main, 1..N=shard workers */
    self = ogs_worker_self_id() - 1;
    if (owner < 0 || owner == self)
        return OGS_ERROR;   /* calling thread owns the UE: send inline */

    e = mme_event_new(MME_EVENT_S1AP_HO_TAIL);
    if (!e) {
        ogs_error("mme_worker_post_rel_ab: mme_event_new() failed");
        return OGS_ERROR;
    }
    e->ho_kind = MME_HO_TAIL_REL_AB;
    e->enb_ue_id = enb_ue_id;   /* may already be removed; passthrough */
    e->mme_ue_id = mme_ue->id;
    e->rel_action = action;

    /* frees e on failure */
    return mme_event_push_to_worker(owner, e);
}

bool mme_worker_rehome_emm(mme_event_t *e, mme_ue_t *mme_ue)
{
    int owner, self;
    mme_event_t *ne;

    if (!mme_workers_active() || !e || !mme_ue)
        return false;

    owner = mme_shard_from_teid(mme_ue->mme_s11_teid);
    if (owner < 0)
        return false;

    /* ogs_worker_self_id(): 0=main, 1..N=shard workers */
    self = ogs_worker_self_id() - 1;
    if (self == owner)
        return false;

    ne = mme_event_new(e->id);
    if (!ne) {
        ogs_error("mme_worker_rehome_emm: mme_event_new() failed");
        return false;
    }

    /*
     * Carry every field the destination EMM path needs. Missing
     * s1ap_code broke CSFB Extended Service Request: after rehome the
     * owner saw ProcedureCode 0 ("Invalid Procedure Code") and never
     * sent UEContextModification / InitialContextSetup (csfb
     * mo-idle-test hang with mme.workers).
     */
    ne->enb_ue_id = e->enb_ue_id;
    ne->mme_ue_id = mme_ue->id;
    ne->nas_type = e->nas_type;
    ne->create_action = e->create_action;
    ne->s1ap_code = e->s1ap_code;
    ne->nas_tai = e->nas_tai;
    ne->nas_e_cgi = e->nas_e_cgi;
    ne->nas_location_present = e->nas_location_present;
    ne->pkbuf = e->pkbuf;
    e->pkbuf = NULL;

    ogs_debug("EMM event %d rehomed: shard %d -> owner %d "
            "(mme_ue id %d s1ap_code %ld)",
            e->id, self, owner, mme_ue->id, (long)ne->s1ap_code);

    /* Frees ne (and its pkbuf) on failure; either way we bounced. */
    mme_event_push_to_worker(owner, ne);
    return true;
}

static void mme_worker_thread_init(ogs_worker_t *worker)
{
    int rv;

    ogs_assert(worker);

    mme_pkbuf_thread_pool_attach();

    rv = ogs_gtp_xact_init();
    ogs_assert(rv == OGS_OK);

    ogs_fsm_init(&worker_fsm, mme_state_initial, mme_state_final, 0);

    ogs_info("MME shard worker %d ready", worker->id);
}

static void mme_worker_thread_fini(ogs_worker_t *worker)
{
    ogs_assert(worker);

    ogs_fsm_fini(&worker_fsm, 0);
    ogs_gtp_xact_final();
    ogs_tlv_thread_final();

    ogs_info("MME shard worker %d stopped", worker->id);
}

static bool mme_event_is_ue_scoped(int id)
{
    switch (id) {
    case MME_EVENT_EMM_MESSAGE:
    case MME_EVENT_EMM_TIMER:
    case MME_EVENT_ESM_MESSAGE:
    case MME_EVENT_ESM_TIMER:
    case MME_EVENT_S11_MESSAGE:
    case MME_EVENT_S11_TIMER:
    case MME_EVENT_S6A_MESSAGE:
    case MME_EVENT_S6A_TIMER:
    case MME_EVENT_ADMIN_DETACH_UE:
    case MME_EVENT_ADMIN_PAGE_UE:
    case MME_EVENT_ADMIN_PURGE_UE:
    case MME_EVENT_S1AP_HO_TAIL:
    case MME_EVENT_GN_MESSAGE:
    case MME_EVENT_GN_TIMER:
    case MME_EVENT_SGSAP_MESSAGE:
    case OGS_FSM_ENTRY_SIG:
    case OGS_FSM_EXIT_SIG:
        return true;
    default:
        return false;
    }
}

static void mme_worker_dispatch(ogs_worker_t *worker, void *data)
{
    mme_event_t *e = data;

    ogs_assert(worker);
    ogs_assert(e);

    if (!mme_event_is_ue_scoped(e->id)) {
        ogs_error("MME shard worker %d got non-UE event %d — dropped",
                worker->id, e->id);
        mme_event_discard_payload(e);
        mme_event_free(e);
        return;
    }

    ogs_fsm_dispatch(&worker_fsm, e);
    mme_event_free(e);
}

int mme_workers_start(int count)
{
    int i;

    if (count <= 0)
        return OGS_OK;

    ogs_assert(count <= OGS_MAX_WORKERS - 1);
    ogs_assert(mme_worker_count == 0);
    ogs_assert(!ogs_worker_active());

    /* Opt-in protocol id sharding BEFORE any worker (incl. helpers). */
    ogs_worker_shards_enable();

    for (i = 0; i < count; i++) {
        /* Same rationale as the main app queue cap (ogs-init.c):
         * pool.event-deep queues waste memory and hide overload. */
        mme_workers[i] = ogs_worker_create(i,
                ogs_min(ogs_app()->pool.event, 1024 * 1024),
                ogs_app()->pool.timer,
                64,
                mme_worker_dispatch, NULL);
        ogs_assert(mme_workers[i]);
        ogs_worker_hooks(mme_workers[i],
                mme_worker_thread_init, mme_worker_thread_fini);
        ogs_worker_start(mme_workers[i]);
    }

    mme_worker_count = count;

    ogs_info("MME SMP workers: %d UE shard(s) (Stage A bounce router)",
            mme_worker_count);

    return OGS_OK;
}

void mme_workers_stop(void)
{
    int i;

    /* Join threads only: UE timers still live on the workers' timer
     * managers and are deleted by mme_context_final() on the main
     * thread. mme_workers_final() frees the managers afterwards. */
    for (i = 0; i < mme_worker_count; i++)
        ogs_worker_join(mme_workers[i]);
}

void mme_workers_final(void)
{
    int i;

    for (i = 0; i < mme_worker_count; i++) {
        ogs_worker_destroy(mme_workers[i]);
        mme_workers[i] = NULL;
    }
    mme_worker_count = 0;
}
