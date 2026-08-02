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

#include "ogs-sctp.h"
#include "ogs-s1ap.h"

#include "mme-context.h"
#include "mme-event.h"
#include "s1ap-path.h"
#include "s1ap-tx.h"
#include "s1ap-io.h"

static ogs_worker_t *tx_workers[OGS_MAX_WORKERS];
static int tx_worker_count = 0;

typedef struct tx_job_s {
    ogs_pool_id_t   enb_id;          /* mme_enb_t pool id (main resolves) */
    uint32_t        mme_ue_s1ap_id;  /* snapshot */
    uint32_t        enb_ue_s1ap_id;  /* snapshot */
    uint16_t        stream_no;       /* snapshot of enb_ue->enb_ostream_id */
    ogs_pkbuf_t     *emmbuf;         /* secured NAS PDU (ownership: job) */
} tx_job_t;

/*
 * Worker-side DownlinkNASTransport build from an ID snapshot. This is
 * s1ap_build_downlink_nas_transport() minus any context access: the two
 * S1AP ids and the NAS bytes are all the PDU contains.
 */
static ogs_pkbuf_t *tx_build_dlnas(
        uint32_t mme_ue_s1ap_id, uint32_t enb_ue_s1ap_id,
        ogs_pkbuf_t *emmbuf)
{
    S1AP_S1AP_PDU_t pdu;
    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_DownlinkNASTransport_t *DownlinkNASTransport = NULL;

    S1AP_DownlinkNASTransport_IEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_NAS_PDU_t *NAS_PDU = NULL;

    ogs_assert(emmbuf);

    memset(&pdu, 0, sizeof (S1AP_S1AP_PDU_t));
    pdu.present = S1AP_S1AP_PDU_PR_initiatingMessage;
    pdu.choice.initiatingMessage = CALLOC(1, sizeof(S1AP_InitiatingMessage_t));

    initiatingMessage = pdu.choice.initiatingMessage;
    initiatingMessage->procedureCode =
        S1AP_ProcedureCode_id_downlinkNASTransport;
    initiatingMessage->criticality = S1AP_Criticality_ignore;
    initiatingMessage->value.present =
        S1AP_InitiatingMessage__value_PR_DownlinkNASTransport;

    DownlinkNASTransport =
        &initiatingMessage->value.choice.DownlinkNASTransport;

    ie = CALLOC(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
    ASN_SEQUENCE_ADD(&DownlinkNASTransport->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID;

    MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;

    ie = CALLOC(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
    ASN_SEQUENCE_ADD(&DownlinkNASTransport->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID;

    ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;

    ie = CALLOC(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
    ASN_SEQUENCE_ADD(&DownlinkNASTransport->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_NAS_PDU;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_NAS_PDU;

    NAS_PDU = &ie->value.choice.NAS_PDU;

    *MME_UE_S1AP_ID = mme_ue_s1ap_id;
    *ENB_UE_S1AP_ID = enb_ue_s1ap_id;

    NAS_PDU->size = emmbuf->len;
    NAS_PDU->buf = CALLOC(NAS_PDU->size, sizeof(uint8_t));
    memcpy(NAS_PDU->buf, emmbuf->data, NAS_PDU->size);
    ogs_pkbuf_free(emmbuf);

    return ogs_s1ap_encode(&pdu);
}

/* Post TX_READY back to main. MUST always run for every job (even on
 * encode failure, with pkbuf NULL) or the eNB's pending counter leaks
 * and its hold list wedges. Blocking push: stalling a TX worker under
 * extreme main-queue pressure is acceptable; losing the decrement is
 * not. */
static void tx_post_ready(
        ogs_pool_id_t enb_id, ogs_pkbuf_t *pkbuf, uint16_t stream_no)
{
    mme_event_t *e = NULL;
    int rv;
    int tries = 0;

    e = mme_event_new(MME_EVENT_S1AP_TX_READY);
    ogs_assert(e);
    e->enb_id = enb_id;
    e->pkbuf = pkbuf;
    e->tx_stream_no = stream_no;

    for (;;) {
        rv = mme_queue_push_main(e);
        if (rv == OGS_OK)
            return;

        /* Shutdown: queue will never accept again. */
        if (rv == OGS_DONE)
            break;

        /*
         * OGS_ERROR used to be treated as fatal here (and the comment
         * claimed "shutdown"), which dropped TX_READY, leaked
         * s1ap_tx_pending, and wedged that eNB's hold list — so Attach /
         * Auth / SMC after a Service-Reject storm never left the MME.
         * Retry until the main queue accepts us.
         */
        /*
         * Every 50 tries (5 ms) x 8 TX workers was ~1,600 flushed log
         * lines/sec, precisely while the main queue was already full -
         * logging that amplifies the congestion it reports. Every 5000
         * tries = one line per worker per 0.5 s.
         */
        if (++tries == 1 || (tries % 5000) == 0)
            ogs_error("s1ap-tx: main queue full:%d — retrying (try %d)",
                    (int)rv, tries);
        ogs_usleep(100);
    }

    if (pkbuf)
        ogs_pkbuf_free(pkbuf);
    mme_event_free(e);

    /* Best-effort pending repair on shutdown only (main is stopping). */
    {
        mme_enb_t *enb = mme_enb_find_by_id(enb_id);
        if (enb &&
            __atomic_load_n(&enb->s1ap_tx_pending, __ATOMIC_ACQUIRE) > 0)
            __atomic_sub_fetch(&enb->s1ap_tx_pending, 1, __ATOMIC_ACQ_REL);
    }
}

static void tx_dispatch(ogs_worker_t *worker, void *data)
{
    tx_job_t *job = data;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(job);
    ogs_assert(job->emmbuf);

    s1apbuf = tx_build_dlnas(
            job->mme_ue_s1ap_id, job->enb_ue_s1ap_id, job->emmbuf);
    if (!s1apbuf)
        ogs_error("s1ap-tx: DownlinkNASTransport encode failed "
                "(MME_UE_S1AP_ID[%u])", job->mme_ue_s1ap_id);

    /* NULL s1apbuf still posts: main must decrement pending */
    tx_post_ready(job->enb_id, s1apbuf, job->stream_no);

    ogs_free(job);
}

static void tx_thread_init(ogs_worker_t *worker)
{
    /* DLNAS encode allocates the S1AP PDU pkbuf on this thread */
    mme_pkbuf_thread_pool_attach();
}

int s1ap_tx_workers_start(int count)
{
    int i;

    ogs_assert(count > 0 && count <= OGS_MAX_WORKERS - 1);
    ogs_assert(tx_worker_count == 0);

    for (i = 0; i < count; i++) {
        /* Encode jobs are drained continuously; cap the queue instead
         * of sizing it to pool.event (millions of 8B slots). On full,
         * s1ap_tx_post_dlnas falls back to the sync path. */
        tx_workers[i] = ogs_worker_create(i,
                ogs_min(ogs_app()->pool.event, 262144),
                64, 64, tx_dispatch, NULL);
        ogs_assert(tx_workers[i]);
        ogs_worker_hooks(tx_workers[i], tx_thread_init, NULL);
        {
            char tname[16];
            ogs_snprintf(tname, sizeof(tname), "s1ap-tx%d", i);
            ogs_worker_set_name(tx_workers[i], tname);
        }
        ogs_worker_start(tx_workers[i]);
    }

    tx_worker_count = count;
    ogs_info("S1AP TX encode offload: %d worker(s)", count);

    return OGS_OK;
}

void s1ap_tx_workers_stop(void)
{
    int i;

    for (i = 0; i < tx_worker_count; i++) {
        ogs_worker_destroy(tx_workers[i]);
        tx_workers[i] = NULL;
    }
    tx_worker_count = 0;
}

bool s1ap_tx_active(void)
{
    return tx_worker_count > 0;
}

int s1ap_tx_worker_count(void)
{
    return tx_worker_count;
}

/* diagnostic (torn read acceptable): depth of one TX worker's job queue */
unsigned int s1ap_tx_queue_depth(int idx)
{
    if (idx < 0 || idx >= tx_worker_count || !tx_workers[idx])
        return 0;
    return ogs_queue_size(tx_workers[idx]->queue);
}

int s1ap_tx_post_dlnas(enb_ue_t *enb_ue, ogs_pkbuf_t *emmbuf)
{
    tx_job_t *job = NULL;
    mme_enb_t *enb = NULL;
    int rv;

    ogs_assert(enb_ue);
    ogs_assert(emmbuf);
    ogs_assert(tx_worker_count > 0);

    enb = mme_enb_find_by_id(enb_ue->enb_id);
    if (!enb)
        return OGS_NOTFOUND;   /* caller's sync path logs and frees */

    job = ogs_calloc(1, sizeof(*job));
    if (!job)
        return OGS_ERROR;

    job->enb_id = enb->id;
    job->mme_ue_s1ap_id = enb_ue->mme_ue_s1ap_id;
    job->enb_ue_s1ap_id = enb_ue->enb_ue_s1ap_id;
    job->stream_no = enb_ue->enb_ostream_id;
    job->emmbuf = emmbuf;

    /*
     * Count BEFORE posting. The increment used to sit after the post,
     * which left a window where the TX worker encoded the job and main
     * processed its TX_READY (guarded decrement: pending==0, skipped)
     * before the increment landed — pending then stuck at +1 FOREVER.
     * From that moment every synchronous S1AP message to this eNB
     * (InitialContextSetup/Attach Accept, UE Context Release, paging)
     * parked on s1ap_tx_hold "until pending reaches 0", i.e. never:
     * a silently half-dead eNB (uplink fine, downlink black hole)
     * until MME restart. Increment-first closes the window; on post
     * failure nothing was enqueued, so the decrement below exactly
     * undoes it.
     */
    __atomic_add_fetch(&enb->s1ap_tx_pending, 1, __ATOMIC_ACQ_REL);

    /* sticky per eNB: all of one association's jobs share one FIFO.
     * Cast id to unsigned so a corrupt/negative pool id cannot yield a
     * negative subscript and a NULL worker pointer. */
    {
        ogs_worker_t *w =
            tx_workers[(uint32_t)enb->id % (uint32_t)tx_worker_count];
        if (!w) {
            ogs_error("s1ap-tx: worker[%u] missing (count=%d) — sync fallback",
                    (unsigned)((uint32_t)enb->id % (uint32_t)tx_worker_count),
                    tx_worker_count);
            __atomic_sub_fetch(&enb->s1ap_tx_pending, 1, __ATOMIC_ACQ_REL);
            ogs_free(job);
            return OGS_ERROR;
        }
        rv = ogs_worker_post(w, job);
    }
    if (rv != OGS_OK) {
        /* worker queue full / gone: caller falls back to sync build+send.
         * Safe only because nothing was enqueued here; earlier
         * in-flight jobs still hold sync sends back via pending. */
        __atomic_sub_fetch(&enb->s1ap_tx_pending, 1, __ATOMIC_ACQ_REL);
        ogs_free(job);
        return rv;
    }

    return OGS_OK;
}

/* Raw send that BYPASSES the hold logic in s1ap_send_to_enb(): used for
 * pkbufs whose FIFO position is already correct (TX_READY, hold flush).
 * Mirrors the write path of s1ap_send_to_enb(). */
static void tx_send_raw(mme_enb_t *enb, ogs_pkbuf_t *pkbuf)
{
    ogs_assert(enb);
    ogs_assert(pkbuf);

    ogs_assert(enb->sctp.sock);
    if (enb->sctp.sock->fd == INVALID_SOCKET) {
        ogs_error("s1ap-tx: eNB socket already destroyed");
        ogs_pkbuf_free(pkbuf);
        return;
    }

    /* dedicated IO thread owns the write side (mme.s1ap_io_thread) */
    if (s1ap_io_active()) {
        s1ap_io_post_send(enb->sctp.sock, pkbuf, enb->sctp.addr,
                enb->sctp.type != SOCK_STREAM);
        return;
    }

    if (enb->sctp.type == SOCK_STREAM)
        ogs_sctp_write_to_buffer(&enb->sctp, pkbuf);
    else
        ogs_sctp_senddata(enb->sctp.sock, pkbuf, enb->sctp.addr);
}

/*
 * Self-healing watchdog (main thread, called from the orphan sweep).
 *
 * Encode jobs take microseconds; even under a full-queue storm a
 * TX_READY per job comes back within seconds, and every time pending
 * reaches 0 the hold list is flushed. A hold list that stays non-empty
 * for this long means s1ap_tx_pending leaked (a decrement was lost) and
 * this eNB's entire synchronous downlink — Attach Accept via
 * InitialContextSetup, UE Context Release, paging — is silently parked
 * forever while uplink still flows. That wedge used to persist until an
 * MME restart. Force-flush and reset the counter instead: a one-off
 * ordering hiccup on one association beats a permanently dead cell.
 * In-flight jobs' TX_READYs then hit the pending>0 guard and are no-ops.
 */
#define S1AP_TX_HOLD_STALL_USEC     ogs_time_from_sec(15)
/* No TX_READY for this eNB for this long → treat pending as leaked. */
#define S1AP_TX_HOLD_NO_PROGRESS_USEC ogs_time_from_sec(5)

void s1ap_tx_hold_watchdog(void)
{
    mme_enb_t *enb = NULL;
    ogs_time_t now = ogs_time_now();

    if (!s1ap_tx_active())
        return;

    /*
     * Per-eNB progress, not a global TX-worker queue check.
     *
     * The previous "if any TX worker has jobs, skip all eNBs" veto left
     * a leaked s1ap_tx_pending on one cell wedged forever during mass
     * attach — other cells kept the workers busy, so this association's
     * hold list (SMC / Attach Accept / ICS) never flushed. Capture
     * 21:00-21:05 showed Attach Complete collapse to ~22% with CSR
     * still flowing: classic per-eNB downlink black-hole.
     *
     * Force-flush only when THIS eNB's hold is old AND it has had no
     * TX_READY for S1AP_TX_HOLD_NO_PROGRESS_USEC (encode backlog on
     * this association still produces TX_READYs).
     */
    ogs_list_for_each(&mme_self()->enb_list, enb) {
        ogs_list_t flush;
        ogs_pkbuf_t *held = NULL, *next = NULL;
        ogs_time_t since, last_ready;
        int pending, count = 0;

        ogs_list_init(&flush);

        ogs_thread_mutex_lock(&enb->s1ap_tx_hold_lock);
        since = enb->s1ap_tx_hold_since;
        last_ready = enb->s1ap_tx_last_ready;
        if (!since || (now - since) < S1AP_TX_HOLD_STALL_USEC) {
            ogs_thread_mutex_unlock(&enb->s1ap_tx_hold_lock);
            continue;
        }
        /* Genuine per-eNB encode backlog: TX_READYs still arriving. */
        if (last_ready &&
                (now - last_ready) < S1AP_TX_HOLD_NO_PROGRESS_USEC) {
            ogs_thread_mutex_unlock(&enb->s1ap_tx_hold_lock);
            continue;
        }
        pending = __atomic_load_n(&enb->s1ap_tx_pending, __ATOMIC_ACQUIRE);
        ogs_list_for_each_safe(&enb->s1ap_tx_hold, next, held) {
            ogs_list_remove(&enb->s1ap_tx_hold, held);
            ogs_list_add(&flush, held);
            count++;
        }
        enb->s1ap_tx_hold_since = 0;
        __atomic_store_n(&enb->s1ap_tx_pending, 0, __ATOMIC_RELEASE);
        ogs_thread_mutex_unlock(&enb->s1ap_tx_hold_lock);

        ogs_error("s1ap-tx: hold list WEDGED for eNB-id[0x%x] "
                "(pending=%d, %d pkbuf(s) parked for %llds, "
                "no TX_READY for %llds) — forced flush + pending reset",
                enb->enb_id, pending, count,
                (long long)ogs_time_to_sec(now - since),
                last_ready ? (long long)ogs_time_to_sec(now - last_ready)
                           : (long long)ogs_time_to_sec(now - since));

        ogs_list_for_each_safe(&flush, next, held) {
            ogs_list_remove(&flush, held);
            tx_send_raw(enb, held);
        }
    }
}

void s1ap_tx_ready_handle(mme_event_t *e)
{
    mme_enb_t *enb = NULL;

    ogs_assert(e);

    enb = mme_enb_find_by_id(e->enb_id);
    if (!enb) {
        /* eNB torn down while the job was in flight; its hold list was
         * drained by mme_enb_remove() */
        if (e->pkbuf)
            ogs_pkbuf_free(e->pkbuf);
        return;
    }

    if (__atomic_load_n(&enb->s1ap_tx_pending, __ATOMIC_ACQUIRE) > 0)
        __atomic_sub_fetch(&enb->s1ap_tx_pending, 1, __ATOMIC_ACQ_REL);

    enb->s1ap_tx_last_ready = ogs_time_now();

    if (e->pkbuf) {
        ogs_sctp_ppid_in_pkbuf(e->pkbuf) = OGS_SCTP_S1AP_PPID;
        ogs_sctp_stream_no_in_pkbuf(e->pkbuf) = e->tx_stream_no;
        tx_send_raw(enb, e->pkbuf);
    }

    /* once nothing is in flight, release messages that s1ap_send_to_enb
     * held back to preserve per-association order.
     *
     * Detach the whole list under the ctx lock (UE-shard workers park
     * pkbufs on it concurrently — see s1ap_send_to_enb), then send
     * outside the lock so no I/O runs under it. ogs_list_add appends,
     * so moving to a local list preserves order. */
    if (__atomic_load_n(&enb->s1ap_tx_pending, __ATOMIC_ACQUIRE) == 0) {
        ogs_list_t flush;
        ogs_pkbuf_t *held = NULL, *next = NULL;

        ogs_list_init(&flush);

        ogs_thread_mutex_lock(&enb->s1ap_tx_hold_lock);
        if (__atomic_load_n(&enb->s1ap_tx_pending, __ATOMIC_ACQUIRE) == 0) {
            ogs_list_for_each_safe(&enb->s1ap_tx_hold, next, held) {
                ogs_list_remove(&enb->s1ap_tx_hold, held);
                ogs_list_add(&flush, held);
            }
            enb->s1ap_tx_hold_since = 0;
        }
        ogs_thread_mutex_unlock(&enb->s1ap_tx_hold_lock);

        ogs_list_for_each_safe(&flush, next, held) {
            ogs_list_remove(&flush, held);
            tx_send_raw(enb, held);
        }
    }
}
