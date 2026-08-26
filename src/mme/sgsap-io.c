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

#include "sgsap-io.h"
#include "sgsap-path.h"

/* Brief backoff when the VLR SCTP send buffer is full (EAGAIN). */
#define SGSAP_IO_EAGAIN_RETRIES     64
#define SGSAP_IO_EAGAIN_SLEEP_US    1000

/*
 * TX stall watchdog: if every send has EAGAINed for this long (peer
 * stopped ACKing - zero receive window / half-dead association - while
 * SCTP heartbeats keep it nominally up), ask main to reset the
 * association. Seen live: VLR wedged for 90+ minutes, 347k PDUs
 * dropped, only an MME restart recovered.
 */
#define SGSAP_IO_TX_STALL_RESET     ogs_time_from_sec(15)

typedef struct io_job_s {
    mme_vlr_t *vlr;
    ogs_pkbuf_t *pkbuf;
    uint16_t stream_no;
    uint16_t retries;
} io_job_t;

static ogs_worker_t *io_worker = NULL;

static void io_dispatch(ogs_worker_t *worker, void *data)
{
    io_job_t *job = data;
    mme_vlr_t *vlr = NULL;
    bool found = false;
    int rv = OGS_ERROR;
    ogs_sock_t *stall_sock = NULL;
    ogs_time_t stalled_for = 0;

    ogs_assert(job);
    ogs_assert(job->pkbuf);

    /*
     * Validate the VLR is still configured (SIGHUP reload may
     * mme_vlr_remove() it) and send while holding the ctx lock:
     * mme_vlr_close() destroys vlr->sock under the same lock, so the
     * socket cannot be freed mid-sendmsg. vlr_list has at most a
     * handful of entries.
     */
    mme_ctx_lock();
    ogs_list_for_each(&mme_self()->vlr_list, vlr) {
        if (vlr == job->vlr) {
            found = true;
            break;
        }
    }

    if (found) {
        /* OK/ERROR consume pkbuf; RETRY leaves ownership with us. */
        rv = sgsap_send(job->vlr->sock, job->pkbuf, job->stream_no);

        /* TX stall watchdog (fields guarded by the ctx lock held here) */
        if (rv == OGS_OK) {
            vlr->tx_stall_since = 0;
            vlr->tx_stall_posted = false;
        } else if (rv == OGS_RETRY && vlr->sock) {
            ogs_time_t now = ogs_time_now();

            if (!vlr->tx_stall_since) {
                vlr->tx_stall_since = now;
            } else if (!vlr->tx_stall_posted &&
                    (now - vlr->tx_stall_since) >= SGSAP_IO_TX_STALL_RESET) {
                vlr->tx_stall_posted = true;
                stall_sock = vlr->sock;
                stalled_for = now - vlr->tx_stall_since;
            }
        }
    } else {
        ogs_warn("sgsap-io: VLR removed; dropping PDU (len:%d stream:%d)",
                job->pkbuf->len, job->stream_no);
        ogs_pkbuf_free(job->pkbuf);
        job->pkbuf = NULL;
        rv = OGS_ERROR;
    }
    mme_ctx_unlock();

    if (stall_sock) {
        ogs_error("sgsap-io: VLR TX stalled for %d s (SCTP send buffer "
                "full, zero progress); requesting association reset",
                (int)ogs_time_sec(stalled_for));
        sgsap_event_push(MME_EVENT_SGSAP_TX_STALL,
                stall_sock, NULL, NULL, 0, 0);
    }

    if (rv == OGS_RETRY) {
        job->retries++;
        if (job->retries <= SGSAP_IO_EAGAIN_RETRIES && io_worker) {
            ogs_usleep(SGSAP_IO_EAGAIN_SLEEP_US);
            if (ogs_worker_post(io_worker, job) == OGS_OK)
                return; /* job stays alive */
        }
        if (ogs_log_guard())
            ogs_warn("sgsap-io: EAGAIN retries exhausted; drop PDU "
                    "(len:%d stream:%d retries:%u)",
                    job->pkbuf ? (int)job->pkbuf->len : 0,
                    job->stream_no, job->retries);
        if (job->pkbuf)
            ogs_pkbuf_free(job->pkbuf);
        ogs_free(job);
        return;
    }

    ogs_free(job);
}

static void io_thread_init(ogs_worker_t *worker)
{
    /* private pkbuf pool (frees of foreign pkbufs route via pkbuf->pool,
     * but keep helper threads uniform with s1ap-io) */
    mme_pkbuf_thread_pool_attach();
}

int sgsap_io_start(void)
{
    ogs_assert(io_worker == NULL);

    /*
     * Queue sized for SGs signaling (per-call / per-SMS rates): 8192
     * jobs is orders of magnitude above any realistic in-flight count.
     * No sockets/timers live on this worker - minimal capacities.
     */
    io_worker = ogs_worker_create(0, 8192, 8, 8, io_dispatch, NULL);
    ogs_assert(io_worker);
    ogs_worker_hooks(io_worker, io_thread_init, NULL);
    ogs_worker_set_name(io_worker, "sgsap-io");
    ogs_worker_start(io_worker);

    ogs_info("SGsAP TX IO thread started");
    return OGS_OK;
}

void sgsap_io_stop(void)
{
    if (!io_worker)
        return;

    /* joins; jobs still queued at shutdown are a one-time leak,
     * same accepted trade-off as s1ap-io */
    ogs_worker_destroy(io_worker);
    io_worker = NULL;
}

bool sgsap_io_active(void)
{
    return io_worker != NULL;
}

unsigned int sgsap_io_queue_depth(void)
{
    return io_worker ? ogs_queue_size(io_worker->queue) : 0;
}

int sgsap_io_post_send(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf,
        uint16_t stream_no)
{
    io_job_t *job = NULL;
    int rv;

    ogs_assert(vlr);
    ogs_assert(pkbuf);

    if (!io_worker) {
        ogs_error("sgsap-io: IO worker not running; drop PDU (len:%d)",
                pkbuf->len);
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    job = ogs_calloc(1, sizeof(*job));
    if (!job) {
        ogs_error("sgsap-io: job alloc failed; drop PDU (len:%d)",
                pkbuf->len);
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    job->vlr = vlr;
    job->pkbuf = pkbuf;
    job->stream_no = stream_no;
    job->retries = 0;

    rv = ogs_worker_post(io_worker, job);
    if (rv != OGS_OK) {
        /* Queue full: DROP, never inline-send from this (shard) thread -
         * SGs recovers via its own timers (Ts6-1 etc.) */
        ogs_error("sgsap-io: queue full; drop PDU (len:%d stream:%d)",
                pkbuf->len, stream_no);
        ogs_pkbuf_free(pkbuf);
        ogs_free(job);
        return OGS_ERROR;
    }

    return OGS_OK;
}
