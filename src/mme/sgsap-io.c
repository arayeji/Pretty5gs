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

typedef struct io_job_s {
    mme_vlr_t *vlr;
    ogs_pkbuf_t *pkbuf;
    uint16_t stream_no;
} io_job_t;

static ogs_worker_t *io_worker = NULL;

static void io_dispatch(ogs_worker_t *worker, void *data)
{
    io_job_t *job = data;
    mme_vlr_t *vlr = NULL;
    bool found = false;

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
        /* sgsap_send() consumes the pkbuf and handles sock == NULL */
        sgsap_send(job->vlr->sock, job->pkbuf, job->stream_no);
    } else {
        ogs_warn("sgsap-io: VLR removed; dropping PDU (len:%d stream:%d)",
                job->pkbuf->len, job->stream_no);
        ogs_pkbuf_free(job->pkbuf);
    }
    mme_ctx_unlock();

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
