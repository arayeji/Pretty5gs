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

#include <stdlib.h>

#include "s1ap-free.h"

/*
 * Job and worker use plain calloc/free so posting does not re-enter the
 * global ogs_talloc_* mutex that this offload is meant to relieve.
 */
typedef struct s1ap_free_job_s {
    ogs_s1ap_message_t *pdu;
    ogs_pkbuf_t *pkbuf;
} s1ap_free_job_t;

static ogs_worker_t *free_worker = NULL;

static void free_job_sync(ogs_s1ap_message_t *pdu, ogs_pkbuf_t *pkbuf)
{
    if (pdu) {
        ogs_s1ap_free(pdu);
        ogs_free(pdu);
    }
    if (pkbuf)
        ogs_pkbuf_free(pkbuf);
}

static void free_dispatch(ogs_worker_t *worker, void *data)
{
    s1ap_free_job_t *job = data;

    ogs_assert(job);
    free_job_sync(job->pdu, job->pkbuf);
    free(job);
}

int s1ap_free_start(void)
{
    ogs_assert(free_worker == NULL);

    /*
     * Large queue: under attach storms main can post one free per
     * non–Stage-C PDU per cycle; dropping would leak ASN.1. Prefer
     * depth over sync fallback (which would put the work back on main).
     */
    free_worker = ogs_worker_create(0, 16384, 8, 8, free_dispatch, NULL);
    ogs_assert(free_worker);
    ogs_worker_set_name(free_worker, "s1ap-free");
    ogs_worker_start(free_worker);

    ogs_info("S1AP deferred-free thread started");
    return OGS_OK;
}

void s1ap_free_stop(void)
{
    if (!free_worker)
        return;

    /* joins; any leftover jobs are a one-time shutdown leak */
    ogs_worker_destroy(free_worker);
    free_worker = NULL;
}

bool s1ap_free_active(void)
{
    return free_worker != NULL;
}

void s1ap_free_defer(ogs_s1ap_message_t *pdu, ogs_pkbuf_t *pkbuf)
{
    s1ap_free_job_t *job = NULL;
    int rv;

    if (!pdu && !pkbuf)
        return;

    if (!free_worker) {
        free_job_sync(pdu, pkbuf);
        return;
    }

    job = calloc(1, sizeof(*job));
    if (!job) {
        ogs_error("s1ap-free: job alloc failed; freeing inline");
        free_job_sync(pdu, pkbuf);
        return;
    }

    job->pdu = pdu;
    job->pkbuf = pkbuf;

    rv = ogs_worker_post(free_worker, job);
    if (rv != OGS_OK) {
        ogs_error("s1ap-free: queue full; freeing inline");
        free_job_sync(pdu, pkbuf);
        free(job);
    }
}
