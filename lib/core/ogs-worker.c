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

#include "ogs-core.h"

static OGS_THREAD_LOCAL ogs_worker_t *worker_self = NULL;
static int worker_count = 0;
static bool worker_shards = false;

static void worker_main(void *data);

ogs_worker_t *ogs_worker_create(int id,
        unsigned int event_capacity, unsigned int timer_capacity,
        unsigned int poll_capacity,
        ogs_worker_dispatch_f dispatch, void *data)
{
    ogs_worker_t *worker = NULL;

    /* shard id = worker->id + 1 must fit the per-shard arrays
     * (sized OGS_MAX_WORKERS) and OGS_WORKER_ID_BITS */
    ogs_assert(id >= 0 && id < OGS_MAX_WORKERS - 1);
    ogs_assert(dispatch);

    worker = ogs_calloc(1, sizeof(*worker));
    ogs_assert(worker);

    worker->id = id;
    worker->dispatch = dispatch;
    worker->data = data;

    worker->pollset = ogs_pollset_create(poll_capacity);
    ogs_assert(worker->pollset);
    worker->timer_mgr = ogs_timer_mgr_create(timer_capacity);
    ogs_assert(worker->timer_mgr);
    worker->queue = ogs_queue_create(event_capacity);
    ogs_assert(worker->queue);

    ogs_thread_mutex_init(&worker->ready_mutex);
    ogs_thread_cond_init(&worker->ready_cond);
    worker->ready = false;

    worker_count++;

    return worker;
}

bool ogs_worker_active(void)
{
    return worker_count > 0;
}

void ogs_worker_shards_enable(void)
{
    /* must be decided before any worker exists (main thread, startup) */
    ogs_assert(worker_count == 0);
    worker_shards = true;
}

bool ogs_worker_shards_active(void)
{
    return worker_shards;
}

void ogs_worker_hooks(ogs_worker_t *worker,
        ogs_worker_hook_f thread_init, ogs_worker_hook_f thread_fini)
{
    ogs_assert(worker);
    ogs_assert(!worker->thread);

    worker->thread_init = thread_init;
    worker->thread_fini = thread_fini;
}

void ogs_worker_start(ogs_worker_t *worker)
{
    ogs_assert(worker);
    ogs_assert(!worker->thread);

    worker->thread = ogs_thread_create(worker_main, worker);
    ogs_assert(worker->thread);

    /* Block until thread_init finished: workers come up one at a time,
     * so per-worker context/config setup needs no locking. */
    ogs_thread_mutex_lock(&worker->ready_mutex);
    while (!worker->ready)
        ogs_thread_cond_wait(&worker->ready_cond, &worker->ready_mutex);
    ogs_thread_mutex_unlock(&worker->ready_mutex);
}

void ogs_worker_destroy(ogs_worker_t *worker)
{
    ogs_assert(worker);

    if (worker->thread) {
        ogs_queue_term(worker->queue);
        ogs_pollset_notify(worker->pollset);
        ogs_thread_destroy(worker->thread);   /* joins */
        worker->thread = NULL;
    }

    ogs_queue_destroy(worker->queue);
    ogs_timer_mgr_destroy(worker->timer_mgr);
    ogs_pollset_destroy(worker->pollset);

    ogs_thread_cond_destroy(&worker->ready_cond);
    ogs_thread_mutex_destroy(&worker->ready_mutex);

    worker_count--;

    ogs_free(worker);
}

int ogs_worker_post(ogs_worker_t *worker, void *event)
{
    int rv;

    ogs_assert(worker);
    ogs_assert(event);

    /*
     * Non-blocking: RX callbacks (GTP/PFCP/S1AP) run on the main poll
     * thread. A blocking push when a shard queue is full freezes that
     * pollset — association replies sit unread in the socket Recv-Q,
     * peers never associate, and the reject storm feeds the same full
     * queues. Callers already treat != OGS_OK as drop/free.
     */
    rv = ogs_queue_trypush(worker->queue, event);
    if (rv != OGS_OK)
        return rv;

    ogs_pollset_notify(worker->pollset);
    return OGS_OK;
}

ogs_worker_t *ogs_worker_self(void)
{
    return worker_self;
}

int ogs_worker_self_id(void)
{
    /*
     * Shard id, NOT worker->id: 0 is reserved for the main thread, so
     * workers map to 1..N. Returning worker->id here made worker 0 and
     * the main thread share shard slot 0 — both mutated the same
     * unlocked xact local_list[0]/remote_list[0]/xact_hash[0] on shared
     * gtp/pfcp nodes and allocated from the same xid partition
     * (observed as SGW-C SEGV/double-free every ~2 min under load).
     */
    return worker_self ? worker_self->id + 1 : 0;
}

ogs_timer_mgr_t *ogs_worker_timer_mgr(ogs_timer_mgr_t *fallback)
{
    return worker_self ? worker_self->timer_mgr : fallback;
}

static void worker_main(void *data)
{
    ogs_worker_t *worker = data;
    int rv;

    ogs_assert(worker);
    worker_self = worker;

    if (worker->thread_init)
        worker->thread_init(worker);

    ogs_thread_mutex_lock(&worker->ready_mutex);
    worker->ready = true;
    ogs_thread_cond_signal(&worker->ready_cond);
    ogs_thread_mutex_unlock(&worker->ready_mutex);

    for ( ;; ) {
        ogs_pollset_poll(worker->pollset,
                ogs_timer_mgr_next(worker->timer_mgr));

        /* Same ordering contract as every NF main loop:
         * expire timers before draining the event queue. */
        ogs_timer_mgr_expire(worker->timer_mgr);

        for ( ;; ) {
            void *event = NULL;

            rv = ogs_queue_trypop(worker->queue, &event);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(event);
            worker->dispatch(worker, event);
        }
    }
done:

    if (worker->thread_fini)
        worker->thread_fini(worker);

    worker_self = NULL;
}
