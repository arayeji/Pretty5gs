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

static void worker_main(void *data);

ogs_worker_t *ogs_worker_create(int id,
        unsigned int event_capacity, unsigned int timer_capacity,
        unsigned int poll_capacity,
        ogs_worker_dispatch_f dispatch, void *data)
{
    ogs_worker_t *worker = NULL;

    ogs_assert(id >= 0 && id < OGS_MAX_WORKERS);
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

    worker_count++;

    return worker;
}

bool ogs_worker_active(void)
{
    return worker_count > 0;
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

    worker_count--;

    ogs_free(worker);
}

int ogs_worker_post(ogs_worker_t *worker, void *event)
{
    int rv;

    ogs_assert(worker);
    ogs_assert(event);

    rv = ogs_queue_push(worker->queue, event);
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
    return worker_self ? worker_self->id : 0;
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
