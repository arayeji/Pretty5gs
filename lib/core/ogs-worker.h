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

#if !defined(OGS_CORE_INSIDE) && !defined(OGS_CORE_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_WORKER_H
#define OGS_WORKER_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SMP worker runtime: a worker is one shard of an NF — its own thread
 * running the canonical Open5GS event loop (pollset poll -> timer expire
 * -> event-queue drain) over its own pollset, timer manager and queue.
 *
 * Share-nothing rule: state owned by a worker is touched only on that
 * worker's thread; everything crosses between threads as queued events
 * (ogs_worker_post). Protocol IDs allocated by a worker embed its id in
 * the top OGS_WORKER_ID_BITS so arriving messages route without lookups.
 */

#define OGS_MAX_WORKERS      8
#define OGS_WORKER_ID_BITS   3

typedef struct ogs_worker_s ogs_worker_t;

typedef void (*ogs_worker_dispatch_f)(ogs_worker_t *worker, void *event);
typedef void (*ogs_worker_hook_f)(ogs_worker_t *worker);

typedef struct ogs_worker_s {
    int id;

    ogs_thread_t *thread;
    ogs_pollset_t *pollset;
    ogs_timer_mgr_t *timer_mgr;
    ogs_queue_t *queue;

    ogs_worker_dispatch_f dispatch;
    ogs_worker_hook_f thread_init;  /* runs on worker thread before loop */
    ogs_worker_hook_f thread_fini;  /* runs on worker thread after loop */

    void *data;                     /* NF-private shard state */
} ogs_worker_t;

ogs_worker_t *ogs_worker_create(int id,
        unsigned int event_capacity, unsigned int timer_capacity,
        unsigned int poll_capacity,
        ogs_worker_dispatch_f dispatch, void *data);
void ogs_worker_hooks(ogs_worker_t *worker,
        ogs_worker_hook_f thread_init, ogs_worker_hook_f thread_fini);
void ogs_worker_start(ogs_worker_t *worker);
void ogs_worker_destroy(ogs_worker_t *worker);

/* Push an event to a worker and wake its pollset. OGS_OK on success. */
int ogs_worker_post(ogs_worker_t *worker, void *event);

/* Worker the calling thread belongs to, or NULL on the main/IO thread. */
ogs_worker_t *ogs_worker_self(void);

/* True once any worker exists in this process. Workers must be created
 * on the main thread before they are started, so this needs no locking. */
bool ogs_worker_active(void);

/* Shard id of the calling thread, or 0 when on the main thread
 * (single-threaded NFs therefore behave exactly as before). */
int ogs_worker_self_id(void);

/* Timer manager of the calling worker, or `fallback` on the main thread.
 * Shared libraries (gtp/pfcp xact) use this so the same code runs
 * single- and multi-threaded. */
ogs_timer_mgr_t *ogs_worker_timer_mgr(ogs_timer_mgr_t *fallback);

/* Embed/extract worker id in a protocol id space of `bits` total bits. */
#define ogs_worker_shard_encode(id, seq, bits) \
    ((((uint32_t)(id)) << ((bits) - OGS_WORKER_ID_BITS)) | \
     ((seq) & ((1u << ((bits) - OGS_WORKER_ID_BITS)) - 1)))
#define ogs_worker_shard_decode(value, bits) \
    (((uint32_t)(value) >> ((bits) - OGS_WORKER_ID_BITS)) & \
     ((1u << OGS_WORKER_ID_BITS) - 1))

#ifdef __cplusplus
}
#endif

#endif /* OGS_WORKER_H */
