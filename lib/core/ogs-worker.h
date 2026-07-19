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

/*
 * Shard-id scheme: shard 0 is RESERVED for the main thread; workers get
 * shard id worker->id + 1 (see ogs_worker_self_id()). Per-shard arrays
 * (xact local/remote lists, xact hashes) are sized OGS_MAX_WORKERS and
 * indexed by shard id, so at most OGS_MAX_WORKERS - 1 workers may exist.
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

    /* startup barrier: ogs_worker_start() returns only after thread_init
     * has completed, so workers can safely take turns parsing the shared
     * app config without extra locking. */
    ogs_thread_mutex_t ready_mutex;
    ogs_thread_cond_t ready_cond;
    bool ready;

    void *data;                     /* NF-private shard state */
} ogs_worker_t;

ogs_worker_t *ogs_worker_create(int id,
        unsigned int event_capacity, unsigned int timer_capacity,
        unsigned int poll_capacity,
        ogs_worker_dispatch_f dispatch, void *data);
void ogs_worker_hooks(ogs_worker_t *worker,
        ogs_worker_hook_f thread_init, ogs_worker_hook_f thread_fini);
void ogs_worker_start(ogs_worker_t *worker);
/*
 * Join the worker thread but keep queue/timer_mgr/pollset alive.
 * Needed when NF contexts still reference the worker's timer manager
 * (UE timers) and must be torn down single-threaded BEFORE the
 * manager memory is freed by ogs_worker_destroy().
 */
void ogs_worker_join(ogs_worker_t *worker);
void ogs_worker_destroy(ogs_worker_t *worker);

/* Non-blocking push + wake. Returns OGS_RETRY if the worker queue is full. */
int ogs_worker_post(ogs_worker_t *worker, void *event);

/* Worker the calling thread belongs to, or NULL on the main/IO thread. */
ogs_worker_t *ogs_worker_self(void);

/* True once any worker exists in this process. Workers must be created
 * on the main thread before they are started, so this needs no locking. */
bool ogs_worker_active(void);

/*
 * Protocol sharding is OPT-IN, separate from worker existence: helper
 * workers (e.g. the MME S1AP RX decode offload) must not change GTP/
 * PFCP xid allocation or TEID/SEID composition. An NF that runs real
 * protocol shard workers calls ogs_worker_shards_enable() once on the
 * main thread BEFORE creating them; only then do the xact layers
 * partition their id spaces and shard composition kicks in.
 */
void ogs_worker_shards_enable(void);
bool ogs_worker_shards_active(void);

/* Shard id of the calling thread: 0 on the main thread (single-threaded
 * NFs therefore behave exactly as before), worker->id + 1 on workers so
 * worker 0 never shares shard slot 0 with the main thread. */
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
