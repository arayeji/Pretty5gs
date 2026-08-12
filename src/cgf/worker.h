/*
 * Copyright (C) 2026 by Open5GS Contributors
 *
 * This file is part of Open5GS.
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
 * Parallel CDR drain workers (cgf.workers: N, 2..CGF_MAX_WORKERS).
 *
 * When enabled, each worker is a fully independent drain pipeline:
 *   - its own UDP sockets to the configured peers (distinct source
 *     ports => independent GTP' sequence/xact spaces, TS 32.295
 *     §6.1.1 — peers must tolerate multiple associations from the
 *     same CGF-forwarder host),
 *   - its own pollset + timer manager (echo / RTO / spool-poll ticks),
 *   - its own set of active spool files (up to max_active_files),
 *     claimed by atomically renaming out of ready/ into
 *     processing/<worker_id>/ so workers never contend for the same
 *     file. Multiple open files keep the GTP' window full while
 *     earlier files wait for ACKs.
 *
 * `workers: 1` (the default) never touches this file's runtime state —
 * cgf_workers_start()/cgf_gtpp_open() is a straight either/or in
 * init.c, and cgf_workers_enabled() is false so every worker-aware
 * branch elsewhere (cgf-sm.c, gtpp-path.c) falls through to the
 * original single-thread behaviour unchanged.
 */

#ifndef CGF_WORKER_H
#define CGF_WORKER_H

#include "context.h"
#include "spool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cgf_worker_s cgf_worker_t;

/* Start/stop the configured worker pool. No-op (returns OGS_OK / does
 * nothing) when cgf_self()->workers <= 1. Safe to call
 * cgf_workers_stop() even if never started. */
int cgf_workers_start(void);
void cgf_workers_stop(void);

/* True once >1 worker is running. Main-thread code (cgf-sm.c,
 * gtpp-path.c) uses this to skip opening/using its own peer sockets
 * so there is exactly one live GTP' association set per peer. */
bool cgf_workers_enabled(void);

/* The worker owning the calling thread, or NULL on the main thread. */
cgf_worker_t *cgf_worker_self(void);

/* Attempt to drain worker `w`'s open spool files to peers with spare
 * window capacity. cgf-sm.c's cgf_sm_try_drain() delegates here when
 * called on a worker thread. */
void cgf_worker_try_drain(cgf_worker_t *w);

/*
 * cgf_sm_on_dtrr_response() (shared between main and worker threads)
 * calls this right after an ack fully delivers `file`. On a worker
 * thread it removes `file` from the worker's open-file set — required
 * because cgf_spool_ack_batch_ex() may have just freed it. No-op on
 * the main thread (main uses the spool active array, which removes
 * itself inside maybe_finish_file).
 */
void cgf_worker_on_file_gone(cgf_spool_file_t *file);

#ifdef __cplusplus
}
#endif

#endif /* CGF_WORKER_H */
