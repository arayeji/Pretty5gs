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

#ifndef CGF_SPOOL_H
#define CGF_SPOOL_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * One entry per file currently being drained. We slurp the file into
 * `data` on open and track two cursors:
 *   next_record_offset — last byte confirmed by the CGF (ACK cursor)
 *   send_offset        — next byte to pack into a pipelined batch
 */
typedef struct {
    size_t batch_start;
    uint32_t records;
} cgf_spool_pending_ack_t;

typedef struct cgf_spool_file_s {
    char *path;
    uint8_t *data;
    size_t data_len;
    size_t next_record_offset;
    size_t send_offset;

    size_t pending_batch_start;
    uint32_t pending_batch_records;
    uint32_t inflight_batches;  /* DTRRs sent, not yet ACKed/NAKed */

    /* Out-of-order DTRR acks buffered until the confirmed cursor catches up. */
    cgf_spool_pending_ack_t pending_acks[CGF_MAX_INFLIGHT];
    uint32_t num_pending_acks;

    /*
     * After uncertain delivery (timeout / failover / peer restart), the
     * next DTRR(s) for this file use Packet Transfer Command = Send
     * possibly duplicated (TS 32.295 §6.2.4.5.2). Cleared once the
     * unacked range has been re-accepted and no batches remain in flight.
     */
    bool send_possibly_dup;
} cgf_spool_file_t;

cgf_spool_file_t *cgf_spool_get_active(void);
void cgf_spool_refill(void);

/*
 * Slurp + validate + return a spool file WITHOUT touching the
 * single-threaded `g_active` slot. Used by drain workers, which own
 * their own `cgf_spool_file_t *active` pointer instead. On a bad
 * header the file is quarantined into failed/ (same as the internal
 * open path) and NULL is returned.
 */
cgf_spool_file_t *cgf_spool_open_path(const char *path);

/* Free an in-memory file handle WITHOUT touching the file on disk or
 * `g_active`. Used by a drain worker that is shutting down while
 * still holding an active file — the on-disk copy stays under
 * processing/<id>/ and is reclaimed into ready/ on next startup. */
void cgf_spool_release(cgf_spool_file_t *file);

/* One-time init for the claim-file mutex. Call once on the main
 * thread before any worker starts. */
void cgf_spool_claim_init(void);

/*
 * Atomically claim one ready/ *.cdr file for `worker_id` by renaming it
 * into processing/<worker_id>/. Serialized by an internal mutex so
 * concurrent workers never race the same directory scan. Returns
 * OGS_OK and fills `out_path` with the new (processing/) path, or
 * OGS_ERROR if ready/ has nothing claimable right now.
 */
int cgf_spool_claim_for_worker(int worker_id, char *out_path, size_t cap);

uint32_t cgf_spool_stage_batch(cgf_spool_file_t *file,
        uint8_t *out, size_t out_cap, size_t *out_used,
        uint32_t max_records, size_t max_bytes);

/* Advance send_offset past the batch just transmitted. */
void cgf_spool_commit_send(cgf_spool_file_t *file,
        size_t batch_start, uint32_t records);

/* Apply a DTRR ack (in-order, out-of-order, or duplicate). Returns false
 * only when the pending-ack buffer is full (caller should abort pipeline). */
bool cgf_spool_ack_batch(cgf_spool_file_t *file,
        size_t batch_start, uint32_t records);

/*
 * Same as cgf_spool_ack_batch(), but also reports whether the ack
 * caused the file to be fully delivered and freed. Callers that hold
 * a persistent pointer to `file` beyond this call (drain workers —
 * `worker->active`) MUST use this variant and clear their pointer
 * when `*out_freed` comes back true, or they will dereference freed
 * memory on the next drain attempt. `out_freed` may be NULL.
 */
bool cgf_spool_ack_batch_ex(cgf_spool_file_t *file,
        size_t batch_start, uint32_t records, bool *out_freed);

void cgf_spool_nack_batch(cgf_spool_file_t *file);

/* Mark subsequent sends as Possibly-Duplicated (uncertain prior delivery). */
void cgf_spool_mark_possibly_dup(cgf_spool_file_t *file);

void cgf_spool_quarantine(cgf_spool_file_t *file);
void cgf_spool_close(void);

#ifdef __cplusplus
}
#endif

#endif /* CGF_SPOOL_H */
