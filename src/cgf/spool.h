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
 * One entry per file currently being drained. We mmap / slurp the file
 * into `data` on open and keep a cursor `next_record_offset` pointing
 * at the first byte that hasn't been handed to the GTP' layer yet.
 * When the cursor reaches `data_len` and the peer has confirmed the
 * last batch, the file is moved to done/.
 */
typedef struct cgf_spool_file_s {
    char *path;         /* absolute path under <spool>/ready/ */
    uint8_t *data;      /* heap-allocated buffer with file contents */
    size_t data_len;
    size_t next_record_offset; /* next byte to feed into a batch */

    /* For rollback on peer failure: the offset the current in-flight
     * batch started at. On ACK, next_record_offset advances past it;
     * on fatal send error we can rewind to retry elsewhere. */
    size_t pending_batch_start;
    uint32_t pending_batch_records;
} cgf_spool_file_t;

/*
 * Non-blocking scan of the ready/ directory. Up to one file is opened
 * at a time to keep memory usage bounded; callers drain it completely
 * (via cgf_spool_next_batch) before another file is picked up.
 * Returns the active file or NULL if the spool is empty.
 */
cgf_spool_file_t *cgf_spool_get_active(void);

/*
 * Scan the on-disk ready/ directory and, if there's no active file,
 * open the oldest one. Idempotent — safe to call from a timer.
 */
void cgf_spool_refill(void);

/*
 * Produce a concatenated blob of up to `max_records` / `max_bytes`
 * records starting at file->next_record_offset. The caller receives
 * the raw ASN.1 BER bytes ready to go inside an IE 252 value; cursor
 * bookkeeping (pending_batch_*) is updated so a later ACK/NAK knows
 * how far to advance. Returns the number of records staged. 0 means
 * nothing more to send from this file.
 */
uint32_t cgf_spool_stage_batch(cgf_spool_file_t *file,
        uint8_t *out, size_t out_cap, size_t *out_used,
        uint32_t max_records, size_t max_bytes);

/* Mark the in-flight batch as confirmed; advances the cursor and, if
 * the whole file is done, renames it to done/ and frees the struct
 * (the pointer must be considered invalid after this call). */
void cgf_spool_ack_batch(cgf_spool_file_t *file);

/* Mark the batch as failed but leave the file in ready/. The cursor
 * rewinds so the records will be re-attempted on the next peer. */
void cgf_spool_nack_batch(cgf_spool_file_t *file);

/* Quarantine the active file (e.g. corrupted framing, or exceeded
 * max_retries on every peer). Moves it to failed/ and frees. */
void cgf_spool_quarantine(cgf_spool_file_t *file);

void cgf_spool_close(void);

#ifdef __cplusplus
}
#endif

#endif /* CGF_SPOOL_H */
