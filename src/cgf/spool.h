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
typedef struct cgf_spool_file_s {
    char *path;
    uint8_t *data;
    size_t data_len;
    size_t next_record_offset;
    size_t send_offset;

    size_t pending_batch_start;
    uint32_t pending_batch_records;
} cgf_spool_file_t;

cgf_spool_file_t *cgf_spool_get_active(void);
void cgf_spool_refill(void);

uint32_t cgf_spool_stage_batch(cgf_spool_file_t *file,
        uint8_t *out, size_t out_cap, size_t *out_used,
        uint32_t max_records, size_t max_bytes);

/* Advance send_offset past the batch just transmitted. */
void cgf_spool_commit_send(cgf_spool_file_t *file,
        size_t batch_start, uint32_t records);

void cgf_spool_ack_batch(cgf_spool_file_t *file,
        size_t batch_start, uint32_t records);

void cgf_spool_nack_batch(cgf_spool_file_t *file);

void cgf_spool_quarantine(cgf_spool_file_t *file);
void cgf_spool_close(void);

#ifdef __cplusplus
}
#endif

#endif /* CGF_SPOOL_H */
