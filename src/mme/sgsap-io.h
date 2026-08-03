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

#ifndef SGSAP_IO_H
#define SGSAP_IO_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Dedicated SGsAP (VLR) SCTP send thread (mme.sgsap_io_thread, 0/1,
 * default 0, startup-only).
 *
 * Why: with mme.workers > 0 the CSFB/SMS logic runs on the UE owner
 * shards, and every sgsap_send_* used to ogs_sctp_sendmsg() straight
 * onto vlr->sock from that shard thread. Main owns the VLR lifecycle
 * (sgsap-sm.c: mme_vlr_close() + reconnect on CONNREFUSED / Ts6-1),
 * so a shard could write to a socket main was destroying.
 *
 * Design (simplified s1ap-io): ONE worker owns all VLR sends. A job
 * carries the mme_vlr_t pointer, not the socket; the worker re-resolves
 * vlr->sock under mme_ctx_lock() and keeps the lock across the send,
 * while mme_vlr_close() destroys/nulls the socket under the same lock.
 * That serialization replaces the s1ap-io DRAIN handshake:
 *   - VLR gone from vlr_list  -> drop the PDU (validated under lock)
 *   - vlr->sock already NULL  -> sgsap_send() logs "not connected"
 * SGs volume is per-call/per-SMS, so holding the ctx lock across a
 * sendmsg of a few tens of bytes is not a contention concern.
 *
 * Single FIFO queue keeps per-UE SGs message order identical to the
 * old inline path.
 */

int sgsap_io_start(void);
void sgsap_io_stop(void);
bool sgsap_io_active(void);

/* diagnostic (torn read acceptable): depth of the IO command queue */
unsigned int sgsap_io_queue_depth(void);

/*
 * Queue a send on the sgsap-io thread. ALWAYS consumes pkbuf (frees it
 * on queue-full / worker-down instead of falling back to an inline
 * cross-thread send, which is exactly the race this thread removes).
 */
int sgsap_io_post_send(mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf,
        uint16_t stream_no);

#ifdef __cplusplus
}
#endif

#endif /* SGSAP_IO_H */
