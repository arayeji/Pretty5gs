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

#ifndef S1AP_IO_H
#define S1AP_IO_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Dedicated S1AP SCTP send (IO) thread — knob `mme.s1ap_io_thread`.
 *
 * A single thread owns every eNB socket's WRITE side: per-socket FIFO,
 * non-blocking sendmsg, POLLOUT on the IO thread's own pollset when the
 * kernel buffer is full. One thread means all sends stay serialized
 * (per-association order is trivially preserved) while `mme_main` no
 * longer spends cycles in sendmsg / sctp_write_callback.
 *
 * Ownership rules (mirrors s1ap-rx.c):
 *  - main posts SEND/DRAIN jobs; it never touches the IO-side queues
 *  - the IO thread never touches mme context (jobs carry the sock
 *    pointer and, for SEQPACKET, a copied destination address)
 *  - socket destroy is deferred until every worker that references the
 *    sock confirms (see the close registry below)
 */

int s1ap_io_start(void);
void s1ap_io_stop(void);
bool s1ap_io_active(void);

/*
 * Queue one encoded S1AP PDU for transmission. ppid/stream_no must
 * already be set in the pkbuf metadata.
 *   peer_addr     — always preferred (EPIPE → CONNREFUSED needs it)
 *   send_with_addr — true for SEQPACKET (pass addr to sendmsg);
 *                    false for connected STREAM
 * Takes ownership of pkbuf (freed on any failure). Returns OGS_OK
 * or OGS_ERROR (job alloc/queue-full drop).
 */
int s1ap_io_post_send(ogs_sock_t *sock, ogs_pkbuf_t *pkbuf,
        const ogs_sockaddr_t *peer_addr, bool send_with_addr);

/*
 * Socket close registry (main thread only).
 *
 * mme_enb_remove() may have both the RX worker (read poll) and the IO
 * thread (write queue) still referencing the socket. It registers the
 * sock with the set of confirmations required; the socket is destroyed
 * on the LAST confirm. A confirm for an unregistered sock is ignored
 * (pointer may already have been reused by accept).
 */
#define S1AP_SOCK_CONFIRM_RX  0x1
#define S1AP_SOCK_CONFIRM_IO  0x2

void s1ap_sock_close_register(ogs_sock_t *sock, int wait_mask);
void s1ap_sock_close_confirm(ogs_sock_t *sock, int which);
bool s1ap_sock_close_pending(ogs_sock_t *sock);
/* Destroy only if no close is already registered (WATCH_FAILED orphan). */
void s1ap_sock_close_orphan(ogs_sock_t *sock);
/* shutdown: reap sockets whose confirmations never arrived (call after
 * ALL worker threads are joined) */
void s1ap_sock_close_final(void);

/*
 * Post a DRAIN for a SOCK_STREAM eNB socket being torn down: the IO
 * thread frees any queued pkbufs, drops its POLLOUT entry and confirms
 * with MME_EVENT_S1AP_IO_DRAINED. Returns true if a drain was posted
 * (caller must include S1AP_SOCK_CONFIRM_IO in the register mask).
 * Never call for SOCK_SEQPACKET (shared server socket).
 */
bool s1ap_io_drain_sock(ogs_sock_t *sock);

#ifdef __cplusplus
}
#endif

#endif /* S1AP_IO_H */
