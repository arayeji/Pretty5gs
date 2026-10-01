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

#ifndef NGAP_IO_H
#define NGAP_IO_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Dedicated NGAP SCTP send (IO) thread(s): amf.ngap_io_thread = 1..4.
 *
 * IO threads own the gNB sockets' WRITE side: per-socket FIFO,
 * non-blocking sendmsg, POLLOUT on the IO thread's own pollset when the
 * kernel buffer is full. Sockets are sticky per IO thread (pointer
 * hash), so per-association order is preserved. IO threads never touch
 * AMF context: jobs carry the sock pointer and a copied peer address.
 * Socket destroy waits until every thread referencing the sock has
 * confirmed (close registry below).
 */

int ngap_io_start(int count);
void ngap_io_stop(void);
bool ngap_io_active(void);

/*
 * Queue one encoded NGAP PDU. ppid/stream_no must already be set in the
 * pkbuf metadata. send_with_addr is true for SEQPACKET. Takes ownership
 * of pkbuf (freed on any failure). Returns OGS_OK or OGS_ERROR.
 *
 * Hard send errors:
 *  - EPIPE / ECONNRESET: mark send-dead; RX (COMM_LOST) tears down.
 *  - ETIMEDOUT, or a write queue full for ngap_io_stall_teardown_sec:
 *    clear the queue and raise CONNREFUSED so NG is dropped.
 */
int ngap_io_post_send(ogs_sock_t *sock, ogs_pkbuf_t *pkbuf,
        const ogs_sockaddr_t *peer_addr, bool send_with_addr);

/*
 * Socket close registry (mutex-protected). amf_gnb_remove() registers
 * the sock with the confirmations it waits for; the socket is destroyed
 * on the LAST confirm. A confirm for an unregistered sock is ignored
 * (the pointer may already have been reused by accept).
 */
#define NGAP_SOCK_CONFIRM_RX  0x1
#define NGAP_SOCK_CONFIRM_IO  0x2

/* MUST run before any worker starts */
void ngap_sock_close_init(void);
void ngap_sock_close_register(ogs_sock_t *sock, int wait_mask);
void ngap_sock_close_confirm(ogs_sock_t *sock, int which);
bool ngap_sock_close_pending(ogs_sock_t *sock);
/* destroy only if no close is registered (WATCH_FAILED orphan) */
void ngap_sock_close_orphan(ogs_sock_t *sock);
/* shutdown: reap sockets whose confirmations never arrived; call after
 * ALL worker threads are joined */
void ngap_sock_close_final(void);

/*
 * Post a DRAIN for a SOCK_STREAM gNB socket being torn down: the IO
 * thread frees queued pkbufs, drops its POLLOUT entry and confirms with
 * AMF_EVENT_NGAP_IO_DRAINED. Returns true if the drain was posted.
 * Never call for SOCK_SEQPACKET (shared server socket).
 */
bool ngap_io_drain_sock(ogs_sock_t *sock);

#ifdef __cplusplus
}
#endif

#endif /* NGAP_IO_H */
