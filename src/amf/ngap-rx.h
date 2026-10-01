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

#ifndef NGAP_RX_H
#define NGAP_RX_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NGAP RX decode offload (amf.ngap_rx_workers). N worker threads own
 * the receive side of the gNB associations: they poll on their own
 * pollsets, do the APER decode off the main thread and post decoded
 * NGAP events to amf_main. Association order holds because each
 * socket lives on exactly one worker and both queues are FIFO. Workers
 * touch only the socket and their own poll entry, never AMF context.
 *
 * Teardown is two-phase: amf_gnb_remove() calls ngap_rx_unwatch_sock(),
 * the worker removes its poll entry and posts
 * AMF_EVENT_NGAP_RX_SOCK_CLOSED, and the close registry (ngap-io.c)
 * destroys the socket once every owner has confirmed.
 *
 * Only the lksctp SOCK_STREAM path is offloaded; usrsctp (SEQPACKET
 * upcalls) keeps the legacy path.
 */

int ngap_rx_workers_start(int count);
void ngap_rx_workers_stop(void);

bool ngap_rx_active(void);

/* Assign an accepted gNB socket to a worker (round-robin). Main only. */
void ngap_rx_watch_sock(ogs_sock_t *sock);

/* True if sock is currently assigned to an RX worker. Main only. */
bool ngap_rx_owned(ogs_sock_t *sock);

/* Detach a socket from its worker. Returns false if the socket is not
 * worker-owned. When true, the caller must NOT destroy the socket; the
 * close registry does on the RX confirm. Main only. */
bool ngap_rx_unwatch_sock(ogs_sock_t *sock);

/* gNB lookup usable from the recv path: amf_gnb_find_by_addr() on
 * main, NULL on an RX worker (the gNB hash is main-thread state). */
amf_gnb_t *ngap_rx_safe_gnb_lookup(ogs_sockaddr_t *addr);

#ifdef __cplusplus
}
#endif

#endif /* NGAP_RX_H */
