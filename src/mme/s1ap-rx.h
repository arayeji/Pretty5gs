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

#ifndef S1AP_RX_H
#define S1AP_RX_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * S1AP RX decode offload: N worker threads own the eNB associations'
 * receive side — blocking on their own pollsets, doing APER decode off
 * the main thread — and post fully-decoded S1AP events to the main
 * loop. Association ordering is preserved because each socket lives on
 * exactly one worker and both queues are FIFO. All MME state stays on
 * the main thread; workers touch only the socket and their own poll
 * entry.
 *
 * Teardown is two-phase: mme_enb_remove() calls s1ap_rx_unwatch_sock()
 * which posts an unwatch command to the owning worker; the worker
 * removes its poll entry and posts MME_EVENT_S1AP_RX_SOCK_CLOSED back;
 * only then does the main thread destroy the socket.
 */

int s1ap_rx_workers_start(int count);
void s1ap_rx_workers_stop(void);

bool s1ap_rx_active(void);

/* Assign an accepted eNB socket to a worker (round-robin). Main only. */
void s1ap_rx_watch_sock(ogs_sock_t *sock);

/* True if sock is currently assigned to an RX worker (main only). */
bool s1ap_rx_owned(ogs_sock_t *sock);

/* Detach a socket from its worker. Returns false if the socket is not
 * worker-owned (single-threaded mode: caller keeps the legacy path).
 * When true, the caller must NOT destroy the socket — it is destroyed
 * on MME_EVENT_S1AP_RX_SOCK_CLOSED. Main only. */
bool s1ap_rx_unwatch_sock(ogs_sock_t *sock);

/* eNB lookup usable from the recv path: on the main thread this is
 * mme_enb_find_by_addr(); on an RX worker it returns NULL, because the
 * eNB hash is main-thread state and must not be read concurrently
 * (callers only use the result for error logging). */
mme_enb_t *s1ap_rx_safe_enb_lookup(const ogs_sockaddr_t *addr);

#ifdef __cplusplus
}
#endif

#endif /* S1AP_RX_H */
