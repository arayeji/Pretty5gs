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

#ifndef S1AP_TX_H
#define S1AP_TX_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * S1AP TX build+encode offload (mme.s1ap_tx_workers, default 0).
 *
 * DownlinkNASTransport is the highest-volume downlink S1AP message
 * (authentication, security mode command, identity request, TAU/detach
 * accept, EMM information). When offload is on, its ASN.1 build + APER
 * encode runs on a TX worker from an ID SNAPSHOT taken on the main
 * thread (MME/eNB S1AP ids + stream id) — the worker never touches
 * mme_ue_t / enb_ue_t / any hash / any socket. The encoded pkbuf comes
 * back as MME_EVENT_S1AP_TX_READY and the MAIN thread performs the
 * send, so socket ownership is unchanged.
 *
 * ORDERING. Per-eNB downlink order must hold not only among DL-NAS
 * messages but against every other downlink S1AP on that association
 * (e.g. TAU Accept immediately followed by UE Context Release
 * Command). Two rules guarantee it:
 *
 *   1. Jobs are sticky per eNB (enb pool id % N) and every queue in
 *      the path is FIFO, so encode jobs for one eNB complete in
 *      submission order.
 *   2. While an eNB has encode jobs in flight (s1ap_tx_pending > 0),
 *      s1ap_send_to_enb() HOLDS synchronous pkbufs on a per-eNB list
 *      instead of writing them; each TX_READY sends its own pkbuf and
 *      then flushes the hold list once pending drops to zero.
 *
 * Worker-queue-full: the post returns != OGS_OK and the caller uses
 * the synchronous path. That is safe: posting failed, so nothing for
 * that eNB was enqueued out of order by this call (any earlier
 * in-flight jobs still hold back the sync pkbuf via rule 2).
 *
 * eNB teardown: mme_enb_remove() drains the hold list; TX_READY for a
 * removed eNB just frees the pkbuf (enb pool id lookup fails).
 */

int s1ap_tx_workers_start(int count);
void s1ap_tx_workers_stop(void);

bool s1ap_tx_active(void);

/* diagnostics for /admin/queues */
int s1ap_tx_worker_count(void);
unsigned int s1ap_tx_queue_depth(int idx);

/* Post a DownlinkNASTransport build+encode job. Main thread only.
 * Takes ownership of emmbuf ONLY on OGS_OK; on failure the caller
 * must fall back to the synchronous build+send path. */
int s1ap_tx_post_dlnas(enb_ue_t *enb_ue, ogs_pkbuf_t *emmbuf);

/* MME_EVENT_S1AP_TX_READY handler body: send e->pkbuf to e->enb_id
 * (or free it if the eNB is gone) and flush that eNB's hold list.
 * Main thread only. */
void s1ap_tx_ready_handle(mme_event_t *e);

/* Periodic self-heal (orphan sweep, main thread): force-flush any eNB
 * whose hold list has been non-empty for far longer than an encode job
 * can take — the signature of a leaked s1ap_tx_pending count, which
 * otherwise black-holes that eNB's synchronous downlink until restart. */
void s1ap_tx_hold_watchdog(void);

#ifdef __cplusplus
}
#endif

#endif /* S1AP_TX_H */
