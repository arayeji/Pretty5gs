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

#ifndef S1AP_SHARD_H
#define S1AP_SHARD_H

#include "mme-event.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stage C: route UE-scoped S1AP procedures from the RX workers directly
 * to the owning UE shard worker, bypassing the main thread.
 *
 * Knob: mme.stage_c (default 0). Requires mme.workers > 0.
 * Whitelist includes UplinkNAS, UECapability, ICS/UECtxtMod/E-RABSetup
 * responses, UEContextReleaseComplete, E-RABModify/Release responses.
 */

/* true when mme.stage_c is on AND UE shard workers are running */
bool s1ap_stage_c_active(void);

/*
 * Classify a decoded PDU on the RX worker. Returns the target shard
 * worker id (>= 0) when the procedure is UE-scoped, whitelisted, and
 * the MME_UE_S1AP_ID carries a valid shard prefix; -1 = main thread.
 * Pure PDU inspection: no context access, safe on any thread.
 */
int s1ap_shard_classify_wid(ogs_s1ap_message_t *pdu);

/*
 * Post a decoded S1AP PDU to shard worker `wid`. Takes ownership of
 * sock/addr/pkbuf/pdu exactly like s1ap_event_push_decoded(); falls
 * back to the main queue if the shard queue rejects the post.
 */
void s1ap_shard_push_decoded(int wid, void *sock, ogs_sockaddr_t *addr,
        ogs_pkbuf_t *pkbuf, ogs_s1ap_message_t *pdu);

/*
 * Handle a MME_EVENT_S1AP_MESSAGE that was routed to this shard worker.
 * Returns true when the event was consumed here (payload already freed;
 * caller frees the event struct). Returns false when ownership was
 * transferred to the main queue — the caller must not touch the event
 * again in that case.
 */
bool s1ap_shard_handle(mme_event_t *e);

#ifdef __cplusplus
}
#endif

#endif /* S1AP_SHARD_H */
