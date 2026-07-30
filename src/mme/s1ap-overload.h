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

#ifndef S1AP_OVERLOAD_H
#define S1AP_OVERLOAD_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * S1AP overload control and ingress admission.
 *
 * Two independent pressure signals, both graded 0 (none) / 1 (moderate)
 * / 2 (severe):
 *
 *  - per-eNB downlink stall: the IO thread reports the write-queue
 *    depth for an association once a second while it sits above
 *    mme.s1ap_io_congest_depth. An eNB we cannot write to is one whose
 *    Attach Accepts are already being dropped, so admitting more
 *    attaches from it only multiplies UE retries on shared workers.
 *
 *  - MME-internal backlog: mme_event_lag(), i.e. how long events wait
 *    between creation and dispatch. This is the same number the timers
 *    use to tell "peer is slow" from "we are behind".
 *
 * Response, in the order a UE sees it:
 *
 *  1. OVERLOAD START to the eNB (TS 36.413 8.9.1) so RRC connections
 *    are rejected before they ever become S1AP messages. Sent at the
 *    congestion watermark, deliberately well below queue-full, so the
 *    PDU can still get out.
 *  2. Ingress shedding of InitialUEMessage that arrives anyway. Never
 *    for emergency or high-priority access, and never for MT access
 *    (paging responses) — that is what the "permit MT only" overload
 *    action promises the eNB.
 *  3. A per-eNB token bucket on InitialUEMessage that applies at all
 *    times (mme.overload.enb_initial_ue_rate), independent of level.
 *
 * Everything here runs on the MME main thread: the S1AP FSM, the
 * IO-congestion event handler and the 1 s tick.
 */

/* mme.overload.<key> — shared by startup parse and SIGHUP reload */
int mme_overload_config_set(const char *key, ogs_yaml_iter_t *iter);

/* 1 s evaluation tick (OVERLOAD START/STOP, global pressure) */
void mme_overload_timer_start(void);
void mme_overload_timer_stop(void);

/*
 * TX congestion heartbeat for enb, reported by the S1AP IO thread and
 * delivered on main as MME_EVENT_S1AP_IO_CONGESTED. depth is the
 * association's write-queue depth.
 */
void mme_overload_enb_congested(mme_enb_t *enb, int depth);

/*
 * Ingress gate for InitialUEMessage. Returns false when the message
 * must be shed: the caller drops it without creating any context and
 * without answering (an Error Indication per shed message would add
 * exactly the downlink load we are trying to shed; the UE's own retry
 * is the backoff).
 *
 * rrc_cause is S1AP_RRC_Establishment_Cause_*; pass present=false when
 * the eNB omitted the IE.
 */
bool s1ap_admit_initial_ue(mme_enb_t *enb, long rrc_cause, bool present);

/* 0 none / 1 moderate / 2 severe — for logs and /enb-info */
int mme_overload_enb_level(mme_enb_t *enb);
int mme_overload_global_level(void);

#ifdef __cplusplus
}
#endif

#endif /* S1AP_OVERLOAD_H */
