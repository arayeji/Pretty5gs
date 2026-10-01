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

#ifndef AMF_WORKERS_H
#define AMF_WORKERS_H

#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AMF UE shard workers (amf.workers, default 0).
 *
 * A UE unit - amf_ue, its sessions, its ran_ue(s) and all their timers -
 * belongs to exactly one shard and is only touched on that shard's
 * thread. Main keeps gNB/SCTP, NRF and OAM and routes everything else:
 *
 *   NGAP UE messages   AMF-UE-NGAP-ID shard bits (InitialUE: identity)
 *   SBI responses      transaction -> UE/session -> owner
 *   SBI requests       ue-contexts/{id} or callback SUPI -> owner
 *
 * Shared lookups (pools, hashes, gNB lists) run under amf_ctx_lock();
 * lib/sbi objects under ogs_sbi_lock(). See docs/smp-workers.md.
 */

int amf_workers_start(int count);
/* Join the threads; their timer managers stay alive for context final */
void amf_workers_stop(void);
/* Free worker resources; call after amf_context_final() */
void amf_workers_final(void);

int amf_workers_count(void);
bool amf_workers_running(void);

/* Shard index of the calling thread: 0..N-1, or -1 off-shard (main) */
int amf_shard_self(void);
/* Timer manager of the calling shard, NULL off-shard */
ogs_timer_mgr_t *amf_shard_timer_mgr(void);

/*
 * AMF-UE-NGAP-ID (40 bits, TS 38.413): bits 36..39 carry wid + 1, so
 * IDs allocated off-shard (and every ID without workers) are unchanged.
 */
#define AMF_SHARD_NGAP_ID_SHIFT 36
#define AMF_SHARD_NGAP_ID_INDEX_MASK \
    ((UINT64_C(1) << AMF_SHARD_NGAP_ID_SHIFT) - 1)

uint64_t amf_shard_compose_ngap_id(uint32_t index, int wid);
/* -1 when the ID carries no shard */
int amf_shard_from_ngap_id(uint64_t amf_ue_ngap_id);

/*
 * M-TMSI bits 16..19, always 0 from amf_m_tmsi_alloc(), carry wid + 1
 * of the shard that assigned the GUTI: main can route a GUTI the owner
 * has not confirmed yet (Registration Complete still queued).
 */
#define AMF_SHARD_M_TMSI_SHIFT 16
uint32_t amf_shard_compose_m_tmsi(uint32_t m_tmsi, int wid);
int amf_shard_from_m_tmsi(uint32_t m_tmsi);

/* Post to shard wid. Frees the event and its payload on failure. */
int amf_workers_post(int wid, amf_event_t *e);
/* Post to the calling shard's own queue. Caller frees on failure. */
int amf_workers_post_self(void *event);

/*
 * Main thread: forward e to its owner shard. Returns true when e was
 * taken (forwarded or dropped); false = main dispatches it itself.
 */
bool amf_workers_route(amf_event_t *e);

/*
 * Ask shard wid to drop its stale UE context (cross-shard SUCI/SUPI).
 * Main picks the InitialUE owner from the NAS identity, so this only
 * fires when two registrations race for one subscriber.
 */
void amf_workers_post_ue_evict(int wid, ogs_pool_id_t amf_ue_id);

/* Shard dispatch of the AMF_EVENT_SHARD_* / SBI_DISCOVER_CB events */
void amf_workers_handle_event(amf_event_t *e);

/*
 * Tear a gNB down on every shard (amf_gnb_remove_begin(), fan-out,
 * amf_gnb_remove_finish() on the last confirmation). Without workers
 * this is amf_sbi_send_deactivate_all_ue_in_gnb() + amf_gnb_remove().
 */
void amf_workers_gnb_teardown(amf_gnb_t *gnb, int state);

/*
 * NG Reset fan-out (main). _partial() returns false only when main owns
 * the ran_ue itself; a shard-owned item is always handed over.
 */
void amf_workers_ng_reset_all(amf_gnb_t *gnb);
bool amf_workers_ng_reset_partial(
        ogs_pool_id_t ran_ue_id, ogs_pool_id_t gnb_id);

/* OAM UE release by PLMN fan-out (main). */
void amf_workers_oam_release_plmn(const ogs_plmn_id_t *plmn_id);

/*
 * SBI discovery callback from main: run it on the UE's shard. Returns
 * true when the response was handed over.
 */
bool amf_workers_post_discover_cb(int status,
        ogs_sbi_response_t *response, void *data);

#ifdef __cplusplus
}
#endif

#endif /* AMF_WORKERS_H */
