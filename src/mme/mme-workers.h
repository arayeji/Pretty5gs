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

#ifndef MME_WORKERS_H
#define MME_WORKERS_H

#include "mme-event.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * MME Stage A UE-shard workers (mme.workers, default 0).
 *
 * Main owns eNB/SCTP/admin; UE-scoped events (EMM/ESM/S11/S6a) bounce to
 * a sticky shard. See docs/mme-smp-todo.md.
 */

int mme_workers_start(int count);
/* Join worker threads (timer managers stay alive for context final). */
void mme_workers_stop(void);
/* Free worker resources; call AFTER mme_context_final(). */
void mme_workers_final(void);

int mme_workers_count(void);
bool mme_workers_active(void);

ogs_worker_t *mme_worker_by_id(int wid);

/* Push event to shard worker index [0..N). Frees event on failure. */
int mme_event_push_to_worker(int wid, mme_event_t *e);

/*
 * Route a UE-scoped event to its owner shard (or main when workers off /
 * owner unknown). Takes ownership of e. Returns OGS_OK / OGS_ERROR.
 */
int mme_event_push_to_ue_owner(mme_event_t *e);

/* Shard helpers: worker index 0..N-1, or -1 = main / unknown. */
int mme_shard_from_teid(uint32_t teid);
int mme_shard_from_ue_s1ap_id(uint32_t mme_ue_s1ap_id);
int mme_shard_from_imsi_bcd(const char *imsi_bcd);
int mme_shard_from_mme_ue_id(ogs_pool_id_t mme_ue_id);
int mme_shard_from_enb_ue_id(ogs_pool_id_t enb_ue_id);

/*
 * EMM messages resolved by GUTI/S-TMSI/message may find an mme_ue owned
 * by a different shard (re-attach: new enb_ue hashes to another worker).
 * If so, re-post the event to the owner (takes the pkbuf) and return
 * true; caller must return immediately without touching mme_ue.
 */
bool mme_worker_rehome_emm(mme_event_t *e, mme_ue_t *mme_ue);

/*
 * Defer an S1AP procedure tail (Path Switch / Handover Notify /
 * InitialContextSetupResponse) to the UE's owner shard. kind is one of
 * MME_HO_TAIL_*. Takes ownership of pkbuf (optional tail payload, e.g.
 * the ICS_RSP E-RAB snapshot); it is freed on every failure path and
 * with the event after dispatch. Returns OGS_OK when queued.
 */
int mme_worker_post_ho_tail(int kind, ogs_pool_id_t enb_ue_id,
        mme_ue_t *mme_ue, ogs_pkbuf_t *pkbuf);

/*
 * Defer the mme_ue-side of UE Context Release Complete to the owner
 * shard (MME_HO_TAIL_UE_REL). old_enb_ue_id names the enb_ue that main
 * ALREADY removed (stale-link comparison only). Returns OGS_ERROR when
 * the owner is main or the post failed — run the tail inline then.
 */
int mme_worker_post_ue_rel_tail(int rel_action, ogs_pool_id_t old_enb_ue_id,
        mme_ue_t *mme_ue, int rel_flags);

/*
 * Bounce a Release Access Bearers send (MME_HO_TAIL_REL_AB) to the UE
 * owner shard so the S11 xact and its response tail live there.
 * Returns OGS_ERROR when the calling thread already owns the UE (or
 * the post failed) — send inline then.
 */
int mme_worker_post_rel_ab(int action, ogs_pool_id_t enb_ue_id,
        mme_ue_t *mme_ue);

/* Peek IMSI from a GTPv2-C pkbuf (Create Session Request TEID=0). */
int mme_gtpv2_peek_imsi_bcd(ogs_pkbuf_t *pkbuf, char *bcd, size_t bcd_size);

/*
 * Compose protocol ids with owner shard bits when sharding is active.
 * shard_id is ogs_worker_self_id() style: 0=main, 1..N=workers.
 * When shards off: returns raw unchanged.
 */
uint32_t mme_shard_compose(uint32_t raw, int shard_id);

/* Timer manager for a new UE owned by worker index wid (or app mgr). */
ogs_timer_mgr_t *mme_ue_timer_mgr_for_wid(int wid);

#ifdef __cplusplus
}
#endif

#endif /* MME_WORKERS_H */
