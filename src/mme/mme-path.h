/*
 * Copyright (C) 2019-2024 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
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

#ifndef MME_PATH_H
#define MME_PATH_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

void mme_ue_enter_ue_context_will_remove(mme_ue_t *mme_ue);
/*
 * Same reclaim, bounced to the UE owner shard when workers are on.
 * Returns OGS_OK if the UE was removed synchronously (no workers) or the
 * ADMIN_PURGE_UE event was successfully queued; OGS_ERROR if the event
 * could not be allocated/queued (caller must not count a purge).
 */
int mme_ue_purge_on_owner(mme_ue_t *mme_ue);

/*
 * Maintenance window: reject a brand-new S1/NAS procedure without
 * allocating mme_ue_t (attach/TAU/service storm path).
 */
int mme_maintenance_reject_without_ue(
        enb_ue_t *enb_ue, const ogs_nas_eps_message_t *message,
        uint8_t nas_type);

/*
 * Reclaim MME-UE contexts with no ESM session (regardless of EMM state).
 * Registered ECM-IDLE subscribers always retain at least one session until
 * detach; empty sess_list means the context is stale.
 *
 * Walks the UE list in lock-held chunks (resumed via cursor across ticks).
 * Returns eligible orphans in this tick that were NOT successfully
 * queued/removed (includes in-grace). Writes successfully queued/removed
 * count to out_purged when non-NULL.
 */
int mme_orphan_ue_sweep(bool do_purge, ogs_time_t grace, int *out_purged);
int mme_orphan_enb_sweep(bool do_purge, ogs_time_t grace, int *out_purged);
int mme_orphan_enb_ue_sweep(bool do_purge, ogs_time_t grace, int *out_purged);
void mme_orphan_timer_start(void);
void mme_orphan_timer_stop(void);
void mme_orphan_timer_rearm(void);

/* Orphan-sweep heartbeat, surfaced via /admin/maintenance/status. */
typedef struct mme_orphan_sweep_stats_s {
    ogs_time_t last_run;
    int last_queued;       /* successfully queued/sync-removed this tick */
    int last_remaining;    /* eligible in this tick, not yet queued (incl grace) */
    int last_examined;     /* UEs walked this tick */
    int last_in_grace;     /* eligible but younger than grace */
    int last_skipped_s1;   /* sessionless skipped: S1 release in progress */
    int last_queue_fail;   /* purge enqueue failures this tick */
    uint64_t total_queued; /* cumulative successful queue/sync-remove */
} mme_orphan_sweep_stats_t;

void mme_orphan_sweep_record(const mme_orphan_sweep_stats_t *stats);
void mme_orphan_sweep_get_stats(mme_orphan_sweep_stats_t *stats);

void mme_admin_detach_ue(mme_ue_t *mme_ue, bool force);

/* Per-APN PDN disconnect (admin /admin/session/delete?imsi=&apn=). */
void mme_admin_detach_sess(mme_sess_t *sess, bool force);

/*
 * Batched maintenance drain (/admin/maintenance/drain). begin() bumps the
 * drain generation and processes the first batch; subsequent batches are
 * driven by a pacing timer on the MME main thread so normal signalling
 * keeps flowing in between. See mme-path.c for the O(N^2) rationale.
 */
void mme_admin_drain_begin(bool force);
void mme_admin_drain_step(void);
void mme_admin_drain_timer_stop(void);

void mme_send_delete_session_or_detach(enb_ue_t *enb_ue, mme_ue_t *mme_ue);
/*
 * UE/network detach: optional SGs Detach Indication, then always Delete
 * Session immediately. Never wait for SGs DETACH-ACK before tearing down
 * PDN (ACK may arrive after S1 is gone and previously skipped DSR).
 */
void mme_send_eps_detach_with_session_delete(enb_ue_t *enb_ue, mme_ue_t *mme_ue);
void mme_send_delete_session_or_mme_ue_context_release(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue);
void mme_send_release_access_bearer_or_ue_context_release(enb_ue_t *enb_ue);

/*
 * Release the S1 UE-associated logical connection after a NAS reject or
 * a failed EMM transaction, leaving the UE context itself alone.
 *
 * The reject helpers only transmit the NAS PDU, so a procedure that ends
 * in a reject used to leave S1 up with nothing scheduled to take it down:
 * the eNB then dangles the UE-associated connection until its own guard
 * timer (~30 s) fires an S1AP Reset partOfS1-Interface, and only then does
 * the MME release. Measured in production at ~7 such Resets per second.
 *
 * No-op when there is no S1 context, when a release is already in flight,
 * or when a pending GTP teardown will drive the release itself.
 */
void mme_send_s1_release_after_emm_failure(mme_ue_t *mme_ue);

void mme_send_after_paging(mme_ue_t *mme_ue, bool failed);

void mme_send_delete_session_or_tau_accept(enb_ue_t *enb_ue, mme_ue_t *mme_ue);
void mme_send_tau_accept_and_check_release(enb_ue_t *enb_ue, mme_ue_t *mme_ue);

/* Tear down S11 session after CSR ok when Attach Accept cannot be delivered. */
void mme_send_delete_session_after_attach_accept_fail(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue);

ogs_time_t mme_time_mobile_reachable_duration(void);
ogs_time_t mme_time_implicit_detach_duration(void);
ogs_time_t mme_time_mobile_reachable_duration_for_ue(mme_ue_t *mme_ue);
ogs_time_t mme_time_implicit_detach_duration_for_ue(mme_ue_t *mme_ue);
bool mme_t3346_should_include(ogs_nas_emm_cause_t emm_cause);
void mme_t3346_on_reject_sent(mme_ue_t *mme_ue, ogs_nas_emm_cause_t emm_cause);
void mme_idle_t3346_clear(mme_ue_t *mme_ue);
void mme_mobile_reachable_start(mme_ue_t *mme_ue);

#ifdef __cplusplus
}
#endif

#endif /* MME_PATH_H */
