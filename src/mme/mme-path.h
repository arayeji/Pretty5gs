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
 * Returns the number of orphan candidates still on mme_ue_list after the
 * sweep; writes the number actually purged to out_purged when non-NULL.
 */
int mme_orphan_ue_sweep(bool do_purge, ogs_time_t grace, int *out_purged);
int mme_orphan_enb_sweep(bool do_purge, ogs_time_t grace, int *out_purged);
void mme_orphan_timer_start(void);
void mme_orphan_timer_stop(void);
void mme_orphan_timer_rearm(void);

/* Orphan-sweep heartbeat, surfaced via /admin/maintenance/status. */
void mme_orphan_sweep_record(int ue_purged, int ue_remaining);
void mme_orphan_sweep_get_stats(ogs_time_t *last_run, int *last_purged,
        int *last_remaining, uint64_t *total_purged);

void mme_admin_detach_ue(mme_ue_t *mme_ue, bool force);

void mme_send_delete_session_or_detach(enb_ue_t *enb_ue, mme_ue_t *mme_ue);
void mme_send_delete_session_or_mme_ue_context_release(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue);
void mme_send_release_access_bearer_or_ue_context_release(enb_ue_t *enb_ue);

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
