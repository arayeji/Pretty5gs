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

#include "s1ap-path.h"
#include "s1ap-tx.h"
#include "nas-path.h"
#include "emm-build.h"
#include "sgsap-path.h"
#include "mme-gtp-path.h"
#include "mme-path.h"
#include "mme-fd-path.h"
#include "mme-sm.h"
#include "mme-trace.h"
#include "mme-timer.h"
#include "mme-workers.h"

void mme_ue_enter_ue_context_will_remove(mme_ue_t *mme_ue)
{
    mme_event_t e;

    ogs_assert(mme_ue);

    /* Already mid-teardown or freed via another path — do not re-enter FSM. */
    if (mme_ue->being_removed)
        return;
    if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_ue_context_will_remove))
        return;

    mme_ue->ue_context_will_remove = true;

    memset(&e, 0, sizeof(e));
    e.id = OGS_FSM_USER_SIG;
    e.mme_ue_id = mme_ue->id;
    ogs_fsm_tran(&mme_ue->sm, &emm_state_ue_context_will_remove, &e);
}

/*
 * Reclaim a UE on its OWNER shard. mme_ue_enter_ue_context_will_remove
 * drives the UE FSM and frees the mme_ue synchronously, so sweeps that
 * run on other threads (orphan sweep on main, SGW-recovery purge on
 * whichever thread saw the new restart counter) must bounce it through
 * MME_EVENT_ADMIN_PURGE_UE instead of calling it in place: the owner
 * could be mid-dispatch on the same UE (emm-sm.c:375 'Assertion
 * mme_ue failed' after the ENTRY of a state transition).
 */
void mme_ue_purge_on_owner(mme_ue_t *mme_ue)
{
    mme_event_t *e = NULL;

    ogs_assert(mme_ue);

    if (!mme_workers_active()) {
        mme_ue_enter_ue_context_will_remove(mme_ue);
        return;
    }

    e = mme_event_new(MME_EVENT_ADMIN_PURGE_UE);
    if (!e) {
        ogs_error("mme_ue_purge_on_owner: mme_event_new() failed");
        return;
    }
    e->mme_ue_id = mme_ue->id;
    e->owner_wid = mme_shard_from_teid(mme_ue->mme_s11_teid);

    /* Frees e on failure; owner unknown falls back to the main queue. */
    mme_event_push_to_ue_owner(e);
}

int mme_maintenance_reject_without_ue(
        enb_ue_t *enb_ue, const ogs_nas_eps_message_t *message,
        uint8_t nas_type)
{
    ogs_pkbuf_t *emmbuf = NULL;
    ogs_nas_emm_cause_t emm_cause = OGS_NAS_EMM_CAUSE_CONGESTION;
    int r, rv = OGS_OK;

    ogs_assert(enb_ue);
    ogs_assert(message);

    if (nas_type == OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE) {
        emmbuf = emm_build_service_reject(emm_cause, NULL);
    } else switch (message->emm.h.message_type) {
    case OGS_NAS_EPS_ATTACH_REQUEST:
        emmbuf = emm_build_attach_reject(NULL, emm_cause, NULL);
        break;
    case OGS_NAS_EPS_TRACKING_AREA_UPDATE_REQUEST:
        emmbuf = emm_build_tau_reject(emm_cause, NULL);
        break;
    case OGS_NAS_EPS_EXTENDED_SERVICE_REQUEST:
        emmbuf = emm_build_service_reject(emm_cause, NULL);
        break;
    default:
        ogs_debug("Maintenance: EMM type[%d]: S1 release only (no MME-UE)",
                message->emm.h.message_type);
        break;
    }

    if (emmbuf) {
        rv = nas_eps_send_to_downlink_nas_transport(enb_ue, emmbuf);
        ogs_expect(rv == OGS_OK);
    }

    r = s1ap_send_ue_context_release_command(enb_ue,
            S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
            S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
    ogs_expect(r == OGS_OK);

    ogs_warn("Maintenance: rejected new UE (EMM type=%d) without MME-UE "
            "context", message->emm.h.message_type);

    return (rv == OGS_OK && r == OGS_OK) ? OGS_OK : OGS_ERROR;
}

static ogs_timer_t *t_orphan_sweep = NULL;

/*
 * Last orphan-sweep outcome, surfaced via /admin/maintenance/status so the
 * sweep can be observed even when the logger is at "error" (its own logs are
 * ogs_warn/ogs_info). Written on the MME main thread, read on the MHD thread;
 * plain ints, a torn read is harmless for a diagnostic counter.
 */
static ogs_time_t orphan_sweep_last_run = 0;
static int orphan_sweep_last_ue_purged = 0;
static int orphan_sweep_last_ue_remaining = 0;
static uint64_t orphan_sweep_total_ue_purged = 0;

void mme_orphan_sweep_record(int ue_purged, int ue_remaining)
{
    orphan_sweep_last_run = ogs_time_now();
    orphan_sweep_last_ue_purged = ue_purged;
    orphan_sweep_last_ue_remaining = ue_remaining;
    if (ue_purged > 0)
        orphan_sweep_total_ue_purged += (uint64_t)ue_purged;
}

void mme_orphan_sweep_get_stats(ogs_time_t *last_run, int *last_purged,
        int *last_remaining, uint64_t *total_purged)
{
    if (last_run) *last_run = orphan_sweep_last_run;
    if (last_purged) *last_purged = orphan_sweep_last_ue_purged;
    if (last_remaining) *last_remaining = orphan_sweep_last_ue_remaining;
    if (total_purged) *total_purged = orphan_sweep_total_ue_purged;
}

static void orphan_sweep_timer_cb(void *data)
{
    mme_event_t *e = NULL;
    int rv;

    (void)data;

    /*
     * Run TX-hold recovery on the timer path before queueing the rest of
     * the sweep. When main is busy draining S1AP/GTP, the ORPHAN_SWEEP
     * event can sit for seconds; hold recovery must not wait on that.
     * Safe: only touches per-eNB hold locks + IO post (same as send path).
     */
    s1ap_tx_hold_watchdog();

    e = mme_event_new(MME_EVENT_ORPHAN_SWEEP);
    if (!e) {
        ogs_error("mme_event_new() failed for orphan sweep");
        return;
    }

    rv = mme_queue_push_main(e);
    if (rv != OGS_OK) {
        ogs_error("orphan sweep event dropped [%d]", rv);
        mme_event_free(e);
    }
}

#define MME_ORPHAN_UE_BATCH     20000

int mme_orphan_ue_sweep(bool do_purge, ogs_time_t grace, int *out_purged)
{
    mme_ue_t *mme_ue = NULL, *next = NULL;
    ogs_time_t now = ogs_time_now();
    int remaining = 0, purged = 0;
    ogs_pool_id_t *purge_ids = NULL;
    int n_purge = 0;
    int i;

    /*
     * Classify under mme_ctx_lock (list walk is not race-free without
     * it), but do not hold the lock across purge: with workers on,
     * mme_ue_purge_on_owner only posts events, yet find_by_id / event
     * alloc still contend; with workers off, purge drives the UE FSM
     * and can take the recursive lock for a long time. Collect up to
     * MME_ORPHAN_UE_BATCH pool IDs, unlock, then purge by id.
     */
    if (do_purge) {
        purge_ids = ogs_malloc(sizeof(*purge_ids) * MME_ORPHAN_UE_BATCH);
        ogs_assert(purge_ids);
    }

    mme_ctx_lock();
    ogs_list_for_each_safe(&mme_self()->mme_ue_list, next, mme_ue) {
        enb_ue_t *enb_ue = NULL;
        ogs_time_t anchor;

        /*
         * Intentionally do NOT blanket-skip ue_context_will_remove==true.
         *
         * Several teardown paths set this flag and then rely on "the
         * caller" to drive the emm_state_ue_context_will_remove transition
         * (see mme_send_delete_session_or_detach(), mme-path.c:449). When
         * that caller never completes the transition - e.g. an S6a/S11
         * failure on a UE that already lost its S1 link during an eNB SCTP
         * reset storm - the context is left session-less and flagged but is
         * never freed. Blanket-skipping the flag here let those stubs
         * accumulate without bound: ue_count stays pinned far above
         * mme_session / enb_ue (the reported slow, stable leak), and the
         * sweep - the very mechanism meant to reclaim them - could not.
         *
         * Only skip a context that is genuinely already in the removal
         * state (it is freed on entry, so it must never be touched again).
         * A flagged-but-un-transitioned stub instead falls through to the
         * session-less / pending / S1 / age gates below; the purge step
         * then re-drives mme_ue_enter_ue_context_will_remove() to finish
         * the removal that its original caller failed to complete.
         */
        if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_ue_context_will_remove))
            continue;

        /*
         * Safety net for "parked" UEs: a REGISTERED, ECM-IDLE context
         * must always have either the mobile-reachable or the implicit
         * detach timer running - that chain is the ONLY thing that ever
         * reclaims an idle subscriber (the purge below deliberately
         * skips contexts with live sessions). If a release path failed
         * to arm it (e.g. an SGs detach that was swallowed, a race on
         * S1 release, or a historic bug), the UE would otherwise stay
         * registered forever and ue_count grows without bound. Restart
         * the chain here; the UE is implicit-detached after
         * mobile-reachable + implicit-detach expire unless it contacts
         * the network first (which stops the timers as usual).
         */
        if (do_purge &&
                OGS_FSM_CHECK(&mme_ue->sm, emm_state_registered) &&
                ECM_IDLE(mme_ue) &&
                !MME_PAGING_ONGOING(mme_ue) &&
                mme_ue->t_mobile_reachable.timer &&
                !mme_ue->t_mobile_reachable.timer->running &&
                mme_ue->t_implicit_detach.timer &&
                !mme_ue->t_implicit_detach.timer->running) {
            ogs_warn("orphan sweep: parked UE imsi=%s - restarting "
                    "mobile-reachable chain",
                    mme_ue->imsi_bcd[0] ? mme_ue->imsi_bcd : "-");
            mme_mobile_reachable_start(mme_ue);
        }

        /*
         * A live ESM session means this is a real subscriber (ECM-IDLE
         * or not). Only reclaim contexts with no session at all — that
         * is what drives ue_count above mme_session / enb_ue.
         */
        if (!ogs_list_empty(&mme_ue->sess_list))
            continue;
        if (MME_SESSION_RELEASE_PENDING(mme_ue))
            continue;

        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (enb_ue &&
                enb_ue->ue_ctx_rel_action != S1AP_UE_CTX_REL_INVALID_ACTION)
            continue;

        remaining++;

        if (!do_purge || !purge_ids || n_purge >= MME_ORPHAN_UE_BATCH)
            continue;

        /*
         * Anchor the grace on the fixed creation time, never on idle_since.
         *
         * idle_since is restamped to "now" on every enb_ue_remove() and
         * zeroed on every enb_ue_associate_mme_ue(). Under an attach /
         * Service-Request failure storm - e.g. the SGW returning Create
         * Session Response cause=103 - a session-less stub briefly gets an
         * enb_ue then loses it every few seconds, so its idle_since never
         * ages past the grace window. Anchoring on idle_since therefore lets
         * such a stub evade the sweep forever: ue_count climbs without bound
         * while mme_session / enb_ue stay low.
         *
         * context_created is stamped once in mme_ue_add() and never moves, so
         * any context that has held no ESM session for longer than the grace
         * is reclaimed regardless of churn. This only changes behaviour for
         * ECM-IDLE stubs: ECM-CONNECTED UEs already have idle_since == 0 (so
         * they were anchored on context_created already), and registered UEs
         * keep their bearer in sess_list and were excluded above. Only true
         * session-less orphans are reaped.
         */
        anchor = mme_ue->context_created ?
                mme_ue->context_created : mme_ue->idle_since;
        if (anchor) {
            if ((now - anchor) < grace)
                continue;
        }
        /* No anchor at all: legacy stub, reclaim it. */

        purge_ids[n_purge++] = mme_ue->id;
    }
    mme_ctx_unlock();

    for (i = 0; i < n_purge; i++) {
        mme_ue = mme_ue_find_by_id(purge_ids[i]);
        if (!mme_ue)
            continue;
        if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_ue_context_will_remove))
            continue;
        if (!ogs_list_empty(&mme_ue->sess_list))
            continue;

        ogs_warn("orphan sweep: purge imsi=%s (no session)",
                mme_ue->imsi_bcd[0] ? mme_ue->imsi_bcd : "-");
        mme_ue_purge_on_owner(mme_ue);
        purged++;
    }

    if (purge_ids)
        ogs_free(purge_ids);

    if (out_purged)
        *out_purged = purged;

    /* remaining counted all eligible orphans; subtract those we queued
     * this pass so the caller sees leftovers (same idea as enb_ue batch). */
    return remaining - purged;
}

int mme_orphan_enb_sweep(bool do_purge, ogs_time_t grace, int *out_purged)
{
    mme_enb_t *enb = NULL, *next = NULL;
    ogs_time_t now = ogs_time_now();
    int remaining = 0, purged = 0;

    ogs_list_for_each_safe(&mme_self()->enb_list, next, enb) {
        if (enb->state.s1_setup_success)
            continue;
        if (enb->num_enb_ues > 0)
            continue;

        remaining++;

        if (!do_purge)
            continue;

        if (enb->context_created && (now - enb->context_created) < grace)
            continue;

        ogs_warn("orphan sweep: removing eNB without S1 setup "
                "(id=0x%x addr=%s age=%llus)",
                enb->enb_id,
                enb->sctp.addr ?
                    ogs_sockaddr_to_string_static(enb->sctp.addr) : "-",
                enb->context_created ?
                    (unsigned long long)ogs_time_to_sec(now -
                        enb->context_created) : 0ULL);
        mme_enb_remove(enb);
        purged++;
    }

    if (out_purged)
        *out_purged = purged;

    return remaining;
}

/*
 * Reclaim orphaned enb_ue (S1) contexts.
 *
 * An enb_ue is created on every Initial UE Message, but several failure
 * paths could leave it behind with no NAS association, no release action
 * and no t_s1_holding running - e.g. the queued EMM event being dropped
 * under overload, or the owning mme_ue being torn down through a path
 * that never released S1. Nothing ever reclaimed such contexts: the
 * enb_ue pool (sized to global max.ue) filled up over eNB flap storms
 * until enb_ue_add() failed for every new connection ("Active UE" gauge
 * far above the real UE count is the visible symptom).
 *
 * Criteria (conservative):
 *   - older than the grace period (creation-time anchored),
 *   - t_s1_holding not running (otherwise removal is already scheduled),
 *   - not the *active* S1 context of a live mme_ue,
 *   - either no release action, OR a stuck held context (action set but
 *     timer dead — RX queue flood used to drop the holding-timer event
 *     and leave immortal enb_ue corpses).
 *
 * Contexts that never had an mme_ue (or whose mme_ue is gone) are freed
 * directly. Work is capped per sweep so a large backlog cannot stall the
 * main thread; successive sweeps drain the rest.
 */
#define MME_ORPHAN_ENB_UE_BATCH     20000

int mme_orphan_enb_ue_sweep(bool do_purge, ogs_time_t grace, int *out_purged)
{
    mme_enb_t *enb = NULL;
    enb_ue_t *enb_ue = NULL, *next = NULL;
    ogs_time_t now = ogs_time_now();
    int remaining = 0, purged = 0;

    ogs_list_for_each(&mme_self()->enb_list, enb) {
        ogs_list_for_each_safe(&enb->enb_ue_list, next, enb_ue) {
            mme_ue_t *mme_ue = NULL;
            bool stuck_held;

            if (enb_ue->t_s1_holding && enb_ue->t_s1_holding->running)
                continue;

            stuck_held =
                (enb_ue->ue_ctx_rel_action != S1AP_UE_CTX_REL_INVALID_ACTION);

            mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
            /* Never touch the UE's current live S1 association. */
            if (mme_ue && mme_ue->enb_ue_id == enb_ue->id)
                continue;
            /*
             * Holding link is reclaimable only when stuck (timer dead).
             * While the holding timer still runs we already continued
             * above; if the mme_ue still points here as holding and the
             * timer is gone, reclaim and clear the reverse link.
             */
            if (!stuck_held && mme_ue &&
                    mme_ue->enb_ue_holding_id == enb_ue->id)
                continue;

            remaining++;

            if (!do_purge || purged >= MME_ORPHAN_ENB_UE_BATCH)
                continue;

            if (enb_ue->context_created &&
                    (now - enb_ue->context_created) < grace)
                continue;

            if (stuck_held) {
                if (mme_ue && mme_ue->enb_ue_holding_id == enb_ue->id)
                    mme_ue->enb_ue_holding_id = OGS_INVALID_POOL_ID;
                ogs_warn("orphan sweep: stuck held S1 "
                        "ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
                        enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);
            }

            enb_ue_remove(enb_ue);
            purged++;
        }
    }

    if (out_purged)
        *out_purged = purged;

    return remaining - purged;
}

void mme_orphan_timer_start(void)
{
    ogs_time_t interval;

    if (t_orphan_sweep)
        return;

    t_orphan_sweep = ogs_timer_add(
            ogs_app()->timer_mgr, orphan_sweep_timer_cb, NULL);
    ogs_assert(t_orphan_sweep);

    interval = mme_timer_cfg(MME_TIMER_S1_HOLDING)->duration;
    ogs_timer_start(t_orphan_sweep, interval);

    ogs_info("MME orphan UE sweep started: interval=%llus grace=%llus",
            (unsigned long long)ogs_time_to_sec(interval),
            (unsigned long long)ogs_time_to_sec(interval));
}

void mme_orphan_timer_stop(void)
{
    if (!t_orphan_sweep)
        return;

    ogs_timer_delete(t_orphan_sweep);
    t_orphan_sweep = NULL;
}

void mme_orphan_timer_rearm(void)
{
    if (!t_orphan_sweep)
        return;

    ogs_timer_start(t_orphan_sweep,
            mme_timer_cfg(MME_TIMER_S1_HOLDING)->duration);
}

/*
 * Batched /admin/maintenance/drain.
 *
 * The old implementation queued one MME_EVENT_ADMIN_DETACH_UE per UE up
 * front. Each session-less UE is then removed *synchronously* while its
 * event is handled, and mme_ue_remove() -> mme_event_purge_mme_ue() pops
 * and re-pushes the entire event queue to drop stale events. With N UEs
 * the queue held ~N detach events, so every removal cost O(N) queue
 * operations under the metrics dump lock: O(N^2) overall. At ~100k UEs
 * the main thread got wedged for hours - no S11 toward the SGW-C, no new
 * S1AP associations - while small drains appeared to work fine.
 *
 * Instead, walk mme_ue_list directly on the main thread in fixed-size
 * batches, pacing batches with a timer so S11 responses, S1AP traffic
 * and everything else queued in between keeps flowing. The event queue
 * stays shallow, which also keeps mme_event_purge_mme_ue() cheap.
 */
#define MME_ADMIN_DRAIN_BATCH       256
#define MME_ADMIN_DRAIN_INTERVAL    ogs_time_from_msec(100)

static ogs_timer_t *t_admin_drain = NULL;

/* Timer callbacks run on the MME main thread (ogs_timer_mgr_expire in
 * mme_main), so the next batch can be driven directly - no event push
 * that could fail against a full queue. */
static void admin_drain_timer_cb(void *data)
{
    (void)data;
    mme_admin_drain_step();
}

void mme_admin_drain_begin(bool force)
{
    mme_self()->drain_generation++;
    if (mme_self()->drain_generation == 0)  /* skip 0: means "never" on UE */
        mme_self()->drain_generation = 1;
    mme_self()->drain_force = force;
    mme_self()->drain_active = true;
    mme_self()->drain_processed = 0;

    ogs_info("admin maintenance drain: start mode=%s ue_count=%d "
            "batch=%d interval=%dms",
            force ? "force" : "graceful",
            ogs_list_count(&mme_self()->mme_ue_list),
            MME_ADMIN_DRAIN_BATCH,
            (int)ogs_time_to_msec(MME_ADMIN_DRAIN_INTERVAL));

    mme_admin_drain_step();
}

void mme_admin_drain_step(void)
{
    mme_ue_t *it = NULL, *next = NULL;
    int processed = 0;
    bool more = false;

    if (!mme_self()->drain_active)
        return;

    ogs_list_for_each_safe(&mme_self()->mme_ue_list, next, it) {
        /* Already handled by this drain (detach may still be in flight). */
        if (it->drain_generation == mme_self()->drain_generation)
            continue;
        if (processed >= MME_ADMIN_DRAIN_BATCH) {
            more = true;
            break;
        }
        it->drain_generation = mme_self()->drain_generation;
        processed++;
        /* May remove `it` synchronously; `next` is already resolved. */
        mme_admin_detach_ue(it, mme_self()->drain_force);
    }

    mme_self()->drain_processed += processed;

    if (more) {
        if (!t_admin_drain) {
            t_admin_drain = ogs_timer_add(
                    ogs_app()->timer_mgr, admin_drain_timer_cb, NULL);
            ogs_assert(t_admin_drain);
        }
        ogs_timer_start(t_admin_drain, MME_ADMIN_DRAIN_INTERVAL);
        return;
    }

    mme_self()->drain_active = false;
    ogs_info("admin maintenance drain: detach issued to %u UEs "
            "(%d still on list awaiting completion)",
            mme_self()->drain_processed,
            ogs_list_count(&mme_self()->mme_ue_list));
}

void mme_admin_drain_timer_stop(void)
{
    mme_self()->drain_active = false;

    if (!t_admin_drain)
        return;

    ogs_timer_delete(t_admin_drain);
    t_admin_drain = NULL;
}

void mme_admin_detach_ue(mme_ue_t *mme_ue, bool force)
{
    enb_ue_t *enb_ue = NULL;
    int r;

    ogs_assert(mme_ue);

    if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_ue_context_will_remove))
        return;

    if (force) {
        ogs_info("admin detach ue (force/implicit): imsi=%s",
                mme_ue->imsi_bcd);

        mme_ue->ue_context_will_remove = false;
        mme_ue->detach_type = MME_DETACH_TYPE_MME_IMPLICIT;

        if (MME_CURRENT_P_TMSI_IS_AVAILABLE(mme_ue)) {
            if (sgsap_send_detach_indication(mme_ue) != OGS_OK)
                ogs_error("sgsap_send_detach_indication() failed");
            /*
             * CS/PS combined UEs still in registered state use the
             * normal async implicit-detach timer path.
             */
            if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_registered)) {
                mme_timer_implicit_detach_expire(
                        OGS_UINT_TO_POINTER(mme_ue->id));
                return;
            }
        }

        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        mme_send_delete_session_or_detach(enb_ue, mme_ue);

        if (mme_ue->ue_context_will_remove) {
            mme_ue_enter_ue_context_will_remove(mme_ue);
            return;
        }

        if (MME_SESSION_RELEASE_PENDING(mme_ue))
            return;

        /*
         * Failed-attach stubs and other non-registered EMM states never
         * handled the queued implicit-detach timer event, so admin drain
         * left them behind. With no GTP work pending, remove locally.
         */
        if (!OGS_FSM_CHECK(&mme_ue->sm, emm_state_registered)) {
            mme_ue_enter_ue_context_will_remove(mme_ue);
            return;
        }

        if (!enb_ue)
            mme_ue_enter_ue_context_will_remove(mme_ue);

        return;
    }

    ogs_info("admin detach ue (graceful): imsi=%s state=%s",
            mme_ue->imsi_bcd,
            ECM_CONNECTED(mme_ue) ? "ECM-CONNECTED" : "ECM-IDLE");

    mme_ue->detach_type = MME_DETACH_TYPE_MME_EXPLICIT;

    if (ECM_IDLE(mme_ue)) {
        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!enb_ue) {
            ogs_warn("admin detach ue: no S1 context for imsi=%s",
                    mme_ue->imsi_bcd);
            if (!MME_SESSION_RELEASE_PENDING(mme_ue))
                mme_ue_enter_ue_context_will_remove(mme_ue);
            return;
        }

        MME_STORE_PAGING_INFO(mme_ue,
                MME_PAGING_TYPE_DETACH_TO_UE, NULL);
        r = s1ap_send_paging(mme_ue, S1AP_CNDomain_ps);
        ogs_expect(r == OGS_OK);
        return;
    }

    MME_CLEAR_PAGING_INFO(mme_ue);
    r = nas_eps_send_detach_request(mme_ue);
    ogs_expect(r == OGS_OK);

    if (MME_CURRENT_P_TMSI_IS_AVAILABLE(mme_ue)) {
        if (sgsap_send_detach_indication(mme_ue) != OGS_OK)
            ogs_error("[%s] SGsAP Detach-Indication not sent "
                    "(VLR/SGs unavailable)", mme_ue->imsi_bcd);
    } else {
        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (enb_ue) {
            mme_send_delete_session_or_detach(enb_ue, mme_ue);
        } else {
            ogs_warn("admin detach ue: no S1 context for imsi=%s",
                    mme_ue->imsi_bcd);
            if (!MME_SESSION_RELEASE_PENDING(mme_ue))
                mme_ue_enter_ue_context_will_remove(mme_ue);
        }
    }
}

void mme_send_delete_session_or_detach(enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    int r, xact_count;
    ogs_assert(mme_ue);

    /*
     * SGsAP DETACH-ACK (and a few fallback paths) can arrive after
     * detach_type was cleared or never set. Aborting the whole MME here
     * previously caused mass session loss; treat unset/invalid as
     * implicit detach instead.
     */
    if (mme_ue->detach_type == 0) {
        ogs_warn("[%s] detach_type unset; treating as MME implicit detach",
                MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
        mme_ue->detach_type = MME_DETACH_TYPE_MME_IMPLICIT;
    }

    xact_count = mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR);

    switch (mme_ue->detach_type) {
    case MME_DETACH_TYPE_REQUEST_FROM_UE:
        ogs_debug("Detach Request from UE");
        mme_gtp_send_delete_all_sessions(
                enb_ue, mme_ue, OGS_GTP_DELETE_SEND_DETACH_ACCEPT);

        if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
            mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                xact_count) {
            r = nas_eps_send_detach_accept(mme_ue);
            ogs_expect(r == OGS_OK);
        }
        break;

    /* MME-initiated explicit detach (TS 23.401 §5.3.8.3),
     * e.g. O&M action via the admin API. Semantically identical
     * to HSS-initiated explicit detach: a NAS Detach Request has
     * already been sent to the UE (or will be after paging) by
     * the caller; here we just tear down the S11 sessions and
     * leave UE-side cleanup to the Detach Accept handler.
     */
    case MME_DETACH_TYPE_MME_EXPLICIT:
        ogs_debug("Explicit MME Detach");
        mme_gtp_send_delete_all_sessions(
                enb_ue, mme_ue, OGS_GTP_DELETE_NO_ACTION);
        break;

    /* HSS Explicit Detach, ie: Subscription Withdrawl Cancel Location
     *
     * TS23.401 - V16.10.0
     * Ch 5.3.8 Detach procedure
     * Ch 5.3.8.4 HSS-initiated Detach procedure
     */
    case MME_DETACH_TYPE_HSS_EXPLICIT:
        ogs_debug("Explicit HSS Detach");
        mme_gtp_send_delete_all_sessions(
                enb_ue, mme_ue, OGS_GTP_DELETE_NO_ACTION);
        break;

    /* MME Implicit Detach, ie: Lost Communication
     * TS23.401 - V16.10.0
     * Ch 5.3.8.3 MME-initiated Detach procedure (Without Step 1)
     */
    case MME_DETACH_TYPE_MME_IMPLICIT:
        ogs_warn("[%s] Implicit MME Detach", mme_ue->imsi_bcd);
        mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
            OGS_GTP_DELETE_SEND_RELEASE_WITH_UE_CONTEXT_REMOVE);

        if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
            mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                xact_count) {
            enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
            if (enb_ue) {
                ogs_warn("[%s] UEContextReleaseCommand Sent", mme_ue->imsi_bcd);
                if (s1ap_send_ue_context_release_command(enb_ue,
                            S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
                            S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0) != OGS_OK)
                    ogs_error("[%s] UEContextReleaseCommand failed",
                            mme_ue->imsi_bcd);
            } else {
            /*
             * No S1 context exists (eNB UE context already gone).
             *
             * Historically, this path removed the UE context immediately.
             * That can free mme_ue while EMM FSM is still handling the timer
             * event, which may lead to invalid FSM transitions or assertions.
             *
             * Defer UE removal to EMM FSM by setting ue_context_will_remove.
             * The caller will transition to emm_state_ue_context_will_remove,
             * and the removal will be performed on state entry.
             */
                ogs_warn("[%s] No S1 Context - defer UE removal to FSM",
                    mme_ue->imsi_bcd);
                mme_ue->ue_context_will_remove = true;
            }
        }
        break;

    /* HSS Implicit Detach, ie: MME-UPDATE-PROCEDURE
     *
     * TS23.401 - V16.10.0
     * Ch 5.3.2 Attach procedure
     * Ch 5.3.2.1 E-UTRAN Initial Attach
     *
     * 9. The HSS sends Cancel Location (IMSI, Cancellation Type)
     * to the old MME. The old MME acknowledges with Cancel Location Ack (IMSI)
     * and removes the MM and bearer contexts. If the ULR-Flags indicates
     * "Initial-Attach-Indicator" and the HSS has the SGSN registration,
     * then the HSS sends Cancel Location (IMSI, Cancellation Type)
     * to the old SGSN. The Cancellation Type indicates the old MME/SGSN
     * to release the old Serving GW resource.
     */
    case MME_DETACH_TYPE_HSS_IMPLICIT:
        ogs_debug("Implicit HSS Detach");
        mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
            OGS_GTP_DELETE_SEND_RELEASE_WITH_UE_CONTEXT_REMOVE);
        break;

    default:
        ogs_error("[%s] Invalid detach_type[%d]; "
                "falling back to MME implicit detach",
                MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-",
                mme_ue->detach_type);
        mme_ue->detach_type = MME_DETACH_TYPE_MME_IMPLICIT;
        mme_send_delete_session_or_detach(enb_ue, mme_ue);
        break;
    }
}

void mme_send_delete_session_after_attach_accept_fail(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    mme_ue_progress(mme_ue, "attach_accept_cleanup");

    if (!MME_SESSION_RELEASE_PENDING(mme_ue))
        mme_gtp_send_delete_all_sessions(
                enb_ue, mme_ue, OGS_GTP_DELETE_NO_ACTION);
}

void mme_send_delete_session_or_mme_ue_context_release(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    int r, xact_count = 0;

    ogs_assert(mme_ue);

    if (!enb_ue)
        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

    xact_count = mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR);

    mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
            OGS_GTP_DELETE_SEND_RELEASE_WITH_UE_CONTEXT_REMOVE);

    if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
        mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
            xact_count) {
        if (enb_ue) {
            r = s1ap_send_ue_context_release_command(enb_ue,
                    S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
                    S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0);
            if (r != OGS_OK)
                ogs_warn("[%s] UE Context Release Command not sent",
                        mme_ue->imsi_bcd);
        } else {
            /*
             * No S1 context exists (eNB UE context already gone).
             *
             * Defer UE removal to EMM FSM by setting ue_context_will_remove.
             */
            ogs_warn("[%s] No S1 Context - defer UE removal to FSM",
                    mme_ue->imsi_bcd);
            mme_ue_enter_ue_context_will_remove(mme_ue);
        }
    }
}

void mme_send_s1_release_after_emm_failure(mme_ue_t *mme_ue)
{
    enb_ue_t *enb_ue = NULL;
    int r;

    ogs_assert(mme_ue);

    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!enb_ue)
        return;
    /* A release is already in flight (CLEAR_S1_CONTEXT, holding, ...) */
    if (enb_ue->ue_ctx_rel_action != S1AP_UE_CTX_REL_INVALID_ACTION)
        return;
    /* GTP teardown in progress will release S1 on completion */
    if (MME_SESSION_RELEASE_PENDING(mme_ue))
        return;

    /*
     * S1_CONTEXT_REMOVE, not UE_CONTEXT_REMOVE: the UE may legitimately
     * stay EMM-REGISTERED after a rejected TAU or Service Request, it
     * just has no business holding an S1 connection. This drops it to
     * ECM-IDLE, arms the mobile-reachable timer, and still reclaims the
     * context when no ESM session is left.
     */
    r = s1ap_send_ue_context_release_command(enb_ue,
            S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
            S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
    if (r != OGS_OK)
        ogs_warn("[%s] UE Context Release Command not sent after EMM failure",
                MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
}

void mme_send_release_access_bearer_or_ue_context_release(enb_ue_t *enb_ue)
{
    int r;
    mme_ue_t *mme_ue = NULL;
    ogs_assert(enb_ue);

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (mme_ue) {
        ogs_debug("[%s] Release access bearer request", mme_ue->imsi_bcd);
        if (mme_gtp_send_release_access_bearers_request(
                enb_ue->id, mme_ue,
                OGS_GTP_RELEASE_SEND_UE_CONTEXT_RELEASE_COMMAND) != OGS_OK)
            ogs_error("[%s] Release Access Bearers failed",
                    mme_ue->imsi_bcd);
    } else {
        ogs_debug("No UE Context");
        if (!enb_ue->relcause.group) {
            ogs_error("Release with no cause set; "
                    "using eutran-generated-reason");
            enb_ue->relcause.group = S1AP_Cause_PR_radioNetwork;
            enb_ue->relcause.cause =
                S1AP_CauseRadioNetwork_release_due_to_eutran_generated_reason;
        }
        r = s1ap_send_ue_context_release_command(enb_ue,
                enb_ue->relcause.group, enb_ue->relcause.cause,
                S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
        ogs_expect(r == OGS_OK);
    }
}

void mme_send_after_paging(mme_ue_t *mme_ue, bool failed)
{
    int r;
    mme_bearer_t *bearer = NULL;

    ogs_assert(mme_ue);

    switch (mme_ue->paging.type) {
    case MME_PAGING_TYPE_DOWNLINK_DATA_NOTIFICATION:
        bearer = mme_bearer_find_by_id(
                OGS_POINTER_TO_UINT(mme_ue->paging.data));
        if (!bearer) {
            mme_ue_warn(mme_ue, NULL, "paging", NULL,
                    "No Bearer [type=%d]", mme_ue->paging.type);
            goto cleanup;
        }

        /* A failed ack must not abort the MME: the SGW retransmits the
         * DDN anyway, and aborting here caused a crash loop. */
        if (mme_gtp_send_downlink_data_notification_ack(bearer,
                failed == true ? OGS_GTP2_CAUSE_UNABLE_TO_PAGE_UE :
                    OGS_GTP2_CAUSE_REQUEST_ACCEPTED) != OGS_OK)
            mme_ue_error(mme_ue, NULL, "paging", NULL,
                    "DDN Ack not sent [failed=%d]", failed);
        break;
    case MME_PAGING_TYPE_CREATE_BEARER:
        bearer = mme_bearer_find_by_id(
                OGS_POINTER_TO_UINT(mme_ue->paging.data));
        if (!bearer) {
            mme_ue_warn(mme_ue, NULL, "paging", NULL,
                    "No Bearer [type=%d]", mme_ue->paging.type);
            goto cleanup;
        }

        if (failed == true) {
            if (mme_gtp_send_create_bearer_response(
                        bearer, OGS_GTP2_CAUSE_UNABLE_TO_PAGE_UE) != OGS_OK)
                ogs_error("[%s] Create Bearer Response (unable to page) "
                        "failed EBI[%d]", mme_ue->imsi_bcd, bearer->ebi);
            /*
             * The Create Bearer Response (failure) was sent back to SGW/SMF,
             * so the network side will tear down the bearer on its end.
             * Remove the MME-side bearer context now to avoid an EBI leak —
             * no Delete Bearer Request will arrive for a bearer whose
             * creation was rejected.
             */
            mme_bearer_remove(bearer);
        } else {
            r = nas_eps_send_activate_dedicated_bearer_context_request(bearer);
            ogs_expect(r == OGS_OK);
        }
        break;
    case MME_PAGING_TYPE_UPDATE_BEARER:
        bearer = mme_bearer_find_by_id(
                OGS_POINTER_TO_UINT(mme_ue->paging.data));
        if (!bearer) {
            mme_ue_warn(mme_ue, NULL, "paging", NULL,
                    "No Bearer [type=%d]", mme_ue->paging.type);
            goto cleanup;
        }

        if (failed == true) {
            if (mme_gtp_send_update_bearer_response(
                        bearer, OGS_GTP2_CAUSE_UNABLE_TO_PAGE_UE) != OGS_OK)
                ogs_error("[%s] Update Bearer Response (unable to page) "
                        "failed EBI[%d]", mme_ue->imsi_bcd, bearer->ebi);
        } else {
            ogs_gtp_xact_t *xact = mme_bearer_update_xact_first(bearer);

            if (!xact) {
                ogs_error("No GTP xact");
                goto cleanup;
            }

            /*
             * MME must wait for Modify Bearer Context Accept
             * before sending Update Bearer Response,
             * To check this, start a peer timer to check it.
             */
            ogs_timer_start(xact->tm_peer,
                    ogs_local_conf()->time.message.gtp.t3_response_duration);

            r = nas_eps_send_modify_bearer_context_request(bearer,
                    (xact->update_flags &
                        OGS_GTP_MODIFY_QOS_UPDATE) ? 1 : 0,
                    (xact->update_flags &
                        OGS_GTP_MODIFY_TFT_UPDATE) ? 1 : 0);
            ogs_expect(r == OGS_OK);
        }
        break;
    case MME_PAGING_TYPE_DELETE_BEARER:
        bearer = mme_bearer_find_by_id(
                OGS_POINTER_TO_UINT(mme_ue->paging.data));
        if (!bearer) {
            mme_ue_warn(mme_ue, NULL, "paging", NULL,
                    "No Bearer [type=%d]", mme_ue->paging.type);
            goto cleanup;
        }

        if (failed == true) {
            /* TS 23.401 §5.4.4: UE unreachable after paging → Unable to page UE */
            if (mme_gtp_send_delete_bearer_response(
                    bearer, OGS_GTP2_CAUSE_UNABLE_TO_PAGE_UE) != OGS_OK)
                mme_ue_error(mme_ue, NULL, "paging", NULL,
                        "Delete Bearer Response not sent after paging fail");
        } else {
            r = nas_eps_send_deactivate_bearer_context_request(
                    bearer, mme_ue->paging.esm_cause);
            if (r == OGS_NOTFOUND) {
                /*
                 * The S1 context vanished between the paging success
                 * and this dispatch (immediate re-release race). The
                 * NAS-Deactivate watchdog was never armed in this
                 * case, so without a synthetic answer the
                 * PGW-initiated bearer deactivation stalls at the
                 * SGW/SMF until GTP timeout. Answer it now; the core
                 * side is tearing the bearer down regardless.
                 */
                mme_ue_warn(mme_ue, NULL, "paging", NULL,
                        "S1 released before NAS Deactivate could be "
                        "sent EBI[%d]; answering SGW/SMF directly",
                        bearer->ebi);
                if (bearer->delete.xact_id >= OGS_MIN_POOL_ID &&
                        bearer->delete.xact_id <= OGS_MAX_POOL_ID &&
                        mme_gtp_send_delete_bearer_response(
                            bearer, OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
                                != OGS_OK)
                    mme_ue_error(mme_ue, NULL, "paging", NULL,
                            "Delete Bearer Response not sent EBI[%d]",
                            bearer->ebi);
            } else if (r != OGS_OK) {
                mme_ue_error(mme_ue, NULL, "paging", NULL,
                        "NAS Deactivate Bearer send failed rv=%d EBI[%d]; "
                        "Delete Bearer Response cause System failure",
                        r, bearer->ebi);
                if (bearer->delete.xact_id >= OGS_MIN_POOL_ID &&
                        bearer->delete.xact_id <= OGS_MAX_POOL_ID &&
                        mme_gtp_send_delete_bearer_response(
                            bearer, OGS_GTP2_CAUSE_SYSTEM_FAILURE) != OGS_OK)
                    mme_ue_error(mme_ue, NULL, "paging", NULL,
                            "Delete Bearer Response not sent EBI[%d]",
                            bearer->ebi);
            }
        }
        break;
    case MME_PAGING_TYPE_CS_CALL_SERVICE:
        if (failed == true) {
            if (sgsap_send_paging_reject(
                    mme_ue, SGSAP_SGS_CAUSE_UE_UNREACHABLE) != OGS_OK)
                ogs_error("[%s] SGsAP Paging-Reject not sent "
                        "(VLR/SGs unavailable)", mme_ue->imsi_bcd);
        } else {
            /* Nothing */
        }
        break;
    case MME_PAGING_TYPE_SMS_SERVICE:
        if (failed == true) {
            if (sgsap_send_paging_reject(
                    mme_ue, SGSAP_SGS_CAUSE_UE_UNREACHABLE) != OGS_OK)
                ogs_error("[%s] SGsAP Paging-Reject not sent "
                        "(VLR/SGs unavailable)", mme_ue->imsi_bcd);
        } else {
            if (sgsap_send_service_request(
                    mme_ue, SGSAP_EMM_CONNECTED_MODE) != OGS_OK)
                ogs_error("[%s] SGsAP Service-Request not sent "
                        "(VLR/SGs unavailable)", mme_ue->imsi_bcd);
        }
        break;
    case MME_PAGING_TYPE_DETACH_TO_UE:
        if (failed == true) {
            /* Nothing */
            ogs_warn("MME-initiated Detach cannot be invoked");
        } else {
            r = nas_eps_send_detach_request(mme_ue);
            if (r != OGS_OK)
                /* UE dropped the connection right after paging response */
                ogs_warn("[%s] Detach request after paging not sent",
                        mme_ue->imsi_bcd);
            if (MME_CURRENT_P_TMSI_IS_AVAILABLE(mme_ue)) {
                if (sgsap_send_detach_indication(mme_ue) != OGS_OK) {
                    enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
                    /* VLR/SGs down: continue the EPS-side detach so
                     * the context is not parked forever. */
                    ogs_error("sgsap_send_detach_indication() failed - "
                            "proceeding with EPS detach");
                    if (enb_ue)
                        mme_send_delete_session_or_detach(enb_ue, mme_ue);
                    else
                        ogs_warn("ENB-S1 Context has already been removed");
                }
            } else {
                enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
                if (enb_ue)
                    mme_send_delete_session_or_detach(enb_ue, mme_ue);
                else
                    ogs_warn("ENB-S1 Context has already been removed");
            }
        }
        break;
    case MME_PAGING_TYPE_UE_REACHABILITY:
        /*
         * T-ADS UE reachability paging (URRP-MME). The reachability report
         * to the HSS (S6a NOR) is sent by the generic URRP check below, so
         * that it also covers the case where URRP was armed while another
         * paging procedure was already ongoing.
         */
        break;
    default:
        ogs_fatal("Invalid Paging Type[%d]", mme_ue->paging.type);
        ogs_assert_if_reached();
    }

    /*
     * T-ADS (3GPP TS 23.272 / TS 29.272): if the HSS armed UE reachability
     * (URRP-MME) and the UE has now become reachable, notify the HSS via
     * S6a Notify-Request so it can inform the IMS Application Server.
     *
     * On success the NOR is normally already sent from the ECM-CONNECTED
     * transition (enb_ue_associate_mme_ue -> mme_s6a_report_urrp); the
     * call here is idempotent and only acts as a safety net.
     *
     * On paging failure we deliberately keep URRP-MME *armed*: the S1AP
     * paging procedure has already exhausted its bounded T3413 retries,
     * so rather than dropping the request we let the next autonomous
     * ECM-CONNECTED transition (periodic TAU / Service Request) report
     * reachability. The arming is cleared when the UE context is removed.
     */
    if (mme_ue->urrp_mme) {
        if (failed == false) {
            mme_s6a_report_urrp(mme_ue);
        } else {
            ogs_warn("[%s] T-ADS: UE reachability paging failed; URRP-MME "
                    "stays armed for autonomous reachability",
                    mme_ue->imsi_bcd);
        }
    }

cleanup:
    CLEAR_SERVICE_INDICATOR(mme_ue);
    MME_CLEAR_PAGING_INFO(mme_ue);
    /* the above will clear the failure flag, restore it if we failed */
    if (failed)
        mme_ue->paging.failed = true;
}

/* ----------------------------------------------------------------------
 * Function: mme_send_delete_session_or_tau_accept
 * ----------------------------------------------------------------------
 * - Check UE's EPS Bearer Context Status (BCS) regardless of active_flag
 *   against MME's sessions before sending TAU ACCEPT.
 * - If UE does not report the default bearer EBI, delete that session.
 * - Otherwise, send TAU ACCEPT immediately.
 * ---------------------------------------------------------------------- */
void mme_send_delete_session_or_tau_accept(enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    sgw_ue_t *sgw_ue = NULL;
    mme_sess_t *sess = NULL;
    mme_bearer_t *def = NULL;

    uint16_t mask;
    uint8_t ebi;
    int deleted = 0;

    ogs_assert(enb_ue);
    ogs_assert(mme_ue);

    mask = mme_ue->tracking_area_update_request_ebcs_value;

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        def = mme_default_bearer_in_sess(sess);
        if (!def) {
            ogs_warn("[%s] No default bearer; skip session", mme_ue->imsi_bcd);
            continue;
        }

        ebi = def->ebi;
        if (ebi > 15) {
            ogs_warn("[%s] Invalid EBI=%u; skip", mme_ue->imsi_bcd, ebi);
            continue;
        }

        /* If UE's BCS bit for this EBI is 0,
         * delete the session */
        if (!(mask & (1 << ebi))) {
            ogs_warn("[%s] BCS mismatch: UE missing EBI=%u",
                    mme_ue->imsi_bcd, ebi);
            sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
            ogs_assert(sgw_ue);

            GTP_COUNTER_INCREMENT(
                mme_ue, GTP_COUNTER_DELETE_SESSION_BY_TAU);

            mme_gtp_send_delete_session_request(
                enb_ue, sgw_ue, sess,
                OGS_GTP_DELETE_SEND_TAU_ACCEPT);

            deleted++;
        }
    }

    if (deleted > 0) {
        ogs_warn("[%s] Deleted %d session(s) due to BCS mismatch, "
                "active_flag=%d",
                mme_ue->imsi_bcd, deleted,
                mme_ue->nas_eps.update.active_flag);
    } else {
        /*
         * Choose S1AP procedure based on active_flag:
         *  - active_flag==1 : InitialContextSetup
         *  - active_flag==0 : DownlinkNASTransport
         */
        ogs_info("[%s] Send TAU accept(BCS match, active_flag=%d)",
                 mme_ue->imsi_bcd, mme_ue->nas_eps.update.active_flag);
        mme_send_tau_accept_and_check_release(enb_ue, mme_ue);
    }
}

void mme_send_tau_accept_and_check_release(enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    int r;

    ogs_assert(mme_ue);
    ogs_assert(enb_ue);

    /*
     * If BCS mismatch deleted all sessions, InitialContextSetup is impossible
     * (requires E-RABs). Fall back to DownlinkNASTransport to deliver TAU
     * Accept without bearer setup. The UE reported no bearers via BCS,
     * so it can re-establish PDN connectivity after TAU completes.
     */
    if (mme_ue->tracking_area_update_accept_proc ==
            S1AP_ProcedureCode_id_InitialContextSetup &&
            ogs_list_count(&mme_ue->sess_list) == 0) {
        ogs_warn("[%s] No sessions after BCS cleanup; "
                "downgrade InitialContextSetup to DownlinkNASTransport",
                mme_ue->imsi_bcd);
        mme_ue->tracking_area_update_accept_proc =
            S1AP_ProcedureCode_id_downlinkNASTransport;
    }

    r = nas_eps_send_tau_accept(mme_ue,
            mme_ue->tracking_area_update_accept_proc);
    ogs_expect(r == OGS_OK);

    /*
     * TS 24.301 Ch5.5.3.3
     * When active_flag is 0, check if the P-TMSI has been updated.
     * If the P-TMSI has changed, wait to receive the TAU Complete message
     * from the UE before sending the UEContextReleaseCommand.
     *
     * This ensures that the UE has acknowledged the new P-TMSI,
     * allowing the TAU procedure to complete successfully
     * and maintaining synchronization between the UE and the network.
     */
    ogs_info("[%s] TAU done (sgsap_connected=%d, next_ptmsi=%u)",
         mme_ue->imsi_bcd,
         MME_SGSAP_IS_CONNECTED(mme_ue),
         (unsigned)mme_ue->next.p_tmsi);
    if (!mme_ue->nas_eps.update.active_flag &&
        !MME_NEXT_P_TMSI_IS_AVAILABLE(mme_ue)) {
        enb_ue->relcause.group = S1AP_Cause_PR_nas;
        enb_ue->relcause.cause = S1AP_CauseNas_normal_release;

        ogs_info("[%s] release access bearer", mme_ue->imsi_bcd);

        mme_send_release_access_bearer_or_ue_context_release(enb_ue);
    }
}

ogs_time_t mme_time_mobile_reachable_duration(void)
{
    return mme_self()->time.t3412.value +
        mme_self()->time.idle.mobile_reachable_margin;
}

ogs_time_t mme_time_implicit_detach_duration(void)
{
    /*
     * TS 24.301 5.3.5: if ISR is activated, implicit detach timer is
     * 4 minutes greater than T3423. Open5GS uses configured t3423 when set.
     */
    if (mme_self()->time.t3423.value)
        return mme_self()->time.t3423.value +
            mme_self()->time.idle.implicit_detach_margin;

    return mme_self()->time.t3412.value +
        mme_self()->time.idle.implicit_detach_margin;
}

static void mme_idle_timer_durations_for_ue(mme_ue_t *mme_ue,
        ogs_time_t *mobile, ogs_time_t *implicit)
{
    ogs_time_t t3346 = 0;

    ogs_assert(mobile);
    ogs_assert(implicit);

    *mobile = mme_time_mobile_reachable_duration();
    *implicit = mme_time_implicit_detach_duration();

    if (!mme_ue || !mme_ue->idle_t3346)
        return;

    t3346 = mme_ue->idle_t3346;
    if (t3346 <= mme_self()->time.t3412.value)
        return;

    /*
     * TS 24.301 5.3.5: when T3346 > T3412 is sent in TAU/Service Reject,
     * mobile reachable + implicit detach shall exceed T3346.
     */
    if (*mobile + *implicit <= t3346) {
        *implicit = t3346 - *mobile + 1;
        if (*mobile + *implicit <= t3346)
            *mobile = t3346 - *implicit + 1;
    }
}

ogs_time_t mme_time_mobile_reachable_duration_for_ue(mme_ue_t *mme_ue)
{
    ogs_time_t mobile = 0, implicit = 0;

    mme_idle_timer_durations_for_ue(mme_ue, &mobile, &implicit);
    return mobile;
}

ogs_time_t mme_time_implicit_detach_duration_for_ue(mme_ue_t *mme_ue)
{
    ogs_time_t mobile = 0, implicit = 0;

    mme_idle_timer_durations_for_ue(mme_ue, &mobile, &implicit);
    return implicit;
}

bool mme_t3346_should_include(ogs_nas_emm_cause_t emm_cause)
{
    if (!mme_self()->time.t3346.value)
        return false;

    if (mme_self()->time.t3346.include_any_reject)
        return true;

    return emm_cause == OGS_NAS_EMM_CAUSE_CONGESTION;
}

void mme_idle_t3346_clear(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);
    mme_ue->idle_t3346 = 0;
}

void mme_t3346_on_reject_sent(mme_ue_t *mme_ue, ogs_nas_emm_cause_t emm_cause)
{
    ogs_assert(mme_ue);

    if (!mme_t3346_should_include(emm_cause))
        return;

    mme_ue->idle_t3346 = mme_self()->time.t3346.value;
    ogs_info("[%s] T3346 backoff active (%ld s) after EMM reject cause[%d]",
            mme_ue->imsi_bcd, (long)mme_ue->idle_t3346, emm_cause);

    if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_registered) && ECM_IDLE(mme_ue))
        mme_mobile_reachable_start(mme_ue);
}

void mme_mobile_reachable_start(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    /*
     * Only act on REGISTERED contexts. The old code cleared ALL UE
     * timers first and then bailed out for non-registered states:
     * a UE that lost S1 in the middle of a procedure (authentication,
     * security mode, initial context setup, MME-initiated detach) had
     * its T3450/T3460/T3470/T3422 retransmission timers killed with
     * nothing restarted, so the procedure could never time out into
     * emm_state_exception and the context was parked forever - the
     * slow, unbounded ue_count growth. Leave in-procedure timers
     * alone; their expiry drives the FSM to exception, whose entry
     * hook bounds the context lifetime.
     */
    if (!OGS_FSM_CHECK(&mme_ue->sm, emm_state_registered))
        return;

    CLEAR_MME_UE_ALL_TIMERS(mme_ue);

    ogs_info("Mobile Reachable timer started for IMSI[%s]",
            mme_ue->imsi_bcd);

    ogs_timer_start(mme_ue->t_mobile_reachable.timer,
            ogs_time_from_sec(
                mme_time_mobile_reachable_duration_for_ue(mme_ue)));
}
