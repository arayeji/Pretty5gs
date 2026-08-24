/*
 * Copyright (C) 2019-2025 by Sukchan Lee <acetcom@gmail.com>
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

#include "mme-event.h"
#include "mme-timer.h"
#include "mme-trace.h"
#include "s1ap-handler.h"
#include "mme-gn-handler.h"
#include "mme-fd-path.h"
#include "mme-path.h"
#include "emm-handler.h"
#include "emm-build.h"
#include "esm-handler.h"
#include "nas-path.h"
#include "mme-provisioning-sms.h"
#include "metrics.h"
#include "nas-security.h"
#include "s1ap-path.h"
#include "sgsap-types.h"
#include "sgsap-path.h"
#include "mme-gtp-path.h"
#include "mme-path.h"
#include "mme-sm.h"

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __emm_log_domain

#define MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s) do {                  \
    if (mme_self()->maintenance_mode) {                                 \
        OGS_FSM_TRAN((s), &emm_state_ue_context_will_remove);           \
        ogs_warn("[%s] Failure during maintenance; removing UE "        \
                 "context.", (mme_ue)->imsi_bcd);                       \
    } else if ((mme_ue)->can_restore_context) {                         \
        /* Restore context if allowed */                                \
        mme_ue_restore_memento((mme_ue), &((mme_ue)->memento));         \
        (mme_ue)->security_context_available = 1;                       \
        (mme_ue)->mac_failed = 0;                                       \
        /*                                                              \
         * EMM state is restored, but the procedure that owned this S1  \
         * connection is over - usually because we just sent a NAS      \
         * reject. Nothing else would take S1 down (the exception state \
         * releases, this branch never did), so the eNB was left to     \
         * time it out and Reset. Drop the UE to ECM-IDLE instead.      \
         */                                                             \
        mme_send_s1_release_after_emm_failure(mme_ue);                  \
        if (!OGS_FSM_CHECK(&mme_ue->sm, emm_state_registered))          \
            OGS_FSM_TRAN((s), &emm_state_registered);                   \
        ogs_warn("[%s] Failure in transaction; restoring context and "  \
                 "transitioning to REGISTERED.", (mme_ue)->imsi_bcd);   \
    } else {                                                            \
        /* Transition to exception state if not allowed */              \
        OGS_FSM_TRAN((s), &emm_state_exception);                        \
        ogs_warn("[%s] Failure in transaction; no context "             \
                 "restoration.", (mme_ue)->imsi_bcd);                   \
    }                                                                   \
} while (0)

/*
 * Late EMM timer / rehomed message / nested FSM entry can outlive the
 * mme_ue (pool slot already freed). Asserting here took production down
 * (emm_state_de_registered). Drop the event instead.
 */
#define EMM_FIND_UE_OR_RETURN(e, mme_ue) do {                            \
    (mme_ue) = mme_ue_find_by_id((e)->mme_ue_id);                       \
    if (!(mme_ue)) {                                                    \
        ogs_warn("EMM: mme_ue id=%d gone (event %s)",                   \
                (e)->mme_ue_id, mme_event_get_name(e));                 \
        return;                                                         \
    }                                                                   \
} while (0)

typedef enum {
    EMM_COMMON_STATE_DEREGISTERED,
    EMM_COMMON_STATE_REGISTERED,
} emm_common_state_e;

static void common_register_state(ogs_fsm_t *s, mme_event_t *e,
        emm_common_state_e state);

static bool emm_defer_retransmission(mme_ue_t *mme_ue, int timer_id);

static void emm_handle_t3450_timer(ogs_fsm_t *s, mme_ue_t *mme_ue)
{
    int r;
    enb_ue_t *enb_ue = NULL;
    ogs_pkbuf_t *emmbuf = NULL;

    ogs_assert(s);
    ogs_assert(mme_ue);

    if (emm_defer_retransmission(mme_ue, MME_TIMER_T3450))
        return;

    if (mme_ue->t3450.retry_count >=
            mme_timer_cfg(MME_TIMER_T3450)->max_count) {
        mme_sess_t *sess = mme_sess_first(mme_ue);
        enb_ue_t *enb_ue_for_log = enb_ue_find_by_id(mme_ue->enb_ue_id);

        ogs_mme_trace_set(enb_ue_for_log, mme_ue,
                (sess && sess->session) ? sess->session->name : NULL, "attach-fail");
        OGS_TLOG_INFO("Attach failed: T3450 expired "
                "(no InitialContextSetupResponse/AttachComplete)");
        ogs_warn("Retransmission of IMSI[%s] failed. "
                "Stop retransmission", mme_ue->imsi_bcd);
        OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
        return;
    }

    mme_ue->t3450.retry_count++;

    if (!mme_ue->t3450.pkbuf) {
        ogs_error("No T3450 NAS buffer");
        OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
        return;
    }

    /*
     * TAU with active_flag=0 uses Downlink NAS Transport; attach and
     * TAU-with-ICS use InitialContextSetupRequest (see nas_eps_send_tau_accept).
     */
    if (mme_ue->tracking_area_update_accept_proc ==
            S1AP_ProcedureCode_id_downlinkNASTransport) {
        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!enb_ue) {
            ogs_warn("[%s] S1 context removed; stop T3450 Downlink NAS",
                    mme_ue->imsi_bcd);
            CLEAR_MME_UE_TIMER(mme_ue->t3450);
            OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
            return;
        }

        emmbuf = MME_UE_TIMER_TAKE_PKBUF(mme_ue->t3450);
        if (!emmbuf) {
            ogs_warn("[%s] T3450 NAS buffer taken concurrently; "
                    "stop retransmission", mme_ue->imsi_bcd);
            OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
            return;
        }
        mme_ue->t3450.pkbuf = ogs_pkbuf_copy(emmbuf);
        if (!mme_ue->t3450.pkbuf) {
            ogs_error("ogs_pkbuf_copy() failed");
            ogs_pkbuf_free(emmbuf);
            OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
            return;
        }

        ogs_timer_start(mme_ue->t3450.timer,
                mme_timer_cfg(MME_TIMER_T3450)->duration);

        r = nas_eps_send_to_downlink_nas_transport(enb_ue, emmbuf);
        if (r != OGS_OK) {
            /* S1 dropped mid-procedure; exception entry bounds cleanup */
            ogs_warn("T3450 Downlink NAS retransmit failed");
            OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
        }
        return;
    }

    r = nas_eps_resend_t3450_initial_context(mme_ue);
    if (r != OGS_OK) {
        /* S1 dropped mid-procedure; exception entry bounds cleanup */
        ogs_warn("T3450 ICS retransmit failed");
        OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
    }
}

static void emm_handle_sgs_ts6_1_timer(ogs_fsm_t *s, mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    if (!mme_ue->sgs_lu_pending) {
        ogs_debug("[%s] Stale %s; ignored",
                mme_ue->imsi_bcd, mme_timer_get_name(MME_TIMER_SGS_TS6_1));
        ogs_timer_stop(mme_ue->t_sgs_ts6_1);
        return;
    }

    mme_sgs_continue_without_cs(mme_ue, "sgsap_lu_timeout");
}

static void emm_handle_s6a_timer(ogs_fsm_t *s, mme_ue_t *mme_ue)
{
    int r, rv;
    enb_ue_t *enb_ue = NULL;
    ogs_gtp_xact_t *xact = NULL;
    uint16_t cmd;
    uint8_t emm_cause = OGS_NAS_EMM_CAUSE_NETWORK_FAILURE;

    ogs_assert(mme_ue);

    cmd = mme_ue->s6a_pending_cmd;
    if (!cmd) {
        ogs_debug("[%s] Stale %s; ignored",
                mme_ue->imsi_bcd, mme_timer_get_name(MME_TIMER_S6A));
        mme_s6a_timer_stop(mme_ue);
        return;
    }

    mme_s6a_timer_stop(mme_ue);

    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!enb_ue) {
        /*
         * S6a (AIR/ULR) timed out for a UE that has already lost its S1
         * link - common during eNB SCTP reset storms. The attach/TAU
         * cannot be completed and no NAS reject can be delivered without
         * S1, so a half-built context with no ESM session would otherwise
         * sit session-less and idle forever, pinning ue_count above
         * mme_session/enb_ue. Drive it to removal here instead of leaking;
         * the orphan sweep is only a backstop for this. Using OGS_FSM_TRAN
         * (not mme_ue_enter_ue_context_will_remove()) keeps the actual free
         * in the FSM dispatch loop that invoked this handler, avoiding a
         * use-after-free of the EMM FSM.
         */
        ogs_error("[%s] S6a timeout but no S1 context "
                "(cmd=%u%s); HSS/Diameter slow and eNB S1 already gone "
                "(reset/HO/release) so NAS reject cannot be delivered — "
                "dropping half-built UE context",
                mme_ue->imsi_bcd, cmd,
                cmd == OGS_DIAM_S6A_CMD_CODE_AUTHENTICATION_INFORMATION
                    ? ":AIR" :
                cmd == OGS_DIAM_S6A_CMD_CODE_UPDATE_LOCATION
                    ? ":ULR" : "");
        /*
         * Previously only removed when sess_list was empty, so leftover
         * sessions (CSR fail / half-attach) pinned all EBIs (bitmap 0xffe0)
         * forever. Clear local sessions and drop the UE regardless.
         */
        if (!MME_SESSION_RELEASE_PENDING(mme_ue)) {
            mme_sess_t *sess = NULL, *next_sess = NULL;
            sgw_ue_t *sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);

            /*
             * If the sessions exist at the SGW, tear them down on S11 as
             * well: the local-only clear stranded the PDN at SGW/PGW
             * forever. UE removal then continues in the Delete Session
             * Response handler (UE_CONTEXT_REMOVE, ECM-IDLE path), safely
             * outside this FSM dispatch.
             */
            if (mme_sess_first(mme_ue) && sgw_ue && sgw_ue->sgw_s11_teid) {
                mme_gtp_send_delete_all_sessions(NULL, mme_ue,
                        OGS_GTP_DELETE_SEND_RELEASE_WITH_UE_CONTEXT_REMOVE);
                if (MME_SESSION_RELEASE_PENDING(mme_ue))
                    return;
            }

            ogs_list_for_each_safe(&mme_ue->sess_list, next_sess, sess)
                MME_SESS_CLEAR(sess);
            OGS_FSM_TRAN(s, &emm_state_ue_context_will_remove);
        }
        return;
    }

    if (cmd == OGS_DIAM_S6A_CMD_CODE_AUTHENTICATION_INFORMATION) {
        ogs_warn("[%s] S6a AIR timeout", mme_ue->imsi_bcd);
        mme_ue_progress(mme_ue, "s6a_air_timeout");
    } else if (cmd == OGS_DIAM_S6A_CMD_CODE_UPDATE_LOCATION) {
        ogs_warn("[%s] S6a ULR timeout", mme_ue->imsi_bcd);
        mme_ue_progress(mme_ue, "s6a_ulr_timeout");
    } else {
        ogs_warn("[%s] S6a timeout for unexpected cmd=%u",
                mme_ue->imsi_bcd, cmd);
    }

    if (cmd == OGS_DIAM_S6A_CMD_CODE_AUTHENTICATION_INFORMATION &&
            mme_ue->gn.gtp_xact_id != OGS_INVALID_POOL_ID) {
        xact = ogs_gtp_xact_find_by_id(mme_ue->gn.gtp_xact_id);
        if (xact) {
            rv = mme_gtp1_send_sgsn_context_ack(mme_ue,
                    OGS_GTP1_CAUSE_AUTHENTICATION_FAILURE, xact);
            if (rv != OGS_OK)
                ogs_warn("Failed to send SGSN Context Ack (rv %d)", rv);
        }
    }

    if (mme_ue->nas_eps.type == MME_EPS_TYPE_ATTACH_REQUEST) {
        OGS_TLOG_INFO("Attach reject [OGS_NAS_EMM_CAUSE:%d]", emm_cause);
        r = nas_eps_send_attach_reject(
                enb_ue, mme_ue, emm_cause,
                OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
        ogs_expect(r == OGS_OK);
    } else if (mme_ue->nas_eps.type == MME_EPS_TYPE_TAU_REQUEST) {
        ogs_info("[%s] TAU reject [OGS_NAS_EMM_CAUSE:%d]",
                mme_ue->imsi_bcd, emm_cause);
        r = nas_eps_send_tau_reject(enb_ue, mme_ue, emm_cause);
        ogs_expect(r == OGS_OK);
    } else {
        ogs_warn("[%s] S6a timeout in unexpected EPS-Type[%d]",
                mme_ue->imsi_bcd, mme_ue->nas_eps.type);
    }

    r = s1ap_send_ue_context_release_command(enb_ue,
            S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
            S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0);
    ogs_expect(r == OGS_OK);

    OGS_FSM_TRAN(s, &emm_state_exception);
}

/*
 * Timer expiry events can be queued before a state transition clears them
 * (e.g. T3450 after ICS failure and S1 release). Drop these quietly.
 */
static bool emm_clear_stale_timer(mme_ue_t *mme_ue, int timer_id)
{
    ogs_assert(mme_ue);

    switch (timer_id) {
    case MME_TIMER_T3413:
        ogs_debug("[%s] Stale %s in EMM state; clearing",
                mme_ue->imsi_bcd, mme_timer_get_name(timer_id));
        CLEAR_MME_UE_TIMER(mme_ue->t3413);
        return true;
    case MME_TIMER_T3422:
        ogs_debug("[%s] Stale %s in EMM state; clearing",
                mme_ue->imsi_bcd, mme_timer_get_name(timer_id));
        CLEAR_MME_UE_TIMER(mme_ue->t3422);
        return true;
    case MME_TIMER_T3450:
        ogs_debug("[%s] Stale %s in EMM state; clearing",
                mme_ue->imsi_bcd, mme_timer_get_name(timer_id));
        CLEAR_MME_UE_TIMER(mme_ue->t3450);
        return true;
    case MME_TIMER_T3460:
        ogs_debug("[%s] Stale %s in EMM state; clearing",
                mme_ue->imsi_bcd, mme_timer_get_name(timer_id));
        CLEAR_MME_UE_TIMER(mme_ue->t3460);
        return true;
    case MME_TIMER_T3470:
        ogs_debug("[%s] Stale %s in EMM state; clearing",
                mme_ue->imsi_bcd, mme_timer_get_name(timer_id));
        CLEAR_MME_UE_TIMER(mme_ue->t3470);
        return true;
    case MME_TIMER_MOBILE_REACHABLE:
    case MME_TIMER_IMPLICIT_DETACH:
        /*
         * Do NOT silently discard these two.
         *
         * They are the ONLY lifetime bound a session-bearing context
         * has: the orphan sweep deliberately skips any UE that still
         * holds a session (mme-path.c), so clearing them here parks
         * the context -- and the PDN session it holds on the SGW-C and
         * on the home PGW -- forever.
         *
         * Measured in production: ~1.0M registered contexts against a
         * TAU + service-request rate that can only account for ~0.5M
         * present devices, with the count still growing; roaming
         * partners saw their session count go 20k -> 200k.
         *
         * Reaching here means the timer expired while the UE was NOT
         * in emm_state_registered. Mobile-reachable only fires
         * T3412 + margin after the S1 release, so a context still
         * stuck mid-procedure that long is dead, not in transit.
         * Tear it down the same way emm_state_registered does --
         * including Delete Session toward the SGW/PGW, so the roaming
         * partner's session is released too, not just ours.
         */
        CLEAR_MME_UE_TIMER(mme_ue->t_mobile_reachable);
        CLEAR_MME_UE_TIMER(mme_ue->t_implicit_detach);

        if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_ue_context_will_remove) ||
                mme_ue->ue_context_will_remove ||
                MME_SESSION_RELEASE_PENDING(mme_ue)) {
            /* Teardown already under way - do not start a second one. */
            ogs_debug("[%s] Stale %s while already removing; clearing",
                    mme_ue->imsi_bcd, mme_timer_get_name(timer_id));
            return true;
        }

        ogs_warn("[%s] %s expired in non-registered EMM state - "
                "implicitly detaching stale context",
                mme_ue->imsi_bcd, mme_timer_get_name(timer_id));

        mme_ue->detach_type = MME_DETACH_TYPE_MME_IMPLICIT;
        mme_metrics_detach(mme_ue, "implicit_stale");
        mme_send_delete_session_or_detach(
                enb_ue_find_by_id(mme_ue->enb_ue_id), mme_ue);

        if (mme_ue->ue_context_will_remove)
            mme_ue_enter_ue_context_will_remove(mme_ue);
        return true;
    case MME_TIMER_SGS_TS6_1:
        ogs_debug("[%s] Stale %s in EMM state; clearing",
                mme_ue->imsi_bcd, mme_timer_get_name(timer_id));
        mme_sgs_ts6_1_timer_stop(mme_ue);
        return true;
    case MME_TIMER_S6A:
        ogs_debug("[%s] Stale %s in EMM state; clearing",
                mme_ue->imsi_bcd, mme_timer_get_name(timer_id));
        mme_s6a_timer_stop(mme_ue);
        return true;
    default:
        return false;
    }
}

/*
 * A retransmission timer only proves the peer is silent if the MME kept up
 * with dispatch. While the event queue is deeper than the defer threshold,
 * the reply may already have arrived and be waiting behind us, so re-arm
 * without spending the UE's retry budget. Bounded, so a peer that really is
 * silent still reaches max_count.
 */
static bool emm_defer_retransmission(mme_ue_t *mme_ue, int timer_id)
{
    ogs_time_t lag;
    uint32_t *defer_count = NULL;
    ogs_timer_t *timer = NULL;

    ogs_assert(mme_ue);

    switch (timer_id) {
    case MME_TIMER_T3450:
        defer_count = &mme_ue->t3450.defer_count;
        timer = mme_ue->t3450.timer;
        break;
    case MME_TIMER_T3460:
        defer_count = &mme_ue->t3460.defer_count;
        timer = mme_ue->t3460.timer;
        break;
    case MME_TIMER_T3470:
        defer_count = &mme_ue->t3470.defer_count;
        timer = mme_ue->t3470.timer;
        break;
    default:
        return false;
    }

    lag = mme_event_lag();
    if (lag < MME_UE_TIMER_LAG_DEFER_THRESHOLD)
        return false;
    if (*defer_count >= MME_UE_TIMER_MAX_DEFER)
        return false;

    (*defer_count)++;
    if (timer)
        ogs_timer_start(timer, mme_timer_cfg(timer_id)->duration);

    ogs_debug("[%s] %s deferred, event lag %dms (defer %u/%u)",
            mme_ue->imsi_bcd, mme_timer_get_name(timer_id),
            (int)(lag / 1000), *defer_count, MME_UE_TIMER_MAX_DEFER);

    return true;
}

void emm_state_initial(ogs_fsm_t *s, mme_event_t *e)
{
    ogs_assert(s);

    mme_sm_debug(e);

    OGS_FSM_TRAN(s, &emm_state_de_registered);
}

void emm_state_final(ogs_fsm_t *s, mme_event_t *e)
{
    ogs_assert(s);

    mme_sm_debug(e);
}


void emm_state_de_registered(ogs_fsm_t *s, mme_event_t *e)
{
    int r;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(e);

    mme_sm_debug(e);

    EMM_FIND_UE_OR_RETURN(e, mme_ue);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        CLEAR_SERVICE_INDICATOR(mme_ue);
        CLEAR_MME_UE_ALL_TIMERS(mme_ue);
        break;
    case OGS_FSM_EXIT_SIG:
        break;

    case MME_EVENT_EMM_MESSAGE:
        common_register_state(s, e, EMM_COMMON_STATE_DEREGISTERED);
        break;

    case MME_EVENT_EMM_TIMER:
        switch (e->timer_id) {
        case MME_TIMER_T3470:
            if (emm_defer_retransmission(mme_ue, MME_TIMER_T3470))
                break;
            if (mme_ue->t3470.retry_count >=
                    mme_timer_cfg(MME_TIMER_T3470)->max_count) {
                ogs_warn("Retransmission of Identity-Request failed. "
                        "Stop retransmission");
                OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
            } else {
                r = nas_eps_send_identity_request(mme_ue);
                if (r == OGS_OK) {
                    mme_ue->t3470.retry_count++;
                } else {
                    ogs_warn("Identity request retransmit not sent");
                    if (++mme_ue->t3470.send_failure_count >=
                            MME_UE_TIMER_MAX_SEND_FAILURE)
                        mme_ue->t3470.retry_count =
                            mme_timer_cfg(MME_TIMER_T3470)->max_count;
                    ogs_timer_start(mme_ue->t3470.timer,
                            mme_timer_cfg(MME_TIMER_T3470)->duration);
                }
            }
            break;

        case MME_TIMER_SGS_TS6_1:
            emm_handle_sgs_ts6_1_timer(s, mme_ue);
            break;
        case MME_TIMER_S6A:
            emm_handle_s6a_timer(s, mme_ue);
            break;

        default:
            if (emm_clear_stale_timer(mme_ue, e->timer_id))
                break;
            ogs_error("Unknown timer[%s:%d]",
                    mme_timer_get_name(e->timer_id), e->timer_id);
        }
        break;

    default:
        ogs_error("Unknown event[%s]", mme_event_get_name(e));
    }
}

void emm_state_registered(ogs_fsm_t *s, mme_event_t *e)
{
    int r;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(e);

    mme_sm_debug(e);

    EMM_FIND_UE_OR_RETURN(e, mme_ue);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        /*
         * Keep the mme_ue_registered gauge in sync with EMM-REGISTERED.
         * Counting only on Attach Complete undercounted badly: UEs that
         * (re)register via TAU - the dominant path after an MME restart,
         * and one that often completes without a TAU Complete when no
         * GUTI is reallocated - never hit the attach path. The increment
         * itself is idempotent per context (metrics_registered flag), so
         * repeated entries are harmless.
         */
        mme_metrics_ue_registered_inc(mme_ue);
        break;
    case OGS_FSM_EXIT_SIG:
        break;

    case MME_EVENT_EMM_MESSAGE:
        common_register_state(s, e, EMM_COMMON_STATE_REGISTERED);
        break;

    case MME_EVENT_EMM_TIMER:
        switch (e->timer_id) {
        case MME_TIMER_T3413:
            if (mme_ue->t3413.retry_count >=
                    mme_timer_cfg(MME_TIMER_T3413)->max_count) {
                /* Paging failed */
                mme_ue_warn(mme_ue, NULL, "emm", NULL,
                        "Paging failed, stop paging");
                CLEAR_MME_UE_TIMER(mme_ue->t3413);
                mme_ue->paging.failed = true;

                if (MME_PAGING_ONGOING(mme_ue))
                    mme_send_after_paging(mme_ue, true);
            } else {
                mme_ue->t3413.retry_count++;
                /*
                 * If t3413 is timeout, the saved pkbuf is used.
                 * We don't have to set CNDomain.
                 * So, we just set CNDomain to 0
                 */
                r = s1ap_send_paging(mme_ue, 0);
                if (r != OGS_OK)
                    ogs_warn("[%s] paging retransmit failed (eNB/S1 gone?)",
                            mme_ue->imsi_bcd);
            }
            break;

        case MME_TIMER_T3470:
            if (emm_defer_retransmission(mme_ue, MME_TIMER_T3470))
                break;
            if (mme_ue->t3470.retry_count >=
                    mme_timer_cfg(MME_TIMER_T3470)->max_count) {
                ogs_warn("Retransmission of Identity-Request failed. "
                        "Stop retransmission");
                OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
            } else {
                r = nas_eps_send_identity_request(mme_ue);
                if (r == OGS_OK) {
                    mme_ue->t3470.retry_count++;
                } else {
                    ogs_warn("Identity request retransmit not sent");
                    if (++mme_ue->t3470.send_failure_count >=
                            MME_UE_TIMER_MAX_SEND_FAILURE)
                        mme_ue->t3470.retry_count =
                            mme_timer_cfg(MME_TIMER_T3470)->max_count;
                    ogs_timer_start(mme_ue->t3470.timer,
                            mme_timer_cfg(MME_TIMER_T3470)->duration);
                }
            }
            break;

        case MME_TIMER_T3422:
            if (mme_ue->t3422.retry_count >=
                    mme_timer_cfg(MME_TIMER_T3422)->max_count) {
                ogs_warn("Retransmission of Detach Request failed. "
                        "Stop retransmission");
                OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
            } else {
                mme_ue->t3422.retry_count++;
                r = nas_eps_send_detach_request(mme_ue);
                ogs_expect(r == OGS_OK);
            }
            break;

        case MME_TIMER_MOBILE_REACHABLE:
            ogs_info("[%s] Mobile Reachable timer expired", mme_ue->imsi_bcd);
            CLEAR_MME_UE_TIMER(mme_ue->t_mobile_reachable);
        /*
         * TS 24.301
         * Section 5.3.5
         * Handling of the periodic tracking area update timer and
         * mobile reachable timer (S1 mode only)
         *
         * The periodic tracking area updating procedure is used to
         * periodically notify the availability of the UE to the network.
         * The procedure is controlled in the UE by timer T3412.
         * The value of timer T3412 is sent by the network to the UE
         * in the ATTACH ACCEPT message and can be sent in the TRACKING AREA
         * UPDATE ACCEPT message. The UE shall apply this value in all tracking
         * areas of the list of tracking areas assigned to the UE
         * until a new value is received.
         *
         * If timer T3412 received by the UE in an ATTACH ACCEPT or TRACKING
         * AREA UPDATE ACCEPT message contains an indication that the timer is
         * deactivated or the timer value is zero, then timer T3412 is
         * deactivated and the UE shall not perform the periodic tracking area
         * updating procedure.
         *
         * Timer T3412 is reset and started with its initial value,
         * when the UE changes from EMM-CONNECTED to EMM-IDLE mode.
         *
         * Timer T3412 is stopped when the UE enters EMM-CONNECTED mode or
         * the EMM-DEREGISTERED state. If the UE is attached for emergency
         * bearer services, and timer T3412 expires, the UE shall not initiate
         * a periodic tracking area updating procedure, but shall locally detach
         * from the network. When the UE is camping on a suitable cell, it may
         * re-attach to regain normal service.
         *
         * When a UE is not attached for emergency bearer services, and timer
         * T3412 expires, the periodic tracking area updating procedure shall
         * be started and the timer shall be set to its initial value
         * for the next start.
         *
         * If the UE is not attached for emergency bearer services, the mobile
         * reachable timer shall be longer than T3412. In this case, by default,
         * the mobile reachable timer is 4 minutes greater than timer T3412.
         *
         * Upon expiry of the mobile reachable timer the network shall start
         * the implicit detach timer. The value of the implicit detach timer is
         * network dependent. If ISR is activated, the default value of
         * the implicit detach timer is 4 minutes greater than timer T3423.
         * If the implicit detach timer expires before the UE contacts
         * the network, the network shall implicitly detach the UE. If the MME
         * includes timer T3346 in the TRACKING AREA UPDATE REJECT message or
         * the SERVICE REJECT message and timer T3346 is greater than timer
         * T3412, the MME sets the mobile reachable timer and the implicit
         * detach timer such that the sum of the timer values is greater than
         * timer T3346.
         */
            ogs_timer_start(mme_ue->t_implicit_detach.timer,
                ogs_time_from_sec(
                    mme_time_implicit_detach_duration_for_ue(mme_ue)));
            break;

        case MME_TIMER_IMPLICIT_DETACH:
            ogs_info("[%s] Implicit Detach timer expired, detaching UE",
                mme_ue->imsi_bcd);

            /*
             * Reset the deferral flag for this implicit detach handling.
             * mme_send_delete_session_or_detach() may set this flag if the UE
             * must be removed locally (e.g., no S1 context exists).
             */
            mme_ue->ue_context_will_remove = false;

            CLEAR_MME_UE_TIMER(mme_ue->t_implicit_detach);
            /* TS 24.301 5.3.5
             * If the implicit detach timer expires before the UE contacts
             * the network, the network shall implicitly detach the UE.
             */
            mme_ue->detach_type = MME_DETACH_TYPE_MME_IMPLICIT;
            /*
             * Implicit detach was invisible in metrics: mme_detach_total
             * only ever saw origin "ue" / "network", so the reaper that
             * bounds every idle context could not be observed working
             * (or not working) at fleet scale. Count it explicitly.
             */
            mme_metrics_detach(mme_ue, "implicit");
            /* Always DSR now; do not wait for SGs DETACH-ACK. */
            mme_send_eps_detach_with_session_delete(
                    enb_ue_find_by_id(mme_ue->enb_ue_id), mme_ue);

            /*
             * Do not remove the UE context directly in this handler.
             *
             * If mme_send_delete_session_or_detach() decided that local removal
             * is required, transition to a dedicated state that will remove the
             * UE context on entry. Otherwise follow the normal de-registered
             * transition for implicit detach.
             */
            if (mme_ue->ue_context_will_remove == true)
                OGS_FSM_TRAN(s, &emm_state_ue_context_will_remove);
            else
                OGS_FSM_TRAN(s, &emm_state_de_registered);
            break;

        case MME_TIMER_T3450:
            emm_handle_t3450_timer(s, mme_ue);
            break;

        case MME_TIMER_SGS_TS6_1:
            emm_handle_sgs_ts6_1_timer(s, mme_ue);
            break;
        case MME_TIMER_S6A:
            emm_handle_s6a_timer(s, mme_ue);
            break;

        default:
            if (emm_clear_stale_timer(mme_ue, e->timer_id))
                break;
            ogs_error("Unknown timer[%s:%d]",
                    mme_timer_get_name(e->timer_id), e->timer_id);
        }
        break;

    default:
        ogs_error("Unknown event[%s]", mme_event_get_name(e));
    }
}

static void common_register_state(ogs_fsm_t *s, mme_event_t *e,
        emm_common_state_e state)
{
    int r, rv, xact_count = 0;

    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    mme_sgsn_t *sgsn = NULL;
    ogs_nas_eps_message_t *message = NULL;
    ogs_nas_rai_t rai;
    ogs_nas_security_header_type_t h;
    ogs_nas_p_tmsi_signature_t *ptmsi_sig = NULL;

    ogs_assert(e);

    mme_sm_debug(e);

    EMM_FIND_UE_OR_RETURN(e, mme_ue);

    /* If transition is from REGISTERED, allow restoration */
    if (state == EMM_COMMON_STATE_REGISTERED) {
        mme_ue->can_restore_context = 1;
        mme_ue_save_memento(mme_ue, &mme_ue->memento);
    } else if (state == EMM_COMMON_STATE_DEREGISTERED) {
        /* Transition from de-registered: do not restore */
        mme_ue->can_restore_context = 0;
    }

    switch (e->id) {
    case MME_EVENT_EMM_MESSAGE:
        message = e->nas_message;
        ogs_assert(message);

        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!enb_ue)
            enb_ue = enb_ue_find_by_id(e->enb_ue_id);
        if (!enb_ue) {
            ogs_warn("No S1 Context IMSI[%s] NAS-Type[%d] "
                    "ENB-UE-ID[%d:%d][%p:%p]",
                    mme_ue->imsi_bcd, message->emm.h.message_type,
                    e->enb_ue_id, mme_ue->enb_ue_id,
                    enb_ue_find_by_id(e->enb_ue_id),
                    enb_ue_find_by_id(mme_ue->enb_ue_id));
            /*
             * Detach must still Delete Session toward SGW/PGW even when
             * the S1 association is already gone; dropping here orphans
             * PDNs (seen in production with ignore_sgs, no SGs wait).
             */
            if (message->emm.h.message_type == OGS_NAS_EPS_DETACH_REQUEST &&
                    (SESSION_CONTEXT_IS_AVAILABLE(mme_ue) ||
                     !ogs_list_empty(&mme_ue->sess_list))) {
                mme_ue->detach_type = MME_DETACH_TYPE_REQUEST_FROM_UE;
                mme_send_delete_session_or_detach(NULL, mme_ue);
                OGS_FSM_TRAN(s, &emm_state_de_registered);
            }
            ogs_assert(e->pkbuf);
            /* perf: 1.7% of production CPU was NAS hexdumps on these
             * chronic error paths — rate-guard the dump, not the line */
            if (ogs_log_guard())
                ogs_log_hexdump(OGS_LOG_WARN,
                        e->pkbuf->data, e->pkbuf->len);
            break;
        }
        if (mme_ue->enb_ue_id != enb_ue->id)
            enb_ue_associate_mme_ue(enb_ue, mme_ue);

        ogs_mme_trace_set(enb_ue, mme_ue, NULL, "emm");

        h.type = e->nas_type;

        xact_count = mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR);

        if (message->emm.h.security_header_type
                == OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE) {
            ogs_mme_trace_set(enb_ue, mme_ue, NULL, "service-req");
            OGS_TLOG_INFO("Service request");

            if (state != EMM_COMMON_STATE_REGISTERED) {
                OGS_TLOG_INFO("Service request : Not registered");
                r = nas_eps_send_service_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            rv = emm_handle_service_request(
                    enb_ue, mme_ue, &message->emm.service_request);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_service_request() failed");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!MME_UE_HAVE_IMSI(mme_ue)) {
                ogs_info("Service request : Unknown UE");
                r = nas_eps_send_service_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            mme_metrics_service_request_attempt(mme_ue);

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_ue_error(mme_ue, enb_ue, "emm", NULL,
                        "No Security Context");
                r = nas_eps_send_service_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!SESSION_CONTEXT_IS_AVAILABLE(mme_ue)) {
                ogs_warn("No Session Context : IMSI[%s]", mme_ue->imsi_bcd);
                r = nas_eps_send_service_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!ACTIVE_EPS_BEARERS_IS_AVAIABLE(mme_ue)) {
                ogs_error("No active EPS bearers : IMSI[%s]", mme_ue->imsi_bcd);
                r = nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_NO_EPS_BEARER_CONTEXT_ACTIVATED);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            r = s1ap_send_initial_context_setup_request(mme_ue);
            if (r != OGS_OK) {
                mme_ue_service_error(mme_ue, enb_ue,
                        "InitialContextSetupRequest failed");
                mme_ue_service_progress(mme_ue, enb_ue, "ics_fail");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }
            mme_ue_service_info(mme_ue, enb_ue,
                    "InitialContextSetupRequest sent");
            mme_ue_service_progress(mme_ue, enb_ue, "ics_sent");
            mme_metrics_service_request_success(mme_ue);
            OGS_FSM_TRAN(s, &emm_state_registered);
            break;
        }

        switch (message->emm.h.message_type) {
        case OGS_NAS_EPS_IDENTITY_RESPONSE:
            if (mme_ue->nas_eps.type == 0) {
                ogs_warn("No Received NAS message");
                r = s1ap_send_error_indication2(mme_ue,
                    S1AP_Cause_PR_protocol, S1AP_CauseProtocol_semantic_error);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            OGS_TLOG_INFO("Identity response");
            CLEAR_MME_UE_TIMER(mme_ue->t3470);

            rv = emm_handle_identity_response(enb_ue, mme_ue,
                    &message->emm.identity_response);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_identity_response() failed");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!MME_UE_HAVE_IMSI(mme_ue)) {
                ogs_warn("Identity response without usable IMSI "
                        "(race / abort)");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
                    OGS_GTP_DELETE_SEND_AUTHENTICATION_REQUEST);

            if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
                mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                    xact_count) {
                mme_s6a_send_air(enb_ue, mme_ue, NULL);
            }

            OGS_FSM_TRAN(s, &emm_state_authentication);
            break;

        case OGS_NAS_EPS_ATTACH_REQUEST:
            OGS_TLOG_INFO("Attach request");
            rv = emm_handle_attach_request(
                    enb_ue, mme_ue, &message->emm.attach_request, e->pkbuf);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_attach_request() failed");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!MME_UE_HAVE_IMSI(mme_ue)) {
                CLEAR_MME_UE_TIMER(mme_ue->t3470);
                r = nas_eps_send_identity_request(mme_ue);
                ogs_expect(r == OGS_OK);
                break;
            }

            if (h.integrity_protected && SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                /*
                 * If the OLD ENB_UE is being maintained in MME-UE Context,
                 * it deletes the S1 Context after exchanging
                 * the UEContextReleaseCommand/Complete with the eNB
                 */
                CLEAR_S1_CONTEXT(mme_ue);

                mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
                    OGS_GTP_DELETE_HANDLE_PDN_CONNECTIVITY_REQUEST);

                if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
                    mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                        xact_count) {
                    rv = nas_eps_send_emm_to_esm(mme_ue,
                            &mme_ue->pdn_connectivity_request);
                    if (rv != OGS_OK) {
                        ogs_debug("nas_eps_send_emm_to_esm() failed");
                        r = nas_eps_send_attach_reject(enb_ue, mme_ue,
                                OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                                OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
                        ogs_expect(r == OGS_OK);
                        MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                        break;
                    }
                }

                OGS_FSM_TRAN(s, &emm_state_initial_context_setup);

            } else {
                mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
                    OGS_GTP_DELETE_SEND_AUTHENTICATION_REQUEST);

                if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
                    mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                        xact_count) {
                    mme_s6a_send_air(enb_ue, mme_ue, NULL);
                }

                OGS_FSM_TRAN(s, &emm_state_authentication);

            }
            break;

        case OGS_NAS_EPS_TRACKING_AREA_UPDATE_REQUEST:
            OGS_TLOG_INFO("Tracking area update request");
            rv = emm_handle_tau_request(enb_ue, mme_ue,
                    &message->emm.tracking_area_update_request, e->pkbuf);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_tau_request() failed");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (emm_tau_request_ue_comes_from_gb_or_iu(&message->emm.tracking_area_update_request)) {
                ogs_info("TAU request : UE comes from SGSN, attempt retrieving context");
                guti_to_rai_ptmsi(&mme_ue->next.guti, &rai, NULL);
                sgsn = mme_sgsn_find_by_routing_address(&rai, 0xffff);
                if (!sgsn) {
                    ogs_plmn_id_t plmn_id;
                    ogs_nas_to_plmn_id(&plmn_id, &rai.lai.nas_plmn_id);
                    ogs_warn("No SGSN route matching RAI[MCC:%u MNC:%u LAC:%u RAC:%u]",
                             ogs_plmn_id_mcc(&plmn_id), ogs_plmn_id_mnc(&plmn_id),
                             rai.lai.lac, rai.rac);
                    r = nas_eps_send_tau_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                    ogs_expect(r == OGS_OK);
                    MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                    break;
                }
                if (message->emm.tracking_area_update_request.presencemask & OGS_NAS_EPS_TRACKING_AREA_UPDATE_REQUEST_OLD_P_TMSI_SIGNATURE_TYPE)
                    ptmsi_sig = &message->emm.tracking_area_update_request.old_p_tmsi_signature;
                rv = mme_gtp1_send_sgsn_context_request(sgsn, mme_ue, ptmsi_sig);
                if (rv != OGS_OK) {
                    ogs_warn("[%s] Gn SGSN Context Request send failed",
                            mme_ue->imsi_bcd[0] ? mme_ue->imsi_bcd : "-");
                    r = nas_eps_send_tau_reject(enb_ue, mme_ue,
                            OGS_NAS_EMM_CAUSE_NETWORK_FAILURE);
                    ogs_expect(r == OGS_OK);
                    MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                    break;
                }
                /* Awaiting SGSN Context Response on Gn (TS 23.401 D.3.6). */
                break;
            }

            /*
             * Inter-MME TAU without S10 (or unknown foreign GUTI): do not
             * reject with #9. Fall back to Identification + authentication /
             * HSS like Attach (TS 24.301). If PDN context still cannot be
             * rebuilt after that, reject with #10 Implicitly detached so the
             * UE performs Attach.
             */
            if (!MME_UE_HAVE_IMSI(mme_ue)) {
                ogs_info("TAU request : Unknown UE - Identity Request");
                CLEAR_MME_UE_TIMER(mme_ue->t3470);
                r = nas_eps_send_identity_request(mme_ue);
                ogs_expect(r == OGS_OK);
                break;
            }

            if (!SESSION_CONTEXT_IS_AVAILABLE(mme_ue)) {
                ogs_warn("No PDN Connection (no S10/local session) : UE[%s] - "
                        "Implicitly detached", mme_ue->imsi_bcd);
                r = nas_eps_send_tau_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_IMPLICITLY_DETACHED);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!ACTIVE_EPS_BEARERS_IS_AVAIABLE(mme_ue)) {
                ogs_warn("No active EPS bearers : IMSI[%s]", mme_ue->imsi_bcd);
                r = nas_eps_send_tau_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_NO_EPS_BEARER_CONTEXT_ACTIVATED);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!h.integrity_protected || !SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_s6a_send_air(enb_ue, mme_ue, NULL);
                OGS_FSM_TRAN(&mme_ue->sm, &emm_state_authentication);
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            /*
             * <EMM-IDLE State>
             * 1. InitialUEMessage + Tracking area update request
             *    Active flag : No bearer establishment requested (0)
             *    EPS update type : TA updating (0) or Periodic updating (3)
             * 2. DownlinkNASTransport + Tracking area update accept
             *    EPS update result value : TA updated (0)
             * 3. UEContextReleaseCommand
             *    Cause : nas(2) + normal-release(0)
             * 4. UEContextReleaseComplete
             *
             * <EMM-IDLE State>
             * 1. InitialUEMessage + Tracking area update request
             *    Active flag : bearer establishment requested (1)
             *    EPS update type : Combined TA/LA updating with IMSI attach (2)
             * 2. InitialContextSetupRequest + Tracking area update accept
             *    EPS update result : Combined TA/LA updated (1)
             *    New GUTI
             * 3. InitialContextSetupResponse
             * 4. UplinkNASTransport + Tracking area update complete
             *
             * <De-registered State>
             * 1. S1SetupRequest/S1SetupResponse
             * 2. InitialUEMessage + Tracking area update request
             *    Active flag : bearer establishment requested (1)
             *    EPS update type : Periodic updating (3)
             * 3. InitialContextSetupRequest + Tracking area update accept
             *    EPS update result : TA updated (0)
             *    No GUTI
             * 4. InitialContextSetupResponse
             *
             * <Handover>
             * 1. HandoverNotify (Target)
             * 2. UplinkNASTransport + Tracking area update request (Target)
             *    Active flag : bearer establishment requested (1)
             *    EPS update type : TA updating (0)
             * 3. UEContextReleaseCommand (Source)
             *    Cause : radioNetwork(0) + successful-handover(2)
             * 4. UEcontextReleaseComplete (Source)
             * 5. DownlinkNASTransport + Tracking area update accept (Target)
             *    EPS update result : TA updated (0)
             *
             * <Handover + EMM-Idle State>
             * 1. HandoverNotify (Target)
             *
             * 2. UEContextReleaseCommand (Source)
             *    Cause : radioNetwork(0) + successful-handover(2)
             * 3. UEcontextReleaseComplete (Source)
             * 4. UEContextReleaseRequest (Target)
             *    Cause : transport(1) + transport-resource-unavailable(0)
             * 5. UEContextReleaseCommand (Target)
             *    Cause : nas(2) + normal-release(0)
             * 6. UEcontextReleaseComplete (Target)
             *
             * 7. InitialUEMessage + Tracking area update request (Target)
             *    Active flag : bearer establishment requested (1)
             *    EPS update type : TA updating (0)
             * 8. InitialContextSetupRequest + Tracking area update accept
             *    EPS update result : TA updated (0)
             *    New GUTI
             * 9. InitialContextSetupResponse (Target)
             *    EPS update result : TA updated (0)
             * 10. UplinkNASTransport + Tracking area update complete (Target)
             */

            /* Save tau-request message */
            mme_ue->tracking_area_update_request_presencemask =
                message->emm.tracking_area_update_request.presencemask;
            mme_ue->tracking_area_update_request_ebcs_value =
                message->emm.tracking_area_update_request.
                    eps_bearer_context_status.value;

            /* Determine S1AP procedure and store it for reuse */
            mme_ue->tracking_area_update_accept_proc =
                S1AP_ProcedureCode_id_downlinkNASTransport;
            if (e->s1ap_code == S1AP_ProcedureCode_id_initialUEMessage &&
                mme_ue->nas_eps.update.active_flag)
                mme_ue->tracking_area_update_accept_proc =
                    S1AP_ProcedureCode_id_InitialContextSetup;

            /* Update CSMAP from Tracking area update request */
            mme_ue->csmap = mme_csmap_find_for_ue(mme_ue);
            if (mme_ue->csmap &&
                ogs_global_conf()->parameter.ignore_sgs == false &&
                mme_ue->network_access_mode ==
                    OGS_NETWORK_ACCESS_MODE_PACKET_AND_CIRCUIT &&
                (mme_ue->nas_eps.update.value ==
                 OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING ||
                 mme_ue->nas_eps.update.value ==
                 OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING_WITH_IMSI_ATTACH)) {

                if (sgsap_send_location_update_request(mme_ue) != OGS_OK) {
                    /*
                     * SGs/VLR association down or send failed (was
                     * ogs_assert / TAU Reject #18). Continue Accept:
                     * fake_csfb → Combined; else EPS-only + #18.
                     */
                    ogs_error("[%s] Combined TAU: SGsAP Location-Update not "
                            "sent (VLR/SGs unavailable); continue without CS",
                            mme_ue->imsi_bcd);
                    mme_sgs_continue_without_cs(mme_ue, "sgsap_lu_send_failed");
                    break;
                }

            } else {

                if (mme_ue->nas_eps.update.active_flag) {

/*
 * TS33.401
 * 7 Security procedures between UE and EPS access network elements
 * 7.2 Handling of user-related keys in E-UTRAN
 * 7.2.7 Key handling for the TAU procedure when registered in E-UTRAN
 *
 * If the "active flag" is set in the TAU request message or
 * the MME chooses to establish radio bearers when there is pending downlink
 * UP data or pending downlink signalling, radio bearers will be established
 * as part of the TAU procedure and a KeNB derivation is necessary.
 */
                    ogs_kdf_kenb(mme_ue->kasme, mme_ue->ul_count.i32,
                            mme_ue->kenb);
                    ogs_kdf_nh_enb(mme_ue->kasme, mme_ue->kenb, mme_ue->nh);
                    mme_ue->nhcc = 1;

                    ogs_info("[%s] KDF update(active_flag=1)",
                            mme_ue->imsi_bcd);
                }

                /* check BCS regardless of active_flag */
                if (mme_ue->tracking_area_update_request_presencemask &
                    OGS_NAS_EPS_TRACKING_AREA_UPDATE_REQUEST_EPS_BEARER_CONTEXT_STATUS_PRESENT) {
                    ogs_info("[%s] TAU accept(active_flag=%d, BCS check)",
                        mme_ue->imsi_bcd,
                        mme_ue->nas_eps.update.active_flag);
                    mme_send_delete_session_or_tau_accept(enb_ue, mme_ue);
                } else {
                    ogs_info("[%s] TAU accept(active_flag=%d, No BCS)",
                        mme_ue->imsi_bcd,
                        mme_ue->nas_eps.update.active_flag);
                    mme_send_tau_accept_and_check_release(enb_ue, mme_ue);
                }
            }

            if (MME_NEXT_GUTI_IS_AVAILABLE(mme_ue)) {
                ogs_fatal("MME does not create new GUTI");
                ogs_assert_if_reached();
                OGS_FSM_TRAN(s, &emm_state_initial_context_setup);
            } else if (mme_ue->tracking_area_update_accept_proc ==
                        S1AP_ProcedureCode_id_InitialContextSetup &&
                    MME_NEXT_P_TMSI_IS_AVAILABLE(mme_ue)) {
                /*
                 * TAU Accept with ICS and a reallocated P-TMSI: the UE
                 * answers with TAU Complete, handled (with the T3450
                 * retransmit) in emm_state_initial_context_setup.
                 */
                OGS_FSM_TRAN(s, &emm_state_initial_context_setup);
            } else {
                /*
                 * No new GUTI/P-TMSI -> the UE will NOT send TAU
                 * Complete (TS 24.301 5.5.3.2.4) and the procedure is
                 * already finished. Parking in initial_context_setup
                 * here wedged the UE: the next EMM message (e.g. a
                 * follow-up TAU or Service Request) fell into the
                 * "Unknown message" hole and T3450 kept retransmitting
                 * an answer nobody would ever acknowledge.
                 */
                CLEAR_MME_UE_TIMER(mme_ue->t3450);
                OGS_FSM_TRAN(s, &emm_state_registered);
            }
            break;

        case OGS_NAS_EPS_EXTENDED_SERVICE_REQUEST:
            mme_ue_info(mme_ue, enb_ue, "extended-svc", NULL,
                    "Extended service request SERVICE_TYPE=%d",
                    message->emm.extended_service_request.service_type.value);

            rv = emm_handle_extended_service_request(
                    enb_ue, mme_ue, &message->emm.extended_service_request);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_extended_service_request() failed");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!MME_UE_HAVE_IMSI(mme_ue)) {
                ogs_warn("Extended Service request : Unknown UE");
                r = nas_eps_send_service_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!SESSION_CONTEXT_IS_AVAILABLE(mme_ue)) {
                ogs_warn("No PDN Connection : UE[%s]", mme_ue->imsi_bcd);
                r = nas_eps_send_service_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_ue_error(mme_ue, enb_ue, "emm", NULL,
                        "No Security Context");
                r = nas_eps_send_service_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            if (e->s1ap_code == S1AP_ProcedureCode_id_initialUEMessage) {
                ogs_debug("    Initial UE Message");

                if (!MME_CURRENT_P_TMSI_IS_AVAILABLE(mme_ue)) {
                    mme_ue_warn(mme_ue, enb_ue, "extended-svc", NULL,
                            "No P-TMSI (CSFB rejected) SERVICE_TYPE=%d",
                            mme_ue->nas_eps.service.value);
                    r = nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                    ogs_expect(r == OGS_OK);
                    enb_ue->relcause.group = S1AP_Cause_PR_nas;
                    enb_ue->relcause.cause = S1AP_CauseNas_normal_release;
                    mme_send_release_access_bearer_or_ue_context_release(
                            enb_ue);
                    break;
                }

                if (mme_ue->nas_eps.service.value ==
                        OGS_NAS_SERVICE_TYPE_CS_FALLBACK_FROM_UE ||
                    mme_ue->nas_eps.service.value ==
                    OGS_NAS_SERVICE_TYPE_CS_FALLBACK_EMERGENCY_CALL_FROM_UE) {
                    ogs_debug("    MO-CSFB-INDICATION[%d]",
                            mme_ue->nas_eps.service.value);
                    if (sgsap_send_mo_csfb_indication(mme_ue) != OGS_OK) {
                        /* Was ogs_assert() - SGs/VLR down must not abort MME */
                        ogs_error("[%s] MO-CSFB-Indication not sent "
                                "(VLR/SGs unavailable); rejecting CSFB",
                                mme_ue->imsi_bcd);
                        r = nas_eps_send_service_reject(enb_ue, mme_ue,
                            OGS_NAS_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE);
                        ogs_expect(r == OGS_OK);
                        MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                        break;
                    }
                } else if (mme_ue->nas_eps.service.value ==
                        OGS_NAS_SERVICE_TYPE_CS_FALLBACK_TO_UE) {
                    ogs_debug("    SERVICE_REQUEST[%d]",
                            mme_ue->nas_eps.service.value);
                    if (sgsap_send_service_request(
                            mme_ue, SGSAP_EMM_IDLE_MODE) != OGS_OK) {
                        /* Was ogs_assert() - SGs/VLR down must not abort MME */
                        ogs_error("[%s] SGsAP Service-Request not sent "
                                "(VLR/SGs unavailable); rejecting CSFB",
                                mme_ue->imsi_bcd);
                        r = nas_eps_send_service_reject(enb_ue, mme_ue,
                            OGS_NAS_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE);
                        ogs_expect(r == OGS_OK);
                        MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                        break;
                    }
                } else {
                    ogs_warn(" Unknown CSFB Service Type[%d]",
                            mme_ue->nas_eps.service.value);
                    r = nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                    ogs_expect(r == OGS_OK);
                    MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                    break;
                }

                r = s1ap_send_initial_context_setup_request(mme_ue);
                ogs_expect(r == OGS_OK);

            } else if (e->s1ap_code ==
                    S1AP_ProcedureCode_id_uplinkNASTransport) {
                ogs_debug("    Uplink NAS Transport");

                if (!MME_CURRENT_P_TMSI_IS_AVAILABLE(mme_ue)) {
                    mme_ue_warn(mme_ue, enb_ue, "extended-svc", NULL,
                            "No P-TMSI (CSFB rejected) SERVICE_TYPE=%d",
                            mme_ue->nas_eps.service.value);
                    r = nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                    ogs_expect(r == OGS_OK);
                    mme_send_s1_release_after_emm_failure(mme_ue);
                    break;
                }

                if (mme_ue->nas_eps.service.value ==
                        OGS_NAS_SERVICE_TYPE_CS_FALLBACK_FROM_UE ||
                    mme_ue->nas_eps.service.value ==
                    OGS_NAS_SERVICE_TYPE_CS_FALLBACK_EMERGENCY_CALL_FROM_UE) {
                    ogs_debug("    MO-CSFB-INDICATION[%d]",
                            mme_ue->nas_eps.service.value);
                    if (sgsap_send_mo_csfb_indication(mme_ue) != OGS_OK) {
                        /* Was ogs_assert() - SGs/VLR down must not abort MME */
                        ogs_error("[%s] MO-CSFB-Indication not sent "
                                "(VLR/SGs unavailable); rejecting CSFB",
                                mme_ue->imsi_bcd);
                        r = nas_eps_send_service_reject(enb_ue, mme_ue,
                            OGS_NAS_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE);
                        ogs_expect(r == OGS_OK);
                        MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                        break;
                    }
                } else if (mme_ue->nas_eps.service.value ==
                        OGS_NAS_SERVICE_TYPE_CS_FALLBACK_TO_UE) {
                    ogs_debug("    SERVICE_REQUEST[%d]",
                            mme_ue->nas_eps.service.value);
                    if (sgsap_send_service_request(
                            mme_ue, SGSAP_EMM_CONNECTED_MODE) != OGS_OK) {
                        /* Was ogs_assert() - SGs/VLR down must not abort MME */
                        ogs_error("[%s] SGsAP Service-Request not sent "
                                "(VLR/SGs unavailable); rejecting CSFB",
                                mme_ue->imsi_bcd);
                        r = nas_eps_send_service_reject(enb_ue, mme_ue,
                            OGS_NAS_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE);
                        ogs_expect(r == OGS_OK);
                        MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                        break;
                    }
                } else {
                    ogs_warn(" Unknown CSFB Service Type[%d]",
                            mme_ue->nas_eps.service.value);
                    r = nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                    ogs_expect(r == OGS_OK);
                    MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                    break;
                }

                r = s1ap_send_ue_context_modification_request(mme_ue);
                ogs_expect(r == OGS_OK);
            } else {
                ogs_error("Invalid Procedure Code[%d]", (int)e->s1ap_code);
            }
            break;

        case OGS_NAS_EPS_EMM_STATUS:
            ogs_warn("EMM STATUS : IMSI[%s] Cause[%d]",
                    mme_ue->imsi_bcd, message->emm.emm_status.emm_cause);
            break;

        case OGS_NAS_EPS_DETACH_REQUEST:
            ogs_info("[%s] Detach request", mme_ue->imsi_bcd);
            rv = emm_handle_detach_request(
                    enb_ue, mme_ue, &message->emm.detach_request_from_ue);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_detach_request() failed");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!MME_UE_HAVE_IMSI(mme_ue)) {
                ogs_warn("Detach request : Unknown UE");
                if (nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK)
                        != OGS_OK)
                    ogs_error("[%s] Service Reject failed",
                            MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_ue_error(mme_ue, enb_ue, "emm", NULL,
                        "No Security Context");
                if (nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK)
                        != OGS_OK)
                    ogs_error("[%s] Service Reject failed",
                            MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            /* Always DSR now; do not wait for SGs DETACH-ACK
             * (ACK often arrives after S1 is gone and previously skipped DSR). */
            mme_send_eps_detach_with_session_delete(enb_ue, mme_ue);

            OGS_FSM_TRAN(s, &emm_state_de_registered);
            break;

        case OGS_NAS_EPS_DETACH_ACCEPT:
            ogs_info("[%s] Detach accept", mme_ue->imsi_bcd);

            CLEAR_MME_UE_TIMER(mme_ue->t3422);

            r = s1ap_send_ue_context_release_command(enb_ue,
                    S1AP_Cause_PR_nas, S1AP_CauseNas_detach,
                    S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0);
            ogs_expect(r == OGS_OK);

            OGS_FSM_TRAN(s, &emm_state_de_registered);
            break;

        case OGS_NAS_EPS_UPLINK_NAS_TRANSPORT:
            ogs_debug("Uplink NAS Transport");
            ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
            if (MME_SGSAP_IS_CONNECTED(mme_ue)) {
                /* Was ogs_assert() - SGs/VLR down must not abort MME */
                if (sgsap_send_uplink_unitdata(mme_ue, &message->emm.
                        uplink_nas_transport.nas_message_container) != OGS_OK)
                    ogs_error("[%s] SGsAP Uplink-Unitdata (SMS) not sent "
                            "(VLR/SGs unavailable)", mme_ue->imsi_bcd);
            } else {
                S1AP_MME_UE_S1AP_ID_t MME_UE_S1AP_ID;
                S1AP_ENB_UE_S1AP_ID_t ENB_UE_S1AP_ID;
                mme_enb_t *enb = NULL;

                ogs_warn("No connection of MSC/VLR");
                MME_UE_S1AP_ID = enb_ue->mme_ue_s1ap_id;
                ENB_UE_S1AP_ID = enb_ue->enb_ue_s1ap_id;

                enb = mme_enb_find_by_id(enb_ue->enb_id);
                if (enb) {
                    r = s1ap_send_error_indication(enb,
                            &MME_UE_S1AP_ID, &ENB_UE_S1AP_ID,
                            S1AP_Cause_PR_transport,
                            S1AP_CauseTransport_transport_resource_unavailable);
                    ogs_expect(r == OGS_OK);
                } else
                    ogs_warn("eNB has already been removed");
            }
            break;

        case OGS_NAS_EPS_ATTACH_COMPLETE:
            ogs_warn("[%s] Attach complete in INVALID-STATE "
                    "(attach already finished or aborted)",
                        mme_ue->imsi_bcd);
            break;

        case OGS_NAS_EPS_TRACKING_AREA_UPDATE_COMPLETE:
            ogs_info("[%s] Tracking area update complete", mme_ue->imsi_bcd);

        /*
         * TS24.301
         * Section 4.4.4.3
         * Integrity checking of NAS signalling messages in the MME:
         *
         * Once the secure exchange of NAS messages has been established
         * for the NAS signalling connection, the receiving EMM or ESM entity
         * in the MME shall not process any NAS signalling messages
         * unless they have been successfully integrity checked by the NAS.
         * If any NAS signalling message, having not successfully passed
         * the integrity check, is received, then the NAS in the MME shall
         * discard that message. If any NAS signalling message is received,
         * as not integrity protected even though the secure exchange
         * of NAS messages has been established, then the NAS shall discard
         * this message.
         */
            h.type = e->nas_type;
            if (h.integrity_protected == 0) {
                ogs_error("[%s] No Integrity Protected", mme_ue->imsi_bcd);
                break;
            }

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_ue_error(mme_ue, enb_ue, "emm", NULL,
                        "No Security Context");
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            CLEAR_MME_UE_TIMER(mme_ue->t3450);

            /* Confirm GUTI */
            if (MME_NEXT_GUTI_IS_AVAILABLE(mme_ue))
                mme_ue_confirm_guti(mme_ue);

            /* Confirm P-TMSI */
            if (MME_NEXT_P_TMSI_IS_AVAILABLE(mme_ue)) {
                mme_ue_confirm_p_tmsi(mme_ue);

                if (sgsap_send_tmsi_reallocation_complete(mme_ue) != OGS_OK)
                    ogs_error("[%s] SGsAP TMSI-Reallocation-Complete not sent "
                            "(VLR/SGs unavailable)", mme_ue->imsi_bcd);

                if (!mme_ue->nas_eps.update.active_flag) {
                    enb_ue->relcause.group = S1AP_Cause_PR_nas;
                    enb_ue->relcause.cause = S1AP_CauseNas_normal_release;
                    mme_send_release_access_bearer_or_ue_context_release(
                            enb_ue);
                }
            }
            break;

        default:
            ogs_warn("Unknown message[%d]", message->emm.h.message_type);
        }
        break;

    default:
        ogs_fatal("Unknown event[%s]", mme_event_get_name(e));
        ogs_assert_if_reached();
    }
}

void emm_state_authentication(ogs_fsm_t *s, mme_event_t *e)
{
    int r, rv, xact_count;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    ogs_nas_eps_message_t *message = NULL;

    ogs_nas_eps_authentication_failure_t *authentication_failure = NULL;

    ogs_assert(s);
    ogs_assert(e);

    mme_sm_debug(e);

    EMM_FIND_UE_OR_RETURN(e, mme_ue);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        mme_ue->auth_synch_fail_count = 0;
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    case MME_EVENT_EMM_MESSAGE:
        message = e->nas_message;
        ogs_assert(message);

        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!enb_ue) {
            ogs_warn("No S1 Context IMSI[%s] NAS-Type[%d] "
                    "ENB-UE-ID[%d:%d][%p:%p]",
                    mme_ue->imsi_bcd, message->emm.h.message_type,
                    e->enb_ue_id, mme_ue->enb_ue_id,
                    enb_ue_find_by_id(e->enb_ue_id),
                    enb_ue_find_by_id(mme_ue->enb_ue_id));
            ogs_assert(e->pkbuf);
            /* perf: 1.7% of production CPU was NAS hexdumps on these
             * chronic error paths — rate-guard the dump, not the line */
            if (ogs_log_guard())
                ogs_log_hexdump(OGS_LOG_WARN,
                        e->pkbuf->data, e->pkbuf->len);
            break;
        }

        xact_count = mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR);

        switch (message->emm.h.message_type) {
        case OGS_NAS_EPS_AUTHENTICATION_RESPONSE:
            rv = emm_handle_authentication_response(enb_ue, mme_ue,
                    &message->emm.authentication_response);
            if (rv == OGS_ERROR) {
                ogs_debug("emm_handle_authentication_response() failed");
                r = nas_eps_send_authentication_reject(mme_ue);
                ogs_expect(r == OGS_OK);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }
            if (rv != OGS_OK) {
                /* OGS_DONE: procedure reject already sent (e.g. #23) */
                ogs_debug("emm_handle_authentication_response() rejected");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            mme_metrics_auth_success(mme_ue);

            OGS_FSM_TRAN(&mme_ue->sm, &emm_state_security_mode);
            break;
        case OGS_NAS_EPS_AUTHENTICATION_FAILURE:
            authentication_failure = &message->emm.authentication_failure;
            ogs_nas_authentication_failure_parameter_t
                *authentication_failure_parameter =
                    &authentication_failure->
                        authentication_failure_parameter;

            ogs_warn("Authentication failure");
            ogs_warn("    IMSI[%s] OGS_NAS_EMM_CAUSE[%d]", mme_ue->imsi_bcd,
                    authentication_failure->emm_cause);

            CLEAR_MME_UE_TIMER(mme_ue->t3460);

            switch (authentication_failure->emm_cause) {
            case OGS_NAS_EMM_CAUSE_MAC_FAILURE:
                ogs_warn("Authentication failure(MAC failure)");
                break;
            case OGS_NAS_EMM_CAUSE_NON_EPS_AUTHENTICATION_UNACCEPTABLE:
                ogs_error("Authentication failure"
                        "(Non-EPS authentication unacceptable)");
                break;
            case OGS_NAS_EMM_CAUSE_SYNCH_FAILURE:
                ogs_warn("[%s] Authentication failure(Synch failure[count=%d])",
                        mme_ue->imsi_bcd, mme_ue->auth_synch_fail_count);

                mme_ue->auth_synch_fail_count++;

                if (mme_ue->auth_synch_fail_count >= 2) {
                    ogs_warn("[%s] Too many authentication synch failures, "
                            "sending AUTHENTICATION REJECT", mme_ue->imsi_bcd);
                    break;
                }

                mme_s6a_send_air(enb_ue, mme_ue,
                        authentication_failure_parameter);
                return;
            default:
                ogs_error("Unknown OGS_NAS_EMM_CAUSE{%d] in Authentication"
                        " failure",
                        authentication_failure->emm_cause);
                break;
            }

            r = nas_eps_send_authentication_reject(mme_ue);
            ogs_expect(r == OGS_OK);
            MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
            break;

        case OGS_NAS_EPS_ATTACH_REQUEST:
            ogs_warn("[%s] Attach request", mme_ue->imsi_bcd);
            rv = emm_handle_attach_request(
                    enb_ue, mme_ue, &message->emm.attach_request, e->pkbuf);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_attach_request() failed");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
                OGS_GTP_DELETE_SEND_AUTHENTICATION_REQUEST);

            if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
                mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                    xact_count) {
                mme_s6a_send_air(enb_ue, mme_ue, NULL);
            }

            OGS_FSM_TRAN(s, &emm_state_authentication);
            break;
        case OGS_NAS_EPS_EMM_STATUS:
            ogs_warn("EMM STATUS : IMSI[%s] Cause[%d]",
                    mme_ue->imsi_bcd, message->emm.emm_status.emm_cause);
            break;
        case OGS_NAS_EPS_DETACH_REQUEST:
            ogs_warn("[%s] Detach request", mme_ue->imsi_bcd);
            rv = emm_handle_detach_request(
                    enb_ue, mme_ue, &message->emm.detach_request_from_ue);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_detach_request() failed");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!MME_UE_HAVE_IMSI(mme_ue)) {
                ogs_warn("Detach request : Unknown UE");
                if (nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK)
                        != OGS_OK)
                    ogs_error("[%s] Service Reject failed",
                            MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_ue_error(mme_ue, enb_ue, "emm", NULL,
                        "No Security Context");
                if (nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK)
                        != OGS_OK)
                    ogs_error("[%s] Service Reject failed",
                            MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            /* Always DSR now; do not wait for SGs DETACH-ACK
             * (ACK often arrives after S1 is gone and previously skipped DSR). */
            mme_send_eps_detach_with_session_delete(enb_ue, mme_ue);

            OGS_FSM_TRAN(s, &emm_state_de_registered);
            break;
        default:
            ogs_warn("Unknown message[%d]", message->emm.h.message_type);
            break;
        }
        break;
    case MME_EVENT_EMM_TIMER:
        switch (e->timer_id) {
        case MME_TIMER_T3460:
            if (emm_defer_retransmission(mme_ue, MME_TIMER_T3460))
                break;
            if (mme_ue->t3460.retry_count >=
                    mme_timer_cfg(MME_TIMER_T3460)->max_count) {
                ogs_warn("Retransmission of IMSI[%s] failed. "
                        "Stop retransmission", mme_ue->imsi_bcd);
                r = nas_eps_send_authentication_reject(mme_ue);
                if (r != OGS_OK)
                    /* S1 usually gone by now; reject is best-effort */
                    ogs_warn("[%s] Authentication reject not sent",
                            mme_ue->imsi_bcd);
                MME_RESTORE_CONTEXT_ON_FAILURE(mme_ue, s);
                break;
            } else {
                r = nas_eps_send_authentication_request(mme_ue);
                if (r == OGS_OK) {
                    mme_ue->t3460.retry_count++;
                } else {
                    ogs_warn("[%s] Authentication request retransmit "
                            "not sent", mme_ue->imsi_bcd);
                    if (++mme_ue->t3460.send_failure_count >=
                            MME_UE_TIMER_MAX_SEND_FAILURE)
                        mme_ue->t3460.retry_count =
                            mme_timer_cfg(MME_TIMER_T3460)->max_count;
                    ogs_timer_start(mme_ue->t3460.timer,
                            mme_timer_cfg(MME_TIMER_T3460)->duration);
                }
            }
            break;
        case MME_TIMER_SGS_TS6_1:
            emm_handle_sgs_ts6_1_timer(s, mme_ue);
            break;
        case MME_TIMER_S6A:
            emm_handle_s6a_timer(s, mme_ue);
            break;
        default:
            if (emm_clear_stale_timer(mme_ue, e->timer_id))
                break;
            ogs_error("Unknown timer[%s:%d]",
                    mme_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    default:
        ogs_error("Unknown event[%s]", mme_event_get_name(e));
        break;
    }
}

void emm_state_security_mode(ogs_fsm_t *s, mme_event_t *e)
{
    int r, rv, xact_count;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    ogs_nas_eps_message_t *message = NULL;
    ogs_nas_security_header_type_t h;

    ogs_assert(s);
    ogs_assert(e);

    mme_sm_debug(e);

    EMM_FIND_UE_OR_RETURN(e, mme_ue);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        CLEAR_MME_UE_TIMER(mme_ue->t3460);
        r = nas_eps_send_security_mode_command(mme_ue);
        if (r != OGS_OK)
            ogs_warn("[%s] Security mode command send failed",
                    mme_ue->imsi_bcd);
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    case MME_EVENT_EMM_MESSAGE:
        message = e->nas_message;
        ogs_assert(message);

        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!enb_ue) {
            ogs_warn("No S1 Context IMSI[%s] NAS-Type[%d] "
                    "ENB-UE-ID[%d:%d][%p:%p]",
                    mme_ue->imsi_bcd, message->emm.h.message_type,
                    e->enb_ue_id, mme_ue->enb_ue_id,
                    enb_ue_find_by_id(e->enb_ue_id),
                    enb_ue_find_by_id(mme_ue->enb_ue_id));
            ogs_assert(e->pkbuf);
            /* perf: 1.7% of production CPU was NAS hexdumps on these
             * chronic error paths — rate-guard the dump, not the line */
            if (ogs_log_guard())
                ogs_log_hexdump(OGS_LOG_WARN,
                        e->pkbuf->data, e->pkbuf->len);
            break;
        }

        xact_count = mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR);

        if (message->emm.h.security_header_type
                == OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE) {
            ogs_debug("Service request");
            r = nas_eps_send_service_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED);
            ogs_expect(r == OGS_OK);
            OGS_FSM_TRAN(s, &emm_state_exception);
            break;
        }

        switch (message->emm.h.message_type) {
        case OGS_NAS_EPS_SECURITY_MODE_COMPLETE:
            ogs_debug("Security mode complete");
            ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

            CLEAR_MME_UE_TIMER(mme_ue->t3460);

        /*
         * TS24.301
         * Section 4.4.4.3
         * Integrity checking of NAS signalling messages in the MME:
         *
         * Once the secure exchange of NAS messages has been established
         * for the NAS signalling connection, the receiving EMM or ESM entity
         * in the MME shall not process any NAS signalling messages
         * unless they have been successfully integrity checked by the NAS.
         * If any NAS signalling message, having not successfully passed
         * the integrity check, is received, then the NAS in the MME shall
         * discard that message. If any NAS signalling message is received,
         * as not integrity protected even though the secure exchange
         * of NAS messages has been established, then the NAS shall discard
         * this message.
         */
            h.type = e->nas_type;
            if (h.integrity_protected == 0) {
                ogs_error("[%s] No Integrity Protected", mme_ue->imsi_bcd);
                break;
            }

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_ue_error(mme_ue, enb_ue, "emm", NULL,
                        "No Security Context");
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            emm_handle_security_mode_complete(
                    enb_ue, mme_ue, &message->emm.security_mode_complete);

            ogs_kdf_kenb(mme_ue->kasme, mme_ue->ul_count.i32,
                    mme_ue->kenb);
            ogs_kdf_nh_enb(mme_ue->kasme, mme_ue->kenb, mme_ue->nh);
            mme_ue->nhcc = 1;

            /* Create New GUTI */
            mme_ue_new_guti(mme_ue);

             /* Special path when SGSN (Gn interface) is involved: */
            if (mme_ue->gn.gtp_xact_id != OGS_INVALID_POOL_ID) {
                ogs_gtp_xact_t *gtp_xact = ogs_gtp_xact_find_by_id(mme_ue->gn.gtp_xact_id);
                if (!gtp_xact) {
                    ogs_warn("Not xact found!");
                    OGS_FSM_TRAN(s, &emm_state_exception);
                    break;
                }
                uint8_t pti = OGS_POINTER_TO_UINT(gtp_xact->data);
                rv = mme_gtp1_send_sgsn_context_ack(mme_ue, OGS_GTP1_CAUSE_REQUEST_ACCEPTED, gtp_xact);
                if (rv != OGS_OK) {
                    ogs_warn("Tx SGSN Context Request failed(%d)", rv);
                    OGS_FSM_TRAN(s, &emm_state_exception);
                    break;
                }
                mme_ue->gn.gtp_xact_id = OGS_INVALID_POOL_ID;

                mme_sess_t *sess = mme_sess_find_by_pti(mme_ue, pti);
                ogs_assert(sess);
                mme_gtp_send_create_session_request(enb_ue, sess,
                                                    OGS_GTP_CREATE_IN_TRACKING_AREA_UPDATE);
                OGS_FSM_TRAN(s, &emm_state_initial_context_setup);
                break;
            }

            /*
             * TAU after Identity/Auth without transferred PDN (no S10): do
             * not ULR+accept a bearer-less TAU. Reject with #9 "UE identity
             * cannot be derived by the network" — integrity protected
             * (post-SMC), it makes the UE delete its foreign GUTI and
             * perform a fresh Attach. The previous #10 (Implicitly
             * detached) left some UEs looping TAU on T3411 every 10s
             * without ever re-attaching (prod 2026-07-26).
             */
            if (mme_ue->nas_eps.type == MME_EPS_TYPE_TAU_REQUEST &&
                !SESSION_CONTEXT_IS_AVAILABLE(mme_ue)) {
                ogs_info("[%s] TAU Identity/Auth OK but no PDN context "
                        "(no S10); TAU reject #9 "
                        "(UE identity cannot be derived)",
                        mme_ue->imsi_bcd);
                r = nas_eps_send_tau_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
                ogs_expect(r == OGS_OK);
                r = s1ap_send_ue_context_release_command(enb_ue,
                        S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
                        S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0);
                ogs_expect(r == OGS_OK);
                OGS_FSM_TRAN(s, &emm_state_exception);
                break;
            }

            mme_s6a_send_ulr(enb_ue, mme_ue, 0);

            if (MME_NEXT_GUTI_IS_AVAILABLE(mme_ue)) {
                OGS_FSM_TRAN(s, &emm_state_initial_context_setup);
            } else {
                ogs_fatal("MME always creates new GUTI");
                ogs_assert_if_reached();
                OGS_FSM_TRAN(s, &emm_state_registered);
            }
            break;
        case OGS_NAS_EPS_SECURITY_MODE_REJECT:
            ogs_warn("Security mode reject : IMSI[%s] Cause[%d]",
                    mme_ue->imsi_bcd,
                    message->emm.security_mode_reject.emm_cause);
            CLEAR_MME_UE_TIMER(mme_ue->t3460);
            OGS_FSM_TRAN(s, &emm_state_exception);
            break;
        case OGS_NAS_EPS_ATTACH_REQUEST:
            ogs_warn("[%s] Attach request", mme_ue->imsi_bcd);
            rv = emm_handle_attach_request(
                    enb_ue, mme_ue, &message->emm.attach_request, e->pkbuf);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_attach_request() failed");
                if (mme_self()->maintenance_mode)
                    OGS_FSM_TRAN(s, &emm_state_ue_context_will_remove);
                else
                    OGS_FSM_TRAN(s, emm_state_exception);
                break;
            }

            mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
                OGS_GTP_DELETE_SEND_AUTHENTICATION_REQUEST);

            if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
                mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                    xact_count) {
                mme_s6a_send_air(enb_ue, mme_ue, NULL);
            }

            OGS_FSM_TRAN(s, &emm_state_authentication);
            break;
        case OGS_NAS_EPS_TRACKING_AREA_UPDATE_REQUEST:
            ogs_debug("Tracking area update request");
            r = nas_eps_send_tau_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED);
            ogs_expect(r == OGS_OK);
            OGS_FSM_TRAN(s, &emm_state_exception);
            break;
        case OGS_NAS_EPS_EMM_STATUS:
            ogs_warn("EMM STATUS : IMSI[%s] Cause[%d]",
                    mme_ue->imsi_bcd, message->emm.emm_status.emm_cause);
            break;
        case OGS_NAS_EPS_DETACH_REQUEST:
            ogs_warn("[%s] Detach request", mme_ue->imsi_bcd);
            rv = emm_handle_detach_request(
                    enb_ue, mme_ue, &message->emm.detach_request_from_ue);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_detach_request() failed");
                OGS_FSM_TRAN(s, emm_state_exception);
                break;
            }

            if (!MME_UE_HAVE_IMSI(mme_ue)) {
                ogs_warn("Detach request : Unknown UE");
                if (nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK)
                        != OGS_OK)
                    ogs_error("[%s] Service Reject failed",
                            MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
                OGS_FSM_TRAN(s, &emm_state_exception);
                break;
            }

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_ue_error(mme_ue, enb_ue, "emm", NULL,
                        "No Security Context");
                if (nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK)
                        != OGS_OK)
                    ogs_error("[%s] Service Reject failed",
                            MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
                OGS_FSM_TRAN(s, &emm_state_exception);
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            /* Always DSR now; do not wait for SGs DETACH-ACK
             * (ACK often arrives after S1 is gone and previously skipped DSR). */
            mme_send_eps_detach_with_session_delete(enb_ue, mme_ue);

            OGS_FSM_TRAN(s, &emm_state_de_registered);
            break;
        default:
            ogs_warn("Unknown message[%d]", message->emm.h.message_type);
            break;
        }
        break;
    case MME_EVENT_EMM_TIMER:
        switch (e->timer_id) {
        case MME_TIMER_T3460:
            if (emm_defer_retransmission(mme_ue, MME_TIMER_T3460))
                break;
            if (mme_ue->t3460.retry_count >=
                    mme_timer_cfg(MME_TIMER_T3460)->max_count) {
                ogs_warn("Retransmission of IMSI[%s] failed. "
                        "Stop retransmission", mme_ue->imsi_bcd);
                OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);

                r = nas_eps_send_attach_reject(
                        enb_ue_find_by_id(mme_ue->enb_ue_id), mme_ue,
                        OGS_NAS_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED,
                        OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
                if (r != OGS_OK)
                    ogs_warn("[%s] attach reject after T3460 max "
                            "retransmit failed to send",
                            mme_ue->imsi_bcd);
            } else {
                r = nas_eps_send_security_mode_command(mme_ue);
                if (r == OGS_OK) {
                    mme_ue->t3460.retry_count++;
                } else {
                    ogs_warn("[%s] Security mode command retransmit "
                            "not sent", mme_ue->imsi_bcd);
                    if (++mme_ue->t3460.send_failure_count >=
                            MME_UE_TIMER_MAX_SEND_FAILURE)
                        mme_ue->t3460.retry_count =
                            mme_timer_cfg(MME_TIMER_T3460)->max_count;
                    ogs_timer_start(mme_ue->t3460.timer,
                            mme_timer_cfg(MME_TIMER_T3460)->duration);
                }
            }
            break;
        case MME_TIMER_SGS_TS6_1:
            emm_handle_sgs_ts6_1_timer(s, mme_ue);
            break;
        case MME_TIMER_S6A:
            emm_handle_s6a_timer(s, mme_ue);
            break;
        default:
            if (emm_clear_stale_timer(mme_ue, e->timer_id))
                break;
            ogs_error("Unknown timer[%s:%d]",
                    mme_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    default:
        ogs_error("Unknown event[%s]", mme_event_get_name(e));
        break;
    }
}

void emm_state_initial_context_setup(ogs_fsm_t *s, mme_event_t *e)
{
    int r, rv, xact_count;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    ogs_nas_eps_message_t *message = NULL;
    ogs_nas_security_header_type_t h;

    ogs_assert(s);
    ogs_assert(e);

    mme_sm_debug(e);

    EMM_FIND_UE_OR_RETURN(e, mme_ue);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    case MME_EVENT_EMM_MESSAGE:
        message = e->nas_message;
        ogs_assert(message);

        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!enb_ue) {
            ogs_warn("No S1 Context IMSI[%s] NAS-Type[%d] "
                    "ENB-UE-ID[%d:%d][%p:%p]",
                    mme_ue->imsi_bcd, message->emm.h.message_type,
                    e->enb_ue_id, mme_ue->enb_ue_id,
                    enb_ue_find_by_id(e->enb_ue_id),
                    enb_ue_find_by_id(mme_ue->enb_ue_id));
            ogs_assert(e->pkbuf);
            /* perf: 1.7% of production CPU was NAS hexdumps on these
             * chronic error paths — rate-guard the dump, not the line */
            if (ogs_log_guard())
                ogs_log_hexdump(OGS_LOG_WARN,
                        e->pkbuf->data, e->pkbuf->len);
            break;
        }

        xact_count = mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR);

        if (message->emm.h.security_header_type
                == OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE) {
            ogs_debug("Service request");
            r = nas_eps_send_service_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
            ogs_expect(r == OGS_OK);
            OGS_FSM_TRAN(s, &emm_state_exception);
            break;
        }

        switch (message->emm.h.message_type) {
        case OGS_NAS_EPS_ATTACH_COMPLETE:
            ogs_mme_trace_set(enb_ue, mme_ue, NULL, "attach");
            if (MME_UE_HAVE_IMSI(mme_ue))
                ogs_trace_alias_refresh_imsi(
                        mme_ue->msisdn_bcd[0] ? mme_ue->msisdn_bcd : NULL,
                        mme_ue->imeisv_bcd[0] ? mme_ue->imeisv_bcd : NULL,
                        mme_ue->imsi_bcd);
            mme_ue_progress(mme_ue, "attach_complete");
            OGS_TLOG_INFO("Attach complete");

        /*
         * TS24.301
         * Section 4.4.4.3
         * Integrity checking of NAS signalling messages in the MME:
         *
         * Once the secure exchange of NAS messages has been established
         * for the NAS signalling connection, the receiving EMM or ESM entity
         * in the MME shall not process any NAS signalling messages
         * unless they have been successfully integrity checked by the NAS.
         * If any NAS signalling message, having not successfully passed
         * the integrity check, is received, then the NAS in the MME shall
         * discard that message. If any NAS signalling message is received,
         * as not integrity protected even though the secure exchange
         * of NAS messages has been established, then the NAS shall discard
         * this message.
         */
            h.type = e->nas_type;
            if (h.integrity_protected == 0) {
                ogs_error("[%s] No Integrity Protected", mme_ue->imsi_bcd);
                break;
            }

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_ue_error(mme_ue, enb_ue, "emm", NULL,
                        "No Security Context");
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            CLEAR_MME_UE_TIMER(mme_ue->t3450);

            rv = emm_handle_attach_complete(
                    enb_ue, mme_ue, &message->emm.attach_complete);
            if (rv != OGS_OK) {
                ogs_error("emm_handle_attach_complete() failed "
                        "in emm_state_initial_context_setup");
                OGS_FSM_TRAN(s, emm_state_exception);
                break;
            }

            /* Confirm GUTI */
            if (MME_NEXT_GUTI_IS_AVAILABLE(mme_ue))
                mme_ue_confirm_guti(mme_ue);

            /* Confirm P-TMSI */
            if (MME_NEXT_P_TMSI_IS_AVAILABLE(mme_ue)) {
                mme_ue_confirm_p_tmsi(mme_ue);
                if (sgsap_send_tmsi_reallocation_complete(mme_ue) != OGS_OK)
                    ogs_error("[%s] SGsAP TMSI-Reallocation-Complete not sent "
                            "(VLR/SGs unavailable)", mme_ue->imsi_bcd);
            }

            mme_metrics_attach_success(mme_ue);

            /* Local IMEI tracker: optional per-IMSI-PLMN binary MT SMS
             * when IMEI is new or changed for this IMSI. */
            mme_provisioning_sms_on_attach_complete(mme_ue);

            OGS_FSM_TRAN(s, &emm_state_registered);
            break;

        case OGS_NAS_EPS_TRACKING_AREA_UPDATE_COMPLETE:
            ogs_info("[%s] Tracking area update complete", mme_ue->imsi_bcd);

        /*
         * TS24.301
         * Section 4.4.4.3
         * Integrity checking of NAS signalling messages in the MME:
         *
         * Once the secure exchange of NAS messages has been established
         * for the NAS signalling connection, the receiving EMM or ESM entity
         * in the MME shall not process any NAS signalling messages
         * unless they have been successfully integrity checked by the NAS.
         * If any NAS signalling message, having not successfully passed
         * the integrity check, is received, then the NAS in the MME shall
         * discard that message. If any NAS signalling message is received,
         * as not integrity protected even though the secure exchange
         * of NAS messages has been established, then the NAS shall discard
         * this message.
         */
            h.type = e->nas_type;
            if (h.integrity_protected == 0) {
                ogs_error("[%s] No Integrity Protected", mme_ue->imsi_bcd);
                break;
            }

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_ue_error(mme_ue, enb_ue, "emm", NULL,
                        "No Security Context");
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            CLEAR_MME_UE_TIMER(mme_ue->t3450);

            /* Confirm GUTI */
            if (MME_NEXT_GUTI_IS_AVAILABLE(mme_ue))
                mme_ue_confirm_guti(mme_ue);

            /* Confirm P-TMSI */
            if (MME_NEXT_P_TMSI_IS_AVAILABLE(mme_ue)) {
                mme_ue_confirm_p_tmsi(mme_ue);

                if (sgsap_send_tmsi_reallocation_complete(mme_ue) != OGS_OK)
                    ogs_error("[%s] SGsAP TMSI-Reallocation-Complete not sent "
                            "(VLR/SGs unavailable)", mme_ue->imsi_bcd);

                if (!mme_ue->nas_eps.update.active_flag) {
                    enb_ue->relcause.group = S1AP_Cause_PR_nas;
                    enb_ue->relcause.cause = S1AP_CauseNas_normal_release;
                    mme_send_release_access_bearer_or_ue_context_release(
                            enb_ue);
                }
            }

            OGS_FSM_TRAN(s, &emm_state_registered);
            break;

        case OGS_NAS_EPS_ATTACH_REQUEST:
            ogs_mme_trace_set(enb_ue, mme_ue, NULL, "attach");
            OGS_TLOG_WARN("Attach request while waiting for "
                    "InitialContextSetupResponse (UE retry)");
            rv = emm_handle_attach_request(
                    enb_ue, mme_ue, &message->emm.attach_request, e->pkbuf);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_attach_request() failed");
                if (mme_self()->maintenance_mode)
                    OGS_FSM_TRAN(s, &emm_state_ue_context_will_remove);
                else
                    OGS_FSM_TRAN(s, emm_state_exception);
                break;
            }

            mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
                OGS_GTP_DELETE_SEND_AUTHENTICATION_REQUEST);

            if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
                mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                    xact_count) {
                mme_s6a_send_air(enb_ue, mme_ue, NULL);
            }

            OGS_FSM_TRAN(s, &emm_state_authentication);
            break;

        case OGS_NAS_EPS_EMM_STATUS:
            ogs_warn("EMM STATUS : IMSI[%s] Cause[%d]",
                    mme_ue->imsi_bcd, message->emm.emm_status.emm_cause);
            break;
        case OGS_NAS_EPS_DETACH_REQUEST:
            ogs_warn("[%s] Detach request", mme_ue->imsi_bcd);
            rv = emm_handle_detach_request(
                    enb_ue, mme_ue, &message->emm.detach_request_from_ue);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_detach_request() failed");
                OGS_FSM_TRAN(s, emm_state_exception);
                break;
            }

            if (!MME_UE_HAVE_IMSI(mme_ue)) {
                ogs_warn("Detach request : Unknown UE");
                if (nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK)
                        != OGS_OK)
                    ogs_error("[%s] Service Reject failed",
                            MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
                OGS_FSM_TRAN(s, &emm_state_exception);
                break;
            }

            if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                mme_ue_error(mme_ue, enb_ue, "emm", NULL,
                        "No Security Context");
                if (nas_eps_send_service_reject(enb_ue, mme_ue,
                        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK)
                        != OGS_OK)
                    ogs_error("[%s] Service Reject failed",
                            MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
                OGS_FSM_TRAN(s, &emm_state_exception);
                break;
            }

            /*
             * If the OLD ENB_UE is being maintained in MME-UE Context,
             * it deletes the S1 Context after exchanging
             * the UEContextReleaseCommand/Complete with the eNB
             */
            CLEAR_S1_CONTEXT(mme_ue);

            /* Always DSR now; do not wait for SGs DETACH-ACK
             * (ACK often arrives after S1 is gone and previously skipped DSR). */
            mme_send_eps_detach_with_session_delete(enb_ue, mme_ue);

            OGS_FSM_TRAN(s, &emm_state_de_registered);
            break;
        case OGS_NAS_EPS_SECURITY_MODE_COMPLETE:
            ogs_warn("[%s] Duplicated : Security mode complete",
                    mme_ue->imsi_bcd);
            break;
        default:
            ogs_warn("Unknown message[%d]", message->emm.h.message_type);
            break;
        }
        break;
    case MME_EVENT_EMM_TIMER:
        switch (e->timer_id) {
        case MME_TIMER_T3450:
            emm_handle_t3450_timer(s, mme_ue);
            break;
        case MME_TIMER_SGS_TS6_1:
            emm_handle_sgs_ts6_1_timer(s, mme_ue);
            break;
        case MME_TIMER_S6A:
            emm_handle_s6a_timer(s, mme_ue);
            break;
        default:
            if (emm_clear_stale_timer(mme_ue, e->timer_id))
                break;
            ogs_error("Unknown timer[%s:%d]",
                    mme_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    default:
        ogs_error("Unknown event[%s]", mme_event_get_name(e));
        break;
    }
}

/*
 * EMM state: UE context will remove.
 *
 * This state exists to perform UE context removal at a safe point,
 * after the triggering EMM event has completed its core handling
 * and a state transition has been decided.
 *
 * It is primarily used by implicit detach paths where the UE may be
 * removed locally (e.g., no S1 context) and we must avoid freeing
 * mme_ue inside the original EMM timer handler.
 */
void emm_state_ue_context_will_remove(ogs_fsm_t *s, mme_event_t *e)
{
    int r;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;

    ogs_assert(s);
    ogs_assert(e);

    mme_sm_debug(e);

    EMM_FIND_UE_OR_RETURN(e, mme_ue);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        /*
         * Remove UE context on state entry.
         *
         * If a live S1 context is still attached (e.g. a maintenance-mode
         * attach reject routed here), release it toward the eNB first.
         * Otherwise mme_ue_remove() below would orphan the enb_ue: it only
         * invalidates mme_ue->enb_ue_id and never frees or releases the S1
         * context, so the enb_ue would leak until the eNB happens to release
         * S1 on its own.
         *
         * S1_CONTEXT_REMOVE frees only the enb_ue when the release completes
         * (or when t_s1_holding fires after 30s should the eNB stay silent),
         * which lets us drop the mme_ue immediately as before. We sever the
         * enb_ue -> mme_ue back-reference so that deferred handler cannot touch
         * the mme_ue freed just below (its pool id could otherwise be reused).
         */
        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (enb_ue &&
                enb_ue->ue_ctx_rel_action == S1AP_UE_CTX_REL_INVALID_ACTION) {
            ogs_warn("[%s] UE context will remove: releasing orphaned S1 "
                    "context", mme_ue->imsi_bcd);
            r = s1ap_send_ue_context_release_command(enb_ue,
                    S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
                    S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
            ogs_expect(r == OGS_OK);
            enb_ue->mme_ue_id = OGS_INVALID_POOL_ID;
        }

        /*
         * MME_UE_REMOVE_WITH_PAGING_FAIL() handles corner cases where
         * paging procedures may still be in progress.
         */
        MME_UE_REMOVE_WITH_PAGING_FAIL(mme_ue);
        break;

    case OGS_FSM_EXIT_SIG:
        break;

    default:
        ogs_error("Unknown event[%s]", mme_event_get_name(e));
    }
}

void emm_state_exception(ogs_fsm_t *s, mme_event_t *e)
{
    int r, rv, xact_count;

    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    ogs_nas_eps_message_t *message = NULL;
    ogs_nas_security_header_type_t h;

    ogs_assert(e);
    mme_sm_debug(e);

    EMM_FIND_UE_OR_RETURN(e, mme_ue);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        CLEAR_SERVICE_INDICATOR(mme_ue);
        CLEAR_MME_UE_ALL_TIMERS(mme_ue);

        /*
         * Bound the S1/UE context lifetime on terminal EMM failure.
         *
         * emm_state_exception is the common sink for rejected or failed
         * procedures: attach reject for roaming-not-allowed / PLMN-not-allowed
         * / no-suitable-cells (mme-roam-access.c, emm-handler.c), authentication
         * reject, T3450 expiry, and assorted protocol errors. Many of those
         * paths only transmit the NAS reject PDU and then land here, leaving the
         * eNB to initiate the S1 release. When the eNB never sends a
         * UEContextReleaseRequest - common with foreign/misbehaving roaming eNBs
         * during a reject storm, or when the UE just drops the RRC connection -
         * neither the enb_ue (S1) nor the mme_ue context is ever freed. They
         * accumulate without bound (observed: enb_ue gauge > 230k and ~16 GB RSS
         * with only a few hundred registered UEs).
         *
         * Proactively release the S1 connection here, exactly as the S6a
         * AIA/ULA reject paths already do (see mme-sm.c). Going through
         * mme_send_delete_session_or_mme_ue_context_release() also tears down any
         * GTP session that may still exist before releasing S1. The underlying
         * s1ap_send_ue_context_release_command() arms t_s1_holding (30s), so the
         * context is reclaimed locally even if the eNB stays silent, and the
         * UE_CONTEXT_REMOVE action drops both the enb_ue and the mme_ue once the
         * release completes.
         *
         * Guards:
         *  - act only while an S1 context is still associated;
         *  - ue_ctx_rel_action != INVALID means a release is already in flight
         *    (e.g. CLEAR_S1_CONTEXT / HOLDING_S1_CONTEXT) - don't double-release;
         *  - a pending session release will drive the S1 release on GTP
         *    completion, so don't start a second teardown.
         */
        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (enb_ue &&
                enb_ue->ue_ctx_rel_action == S1AP_UE_CTX_REL_INVALID_ACTION &&
                !MME_SESSION_RELEASE_PENDING(mme_ue)) {
            ogs_warn("[%s] EMM exception: releasing S1/UE context "
                    "(no eNB-initiated release)", mme_ue->imsi_bcd);
            mme_send_delete_session_or_mme_ue_context_release(enb_ue, mme_ue);
        } else if (!enb_ue && !MME_SESSION_RELEASE_PENDING(mme_ue)) {
            /*
             * No S1 association: still tear down any live S11 PDN before
             * local UE remove. mme_ue_enter_ue_context_will_remove() only
             * frees local state and orphans SGW/PGW sessions.
             */
            ogs_warn("[%s] EMM exception: no S1 context, "
                    "Delete Session (if any) then remove UE",
                    mme_ue->imsi_bcd);
            mme_send_delete_session_or_mme_ue_context_release(NULL, mme_ue);
        }
        break;
    case OGS_FSM_EXIT_SIG:
        break;

    case MME_EVENT_EMM_MESSAGE:
        message = e->nas_message;
        ogs_assert(message);

        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
        if (!enb_ue)
            enb_ue = enb_ue_find_by_id(e->enb_ue_id);
        if (!enb_ue) {
            ogs_warn("No S1 Context IMSI[%s] NAS-Type[%d] "
                    "ENB-UE-ID[%d:%d][%p:%p]",
                    mme_ue->imsi_bcd, message->emm.h.message_type,
                    e->enb_ue_id, mme_ue->enb_ue_id,
                    enb_ue_find_by_id(e->enb_ue_id),
                    enb_ue_find_by_id(mme_ue->enb_ue_id));
            if (message->emm.h.message_type == OGS_NAS_EPS_DETACH_REQUEST &&
                    (SESSION_CONTEXT_IS_AVAILABLE(mme_ue) ||
                     !ogs_list_empty(&mme_ue->sess_list))) {
                mme_ue->detach_type = MME_DETACH_TYPE_REQUEST_FROM_UE;
                mme_send_delete_session_or_detach(NULL, mme_ue);
            }
            ogs_assert(e->pkbuf);
            /* perf: 1.7% of production CPU was NAS hexdumps on these
             * chronic error paths — rate-guard the dump, not the line */
            if (ogs_log_guard())
                ogs_log_hexdump(OGS_LOG_WARN,
                        e->pkbuf->data, e->pkbuf->len);
            break;
        }
        if (mme_ue->enb_ue_id != enb_ue->id)
            enb_ue_associate_mme_ue(enb_ue, mme_ue);

        h.type = e->nas_type;

        xact_count = mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR);

        switch (message->emm.h.message_type) {
        case OGS_NAS_EPS_DETACH_REQUEST:
            ogs_warn("[%s] Detach request in exception", mme_ue->imsi_bcd);
            rv = emm_handle_detach_request(
                    enb_ue, mme_ue, &message->emm.detach_request_from_ue);
            if (rv != OGS_OK)
                break;
            /* Only DSR if a PDN still exists on this mme_ue. */
            if (SESSION_CONTEXT_IS_AVAILABLE(mme_ue) ||
                    !ogs_list_empty(&mme_ue->sess_list))
                mme_send_eps_detach_with_session_delete(enb_ue, mme_ue);
            OGS_FSM_TRAN(s, &emm_state_de_registered);
            break;
        case OGS_NAS_EPS_ATTACH_REQUEST:
            ogs_warn("[%s] Attach request", mme_ue->imsi_bcd);
            rv = emm_handle_attach_request(
                    enb_ue, mme_ue, &message->emm.attach_request, e->pkbuf);
            if (rv != OGS_OK) {
                ogs_debug("emm_handle_attach_request() failed");
                if (mme_self()->maintenance_mode)
                    OGS_FSM_TRAN(s, &emm_state_ue_context_will_remove);
                else
                    OGS_FSM_TRAN(s, emm_state_exception);
                break;
            }

            if (!MME_UE_HAVE_IMSI(mme_ue)) {
                CLEAR_MME_UE_TIMER(mme_ue->t3470);
                r = nas_eps_send_identity_request(mme_ue);
                ogs_expect(r == OGS_OK);

                OGS_FSM_TRAN(s, &emm_state_de_registered);
                break;
            }

            if (h.integrity_protected && SECURITY_CONTEXT_IS_VALID(mme_ue)) {
                /*
                 * If the OLD ENB_UE is being maintained in MME-UE Context,
                 * it deletes the S1 Context after exchanging
                 * the UEContextReleaseCommand/Complete with the eNB
                 */
                CLEAR_S1_CONTEXT(mme_ue);

                mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
                    OGS_GTP_DELETE_HANDLE_PDN_CONNECTIVITY_REQUEST);

                if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
                    mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                        xact_count) {
                    rv = nas_eps_send_emm_to_esm(mme_ue,
                            &mme_ue->pdn_connectivity_request);
                    if (rv != OGS_OK) {
                        ogs_debug("nas_eps_send_emm_to_esm() failed");
                        r = nas_eps_send_attach_reject(enb_ue, mme_ue,
                                OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                                OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
                        ogs_expect(r == OGS_OK);
                        OGS_FSM_TRAN(s, &emm_state_exception);
                        break;
                    }
                }

                OGS_FSM_TRAN(s, &emm_state_initial_context_setup);

            } else {
                mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
                    OGS_GTP_DELETE_SEND_AUTHENTICATION_REQUEST);

                if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
                    mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                        xact_count) {
                    mme_s6a_send_air(enb_ue, mme_ue, NULL);
                }

                OGS_FSM_TRAN(s, &emm_state_authentication);

            }
            break;

        default:
            ogs_warn("Unknown message[%d]", message->emm.h.message_type);
        }
        break;

    case MME_EVENT_EMM_TIMER:
        /*
         * Exception entry clears all UE timers, but an expiry event that
         * was already queued (or a cross-thread race with the owner
         * shard) still lands here. These are stale by definition - the
         * context lifetime is bounded by the entry hook - so clear them
         * quietly instead of spamming "Unknown event[MME_EVENT_EMM_TIMER]"
         * errors.
         */
        switch (e->timer_id) {
        case MME_TIMER_SGS_TS6_1:
            emm_handle_sgs_ts6_1_timer(s, mme_ue);
            break;
        case MME_TIMER_S6A:
            emm_handle_s6a_timer(s, mme_ue);
            break;
        default:
            if (emm_clear_stale_timer(mme_ue, e->timer_id))
                break;
            ogs_error("Unknown timer[%s:%d]",
                    mme_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;

    default:
        ogs_error("Unknown event[%s]", mme_event_get_name(e));
    }
}
