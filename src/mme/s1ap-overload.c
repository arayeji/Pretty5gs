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

#include "S1AP_RRC-Establishment-Cause.h"

#include "mme-event.h"
#include "metrics.h"
#include "s1ap-io.h"
#include "s1ap-path.h"
#include "s1ap-overload.h"

#define OVL_TICK_SEC                    1
#define OVL_CONGEST_LEASE_SEC_DEFAULT   3
/*
 * Event-queue lag thresholds. 1500 ms is where the MME already
 * considers itself (not the peer) to be behind and defers NAS
 * retransmissions — MME_UE_TIMER_LAG_DEFER_THRESHOLD. Anything lower
 * would shed traffic on a busy-but-healthy MME, since the lag metric
 * rises to the worst value seen and only decays.
 */
#define OVL_LAG_HIGH_MS_DEFAULT         1500
#define OVL_LAG_CRITICAL_MS_DEFAULT     4000
/* seconds the raw lag level must hold before it throttles anything */
#define OVL_GLOBAL_SUSTAIN_SEC_DEFAULT  3
#define OVL_TRAFFIC_REDUCTION_DEFAULT   50
#define OVL_RESEND_INTERVAL_SEC_DEFAULT 10
#define OVL_RECOVERY_SEC_DEFAULT        5
#define OVL_BURST_MIN                   20

static int cfg_int(int v, int dflt)
{
    return v > 0 ? v : dflt;
}

static int congest_lease_sec(void)
{
    return cfg_int(mme_self()->overload.congest_lease_sec,
            OVL_CONGEST_LEASE_SEC_DEFAULT);
}

static int recovery_sec(void)
{
    return cfg_int(mme_self()->overload.recovery_sec,
            OVL_RECOVERY_SEC_DEFAULT);
}

static int resend_interval_sec(void)
{
    return cfg_int(mme_self()->overload.resend_interval_sec,
            OVL_RESEND_INTERVAL_SEC_DEFAULT);
}

static int traffic_reduction(void)
{
    int v = cfg_int(mme_self()->overload.traffic_reduction,
            OVL_TRAFFIC_REDUCTION_DEFAULT);

    /* TS 36.413: TrafficLoadReductionIndication is 1..99 */
    if (v > 99)
        v = 99;
    return v;
}

int mme_overload_config_set(const char *key, ogs_yaml_iter_t *iter)
{
    const char *v = NULL;

    ogs_assert(key);
    ogs_assert(iter);

    if (!strcmp(key, "enabled")) {
        mme_self()->overload.enabled = ogs_yaml_iter_bool(iter);
        return OGS_OK;
    }
    if (!strcmp(key, "signal_enb")) {
        mme_self()->overload.signal_enb = ogs_yaml_iter_bool(iter);
        return OGS_OK;
    }

    v = ogs_yaml_iter_value(iter);
    if (!v)
        return OGS_OK;

    if (!strcmp(key, "enb_initial_ue_rate"))
        mme_self()->overload.enb_initial_ue_rate = atoi(v);
    else if (!strcmp(key, "enb_initial_ue_burst"))
        mme_self()->overload.enb_initial_ue_burst = atoi(v);
    else if (!strcmp(key, "congest_lease_sec"))
        mme_self()->overload.congest_lease_sec = atoi(v);
    else if (!strcmp(key, "lag_high_ms"))
        mme_self()->overload.lag_high_ms = atoi(v);
    else if (!strcmp(key, "lag_critical_ms"))
        mme_self()->overload.lag_critical_ms = atoi(v);
    else if (!strcmp(key, "global_sustain_sec"))
        mme_self()->overload.global_sustain_sec = atoi(v);
    else if (!strcmp(key, "traffic_reduction"))
        mme_self()->overload.traffic_reduction = atoi(v);
    else if (!strcmp(key, "resend_interval_sec"))
        mme_self()->overload.resend_interval_sec = atoi(v);
    else if (!strcmp(key, "recovery_sec"))
        mme_self()->overload.recovery_sec = atoi(v);
    else
        return OGS_ERROR;

    if (mme_self()->overload.enb_initial_ue_rate < 0)
        mme_self()->overload.enb_initial_ue_rate = 0;
    if (mme_self()->overload.enb_initial_ue_burst < 0)
        mme_self()->overload.enb_initial_ue_burst = 0;

    return OGS_OK;
}

/*
 * MME-internal pressure. Event-queue lag is the one number that
 * already accounts for every source of MME slowness (S6a stalls, GTP
 * timeouts, a shard pegged by one eNB's retry storm) without needing a
 * per-subsystem probe.
 *
 * Raw, instantaneous reading. Nothing throttles on this directly: the
 * metric is a peak-with-decay, so a single slow dispatch shows up as a
 * spike, and network-wide shedding on a spike would be its own
 * outage. mme_overload_global_level() applies the hysteresis.
 */
static int lag_level_raw(void)
{
    ogs_time_t lag;
    int high, critical;

    high = cfg_int(mme_self()->overload.lag_high_ms, OVL_LAG_HIGH_MS_DEFAULT);
    critical = cfg_int(mme_self()->overload.lag_critical_ms,
            OVL_LAG_CRITICAL_MS_DEFAULT);
    if (critical < high)
        critical = high;

    lag = mme_event_lag();
    if (lag >= ogs_time_from_msec(critical))
        return 2;
    if (lag >= ogs_time_from_msec(high))
        return 1;
    return 0;
}

/*
 * Hysteresis-filtered global level, recomputed once a second by the
 * tick: a level must hold for global_sustain_sec before it takes
 * effect, and must be gone for recovery_sec before it is released.
 */
static int global_level = 0;

int mme_overload_global_level(void)
{
    if (!mme_self()->overload.enabled)
        return 0;
    return global_level;
}

static void global_level_update(ogs_time_t now)
{
    static ogs_time_t high_since, critical_since, down_since;
    static int last_logged;
    int raw = lag_level_raw();
    int sustain = cfg_int(mme_self()->overload.global_sustain_sec,
            OVL_GLOBAL_SUSTAIN_SEC_DEFAULT);
    int target = 0;

    if (raw >= 1) {
        if (!high_since)
            high_since = now;
    } else {
        high_since = 0;
    }
    if (raw >= 2) {
        if (!critical_since)
            critical_since = now;
    } else {
        critical_since = 0;
    }

    if (high_since && (now - high_since) >= ogs_time_from_sec(sustain))
        target = 1;
    if (critical_since && (now - critical_since) >= ogs_time_from_sec(sustain))
        target = 2;

    if (target >= global_level) {
        global_level = target;
        down_since = 0;
    } else {
        if (!down_since)
            down_since = now;
        if ((now - down_since) >= ogs_time_from_sec(recovery_sec())) {
            global_level = target;
            down_since = 0;
        }
    }

    if (global_level != last_logged) {
        if (global_level > last_logged)
            ogs_warn("MME overload level %d -> %d (event lag %dms): "
                    "shedding new access network-wide",
                    last_logged, global_level, (int)(mme_event_lag() / 1000));
        else
            ogs_info("MME overload level %d -> %d (event lag %dms)",
                    last_logged, global_level, (int)(mme_event_lag() / 1000));
        last_logged = global_level;
    }
}

/*
 * TX congestion lease. The IO thread refreshes congested_at every
 * second while the association's write queue stays above the
 * watermark, so an expired lease means the queue drained — or that a
 * heartbeat was dropped, which can only clear the state early, never
 * latch it.
 */
static int enb_tx_congestion_level(mme_enb_t *enb, ogs_time_t now)
{
    if (!enb->overload.congested_at)
        return 0;
    if ((now - enb->overload.congested_at) >=
            ogs_time_from_sec(congest_lease_sec()))
        return 0;

    return enb->overload.congested_depth >= 2 * s1ap_io_congest_depth() ?
        2 : 1;
}

int mme_overload_enb_level(mme_enb_t *enb)
{
    ogs_time_t now;
    int level, tx_level;

    ogs_assert(enb);

    if (!mme_self()->overload.enabled)
        return 0;

    now = ogs_time_now();
    level = mme_overload_global_level();
    tx_level = enb_tx_congestion_level(enb, now);
    if (tx_level > level)
        level = tx_level;

    enb->overload.level = level;
    if (level > 0)
        enb->overload.hot_at = now;

    return level;
}

/*
 * Telling the RAN to reject connections is the loudest thing the MME
 * can do, so it is reserved for the cases where this eNB is what is
 * wrong: its own downlink is backing up, or it is exceeding a rate cap
 * the operator set for it. Pressure that is purely MME-internal is
 * handled by shedding locally — reversible, invisible to the RAN — and
 * only escalates to OVERLOAD START once the MME is critically behind,
 * where the alternative is admitting attaches that will time out
 * anyway.
 */
static bool overload_may_signal(mme_enb_t *enb, int level, ogs_time_t now)
{
    if (!mme_self()->overload.signal_enb)
        return false;
    /* nothing to talk to yet — the eNB is not through S1 Setup */
    if (!enb->state.s1_setup_success)
        return false;
    /* OVERLOAD STOP must always be allowed to clear a START we sent */
    if (level <= 0)
        return true;
    /*
     * Likewise a level change once this eNB is already throttled:
     * otherwise an eNB told "emergency and MT only" at global level 2
     * would stay there while the MME relaxes to level 1, since the
     * milder START would be the message we refused to send.
     */
    if (enb->overload.signalled_level)
        return true;

    if (enb_tx_congestion_level(enb, now) > 0)
        return true;
    if (enb->overload.rate_shed_at &&
        (now - enb->overload.rate_shed_at) <
            ogs_time_from_sec(congest_lease_sec()))
        return true;

    return mme_overload_global_level() >= 2;
}

/*
 * OVERLOAD START/STOP for one eNB, with hysteresis so a queue that
 * oscillates around the watermark does not turn into an S1AP ping-pong.
 */
static void overload_signal_enb(mme_enb_t *enb, int level, ogs_time_t now)
{
    int r;

    ogs_assert(enb);

    if (!overload_may_signal(enb, level, now))
        return;

    if (level > 0) {
        if (enb->overload.signalled_level == level &&
            (now - enb->overload.signalled_at) <
                ogs_time_from_sec(resend_interval_sec()))
            return;

        r = s1ap_send_overload_start(enb, level, traffic_reduction());
        if (r != OGS_OK)
            return;

        mme_metrics_inst_global_inc(MME_METR_GLOB_CTR_S1AP_OVERLOAD_START);

        if (enb->overload.signalled_level != level)
            ogs_warn("eNB-id[0x%x] OVERLOAD START level=%d "
                    "(tx-queue:%d lag:%dms reduction:%d%%)",
                    enb->enb_id, level, enb->overload.congested_depth,
                    (int)(mme_event_lag() / 1000), traffic_reduction());
        enb->overload.signalled_level = level;
        enb->overload.signalled_at = now;
        return;
    }

    if (!enb->overload.signalled_level)
        return;

    /* Calm for recovery_sec beyond the congestion lease before STOP. */
    if (enb->overload.hot_at &&
        (now - enb->overload.hot_at) < ogs_time_from_sec(recovery_sec()))
        return;

    r = s1ap_send_overload_stop(enb);
    if (r != OGS_OK)
        return;

    ogs_info("eNB-id[0x%x] OVERLOAD STOP (shed %llu InitialUEMessage(s) "
            "total)", enb->enb_id,
            (unsigned long long)enb->overload.shed_total);
    enb->overload.signalled_level = 0;
    enb->overload.signalled_at = now;
}

void mme_overload_enb_congested(mme_enb_t *enb, int depth)
{
    ogs_time_t now;

    ogs_assert(enb);

    now = ogs_time_now();
    enb->overload.congested_at = now;
    enb->overload.congested_depth = depth;

    /*
     * Signal immediately rather than waiting for the tick: the whole
     * point of the early watermark is that the OVERLOAD START still
     * fits in the queue, and every 100 ms of delay is more RRC
     * connections the eNB let through.
     */
    overload_signal_enb(enb, mme_overload_enb_level(enb), now);
}

/* ---- ingress admission ---- */

static bool rrc_cause_is_priority(long cause, bool present)
{
    if (!present)
        return false;
    return cause == S1AP_RRC_Establishment_Cause_emergency ||
           cause == S1AP_RRC_Establishment_Cause_highPriorityAccess;
}

/*
 * Mobile-terminated access is the paging response: shedding it breaks
 * terminating calls and SMS for a UE that did nothing wrong, and it is
 * explicitly what the "permit ... mobile terminated services only"
 * overload action promises to keep working.
 */
static bool rrc_cause_is_mt(long cause, bool present)
{
    return present && cause == S1AP_RRC_Establishment_Cause_mt_Access;
}

static bool rrc_cause_shed(long cause, bool present, int level)
{
    if (rrc_cause_is_priority(cause, present))
        return false;
    if (rrc_cause_is_mt(cause, present))
        return false;

    if (level >= 2)
        return true;

    /* moderate: background/data access goes, a voice call attempt stays */
    if (present && cause == S1AP_RRC_Establishment_Cause_mo_VoiceCall)
        return false;

    return true;
}

/* Refill and take one token. true = allowed. */
static bool initial_ue_token_take(mme_enb_t *enb, ogs_time_t now)
{
    int rate = mme_self()->overload.enb_initial_ue_rate;
    int burst = mme_self()->overload.enb_initial_ue_burst;
    double elapsed_sec;

    if (rate <= 0)
        return true;

    if (burst <= 0)
        burst = rate * 2;
    if (burst < OVL_BURST_MIN)
        burst = OVL_BURST_MIN;

    if (!enb->overload.tokens_at) {
        enb->overload.tokens = burst;
        enb->overload.tokens_at = now;
    } else {
        elapsed_sec = (double)(now - enb->overload.tokens_at) /
                (double)OGS_USEC_PER_SEC;
        if (elapsed_sec > 0) {
            enb->overload.tokens += elapsed_sec * rate;
            if (enb->overload.tokens > burst)
                enb->overload.tokens = burst;
            enb->overload.tokens_at = now;
        }
    }

    if (enb->overload.tokens < 1.0)
        return false;

    enb->overload.tokens -= 1.0;
    return true;
}

static void shed_account(mme_enb_t *enb, const char *why, int level,
        ogs_time_t now)
{
    enb->overload.shed_total++;
    enb->overload.shed_window_count++;
    /*
     * Any shed counts as "hot", including a pure rate-cap rejection
     * with no congestion behind it. Without this, sustained rate
     * limiting would satisfy the OVERLOAD STOP condition on the very
     * next tick and flap START/STOP once a second.
     */
    enb->overload.hot_at = now;

    mme_metrics_inst_global_inc(MME_METR_GLOB_CTR_S1AP_INITIAL_UE_SHED);

    if (!enb->overload.shed_window ||
        (now - enb->overload.shed_window) >= ogs_time_from_sec(1)) {
        ogs_warn("eNB-id[0x%x] shed %u InitialUEMessage(s) in last window "
                "(%s, level:%d tx-queue:%d)", enb->enb_id,
                enb->overload.shed_window_count, why, level,
                enb->overload.congested_depth);
        enb->overload.shed_window = now;
        enb->overload.shed_window_count = 0;
    }
}

bool s1ap_admit_initial_ue(mme_enb_t *enb, long rrc_cause, bool present)
{
    ogs_time_t now;
    int level;

    ogs_assert(enb);

    if (!mme_self()->overload.enabled)
        return true;

    now = ogs_time_now();
    level = mme_overload_enb_level(enb);

    /*
     * Emergency and high-priority access bypass everything, including
     * the rate cap: a cap that drops emergency calls is worse than the
     * overload it protects against.
     */
    if (rrc_cause_is_priority(rrc_cause, present))
        return true;

    if (!initial_ue_token_take(enb, now)) {
        enb->overload.rate_shed_total++;
        enb->overload.rate_shed_at = now;
        shed_account(enb, "rate-limit", level, now);
        /*
         * A cell exceeding the cap the operator set for it should be
         * told to throttle at the source, even when nothing else on the
         * MME is under pressure.
         */
        overload_signal_enb(enb, level > 0 ? level : 1, now);
        return false;
    }

    if (level > 0 && rrc_cause_shed(rrc_cause, present, level)) {
        shed_account(enb, "overload", level, now);
        return false;
    }

    return true;
}

/* ---- 1 s evaluation tick ---- */

static ogs_timer_t *t_overload = NULL;

static void overload_tick(void)
{
    mme_enb_t *enb = NULL, *next = NULL;
    ogs_time_t now = ogs_time_now();
    int hot = 0;

    if (!mme_self()->overload.enabled) {
        /*
         * Turned off at runtime while eNBs are still throttled: release
         * them instead of leaving stale OVERLOAD START in force.
         */
        ogs_list_for_each_safe(&mme_self()->enb_list, next, enb) {
            if (!enb->overload.signalled_level)
                continue;
            if (s1ap_send_overload_stop(enb) == OGS_OK)
                enb->overload.signalled_level = 0;
        }
        mme_metrics_inst_global_set(MME_METR_GLOB_GAUGE_ENB_OVERLOADED, 0);
        global_level = 0;
        return;
    }

    global_level_update(now);

    ogs_list_for_each_safe(&mme_self()->enb_list, next, enb) {
        int level = mme_overload_enb_level(enb);

        overload_signal_enb(enb, level, now);
        if (level > 0)
            hot++;
    }

    mme_metrics_inst_global_set(MME_METR_GLOB_GAUGE_ENB_OVERLOADED, hot);
}

static void overload_timer_cb(void *data)
{
    (void)data;

    overload_tick();

    if (t_overload)
        ogs_timer_start(t_overload, ogs_time_from_sec(OVL_TICK_SEC));
}

void mme_overload_timer_start(void)
{
    if (t_overload)
        return;

    t_overload = ogs_timer_add(
            ogs_app()->timer_mgr, overload_timer_cb, NULL);
    ogs_assert(t_overload);
    ogs_timer_start(t_overload, ogs_time_from_sec(OVL_TICK_SEC));

    ogs_info("MME overload control: %s (signal_enb=%s, "
            "enb_initial_ue_rate=%d/s)",
            mme_self()->overload.enabled ? "on" : "off",
            mme_self()->overload.signal_enb ? "on" : "off",
            mme_self()->overload.enb_initial_ue_rate);
}

void mme_overload_timer_stop(void)
{
    if (!t_overload)
        return;

    ogs_timer_delete(t_overload);
    t_overload = NULL;
}
