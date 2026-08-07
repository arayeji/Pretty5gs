/*
 * Copyright (C) 2026 by Open5GS Contributors
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

#include "cgf-sm.h"
#include "gtpp-path.h"
#include "spool.h"
#include "worker.h"

/* Stack buffer for one MTU-safe DTRR payload (+ GTP'/IE overhead). */
#define CGF_BATCH_BUF_SIZE 4096

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static cgf_peer_t *active_peer(void)
{
    cgf_context_t *self = cgf_self();
    if (self->active_peer_idx >= self->num_of_peers) return NULL;
    return &self->peers[self->active_peer_idx];
}

static void switch_to_next_peer(void)
{
    cgf_context_t *self = cgf_self();
    uint32_t i, start = self->active_peer_idx;
    for (i = 1; i <= self->num_of_peers; i++) {
        uint32_t idx = (start + i) % self->num_of_peers;
        if (self->peers[idx].sock) {
            self->active_peer_idx = idx;
            ogs_warn("cgf: failover to peer %u='%s' (%s)",
                    idx, self->peers[idx].address_str,
                    self->peers[idx].role == CGF_PEER_ROLE_PRIMARY ?
                        "primary" : "secondary");
            return;
        }
    }
}

/*
 * Tear down in-flight DTRRs for one spool file and rewind to the last
 * confirmed offset. When `uncertain` is true the prior packets may have
 * reached the CGF without an ACK (timeout / failover / peer restart), so
 * the next send must use Send-possibly-duplicated (TS 32.295 §6.2.4.5.2).
 * Explicit CGF rejects are not uncertain.
 */
static void abort_file_pipeline(cgf_peer_t *peer, cgf_spool_file_t *file,
        bool uncertain)
{
    uint32_t i;

    if (!peer || !file) return;

    for (i = 0; i < CGF_MAX_INFLIGHT; i++) {
        cgf_xact_t *x = &peer->xacts[i];
        if (x->active && x->file == file)
            cgf_gtpp_free_xact(x);
    }
    cgf_spool_nack_batch(file);
    if (uncertain)
        cgf_spool_mark_possibly_dup(file);
}

static void abort_in_flight(cgf_peer_t *peer, const char *reason)
{
    uint32_t i;
    cgf_spool_file_t *nacked[CGF_MAX_INFLIGHT];
    uint32_t n_nacked = 0;

    if (cgf_gtpp_inflight_count(peer) == 0) return;
    ogs_warn("cgf: aborting in-flight xacts to '%s': %s",
            peer->address_str, reason);
    for (i = 0; i < CGF_MAX_INFLIGHT; i++) {
        cgf_xact_t *x = &peer->xacts[i];
        cgf_spool_file_t *f;
        uint32_t j;
        bool seen;

        if (!x->active) continue;

        f = x->file;
        if (f) {
            seen = false;
            for (j = 0; j < n_nacked; j++) {
                if (nacked[j] == f) { seen = true; break; }
            }
            if (!seen && n_nacked < CGF_MAX_INFLIGHT)
                nacked[n_nacked++] = f;
        }
        cgf_gtpp_free_xact(x);
    }
    for (i = 0; i < n_nacked; i++) {
        cgf_spool_nack_batch(nacked[i]);
        cgf_spool_mark_possibly_dup(nacked[i]);
    }
}

static bool peer_may_send(const cgf_peer_t *peer)
{
    return peer->state == CGF_PEER_STATE_UP ||
            peer->state == CGF_PEER_STATE_PROBING;
}

/* ------------------------------------------------------------------ */
/*  FSM entry points                                                  */
/* ------------------------------------------------------------------ */

void cgf_state_initial(ogs_fsm_t *s, ogs_event_t *e)
{
    (void)e;
    OGS_FSM_TRAN(s, cgf_state_running);
}

void cgf_state_final(ogs_fsm_t *s, ogs_event_t *e) { (void)s; (void)e; }

void cgf_state_running(ogs_fsm_t *s, ogs_event_t *e)
{
    cgf_event_t *ce = (cgf_event_t *)e;
    cgf_context_t *self = cgf_self();
    (void)s;

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        {
            uint32_t i;
            for (i = 0; i < self->num_of_peers; i++) {
                cgf_peer_t *p = &self->peers[i];
                if (p->sock) {
                    if (cgf_gtpp_send_echo_request(p) == OGS_OK)
                        p->state = CGF_PEER_STATE_PROBING;
                }
            }
        }
        ogs_timer_start(self->t_echo,
                ogs_time_from_sec(self->echo_interval_s));
        ogs_timer_start(self->t_rto,
                ogs_time_from_msec(self->request_rto_ms));
        ogs_timer_start(self->t_spool,
                ogs_time_from_msec(self->spool_poll_ms));
        break;

    case OGS_FSM_EXIT_SIG:
        break;

    case CGF_EVENT_ECHO_TIMER:
        cgf_sm_on_echo_tick();
        ogs_timer_start(self->t_echo,
                ogs_time_from_sec(self->echo_interval_s));
        break;

    case CGF_EVENT_RTO_TIMER:
        cgf_sm_on_rto_tick();
        ogs_timer_start(self->t_rto,
                ogs_time_from_msec(self->request_rto_ms));
        break;

    case CGF_EVENT_SPOOL_TIMER:
        cgf_sm_on_spool_tick();
        ogs_timer_start(self->t_spool,
                ogs_time_from_msec(self->spool_poll_ms));
        break;

    case CGF_EVENT_GTPP_RECV:
        if (ce->peer_idx >= 0 &&
                (uint32_t)ce->peer_idx < self->num_of_peers &&
                ce->pkbuf) {
            cgf_gtpp_handle_recv(&self->peers[ce->peer_idx], ce->pkbuf);
        }
        break;

    default:
        ogs_warn("cgf: unhandled event id=%d", e->id);
        break;
    }
}

/* ------------------------------------------------------------------ */
/*  Recv callbacks                                                    */
/* ------------------------------------------------------------------ */

void cgf_sm_on_echo_response(cgf_peer_t *peer, uint16_t seq,
        uint8_t cause, uint8_t recovery, bool recovery_present)
{
    (void)seq; (void)cause;

    peer->last_echo_received = ogs_time_now();
    peer->consecutive_missed_echoes = 0;
    if (peer->state != CGF_PEER_STATE_UP) {
        ogs_info("cgf: peer '%s' is UP", peer->address_str);
        peer->state = CGF_PEER_STATE_UP;
    }

    if (recovery_present) {
        if (peer->peer_restart_counter_valid &&
                peer->peer_restart_counter != recovery) {
            ogs_warn("cgf: peer '%s' restarted (recovery %u->%u)",
                    peer->address_str,
                    peer->peer_restart_counter, recovery);
            abort_in_flight(peer, "peer restarted");
            /* CGF restarted: restart our outbound sequence space too. */
            cgf_gtpp_reset_seq(peer);
        }
        peer->peer_restart_counter = recovery;
        peer->peer_restart_counter_valid = true;
    }

    cgf_sm_try_drain();
}

void cgf_sm_on_dtrr_response(cgf_peer_t *peer, uint16_t seq, uint8_t cause)
{
    cgf_xact_t *xact = cgf_gtpp_find_xact(peer, seq);
    cgf_spool_file_t *file;
    uint8_t ptc;
    uint16_t released_seq = 0;
    bool need_release = false;

    if (!xact) {
        ogs_debug("cgf: stale DTRR response seq=%u from '%s'",
                seq, peer->address_str);
        return;
    }

    file = xact->file;
    ptc = xact->ptc;

    if (cause < 128) {
        ogs_warn("cgf: DTRR seq=%u ptc=%u rejected by '%s' (cause=%u)",
                seq, ptc, peer->address_str, cause);
        if (file)
            abort_file_pipeline(peer, file, false);
        cgf_gtpp_free_xact(xact);
        cgf_sm_try_drain();
        return;
    }

    if (peer->state != CGF_PEER_STATE_UP) {
        ogs_info("cgf: peer '%s' is UP (DTRR accepted)",
                peer->address_str);
        peer->state = CGF_PEER_STATE_UP;
    }

    if (ptc == CGF_GTPP_PTC_RELEASE_DATA_REC) {
        ogs_info("cgf: Release seq=%u accepted by '%s'",
                seq, peer->address_str);
        cgf_gtpp_free_xact(xact);
        cgf_sm_try_drain();
        return;
    }

    if (file) {
        bool freed = false;

        if (!cgf_spool_ack_batch_ex(file, xact->batch_start,
                xact->records_in_batch, &freed)) {
            abort_file_pipeline(peer, file, true);
            cgf_gtpp_free_xact(xact);
            cgf_sm_try_drain();
            return;
        }
        /*
         * On a drain worker thread, `file` may be a stale/freed
         * pointer past this point — the worker caches it in
         * worker->active across ticks (unlike the main thread, which
         * always re-fetches cgf_spool_get_active()). Let the worker
         * null its cached pointer before we touch anything else that
         * (indirectly) reads worker->active, i.e. cgf_sm_try_drain()
         * below.
         */
        if (freed) cgf_worker_on_file_gone(file);

        ogs_debug("cgf: DTRR seq=%u ptc=%u accepted by '%s' "
                "(cause=%u, %u records)",
                seq, ptc, peer->address_str, cause, xact->records_in_batch);

        /*
         * Spec: after Possibly-Duplicated is accepted, CGF holds CDRs until
         * Release. Authorize forward to BD now that we treat this peer as
         * the delivery path for these packets.
         */
        if (ptc == CGF_GTPP_PTC_SEND_POSS_DUP) {
            need_release = true;
            released_seq = xact->seq;
        }
    }

    cgf_gtpp_free_xact(xact);

    if (need_release) {
        int rv = cgf_gtpp_send_release(peer, released_seq);
        if (rv != OGS_OK)
            ogs_warn("cgf: Release for seq=%u failed (%d); "
                    "CGF may hold Possibly-Dup CDRs until retry",
                    released_seq, rv);
    }

    cgf_sm_try_drain();
}

/* ------------------------------------------------------------------ */
/*  Timers                                                            */
/* ------------------------------------------------------------------ */

void cgf_sm_on_echo_tick(void)
{
    cgf_context_t *self = cgf_self();
    uint32_t i;

    /* Drain workers own the real peer sockets and run their own echo
     * tick (see worker.c); the main thread's peers[] entries have no
     * socket in that mode, so this loop would be a no-op anyway, but
     * skip it explicitly for clarity. */
    if (cgf_workers_enabled()) return;

    for (i = 0; i < self->num_of_peers; i++) {
        cgf_peer_t *p = &self->peers[i];
        if (!p->sock) continue;

        if (p->last_echo_sent > p->last_echo_received) {
            p->consecutive_missed_echoes++;
            if (p->state == CGF_PEER_STATE_UP)
                ogs_warn("cgf: peer '%s' missed echo (%u consecutive)",
                        p->address_str, p->consecutive_missed_echoes);
            if (p->consecutive_missed_echoes >=
                    self->failover_after_missed_echoes &&
                    p->state != CGF_PEER_STATE_DOWN) {
                ogs_warn("cgf: peer '%s' marked DOWN", p->address_str);
                p->state = CGF_PEER_STATE_DOWN;
                if ((uint32_t)(p - self->peers) == self->active_peer_idx) {
                    abort_in_flight(p, "peer went down");
                    switch_to_next_peer();
                }
            }
        }

        cgf_gtpp_send_echo_request(p);
    }
}

void cgf_sm_on_rto_tick(void)
{
    cgf_context_t *self = cgf_self();
    cgf_peer_t *p;
    ogs_time_t now = ogs_time_now();
    ogs_time_t rto = ogs_time_from_msec(self->request_rto_ms);
    uint32_t i;
    bool gave_up = false;

    if (cgf_workers_enabled()) return;

    p = active_peer();
    if (!p) return;

    for (i = 0; i < CGF_MAX_INFLIGHT; i++) {
        cgf_xact_t *x = &p->xacts[i];

        if (!x->active) continue;
        if (now - x->sent_at < rto) continue;

        if (x->retries >= self->request_retries) {
            ogs_warn("cgf: DTRR seq=%u ptc=%u gave up after %u retries",
                    x->seq, x->ptc, x->retries);
            if (x->file)
                abort_file_pipeline(p, x->file, true);
            else
                cgf_gtpp_free_xact(x);
            gave_up = true;
            continue;
        }

        cgf_gtpp_retransmit_xact(x);
    }

    if (gave_up) {
        p->state = CGF_PEER_STATE_DOWN;
        switch_to_next_peer();
        cgf_sm_try_drain();
    }
}

void cgf_sm_on_spool_tick(void)
{
    /* Workers claim files themselves (atomic rename out of ready/);
     * letting the main thread's cgf_spool_refill() also scan ready/
     * here would race their claims and could open (via g_active) a
     * file a worker is trying to claim at the same time. */
    if (cgf_workers_enabled()) return;

    cgf_spool_refill();
    cgf_sm_try_drain();
}

/* ------------------------------------------------------------------ */
/*  Drain                                                             */
/* ------------------------------------------------------------------ */

void cgf_sm_try_drain(void)
{
    cgf_context_t *self = cgf_self();
    cgf_peer_t *p;
    cgf_spool_file_t *f;
    uint32_t window;
    static uint8_t batch[CGF_BATCH_BUF_SIZE];

    /*
     * Called from cgf_sm_on_echo_response()/on_dtrr_response(), which
     * are shared between the main thread and every drain worker
     * thread (worker.c's recv callback calls cgf_gtpp_handle_recv()
     * directly). On a worker thread, drain worker-local state instead
     * of this function's `static batch` / cgf_self()->peers — that
     * buffer is not safe to share across concurrently-running worker
     * threads, and the active peer/file live on the worker, not here.
     */
    if (cgf_worker_self()) {
        cgf_worker_try_drain(cgf_worker_self());
        return;
    }

    p = active_peer();
    if (!p || !peer_may_send(p)) return;

    window = self->max_inflight;
    if (!window) window = 1;
    if (window > CGF_MAX_INFLIGHT) window = CGF_MAX_INFLIGHT;

    while (cgf_gtpp_inflight_count(p) < window) {
        size_t used = 0;
        size_t cap = self->max_bytes_per_packet;
        uint32_t n;
        int rv;

        f = cgf_spool_get_active();
        if (!f) {
            cgf_spool_refill();
            f = cgf_spool_get_active();
            if (!f) break;
        }

        if (f->send_offset >= f->data_len) break;

        if (cap > sizeof(batch)) cap = sizeof(batch);

        n = cgf_spool_stage_batch(f, batch, sizeof(batch), &used,
                self->max_records_per_packet, cap);
        if (n == 0) {
            if (f->send_offset < f->data_len)
                cgf_spool_quarantine(f);
            break;
        }

        rv = cgf_gtpp_send_data_record_transfer(p, batch, used, n, f,
                f->pending_batch_start);
        if (rv == OGS_RETRY)
            break;
        if (rv != OGS_OK) {
            ogs_warn("cgf: send failed, backing off");
            abort_file_pipeline(p, f, true);
            p->state = CGF_PEER_STATE_DOWN;
            switch_to_next_peer();
            break;
        }

        cgf_spool_commit_send(f, f->pending_batch_start, n);
    }
}
