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

#include "worker.h"
#include "gtpp-path.h"
#include "spool.h"

/* One MTU-safe DTRR payload buffer per drain attempt. MUST be a local
 * (stack) buffer, not `static` — cgf_worker_try_drain() runs
 * concurrently on every worker thread. */
#define CGF_WORKER_BATCH_BUF_SIZE 4096

typedef struct cgf_worker_s {
    int id;

    ogs_worker_t *ow;           /* thread + own pollset + own timer_mgr */
    ogs_timer_t *t_echo, *t_rto, *t_spool;

    /* Independent copy of the peer list: own sockets (own source
     * ports/GTP' sequence spaces), own liveness/failover state. */
    cgf_peer_t peers[CGF_MAX_PEERS];
    uint32_t num_of_peers;
    uint32_t active_peer_idx;

    /* Open files this worker is draining (send + wait-for-ACK). */
    cgf_spool_file_t *files[CGF_MAX_INFLIGHT];
    uint32_t num_files;

    volatile bool running;
} cgf_worker_t;

static cgf_worker_t *g_cgf_workers[CGF_MAX_WORKERS];
static int g_cgf_worker_count = 0;

static OGS_THREAD_LOCAL cgf_worker_t *cgf_tls_worker = NULL;

bool cgf_workers_enabled(void) { return g_cgf_worker_count > 0; }
cgf_worker_t *cgf_worker_self(void) { return cgf_tls_worker; }

static void worker_forget_file(cgf_worker_t *w, cgf_spool_file_t *file)
{
    uint32_t i;

    if (!w || !file) return;
    for (i = 0; i < w->num_files; i++) {
        if (w->files[i] != file) continue;
        if (i + 1 < w->num_files) {
            memmove(&w->files[i], &w->files[i + 1],
                    (w->num_files - i - 1) * sizeof(w->files[0]));
        }
        w->num_files--;
        w->files[w->num_files] = NULL;
        return;
    }
}

void cgf_worker_on_file_gone(cgf_spool_file_t *file)
{
    if (cgf_tls_worker)
        worker_forget_file(cgf_tls_worker, file);
}

/* ------------------------------------------------------------------ */
/*  Peer helpers (worker-scoped copies of the cgf-sm.c logic)          */
/* ------------------------------------------------------------------ */

static cgf_peer_t *worker_active_peer(cgf_worker_t *w)
{
    if (w->active_peer_idx >= w->num_of_peers) return NULL;
    return &w->peers[w->active_peer_idx];
}

static bool worker_peer_may_send(const cgf_peer_t *peer);

static void worker_switch_to_next_peer(cgf_worker_t *w)
{
    uint32_t i, start = w->active_peer_idx;

    if (!w->num_of_peers) return;
    for (i = 1; i <= w->num_of_peers; i++) {
        uint32_t idx = (start + i) % w->num_of_peers;
        if (w->peers[idx].sock) {
            w->active_peer_idx = idx;
            ogs_warn("cgf: worker %d failover to peer %u='%s' (%s)",
                    w->id, idx, w->peers[idx].address_str,
                    w->peers[idx].role == CGF_PEER_ROLE_PRIMARY ?
                        "primary" : "secondary");
            return;
        }
    }
}

static bool worker_peer_may_send(const cgf_peer_t *peer)
{
    return peer->state == CGF_PEER_STATE_UP ||
            peer->state == CGF_PEER_STATE_PROBING;
}

static cgf_peer_t *worker_peer_holding_file(cgf_worker_t *w,
        cgf_spool_file_t *file)
{
    uint32_t i, j;

    if (!file) return NULL;
    for (i = 0; i < w->num_of_peers; i++) {
        cgf_peer_t *p = &w->peers[i];
        for (j = 0; j < CGF_MAX_INFLIGHT; j++) {
            if (p->xacts[j].active && p->xacts[j].file == file)
                return p;
        }
    }
    return NULL;
}

static cgf_peer_t *worker_rr_pick_peer(cgf_worker_t *w, uint32_t window)
{
    uint32_t i, start;

    if (!w->num_of_peers) return NULL;
    start = w->active_peer_idx % w->num_of_peers;

    for (i = 0; i < w->num_of_peers; i++) {
        uint32_t idx = (start + i) % w->num_of_peers;
        cgf_peer_t *p = &w->peers[idx];

        if (!p->sock || !worker_peer_may_send(p)) continue;
        if (cgf_gtpp_inflight_count(p) >= window) continue;

        w->active_peer_idx = (idx + 1) % w->num_of_peers;
        return p;
    }
    return NULL;
}

static cgf_peer_t *worker_select_peer_for_file(cgf_worker_t *w,
        cgf_spool_file_t *file, uint32_t window)
{
    cgf_peer_t *p;

    if (cgf_self()->send_mode == CGF_SEND_MODE_ROUND_ROBIN) {
        p = worker_peer_holding_file(w, file);
        if (p) {
            if (!worker_peer_may_send(p) ||
                    cgf_gtpp_inflight_count(p) >= window)
                return NULL;
            return p;
        }
        return worker_rr_pick_peer(w, window);
    }

    p = worker_active_peer(w);
    if (!p || !worker_peer_may_send(p) ||
            cgf_gtpp_inflight_count(p) >= window)
        return NULL;
    return p;
}

/* Tear down in-flight DTRRs for `file` on `peer` and rewind to the
 * last confirmed offset (mirrors abort_file_pipeline() in cgf-sm.c). */
static void worker_abort_file_pipeline(cgf_peer_t *peer,
        cgf_spool_file_t *file, bool uncertain)
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

/* Abort every in-flight xact on `peer` and nack each distinct file
 * those xacts referenced (a worker may hold many open files). */
static void worker_abort_in_flight(cgf_worker_t *w, cgf_peer_t *peer,
        const char *reason)
{
    uint32_t i;
    cgf_spool_file_t *nacked[CGF_MAX_INFLIGHT];
    uint32_t n_nacked = 0;

    if (cgf_gtpp_inflight_count(peer) == 0) return;
    ogs_warn("cgf: worker %d aborting in-flight xacts to '%s': %s",
            w->id, peer->address_str, reason);
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
    (void)w;
}

/* ------------------------------------------------------------------ */
/*  Receive path                                                      */
/* ------------------------------------------------------------------ */

static void worker_recv_cb(short when, ogs_socket_t fd, void *data)
{
    cgf_peer_t *peer = data;
    cgf_worker_t *w = cgf_tls_worker;
    ogs_pkbuf_t *pkbuf;
    ogs_sockaddr_t from;
    ssize_t size;

    (void)when;
    ogs_assert(peer);
    ogs_assert(w);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_pkbuf_free(pkbuf);
        return;
    }
    ogs_pkbuf_trim(pkbuf, size);

    /*
     * Handle inline on this worker's own thread — NOT posted to
     * ogs_app()->queue. cgf_tls_worker is already set (thread_init ran
     * before the pollset ever polls), so cgf_sm_on_echo_response() /
     * cgf_sm_on_dtrr_response() (called from here) delegate their
     * cgf_sm_try_drain() call to cgf_worker_try_drain() automatically.
     */
    cgf_gtpp_handle_recv(peer, pkbuf);
    ogs_pkbuf_free(pkbuf);

    cgf_worker_try_drain(w);
}

/* ------------------------------------------------------------------ */
/*  File claiming                                                     */
/* ------------------------------------------------------------------ */

static bool worker_any_peer_has_room(cgf_worker_t *w, uint32_t window)
{
    uint32_t i;

    for (i = 0; i < w->num_of_peers; i++) {
        cgf_peer_t *p = &w->peers[i];
        if (!p->sock || !worker_peer_may_send(p)) continue;
        if (cgf_gtpp_inflight_count(p) < window) return true;
    }
    return false;
}

static int worker_claim_next_file(cgf_worker_t *w)
{
    char claimed[512];
    cgf_spool_file_t *f;
    uint32_t max_files = cgf_self()->max_active_files;

    if (!max_files) max_files = 1;
    if (max_files > CGF_MAX_INFLIGHT) max_files = CGF_MAX_INFLIGHT;
    if (w->num_files >= max_files) return OGS_ERROR;

    if (cgf_spool_claim_for_worker(w->id, claimed, sizeof(claimed)) != OGS_OK)
        return OGS_ERROR;

    f = cgf_spool_open_path(claimed);
    if (!f) {
        /* cgf_spool_open_path() already warned/quarantined; the file
         * is gone from processing/<id>/ one way or the other, try
         * again on the next tick. */
        return OGS_ERROR;
    }

    w->files[w->num_files++] = f;
    ogs_debug("cgf: worker %d claimed '%s' (%u open)",
            w->id, claimed, w->num_files);
    return OGS_OK;
}

/* Pick an open file that still has unsent bytes and whose peer has
 * spare window capacity. Returns NULL when nothing is sendable right
 * now (caller may claim another file or stop). */
static cgf_spool_file_t *worker_pick_sendable_file(cgf_worker_t *w,
        uint32_t window, cgf_peer_t **out_peer)
{
    uint32_t i;

    for (i = 0; i < w->num_files; i++) {
        cgf_spool_file_t *f = w->files[i];
        cgf_peer_t *p;

        if (!f || f->send_offset >= f->data_len) continue;
        p = worker_select_peer_for_file(w, f, window);
        if (!p) continue;
        if (out_peer) *out_peer = p;
        return f;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Drain (worker-local copy of cgf_sm_try_drain())                   */
/* ------------------------------------------------------------------ */

void cgf_worker_try_drain(cgf_worker_t *w)
{
    cgf_context_t *self = cgf_self();
    cgf_peer_t *p;
    cgf_spool_file_t *f;
    uint32_t window;
    uint32_t max_files;
    uint8_t batch[CGF_WORKER_BATCH_BUF_SIZE];

    ogs_assert(w);

    window = self->max_inflight;
    if (!window) window = 1;
    if (window > CGF_MAX_INFLIGHT) window = CGF_MAX_INFLIGHT;

    max_files = self->max_active_files;
    if (!max_files) max_files = 1;
    if (max_files > CGF_MAX_INFLIGHT) max_files = CGF_MAX_INFLIGHT;

    for (;;) {
        size_t used = 0;
        size_t cap = self->max_bytes_per_packet;
        uint32_t n;
        int rv;

        p = NULL;
        f = worker_pick_sendable_file(w, window, &p);
        if (!f) {
            /* No open file with unsent data + peer room. Claim another
             * while peers still have window capacity so ACKs in flight
             * on earlier files do not stall the pipeline. */
            if (w->num_files >= max_files) break;
            if (!worker_any_peer_has_room(w, window)) break;
            if (worker_claim_next_file(w) != OGS_OK) break;
            continue;
        }

        if (cap > sizeof(batch)) cap = sizeof(batch);

        n = cgf_spool_stage_batch(f, batch, sizeof(batch), &used,
                self->max_records_per_packet, cap);
        if (n == 0) {
            if (f->send_offset < f->data_len) {
                worker_forget_file(w, f);
                cgf_spool_quarantine(f);
            }
            continue;
        }

        rv = cgf_gtpp_send_data_record_transfer(p, batch, used, n, f,
                f->pending_batch_start);
        if (rv == OGS_RETRY)
            break;
        if (rv != OGS_OK) {
            ogs_warn("cgf: worker %d send failed to '%s', backing off",
                    w->id, p->address_str);
            worker_abort_file_pipeline(p, f, true);
            p->state = CGF_PEER_STATE_DOWN;
            if (self->send_mode != CGF_SEND_MODE_ROUND_ROBIN)
                worker_switch_to_next_peer(w);
            break;
        }

        cgf_spool_commit_send(f, f->pending_batch_start, n);
    }
}

/* ------------------------------------------------------------------ */
/*  Timers (worker-local copies of the cgf-sm.c tick handlers)        */
/* ------------------------------------------------------------------ */

static void worker_on_echo_tick(cgf_worker_t *w)
{
    cgf_context_t *self = cgf_self();
    uint32_t i;

    for (i = 0; i < w->num_of_peers; i++) {
        cgf_peer_t *p = &w->peers[i];
        if (!p->sock) continue;

        if (p->last_echo_sent > p->last_echo_received) {
            p->consecutive_missed_echoes++;
            if (p->state == CGF_PEER_STATE_UP)
                ogs_warn("cgf: worker %d peer '%s' missed echo "
                        "(%u consecutive)",
                        w->id, p->address_str, p->consecutive_missed_echoes);
            if (p->consecutive_missed_echoes >=
                    self->failover_after_missed_echoes &&
                    p->state != CGF_PEER_STATE_DOWN) {
                ogs_warn("cgf: worker %d peer '%s' marked DOWN",
                        w->id, p->address_str);
                p->state = CGF_PEER_STATE_DOWN;
                if (self->send_mode == CGF_SEND_MODE_ROUND_ROBIN ||
                        i == w->active_peer_idx) {
                    worker_abort_in_flight(w, p, "peer went down");
                    if (self->send_mode != CGF_SEND_MODE_ROUND_ROBIN)
                        worker_switch_to_next_peer(w);
                }
            }
        }

        cgf_gtpp_send_echo_request(p);
    }
}

static bool worker_peer_rto_tick(cgf_worker_t *w, cgf_peer_t *p,
        ogs_time_t now, ogs_time_t rto)
{
    cgf_context_t *self = cgf_self();
    uint32_t i;
    bool gave_up = false;

    if (!p) return false;

    for (i = 0; i < CGF_MAX_INFLIGHT; i++) {
        cgf_xact_t *x = &p->xacts[i];

        if (!x->active) continue;
        if (now - x->sent_at < rto) continue;

        if (x->retries >= self->request_retries) {
            ogs_warn("cgf: worker %d DTRR seq=%u ptc=%u gave up after "
                    "%u retries", w->id, x->seq, x->ptc, x->retries);
            if (x->file)
                worker_abort_file_pipeline(p, x->file, true);
            else
                cgf_gtpp_free_xact(x);
            gave_up = true;
            continue;
        }

        cgf_gtpp_retransmit_xact_on(p, x);
    }

    if (gave_up) {
        p->state = CGF_PEER_STATE_DOWN;
        if (self->send_mode != CGF_SEND_MODE_ROUND_ROBIN)
            worker_switch_to_next_peer(w);
    }
    return gave_up;
}

static void worker_on_rto_tick(cgf_worker_t *w)
{
    cgf_context_t *self = cgf_self();
    ogs_time_t now = ogs_time_now();
    ogs_time_t rto = ogs_time_from_msec(self->request_rto_ms);
    bool any_gave_up = false;

    if (self->send_mode == CGF_SEND_MODE_ROUND_ROBIN) {
        uint32_t i;
        for (i = 0; i < w->num_of_peers; i++) {
            if (worker_peer_rto_tick(w, &w->peers[i], now, rto))
                any_gave_up = true;
        }
    } else {
        any_gave_up = worker_peer_rto_tick(w, worker_active_peer(w),
                now, rto);
    }

    if (any_gave_up)
        cgf_worker_try_drain(w);
}

static void worker_echo_timer_expired(void *data)
{
    cgf_worker_t *w = data;
    worker_on_echo_tick(w);
    ogs_timer_start(w->t_echo,
            ogs_time_from_sec(cgf_self()->echo_interval_s));
}

static void worker_rto_timer_expired(void *data)
{
    cgf_worker_t *w = data;
    worker_on_rto_tick(w);
    ogs_timer_start(w->t_rto,
            ogs_time_from_msec(cgf_self()->request_rto_ms));
}

static void worker_spool_timer_expired(void *data)
{
    cgf_worker_t *w = data;
    cgf_worker_try_drain(w);
    ogs_timer_start(w->t_spool,
            ogs_time_from_msec(cgf_self()->spool_poll_ms));
}

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                         */
/* ------------------------------------------------------------------ */

static void cgf_worker_dispatch(ogs_worker_t *ow, void *event)
{
    /* Workers never use the generic event queue: peer sockets are
     * polled directly on `ow->pollset` and ticks fire from
     * `ow->timer_mgr`. Nothing is ever posted here (ogs_worker_join()
     * only pushes the queue-termination sentinel on shutdown, which
     * ogs_worker's own loop consumes before calling dispatch). */
    (void)ow;
    ogs_error("cgf: unexpected worker event %p (ignored)", event);
}

static void cgf_worker_thread_init(ogs_worker_t *ow)
{
    cgf_worker_t *w = ow->data;
    uint32_t i;

    ogs_assert(w);
    cgf_tls_worker = w;

    for (i = 0; i < w->num_of_peers; i++) {
        cgf_peer_t *p = &w->peers[i];
        if (cgf_gtpp_open_peer(p, ow->pollset, worker_recv_cb, p) != OGS_OK) {
            ogs_warn("cgf: worker %d failed to open peer '%s':%u",
                    w->id, p->address_str, p->port);
            continue;
        }
        ogs_info("cgf: worker %d peer %u='%s':%u (%s) ready",
                w->id, i, p->address_str, p->port,
                p->role == CGF_PEER_ROLE_PRIMARY ? "primary" : "secondary");
    }

    w->t_echo = ogs_timer_add(ow->timer_mgr, worker_echo_timer_expired, w);
    w->t_rto = ogs_timer_add(ow->timer_mgr, worker_rto_timer_expired, w);
    w->t_spool = ogs_timer_add(ow->timer_mgr, worker_spool_timer_expired, w);
    ogs_assert(w->t_echo && w->t_rto && w->t_spool);

    /* Mirror OGS_FSM_ENTRY_SIG in cgf-sm.c: kick off an initial echo
     * to every reachable peer, then arm the periodic ticks. */
    for (i = 0; i < w->num_of_peers; i++) {
        cgf_peer_t *p = &w->peers[i];
        if (p->sock && cgf_gtpp_send_echo_request(p) == OGS_OK)
            p->state = CGF_PEER_STATE_PROBING;
    }
    ogs_timer_start(w->t_echo,
            ogs_time_from_sec(cgf_self()->echo_interval_s));
    ogs_timer_start(w->t_rto,
            ogs_time_from_msec(cgf_self()->request_rto_ms));
    ogs_timer_start(w->t_spool,
            ogs_time_from_msec(cgf_self()->spool_poll_ms));

    w->running = true;
    ogs_info("cgf: worker %d ready (%u peer(s))", w->id, w->num_of_peers);
}

static void cgf_worker_thread_fini(ogs_worker_t *ow)
{
    cgf_worker_t *w = ow->data;
    uint32_t i;

    ogs_assert(w);
    w->running = false;

    for (i = 0; i < w->num_of_peers; i++) {
        cgf_peer_t *p = &w->peers[i];
        cgf_gtpp_abort_all_xacts(p);
        if (p->poll) { ogs_pollset_remove(p->poll); p->poll = NULL; }
        if (p->sock) { ogs_sock_destroy(p->sock); p->sock = NULL; }
        if (p->addr) { ogs_freeaddrinfo(p->addr); p->addr = NULL; }
    }

    /*
     * Leave on-disk files under processing/<id>/ —
     * cgf_context_parse_config() reclaims them into ready/ on the next
     * start. Dropping in-memory handles loses only unconfirmed-ack
     * bookkeeping, which Send-possibly-duplicated covers on resend.
     */
    while (w->num_files > 0) {
        cgf_spool_file_t *f = w->files[w->num_files - 1];
        w->num_files--;
        w->files[w->num_files] = NULL;
        cgf_spool_release(f);
    }

    if (w->t_echo) { ogs_timer_delete(w->t_echo); w->t_echo = NULL; }
    if (w->t_rto) { ogs_timer_delete(w->t_rto); w->t_rto = NULL; }
    if (w->t_spool) { ogs_timer_delete(w->t_spool); w->t_spool = NULL; }

    ogs_info("cgf: worker %d stopped", w->id);
    cgf_tls_worker = NULL;
}

int cgf_workers_start(void)
{
    cgf_context_t *self = cgf_self();
    uint32_t configured = self->workers;
    uint32_t i;

    if (configured <= 1) return OGS_OK;

    ogs_assert(g_cgf_worker_count == 0);

    cgf_spool_claim_init();

    for (i = 0; i < configured; i++) {
        cgf_worker_t *w = ogs_calloc(1, sizeof(*w));
        uint32_t j;
        char tname[16];

        ogs_assert(w);
        w->id = (int)i;

        /* Independent copy of the peer config template. Each worker
         * gets its own next_seq (starts at 0, TS 32.295 §6.1.1) and
         * liveness state — sockets are opened per-worker in
         * cgf_worker_thread_init() so the source port differs too. */
        w->num_of_peers = self->num_of_peers;
        for (j = 0; j < self->num_of_peers; j++) {
            w->peers[j].address_str = self->peers[j].address_str;
            w->peers[j].port = self->peers[j].port;
            w->peers[j].role = self->peers[j].role;
            w->peers[j].state = CGF_PEER_STATE_DOWN;
            w->peers[j].next_seq = 0;
        }
        w->active_peer_idx = 0;
        for (j = 0; j < w->num_of_peers; j++) {
            if (w->peers[j].role == CGF_PEER_ROLE_PRIMARY) {
                w->active_peer_idx = j;
                break;
            }
        }
        /*
         * Stagger the RR cursor across workers so parallel drains
         * naturally spread across peers instead of all starting on
         * the same primary.
         */
        if (self->send_mode == CGF_SEND_MODE_ROUND_ROBIN &&
                w->num_of_peers > 0) {
            w->active_peer_idx =
                    (w->active_peer_idx + (uint32_t)w->id) % w->num_of_peers;
        }

        w->ow = ogs_worker_create((int)i,
                ogs_app()->pool.event, ogs_app()->pool.timer, 64,
                cgf_worker_dispatch, w);
        ogs_assert(w->ow);
        ogs_worker_hooks(w->ow, cgf_worker_thread_init, cgf_worker_thread_fini);
        ogs_snprintf(tname, sizeof(tname), "cgf-drain%u", i);
        ogs_worker_set_name(w->ow, tname);

        ogs_worker_start(w->ow);   /* blocks until thread_init() done */

        g_cgf_workers[i] = w;
    }

    g_cgf_worker_count = (int)configured;
    ogs_info("cgf: %d parallel drain worker(s) started", g_cgf_worker_count);
    return OGS_OK;
}

void cgf_workers_stop(void)
{
    int i;

    for (i = 0; i < g_cgf_worker_count; i++) {
        if (!g_cgf_workers[i]) continue;
        ogs_worker_join(g_cgf_workers[i]->ow);   /* runs thread_fini() */
        ogs_worker_destroy(g_cgf_workers[i]->ow);
        ogs_free(g_cgf_workers[i]);
        g_cgf_workers[i] = NULL;
    }
    g_cgf_worker_count = 0;
}
