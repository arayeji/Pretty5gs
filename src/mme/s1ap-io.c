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

#include "ogs-sctp.h"

#include "mme-event.h"
#include "s1ap-path.h"
#include "s1ap-io.h"

#ifndef EPIPE
#define EPIPE 32
#endif
#ifndef ENOTCONN
#define ENOTCONN 107
#endif
#ifndef ECONNABORTED
#define ECONNABORTED 103
#endif

static ogs_worker_t *io_worker = NULL;

typedef struct io_job_s {
#define IO_CMD_SEND     1
#define IO_CMD_DRAIN    2
    int             op;
    ogs_sock_t      *sock;
    ogs_pkbuf_t     *pkbuf;         /* IO_CMD_SEND (ownership: job) */
    bool            send_addr;      /* SEQPACKET: pass addr to sendmsg */
    bool            has_peer;       /* peer addr copy (SEQPACKET / diag) */
    ogs_sockaddr_t  addr;           /* copied: enb->sctp.addr dies with enb */
} io_job_t;

/*
 * IO-thread-side per-socket write state, keyed by sock pointer.
 * Touched ONLY on the IO thread (single thread; the hash needs no lock).
 */
typedef struct io_sock_s {
    ogs_sock_t      *sock;
    ogs_list_t      write_queue;    /* ogs_pkbuf_t FIFO */
    ogs_poll_t      *poll_write;    /* POLLOUT on io_worker->pollset */
    bool            send_addr;      /* pass addr to sendmsg (SEQPACKET) */
    bool            has_peer;
    ogs_sockaddr_t  addr;
    bool            dead;           /* hard send error; drop further SEND */
    bool            dead_reported;  /* CONNREFUSED posted once */
} io_sock_t;

/*
 * Soft per-assoc backlog. When exceeded we DROP the new PDU only —
 * never tear the eNB down. (Earlier code raised CONNREFUSED here and
 * that alone could cascade-kill hundreds of cells under attach load.)
 */
#define IO_WRITE_QUEUE_MAX  1024

static OGS_THREAD_LOCAL ogs_hash_t *io_sock_hash = NULL;

static void io_thread_init(ogs_worker_t *worker)
{
    io_sock_hash = ogs_hash_make();
    ogs_assert(io_sock_hash);
}

static void io_thread_fini(ogs_worker_t *worker)
{
    /* free anything still queued (shutdown path) */
    ogs_hash_index_t *hi = NULL;

    for (hi = ogs_hash_first(io_sock_hash); hi; hi = ogs_hash_next(hi)) {
        io_sock_t *ctx = ogs_hash_this_val(hi);
        ogs_pkbuf_t *pkbuf = NULL, *next = NULL;

        if (!ctx)
            continue;
        ogs_list_for_each_safe(&ctx->write_queue, next, pkbuf) {
            ogs_list_remove(&ctx->write_queue, pkbuf);
            ogs_pkbuf_free(pkbuf);
        }
        if (ctx->poll_write)
            ogs_pollset_remove(ctx->poll_write);
        ogs_free(ctx);
    }
    ogs_hash_destroy(io_sock_hash);
    io_sock_hash = NULL;
}

static io_sock_t *io_sock_find(ogs_sock_t *sock)
{
    return ogs_hash_get(io_sock_hash, &sock, sizeof(sock));
}

static io_sock_t *io_sock_get(ogs_sock_t *sock)
{
    io_sock_t *ctx = io_sock_find(sock);

    if (ctx)
        return ctx;

    ctx = ogs_calloc(1, sizeof(*ctx));
    ogs_assert(ctx);
    ctx->sock = sock;
    ogs_list_init(&ctx->write_queue);

    ogs_hash_set(io_sock_hash, &ctx->sock, sizeof(ctx->sock), ctx);
    return ctx;
}

static void io_sock_free(io_sock_t *ctx)
{
    ogs_pkbuf_t *pkbuf = NULL, *next = NULL;

    ogs_list_for_each_safe(&ctx->write_queue, next, pkbuf) {
        ogs_list_remove(&ctx->write_queue, pkbuf);
        ogs_pkbuf_free(pkbuf);
    }
    if (ctx->poll_write)
        ogs_pollset_remove(ctx->poll_write);
    ogs_hash_set(io_sock_hash, &ctx->sock, sizeof(ctx->sock), NULL);
    ogs_free(ctx);
}

static void io_write_cb(short when, ogs_socket_t fd, void *data);

static bool io_errno_assoc_dead(ogs_err_t err)
{
    return err == EPIPE ||
           err == OGS_ECONNRESET ||
           err == ENOTCONN ||
           err == ECONNABORTED ||
           err == OGS_EBADF;
}

/*
 * Stop sending on this sock. Do NOT raise CONNREFUSED from the IO
 * thread.
 *
 * Why: with s1ap_io_thread off, ogs_sctp_senddata() on EPIPE only
 * drops the PDU — RX (COMM_LOST / SHUTDOWN / recv0) owns teardown.
 * Raising CONNREFUSED from IO on every EPIPE / write-queue-full caused
 * mass mme_enb_remove + UE release storms and wedged the MME even
 * after the CONNREFUSED side-queue fix. Marking dead locally stops the
 * Broken-pipe send spam; lifecycle stays on the RX path (same as IO off).
 */
static void io_mark_assoc_dead(io_sock_t *ctx, const char *why)
{
    ogs_pkbuf_t *pkbuf = NULL, *next = NULL;
    static ogs_time_t log_window;
    static int log_count;

    ogs_assert(ctx);

    if (ctx->dead)
        return;
    ctx->dead = true;
    ctx->dead_reported = true;

    ogs_list_for_each_safe(&ctx->write_queue, next, pkbuf) {
        ogs_list_remove(&ctx->write_queue, pkbuf);
        ogs_pkbuf_free(pkbuf);
    }
    if (ctx->poll_write) {
        ogs_pollset_remove(ctx->poll_write);
        ctx->poll_write = NULL;
    }

    {
        ogs_time_t now = ogs_time_now();
        if (now - log_window > ogs_time_from_sec(1)) {
            if (log_count > 1)
                ogs_warn("s1ap-io: marked %d sock(s) send-dead in last "
                        "window (latest: %s sock:%p)",
                        log_count, why ? why : "?", (void *)ctx->sock);
            else
                ogs_warn("s1ap-io: sock:%p send-dead (%s) — waiting for "
                        "RX teardown", (void *)ctx->sock,
                        why ? why : "?");
            log_window = now;
            log_count = 0;
        }
        log_count++;
    }
}

/*
 * Drain ctx->write_queue with non-blocking sendmsg. On would-block,
 * arm POLLOUT on the IO thread's pollset and return; io_write_cb
 * re-enters here. Hard errors mark the assoc dead and notify main.
 */
static void io_sock_flush(io_sock_t *ctx)
{
    ogs_pkbuf_t *pkbuf = NULL;
    int sent;

    if (ctx->dead) {
        ogs_pkbuf_t *next = NULL;
        ogs_list_for_each_safe(&ctx->write_queue, next, pkbuf) {
            ogs_list_remove(&ctx->write_queue, pkbuf);
            ogs_pkbuf_free(pkbuf);
        }
        if (ctx->poll_write) {
            ogs_pollset_remove(ctx->poll_write);
            ctx->poll_write = NULL;
        }
        return;
    }

    while ((pkbuf = ogs_list_first(&ctx->write_queue)) != NULL) {
        sent = ogs_sctp_sendmsg(ctx->sock, pkbuf->data, pkbuf->len,
                ctx->send_addr ? &ctx->addr : NULL,
                ogs_sctp_ppid_in_pkbuf(pkbuf),
                ogs_sctp_stream_no_in_pkbuf(pkbuf));

        if (sent >= 0 && sent == (int)pkbuf->len) {
            ogs_list_remove(&ctx->write_queue, pkbuf);
            ogs_pkbuf_free(pkbuf);
            continue;
        }

        if (sent < 0 && ogs_socket_errno_would_block()) {
            if (!ctx->poll_write) {
                ctx->poll_write = ogs_pollset_add(
                        ogs_worker_self()->pollset,
                        OGS_POLLOUT, ctx->sock->fd, io_write_cb, ctx);
                if (!ctx->poll_write) {
                    /* fd died under us (teardown race): stop sending;
                     * RX/DRAIN finish lifecycle — do not CONNREFUSED. */
                    ogs_error("s1ap-io: POLLOUT add failed (fd:%d)",
                            ctx->sock->fd);
                    io_mark_assoc_dead(ctx, "pollout-add-failed");
                    return;
                }
            }
            return;
        }

        {
            ogs_err_t err = ogs_socket_errno;
            int pklen = (int)pkbuf->len;

            ogs_list_remove(&ctx->write_queue, pkbuf);
            ogs_pkbuf_free(pkbuf);

            if (sent >= 0) {
                /* Unexpected short SCTP send — drop PDU, keep assoc. */
                ogs_error("s1ap-io: short sendmsg (%d/%d) sock:%p",
                        sent, pklen, (void *)ctx->sock);
                continue;
            }

            if (io_errno_assoc_dead(err)) {
                /* Match IO-off: drop + stop spam; RX raises CONNREFUSED. */
                io_mark_assoc_dead(ctx, "hard-send-error");
                return;
            }

            ogs_log_message(OGS_LOG_ERROR, err,
                    "s1ap-io: sendmsg failed (non-fatal)");
        }
    }

    if (ctx->poll_write) {
        ogs_pollset_remove(ctx->poll_write);
        ctx->poll_write = NULL;
    }
}

static void io_write_cb(short when, ogs_socket_t fd, void *data)
{
    io_sock_t *ctx = data;

    ogs_assert(ctx);
    io_sock_flush(ctx);
}

static void io_dispatch(ogs_worker_t *worker, void *data)
{
    io_job_t *job = data;
    io_sock_t *ctx = NULL;

    ogs_assert(job);
    ogs_assert(job->sock);

    switch (job->op) {
    case IO_CMD_SEND:
        ogs_assert(job->pkbuf);
        ctx = io_sock_get(job->sock);
        if (job->has_peer) {
            ctx->has_peer = true;
            memcpy(&ctx->addr, &job->addr, sizeof(ctx->addr));
        }
        ctx->send_addr = job->send_addr;

        if (ctx->dead) {
            ogs_pkbuf_free(job->pkbuf);
            break;
        }

        if (ogs_list_count(&ctx->write_queue) >= IO_WRITE_QUEUE_MAX) {
            /*
             * Soft backpressure only. Never CONNREFUSED / mark-dead here:
             * a slow eNB under attach load easily exceeds a few hundred
             * queued PDUs; killing the cell made IO-on unusable.
             */
            ogs_error("s1ap-io: per-sock write queue full (sock:%p); "
                    "dropping PDU", (void *)job->sock);
            ogs_pkbuf_free(job->pkbuf);
            break;
        }

        ogs_list_add(&ctx->write_queue, job->pkbuf);
        io_sock_flush(ctx);
        break;

    case IO_CMD_DRAIN:
        ctx = io_sock_find(job->sock);
        if (ctx)
            io_sock_free(ctx);
        /* confirm to main: IO no longer references the sock */
        mme_sctp_event_push(MME_EVENT_S1AP_IO_DRAINED,
                job->sock, NULL, NULL, 0, 0);
        break;

    default:
        ogs_fatal("s1ap-io: unknown command %d", job->op);
        ogs_assert_if_reached();
    }

    ogs_free(job);
}

int s1ap_io_start(void)
{
    ogs_assert(io_worker == NULL);

    /*
     * poll capacity: every connected eNB could in theory be waiting on
     * POLLOUT at once, plus the queue-notify eventfd.
     * Command queue capped: SEND jobs are drained continuously and
     * per-sock backlog is bounded by IO_WRITE_QUEUE_MAX anyway.
     */
    io_worker = ogs_worker_create(0,
            ogs_min(ogs_app()->pool.event, 262144), 64,
            ogs_global_conf()->max.peer * 2 + 64,
            io_dispatch, NULL);
    ogs_assert(io_worker);
    ogs_worker_hooks(io_worker, io_thread_init, io_thread_fini);
    ogs_worker_start(io_worker);

    ogs_info("S1AP TX IO thread: on");
    return OGS_OK;
}

void s1ap_io_stop(void)
{
    if (!io_worker)
        return;

    ogs_worker_destroy(io_worker);   /* joins; thread_fini frees queues */
    io_worker = NULL;
}

bool s1ap_io_active(void)
{
    return io_worker != NULL;
}

int s1ap_io_post_send(ogs_sock_t *sock, ogs_pkbuf_t *pkbuf,
        const ogs_sockaddr_t *peer_addr, bool send_with_addr)
{
    io_job_t *job = NULL;
    int rv;

    ogs_assert(sock);
    ogs_assert(pkbuf);

    if (!io_worker) {
        ogs_error("s1ap-io: IO worker not running; drop PDU (len:%d)",
                pkbuf->len);
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    job = ogs_calloc(1, sizeof(*job));
    if (!job) {
        ogs_error("s1ap-io: job alloc failed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    job->op = IO_CMD_SEND;
    job->sock = sock;
    job->pkbuf = pkbuf;
    job->send_addr = send_with_addr;
    if (peer_addr) {
        job->has_peer = true;
        memcpy(&job->addr, peer_addr, sizeof(job->addr));
    }

    rv = ogs_worker_post(io_worker, job);
    if (rv != OGS_OK) {
        /*
         * IO queue full — meltdown-level backlog. Dropping keeps order
         * (nothing was enqueued); falling back to a main-thread send
         * would overtake everything already queued for this assoc.
         */
        ogs_error("s1ap-io: queue full, dropping PDU (len:%d)", pkbuf->len);
        ogs_pkbuf_free(job->pkbuf);
        ogs_free(job);
        return OGS_ERROR;
    }

    return OGS_OK;
}

bool s1ap_io_drain_sock(ogs_sock_t *sock)
{
    io_job_t *job = NULL;
    int rv;

    ogs_assert(sock);

    if (!io_worker)
        return false;

    job = ogs_calloc(1, sizeof(*job));
    ogs_assert(job);
    job->op = IO_CMD_DRAIN;
    job->sock = sock;

    rv = ogs_worker_post(io_worker, job);
    if (rv != OGS_OK) {
        /*
         * DRAIN must not be lost: without it the close registry never
         * confirms and the socket leaks (or worse, a forced destroy
         * races the IO thread). The command queue is deep; hitting
         * this means shutdown-level pressure. Retry synchronously.
         */
        int tries = 0;
        while (rv != OGS_OK && tries++ < 1000) {
            ogs_usleep(1000);
            rv = ogs_worker_post(io_worker, job);
        }
        if (rv != OGS_OK) {
            ogs_error("s1ap-io: DRAIN post failed; leaking sock ref");
            ogs_free(job);
            return false;
        }
    }

    return true;
}

/*
 * ---- Socket close registry ----
 *
 * sock -> outstanding-confirmation entry.
 *
 * ogs_hash stores the key POINTER, not a copy. The key must therefore
 * live on the heap for as long as the entry does: it is embedded in the
 * entry struct (never `&sock` of a caller's stack frame — with
 * mme.workers the registering frame may belong to a worker thread whose
 * stack is unmapped before s1ap_sock_close_final() walks the hash).
 */
typedef struct close_wait_entry_s {
    ogs_sock_t *sock;       /* hash key storage — must stay first-class */
    unsigned    mask;       /* confirmations still outstanding */
} close_wait_entry_t;

static ogs_hash_t *close_wait_hash = NULL;
static ogs_thread_mutex_t close_wait_lock;
static bool close_wait_lock_ready = false;

void s1ap_sock_close_init(void)
{
    /* Called from mme_initialize() BEFORE any worker thread exists, so
     * plain flags need no synchronization here. */
    if (!close_wait_lock_ready) {
        ogs_thread_mutex_init(&close_wait_lock);
        close_wait_lock_ready = true;
    }
    if (!close_wait_hash) {
        close_wait_hash = ogs_hash_make();
        ogs_assert(close_wait_hash);
    }
}

void s1ap_sock_close_register(ogs_sock_t *sock, int wait_mask)
{
    close_wait_entry_t *entry = NULL;

    ogs_assert(sock);
    ogs_assert(wait_mask);
    ogs_assert(close_wait_lock_ready);

    ogs_thread_mutex_lock(&close_wait_lock);

    /*
     * Duplicate register is a tear-down race (e.g. CONNREFUSED overlapping
     * WATCH_FAILED, or a recycled sock pointer while a prior close is still
     * in flight). Merge outstanding confirms; never abort the MME.
     */
    entry = ogs_hash_get(close_wait_hash, &sock, sizeof(sock));
    if (entry) {
        ogs_warn("s1ap-io: close already registered sock:%p "
                "(pending=0x%x, add=0x%x)",
                (void *)sock, entry->mask, (unsigned)wait_mask);
        entry->mask |= (unsigned)wait_mask;
        ogs_thread_mutex_unlock(&close_wait_lock);
        return;
    }

    entry = ogs_calloc(1, sizeof(*entry));
    ogs_assert(entry);
    entry->sock = sock;
    entry->mask = (unsigned)wait_mask;
    ogs_hash_set(close_wait_hash, &entry->sock, sizeof(entry->sock), entry);
    ogs_thread_mutex_unlock(&close_wait_lock);
}

bool s1ap_sock_close_pending(ogs_sock_t *sock)
{
    bool pending;

    ogs_assert(sock);
    ogs_assert(close_wait_lock_ready);

    ogs_thread_mutex_lock(&close_wait_lock);
    pending = close_wait_hash &&
        ogs_hash_get(close_wait_hash, &sock, sizeof(sock)) != NULL;
    ogs_thread_mutex_unlock(&close_wait_lock);
    return pending;
}

void s1ap_sock_close_orphan(ogs_sock_t *sock)
{
    ogs_assert(sock);

    /* Teardown already in flight via mme_enb_remove — leave it alone. */
    if (s1ap_sock_close_pending(sock))
        return;

    ogs_sctp_destroy(sock);
}

void s1ap_sock_close_confirm(ogs_sock_t *sock, int which)
{
    close_wait_entry_t *entry = NULL;

    ogs_assert(sock);
    ogs_assert(close_wait_lock_ready);

    ogs_thread_mutex_lock(&close_wait_lock);

    entry = close_wait_hash ?
        ogs_hash_get(close_wait_hash, &sock, sizeof(sock)) : NULL;

    if (!entry) {
        /*
         * Spurious / late confirm after destroy (or for a sock that was
         * never registered). MUST NOT destroy here: the pointer may
         * already have been reused by a new accept().
         */
        ogs_thread_mutex_unlock(&close_wait_lock);
        ogs_warn("s1ap-io: close confirm 0x%x for unregistered sock:%p",
                which, (void *)sock);
        return;
    }

    entry->mask &= ~(unsigned)which;
    if (entry->mask) {
        ogs_thread_mutex_unlock(&close_wait_lock);
        return;
    }

    ogs_hash_set(close_wait_hash, &entry->sock, sizeof(entry->sock), NULL);
    ogs_free(entry);
    ogs_thread_mutex_unlock(&close_wait_lock);
    ogs_sctp_destroy(sock);
}

void s1ap_sock_close_final(void)
{
    ogs_hash_index_t *hi = NULL;

    if (!close_wait_lock_ready)
        return;

    ogs_thread_mutex_lock(&close_wait_lock);

    if (!close_wait_hash) {
        ogs_thread_mutex_unlock(&close_wait_lock);
        return;
    }

    /* all worker threads are joined: confirmations that never arrived
     * can no longer race a destroy — reap the leftovers */
    for (hi = ogs_hash_first(close_wait_hash); hi; hi = ogs_hash_next(hi)) {
        close_wait_entry_t *entry = ogs_hash_this_val(hi);
        if (entry) {
            if (entry->sock)
                ogs_sctp_destroy(entry->sock);
            ogs_free(entry);
        }
    }
    ogs_hash_destroy(close_wait_hash);
    close_wait_hash = NULL;
    ogs_thread_mutex_unlock(&close_wait_lock);
}
