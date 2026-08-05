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
#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif

/*
 * mme.s1ap_io_thread: N (1..MME_S1AP_IO_MAX) IO threads. Each socket is
 * sticky to one IO worker (pointer hash), so per-association order is
 * preserved and each worker's io_sock_hash stays thread-local. SEND and
 * DRAIN for one sock always land on the same worker's FIFO.
 */
#define MME_S1AP_IO_MAX 4

static ogs_worker_t *io_workers[MME_S1AP_IO_MAX];
static int io_worker_count = 0;

static ogs_worker_t *io_pick(ogs_sock_t *sock)
{
    /* >>6: strip allocator alignment so socks spread across workers */
    return io_workers[((uintptr_t)sock >> 6) % (unsigned)io_worker_count];
}

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
    int             wq_count;       /* O(1) depth of write_queue */
    uint32_t        wq_dropped;     /* drops in current log window */
    ogs_time_t      wq_drop_window; /* start of current log window */
    ogs_time_t      wq_full_since;  /* when depth first hit max (0=ok) */
    ogs_time_t      congest_report; /* last congestion heartbeat to main */
    ogs_poll_t      *poll_write;    /* POLLOUT on io_worker->pollset */
    bool            send_addr;      /* pass addr to sendmsg (SEQPACKET) */
    bool            has_peer;
    ogs_sockaddr_t  addr;
    bool            dead;           /* hard send error; drop further SEND */
    bool            teardown_posted; /* CONNREFUSED already queued */
} io_sock_t;

/*
 * Soft per-assoc backlog. When exceeded we DROP the new PDU only at
 * first — a brief spike must not kill the cell. If the queue stays
 * full for s1ap_io_stall_teardown_sec, we tear that assoc down so a
 * single stuck eNB cannot retry-flood the shared MME.
 * Overridable via mme.s1ap_io_write_queue_max.
 */
#define IO_WRITE_QUEUE_MAX_DEFAULT          10240
#define IO_STALL_TEARDOWN_SEC_DEFAULT       10

static int io_write_queue_max(void)
{
    int v = mme_self()->s1ap_io_write_queue_max;

    return v > 0 ? v : IO_WRITE_QUEUE_MAX_DEFAULT;
}

/*
 * Depth at which an association counts as TX-congested for overload
 * control. A quarter of the cap by default: far enough below full that
 * an OVERLOAD START still gets out, far enough above idle that normal
 * attach bursts do not trip it.
 */
int s1ap_io_congest_depth(void)
{
    int v = mme_self()->s1ap_io_congest_depth;

    if (v > 0)
        return v;
    v = io_write_queue_max() / 4;
    return v > 0 ? v : 1;
}

/* 0/unset → default; negative → disabled */
static int io_stall_teardown_sec(void)
{
    int v = mme_self()->s1ap_io_stall_teardown_sec;

    if (v < 0)
        return 0;
    if (v == 0)
        return IO_STALL_TEARDOWN_SEC_DEFAULT;
    return v;
}

static OGS_THREAD_LOCAL ogs_hash_t *io_sock_hash = NULL;

static bool io_sockaddr_usable(const ogs_sockaddr_t *a)
{
    return a && (a->ogs_sa_family == AF_INET || a->ogs_sa_family == AF_INET6);
}

/* eNB peer address for diagnostics (both send paths pass enb->sctp.addr) */
static const char *io_sock_peer_str(io_sock_t *ctx, char *buf)
{
    ogs_sockaddr_t *a = NULL;

    /* has_peer alone is not enough: enb->sctp.addr can be non-NULL with
     * AF_UNSPEC/zeroed during teardown; OGS_ADDR used to abort MME. */
    if (ctx->has_peer && io_sockaddr_usable(&ctx->addr))
        a = &ctx->addr;
    else if (ctx->sock && io_sockaddr_usable(&ctx->sock->remote_addr))
        a = &ctx->sock->remote_addr;

    if (!a)
        return "unknown";
    return OGS_ADDR(a, buf) ? buf : "unknown";
}

static void io_thread_init(ogs_worker_t *worker)
{
    mme_pkbuf_thread_pool_attach();

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

/*
 * Timeout on send: the peer is not taking data even though RX may stay
 * quiet, so the IO thread has to drive teardown itself. OGS_ETIMEDOUT
 * is the portable spelling (WSAETIMEDOUT on Windows, ETIMEDOUT here);
 * listing both is a duplicated test on POSIX.
 */
static bool io_errno_needs_teardown(ogs_err_t err)
{
    return err == OGS_ETIMEDOUT;
}

static bool io_errno_assoc_dead(ogs_err_t err)
{
    return err == EPIPE ||
           err == OGS_ECONNRESET ||
           err == ENOTCONN ||
           err == ECONNABORTED ||
           err == OGS_EBADF ||
           io_errno_needs_teardown(err);
}

/*
 * Clear the per-eNB write queue and stop further SEND. Does not by
 * itself raise CONNREFUSED — see io_request_teardown().
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
    ctx->wq_full_since = 0;

    ogs_list_for_each_safe(&ctx->write_queue, next, pkbuf) {
        ogs_list_remove(&ctx->write_queue, pkbuf);
        ogs_pkbuf_free(pkbuf);
    }
    ctx->wq_count = 0;
    if (ctx->poll_write) {
        ogs_pollset_remove(ctx->poll_write);
        ctx->poll_write = NULL;
    }

    {
        ogs_time_t now = ogs_time_now();
        if (now - log_window > ogs_time_from_sec(1)) {
            char peer[OGS_ADDRSTRLEN];

            if (log_count > 1)
                ogs_warn("s1ap-io: marked %d sock(s) send-dead in last "
                        "window (latest: %s eNB[%s] sock:%p)",
                        log_count, why ? why : "?",
                        io_sock_peer_str(ctx, peer), (void *)ctx->sock);
            else
                ogs_warn("s1ap-io: eNB[%s] sock:%p send-dead (%s)",
                        io_sock_peer_str(ctx, peer), (void *)ctx->sock,
                        why ? why : "?");
            log_window = now;
            log_count = 0;
        }
        log_count++;
    }
}

/*
 * Clear TX queue for this eNB and ask main to drop S1 (CONNREFUSED
 * side-queue coalesces duplicates). Used for ETIMEDOUT and for a
 * write-queue that has stayed full too long — not for a one-shot
 * queue spike under attach load.
 */
static void io_request_teardown(io_sock_t *ctx, const char *why)
{
    ogs_sockaddr_t *addr = NULL;
    char peer[OGS_ADDRSTRLEN];

    ogs_assert(ctx);

    if (ctx->teardown_posted) {
        if (!ctx->dead)
            io_mark_assoc_dead(ctx, why);
        return;
    }
    ctx->teardown_posted = true;

    io_mark_assoc_dead(ctx, why);

    ogs_error("s1ap-io: tearing down eNB[%s] sock:%p (%s) — "
            "clear TX queue + S1 CONNREFUSED",
            io_sock_peer_str(ctx, peer), (void *)ctx->sock,
            why ? why : "?");

    if (ctx->has_peer && io_sockaddr_usable(&ctx->addr)) {
        addr = ogs_calloc(1, sizeof(*addr));
        if (addr)
            memcpy(addr, &ctx->addr, sizeof(*addr));
    } else if (ctx->sock &&
            io_sockaddr_usable(&ctx->sock->remote_addr)) {
        addr = ogs_calloc(1, sizeof(*addr));
        if (addr)
            memcpy(addr, &ctx->sock->remote_addr, sizeof(*addr));
    }

    /* addr may be NULL — handler falls back to sock lookup */
    mme_sctp_event_push(MME_EVENT_S1AP_LO_CONNREFUSED,
            ctx->sock, addr, NULL, 0, 0);
}

/*
 * Tell main this association's downlink is backing up, at most once a
 * second. Deliberately a repeated heartbeat rather than an edge event:
 * main holds it as a short lease (mme.overload.congest_lease_sec), so a
 * heartbeat lost to a full event queue can only clear the state early
 * — it can never leave an eNB throttled forever. Also why this is not
 * a "congestion cleared" event: there is nothing to lose.
 */
static void io_report_congestion(io_sock_t *ctx, ogs_time_t now)
{
    if (ctx->congest_report &&
        (now - ctx->congest_report) < ogs_time_from_sec(1))
        return;
    ctx->congest_report = now;

    s1ap_io_congestion_event_push(ctx->sock, ctx->wq_count);
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
        ctx->wq_count = 0;
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
            ctx->wq_count--;
            ogs_pkbuf_free(pkbuf);
            if (ctx->wq_count < io_write_queue_max())
                ctx->wq_full_since = 0;
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
            ctx->wq_count--;
            ogs_pkbuf_free(pkbuf);

            if (sent >= 0) {
                /* Unexpected short SCTP send — drop PDU, keep assoc. */
                ogs_error("s1ap-io: short sendmsg (%d/%d) sock:%p",
                        sent, pklen, (void *)ctx->sock);
                continue;
            }

            if (io_errno_needs_teardown(err)) {
                /*
                 * ETIMEDOUT: peer not accepting data but SCTP may still
                 * look "up" on RX. Clear this eNB's TX queue and drop S1
                 * so UEs stop retry-flooding the shared MME.
                 */
                io_request_teardown(ctx, "send-ETIMEDOUT");
                return;
            }

            if (io_errno_assoc_dead(err)) {
                /* EPIPE/RESET: stop spam; RX COMM_LOST usually finishes. */
                io_mark_assoc_dead(ctx, "hard-send-error");
                return;
            }

            ogs_log_message(OGS_LOG_ERROR, err,
                    "s1ap-io: sendmsg failed (non-fatal)");
        }
    }

    /* Queue drained — clear stall clock */
    ctx->wq_full_since = 0;

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
        if (job->has_peer && io_sockaddr_usable(&job->addr)) {
            ctx->has_peer = true;
            memcpy(&ctx->addr, &job->addr, sizeof(ctx->addr));
        }
        ctx->send_addr = job->send_addr;

        if (ctx->dead) {
            ogs_pkbuf_free(job->pkbuf);
            break;
        }

        if (ctx->wq_count >= s1ap_io_congest_depth())
            io_report_congestion(ctx, ogs_time_now());

        if (ctx->wq_count >= io_write_queue_max()) {
            /*
             * Soft backpressure first: drop this PDU only. If the queue
             * has stayed full for too long, tear THIS eNB down (clear
             * TX + CONNREFUSED) so one stuck cell cannot wedge the
             * shared IO thread / worker pool via endless UE retries.
             */
            ogs_time_t now = ogs_time_now();
            int stall_sec = io_stall_teardown_sec();

            if (!ctx->wq_full_since)
                ctx->wq_full_since = now;

            if (stall_sec > 0 &&
                (now - ctx->wq_full_since) >= ogs_time_from_sec(stall_sec)) {
                ogs_pkbuf_free(job->pkbuf);
                io_request_teardown(ctx, "write-queue-stall");
                break;
            }

            ctx->wq_dropped++;
            if (now - ctx->wq_drop_window > ogs_time_from_sec(1)) {
                char peer[OGS_ADDRSTRLEN];

                ogs_error("s1ap-io: write queue full for eNB[%s] "
                        "(sock:%p depth:%d max:%d); dropped %u PDU(s) "
                        "in last window (stall %ld/%d s)",
                        io_sock_peer_str(ctx, peer),
                        (void *)job->sock, ctx->wq_count,
                        io_write_queue_max(), ctx->wq_dropped,
                        (long)((now - ctx->wq_full_since) /
                            ogs_time_from_sec(1)),
                        stall_sec);
                ctx->wq_drop_window = now;
                ctx->wq_dropped = 0;
            }
            ogs_pkbuf_free(job->pkbuf);
            break;
        }

        ogs_list_add(&ctx->write_queue, job->pkbuf);
        ctx->wq_count++;
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

int s1ap_io_start(int count)
{
    int i;

    ogs_assert(io_worker_count == 0);
    ogs_assert(count > 0 && count <= MME_S1AP_IO_MAX);

    for (i = 0; i < count; i++) {
        char tname[16];

        /*
         * poll capacity: every connected eNB could in theory be waiting
         * on POLLOUT at once, plus the queue-notify eventfd.
         * Command queue capped: SEND jobs are drained continuously and
         * per-sock backlog is bounded by io_write_queue_max() anyway.
         */
        io_workers[i] = ogs_worker_create(i,
                ogs_min(ogs_app()->pool.event, 262144), 64,
                ogs_global_conf()->max.peer * 2 + 64,
                io_dispatch, NULL);
        ogs_assert(io_workers[i]);
        ogs_worker_hooks(io_workers[i], io_thread_init, io_thread_fini);
        ogs_snprintf(tname, sizeof(tname), "s1ap-io%d", i);
        ogs_worker_set_name(io_workers[i], tname);
        ogs_worker_start(io_workers[i]);
    }
    io_worker_count = count;

    ogs_info("S1AP TX IO thread(s): %d", count);
    return OGS_OK;
}

void s1ap_io_stop(void)
{
    int i;

    for (i = 0; i < io_worker_count; i++) {
        /* joins; thread_fini frees queues */
        ogs_worker_destroy(io_workers[i]);
        io_workers[i] = NULL;
    }
    io_worker_count = 0;
}

bool s1ap_io_active(void)
{
    return io_worker_count > 0;
}

/* diagnostic (torn read acceptable): total depth across IO command queues */
unsigned int s1ap_io_queue_depth(void)
{
    unsigned int depth = 0;
    int i;

    for (i = 0; i < io_worker_count; i++)
        if (io_workers[i])
            depth += ogs_queue_size(io_workers[i]->queue);
    return depth;
}

int s1ap_io_post_send(ogs_sock_t *sock, ogs_pkbuf_t *pkbuf,
        const ogs_sockaddr_t *peer_addr, bool send_with_addr)
{
    io_job_t *job = NULL;
    int rv;

    ogs_assert(sock);
    ogs_assert(pkbuf);

    if (!io_worker_count) {
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
    if (io_sockaddr_usable(peer_addr)) {
        job->has_peer = true;
        memcpy(&job->addr, peer_addr, sizeof(job->addr));
    } else if (peer_addr) {
        /* Non-NULL but unusable (AF_UNSPEC): keep send_addr false so we
         * do not pass a zeroed sockaddr into sendmsg. */
        job->send_addr = false;
    }

    rv = ogs_worker_post(io_pick(sock), job);
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
    ogs_worker_t *worker = NULL;
    int rv;

    ogs_assert(sock);

    if (!io_worker_count)
        return false;

    /* same worker as every SEND for this sock — FIFO makes the drain
     * observe all prior sends */
    worker = io_pick(sock);

    job = ogs_calloc(1, sizeof(*job));
    ogs_assert(job);
    job->op = IO_CMD_DRAIN;
    job->sock = sock;

    rv = ogs_worker_post(worker, job);
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
            rv = ogs_worker_post(worker, job);
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
