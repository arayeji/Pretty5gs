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

static ogs_worker_t *io_worker = NULL;

typedef struct io_job_s {
#define IO_CMD_SEND     1
#define IO_CMD_DRAIN    2
    int             op;
    ogs_sock_t      *sock;
    ogs_pkbuf_t     *pkbuf;         /* IO_CMD_SEND (ownership: job) */
    bool            has_addr;       /* SEQPACKET destination present */
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
    bool            has_addr;
    ogs_sockaddr_t  addr;
} io_sock_t;

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

/*
 * Drain ctx->write_queue with non-blocking sendmsg. On would-block,
 * arm POLLOUT on the IO thread's pollset and return; io_write_cb
 * re-enters here. Any other send error drops that pkbuf and continues
 * (matches ogs_sctp_senddata semantics).
 */
static void io_sock_flush(io_sock_t *ctx)
{
    ogs_pkbuf_t *pkbuf = NULL;
    int sent;

    while ((pkbuf = ogs_list_first(&ctx->write_queue)) != NULL) {
        sent = ogs_sctp_sendmsg(ctx->sock, pkbuf->data, pkbuf->len,
                ctx->has_addr ? &ctx->addr : NULL,
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
                    /* fd died under us (teardown race): drop the queue,
                     * DRAIN/close will finish the cleanup */
                    ogs_error("s1ap-io: POLLOUT add failed (fd:%d)",
                            ctx->sock->fd);
                    ogs_list_remove(&ctx->write_queue, pkbuf);
                    ogs_pkbuf_free(pkbuf);
                    continue;
                }
            }
            return;
        }

        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "s1ap-io: sendmsg(len:%d,ssn:%d) failed",
                pkbuf->len, (int)ogs_sctp_stream_no_in_pkbuf(pkbuf));
        ogs_list_remove(&ctx->write_queue, pkbuf);
        ogs_pkbuf_free(pkbuf);
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
        if (job->has_addr) {
            ctx->has_addr = true;
            memcpy(&ctx->addr, &job->addr, sizeof(ctx->addr));
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
     */
    io_worker = ogs_worker_create(0,
            ogs_app()->pool.event, 64,
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

int s1ap_io_post_send(
        ogs_sock_t *sock, ogs_pkbuf_t *pkbuf, const ogs_sockaddr_t *addr)
{
    io_job_t *job = NULL;
    int rv;

    ogs_assert(sock);
    ogs_assert(pkbuf);
    ogs_assert(io_worker);

    job = ogs_calloc(1, sizeof(*job));
    if (!job) {
        ogs_error("s1ap-io: job alloc failed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    job->op = IO_CMD_SEND;
    job->sock = sock;
    job->pkbuf = pkbuf;
    if (addr) {
        job->has_addr = true;
        memcpy(&job->addr, addr, sizeof(job->addr));
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
 * ---- Socket close registry (main thread only) ----
 *
 * sock -> bitmask of confirmations still outstanding.
 */
static ogs_hash_t *close_wait_hash = NULL;

void s1ap_sock_close_register(ogs_sock_t *sock, int wait_mask)
{
    ogs_assert(sock);
    ogs_assert(wait_mask);

    if (!close_wait_hash) {
        close_wait_hash = ogs_hash_make();
        ogs_assert(close_wait_hash);
    }

    ogs_assert(!ogs_hash_get(close_wait_hash, &sock, sizeof(sock)));
    ogs_hash_set(close_wait_hash, &sock, sizeof(sock),
            (void *)(uintptr_t)wait_mask);
}

void s1ap_sock_close_confirm(ogs_sock_t *sock, int which)
{
    uintptr_t mask;

    ogs_assert(sock);

    mask = close_wait_hash ?
        (uintptr_t)ogs_hash_get(close_wait_hash, &sock, sizeof(sock)) : 0;

    if (!mask) {
        /* not registered: single-confirm teardown (RX-only compat) */
        ogs_sctp_destroy(sock);
        return;
    }

    mask &= ~(uintptr_t)which;
    if (mask) {
        ogs_hash_set(close_wait_hash, &sock, sizeof(sock),
                (void *)mask);
        return;
    }

    ogs_hash_set(close_wait_hash, &sock, sizeof(sock), NULL);
    ogs_sctp_destroy(sock);
}

void s1ap_sock_close_final(void)
{
    ogs_hash_index_t *hi = NULL;

    if (!close_wait_hash)
        return;

    /* all worker threads are joined: confirmations that never arrived
     * can no longer race a destroy — reap the leftovers */
    for (hi = ogs_hash_first(close_wait_hash); hi; hi = ogs_hash_next(hi)) {
        ogs_sock_t *sock = NULL;
        memcpy(&sock, ogs_hash_this_key(hi), sizeof(sock));
        if (sock)
            ogs_sctp_destroy(sock);
    }
    ogs_hash_destroy(close_wait_hash);
    close_wait_hash = NULL;
}
