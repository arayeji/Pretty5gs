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
#include "s1ap-rx.h"

static ogs_worker_t *rx_workers[OGS_MAX_WORKERS];
static int rx_worker_count = 0;
static int rx_next_worker = 0;          /* round-robin cursor, main only */
static ogs_hash_t *rx_owner_hash = NULL; /* sock -> worker+1, main only */

/* worker-side: sock -> ogs_poll_t*, touched only by the owning worker */
static OGS_THREAD_LOCAL ogs_hash_t *rx_poll_hash = NULL;

typedef struct rx_cmd_s {
#define RX_CMD_WATCH    1
#define RX_CMD_UNWATCH  2
    int op;
    ogs_sock_t *sock;
} rx_cmd_t;

static void rx_thread_init(ogs_worker_t *worker)
{
    rx_poll_hash = ogs_hash_make();
    ogs_assert(rx_poll_hash);
}

static void rx_thread_fini(ogs_worker_t *worker)
{
    ogs_hash_destroy(rx_poll_hash);
    rx_poll_hash = NULL;
}

static void rx_dispatch(ogs_worker_t *worker, void *data)
{
    rx_cmd_t *cmd = data;
    ogs_poll_t *poll = NULL;

    ogs_assert(cmd);
    ogs_assert(cmd->sock);

    switch (cmd->op) {
    case RX_CMD_WATCH:
        poll = ogs_pollset_add(worker->pollset,
                OGS_POLLIN, cmd->sock->fd, s1ap_recv_upcall, cmd->sock);
        if (!poll) {
            /*
             * epoll_ctl failed: the eNB fd was already closed between
             * accept and this WATCH (reconnect-storm race). This is NOT
             * fatal — never abort the whole MME for one dead socket.
             * Ask main to tear down the half-created eNB; its normal
             * two-phase path (unwatch -> SOCK_CLOSED) then runs, and the
             * UNWATCH for an un-hashed socket is handled gracefully.
             */
            ogs_error("s1ap-rx: WATCH failed (fd %d gone); dropping eNB",
                    cmd->sock->fd);
            mme_sctp_event_push(MME_EVENT_S1AP_RX_WATCH_FAILED,
                    cmd->sock, NULL, NULL, 0, 0);
            break;
        }
        ogs_hash_set(rx_poll_hash, &cmd->sock, sizeof(cmd->sock), poll);
        break;

    case RX_CMD_UNWATCH:
        poll = ogs_hash_get(rx_poll_hash, &cmd->sock, sizeof(cmd->sock));
        if (poll) {
            ogs_pollset_remove(poll);
            ogs_hash_set(rx_poll_hash, &cmd->sock, sizeof(cmd->sock), NULL);
        } else
            ogs_error("s1ap-rx: UNWATCH for unknown socket");

        /* confirm to main: safe to destroy the socket now */
        mme_sctp_event_push(MME_EVENT_S1AP_RX_SOCK_CLOSED,
                cmd->sock, NULL, NULL, 0, 0);
        break;

    default:
        ogs_fatal("s1ap-rx: unknown command %d", cmd->op);
        ogs_assert_if_reached();
    }

    ogs_free(cmd);
}

int s1ap_rx_workers_start(int count)
{
    int i;

    ogs_assert(count > 0 && count <= OGS_MAX_WORKERS);
    ogs_assert(rx_worker_count == 0);

    rx_owner_hash = ogs_hash_make();
    ogs_assert(rx_owner_hash);

    for (i = 0; i < count; i++) {
        rx_workers[i] = ogs_worker_create(i,
                ogs_app()->pool.event, 64,
                ogs_global_conf()->max.peer * 2 + 64,
                rx_dispatch, NULL);
        ogs_assert(rx_workers[i]);
        ogs_worker_hooks(rx_workers[i], rx_thread_init, rx_thread_fini);
        ogs_worker_start(rx_workers[i]);
    }

    rx_worker_count = count;
    ogs_info("S1AP RX decode offload: %d worker(s)", count);

    return OGS_OK;
}

void s1ap_rx_workers_stop(void)
{
    int i;

    for (i = 0; i < rx_worker_count; i++) {
        ogs_worker_destroy(rx_workers[i]);
        rx_workers[i] = NULL;
    }
    rx_worker_count = 0;

    if (rx_owner_hash) {
        ogs_hash_destroy(rx_owner_hash);
        rx_owner_hash = NULL;
    }
}

bool s1ap_rx_active(void)
{
    return rx_worker_count > 0;
}

static void rx_post(ogs_worker_t *worker, int op, ogs_sock_t *sock)
{
    rx_cmd_t *cmd = NULL;
    int rv;

    cmd = ogs_calloc(1, sizeof(*cmd));
    ogs_assert(cmd);
    cmd->op = op;
    cmd->sock = sock;

    rv = ogs_worker_post(worker, cmd);
    ogs_assert(rv == OGS_OK);
}

void s1ap_rx_watch_sock(ogs_sock_t *sock)
{
    int wid;

    ogs_assert(sock);
    ogs_assert(rx_worker_count > 0);

    wid = rx_next_worker;
    rx_next_worker = (rx_next_worker + 1) % rx_worker_count;

    ogs_hash_set(rx_owner_hash, &sock, sizeof(sock),
            (void *)(uintptr_t)(wid + 1));

    rx_post(rx_workers[wid], RX_CMD_WATCH, sock);
}

mme_enb_t *s1ap_rx_safe_enb_lookup(const ogs_sockaddr_t *addr)
{
    if (ogs_worker_self())
        return NULL;

    return mme_enb_find_by_addr(addr);
}

bool s1ap_rx_unwatch_sock(ogs_sock_t *sock)
{
    uintptr_t owner;

    ogs_assert(sock);

    if (!rx_owner_hash)
        return false;

    owner = (uintptr_t)ogs_hash_get(rx_owner_hash, &sock, sizeof(sock));
    if (!owner)
        return false;

    ogs_hash_set(rx_owner_hash, &sock, sizeof(sock), NULL);
    rx_post(rx_workers[owner - 1], RX_CMD_UNWATCH, sock);

    return true;
}
