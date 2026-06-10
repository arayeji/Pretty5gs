/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#include "ogs-sctp.h"

#include "mme-event.h"
#include "s1ap-path.h"

#if HAVE_USRSCTP
static void usrsctp_recv_handler(struct socket *socket, void *data, int flags);
#else
static void lksctp_accept_handler(short when, ogs_socket_t fd, void *data);
#endif

static int s1ap_accept_handler(ogs_sock_t *sock);
static int s1ap_recv_handler(ogs_sock_t *sock);

static ogs_sockopt_t s1ap_default_sockopt;
static bool s1ap_default_sockopt_ready = false;

static ogs_sockopt_t *s1ap_default_option(void)
{
    if (!s1ap_default_sockopt_ready) {
        ogs_sockopt_init(&s1ap_default_sockopt);
        s1ap_default_sockopt_ready = true;
    }
    return &s1ap_default_sockopt;
}

static ogs_sockopt_t *mme_s1ap_server_option(ogs_sock_t *listen)
{
    ogs_socknode_t *node = NULL;

    if (!listen)
        return s1ap_default_option();

    ogs_list_for_each(&mme_self()->s1ap_list, node) {
        if (node->sock == listen)
            return node->option ? node->option : s1ap_default_option();
    }
    ogs_list_for_each(&mme_self()->s1ap_list6, node) {
        if (node->sock == listen)
            return node->option ? node->option : s1ap_default_option();
    }

    return s1ap_default_option();
}

ogs_sock_t *s1ap_server(ogs_socknode_t *node)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_sock_t *sock = NULL;
#if !HAVE_USRSCTP
    ogs_poll_t *poll = NULL;
#endif

    ogs_assert(node);

#if HAVE_USRSCTP
    sock = ogs_sctp_server(SOCK_SEQPACKET, node->addr, node->option);
    if (!sock) return NULL;
    usrsctp_set_non_blocking((struct socket *)sock, 1);
    usrsctp_set_upcall((struct socket *)sock, usrsctp_recv_handler, NULL);
#else
    sock = ogs_sctp_server(SOCK_STREAM, node->addr, node->option);
    if (!sock) return NULL;
    ogs_nonblocking(sock->fd);
    poll = ogs_pollset_add(ogs_app()->pollset,
            OGS_POLLIN, sock->fd, lksctp_accept_handler, sock);
    ogs_assert(poll);

    node->poll = poll;
#endif

    node->sock = sock;
    node->cleanup = ogs_sctp_destroy;

    ogs_info("s1ap_server() [%s]:%d",
            OGS_ADDR(node->addr, buf), OGS_PORT(node->addr));

    return sock;
}

void s1ap_recv_upcall(short when, ogs_socket_t fd, void *data)
{
    ogs_sock_t *sock = NULL;

    ogs_assert(fd != INVALID_SOCKET);
    sock = data;
    ogs_assert(sock);

    while (s1ap_recv_handler(sock) > 0)
        ;
}

#if HAVE_USRSCTP
static void usrsctp_recv_handler(struct socket *socket, void *data, int flags)
{
    int events;

    while ((events = usrsctp_get_events(socket)) &&
           (events & SCTP_EVENT_READ)) {
        if (s1ap_recv_handler((ogs_sock_t *)socket) <= 0)
            break;
    }
}
#else
static void lksctp_accept_handler(short when, ogs_socket_t fd, void *data)
{
    ogs_assert(data);
    ogs_assert(fd != INVALID_SOCKET);

    while (s1ap_accept_handler(data) > 0)
        ;
}
#endif

static int s1ap_accept_handler(ogs_sock_t *sock)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_sock_t *new = NULL;
    ogs_sockaddr_t *addr = NULL;

    ogs_assert(sock);

    new = ogs_sock_accept(sock);
    if (!new) {
        if (ogs_socket_errno_would_block())
            return 0;
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno, "accept() failed");
        return -1;
    }

    if (ogs_sctp_tune_connected(new, mme_s1ap_server_option(sock)) != OGS_OK) {
        ogs_error("ogs_sctp_tune_connected() failed");
        ogs_sock_destroy(new);
        return -1;
    }

    addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));
    ogs_assert(addr);
    memcpy(addr, &new->remote_addr, sizeof(ogs_sockaddr_t));

    ogs_info("eNB-S1 accepted[%s]:%d in s1_path module",
            OGS_ADDR(addr, buf), OGS_PORT(addr));

    s1ap_event_push(MME_EVENT_S1AP_LO_ACCEPT, new, addr, NULL, 0, 0);
    return 1;
}

static int s1ap_recv_handler(ogs_sock_t *sock)
{
    ogs_pkbuf_t *pkbuf;
    int size;
    ogs_sockaddr_t *addr = NULL;
    ogs_sockaddr_t from;
    ogs_sctp_info_t sinfo;
    int flags = 0;

    ogs_assert(sock);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);
    size = ogs_sctp_recvmsg(
            sock, pkbuf->data, pkbuf->len, &from, &sinfo, &flags);
    if (size < 0) {
        ogs_pkbuf_free(pkbuf);
        if (ogs_sctp_recv_would_block(size))
            return 0;
        ogs_error("ogs_sctp_recvmsg(%d) failed(%d:%s)",
                size, errno, strerror(errno));
        return -1;
    }
    if (size >= OGS_MAX_SDU_LEN) {
        ogs_error("ogs_sctp_recvmsg(%d) too large", size);
        ogs_pkbuf_free(pkbuf);
        return -1;
    }

    if (flags & MSG_NOTIFICATION) {
        union sctp_notification *not =
            (union sctp_notification *)pkbuf->data;

        switch(not->sn_header.sn_type) {
        case SCTP_ASSOC_CHANGE :
            ogs_debug("SCTP_ASSOC_CHANGE:"
                    "[T:%d, F:0x%x, S:%d, I/O:%d/%d]",
                    not->sn_assoc_change.sac_type,
                    not->sn_assoc_change.sac_flags,
                    not->sn_assoc_change.sac_state,
                    not->sn_assoc_change.sac_inbound_streams,
                    not->sn_assoc_change.sac_outbound_streams);

            if (not->sn_assoc_change.sac_state == SCTP_COMM_UP) {
                ogs_debug("SCTP_COMM_UP");

                if ((not->sn_assoc_change.sac_outbound_streams-1) >= 1) {
                    /* NEXT_ID(MAX >= MIN) */
                    addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));
                    ogs_assert(addr);
                    memcpy(addr, &from, sizeof(ogs_sockaddr_t));

                    s1ap_event_push(MME_EVENT_S1AP_LO_SCTP_COMM_UP,
                            sock, addr, NULL,
                            not->sn_assoc_change.sac_inbound_streams,
                            not->sn_assoc_change.sac_outbound_streams);
                } else
                    ogs_error("Invalid sn_assoc_change.sac_outbound_streams %d",
                            not->sn_assoc_change.sac_outbound_streams);
            } else if (not->sn_assoc_change.sac_state == SCTP_SHUTDOWN_COMP ||
                    not->sn_assoc_change.sac_state == SCTP_COMM_LOST) {

                if (not->sn_assoc_change.sac_state == SCTP_SHUTDOWN_COMP)
                    ogs_debug("SCTP_SHUTDOWN_COMP");
                if (not->sn_assoc_change.sac_state == SCTP_COMM_LOST)
                    ogs_debug("SCTP_COMM_LOST");

                addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));
                ogs_assert(addr);
                memcpy(addr, &from, sizeof(ogs_sockaddr_t));

                s1ap_event_push(MME_EVENT_S1AP_LO_CONNREFUSED,
                        sock, addr, NULL, 0, 0);
            }
            break;

        case SCTP_SHUTDOWN_EVENT :
            ogs_debug("SCTP_SHUTDOWN_EVENT:[T:%d, F:0x%x, L:%d]",
                    not->sn_shutdown_event.sse_type,
                    not->sn_shutdown_event.sse_flags,
                    not->sn_shutdown_event.sse_length);

            addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));
            ogs_assert(addr);
            memcpy(addr, &from, sizeof(ogs_sockaddr_t));

            s1ap_event_push(MME_EVENT_S1AP_LO_CONNREFUSED,
                    sock, addr, NULL, 0, 0);
            break;

        case SCTP_SEND_FAILED :
#if HAVE_USRSCTP
            ogs_error("SCTP_SEND_FAILED:[T:%d, F:0x%x, S:%d]",
                    not->sn_send_failed_event.ssfe_type,
                    not->sn_send_failed_event.ssfe_flags,
                    not->sn_send_failed_event.ssfe_error);
#else
            ogs_error("SCTP_SEND_FAILED:[T:%d, F:0x%x, S:%d]",
                    not->sn_send_failed.ssf_type,
                    not->sn_send_failed.ssf_flags,
                    not->sn_send_failed.ssf_error);
#endif
            break;

        case SCTP_PEER_ADDR_CHANGE:
            ogs_warn("SCTP_PEER_ADDR_CHANGE:[T:%d, F:0x%x, S:%d]",
                    not->sn_paddr_change.spc_type,
                    not->sn_paddr_change.spc_flags,
                    not->sn_paddr_change.spc_error);
            break;
        case SCTP_REMOTE_ERROR:
            ogs_warn("SCTP_REMOTE_ERROR:[T:%d, F:0x%x, S:%d]",
                    not->sn_remote_error.sre_type,
                    not->sn_remote_error.sre_flags,
                    not->sn_remote_error.sre_error);
            break;
        default :
            ogs_error("Discarding event with unknown flags:0x%x type:0x%x",
                    flags, not->sn_header.sn_type);
            break;
        }

        ogs_pkbuf_free(pkbuf);
        return 1;
    } else if (flags & MSG_EOR) {
        ogs_pkbuf_trim(pkbuf, size);

        addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));
        ogs_assert(addr);
        memcpy(addr, &from, sizeof(ogs_sockaddr_t));

        s1ap_event_push(MME_EVENT_S1AP_MESSAGE, sock, addr, pkbuf, 0, 0);
        return 1;
    } else if (size == 0) {
        ogs_pkbuf_free(pkbuf);

        if (ogs_socket_errno_would_block())
            return 0;

        ogs_warn("SCTP recv returned 0 (peer shutdown)");

        addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));
        if (addr) {
            memcpy(addr, &from, sizeof(ogs_sockaddr_t));
            s1ap_event_push(MME_EVENT_S1AP_LO_CONNREFUSED,
                    sock, addr, NULL, 0, 0);
        }
        return -1;
    } else {
        ogs_error("ogs_sctp_recvmsg(%d) failed(%d:%s-0x%x)",
                size, errno, strerror(errno), flags);
        ogs_pkbuf_free(pkbuf);
        return -1;
    }
}
