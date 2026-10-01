/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
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

#include "ngap-path.h"
#include "ngap-rx.h"
#include "ngap-io.h"

#if HAVE_USRSCTP
static void usrsctp_recv_handler(struct socket *socket, void *data, int flags);
#else
static void lksctp_accept_handler(short when, ogs_socket_t fd, void *data);
#endif

static int ngap_accept_handler(ogs_sock_t *sock);
static int ngap_recv_handler(ogs_sock_t *sock);

static bool ngap_sockaddr_valid(const ogs_sockaddr_t *addr)
{
    if (!addr)
        return false;
    return addr->ogs_sa_family == AF_INET ||
            addr->ogs_sa_family == AF_INET6;
}

static void ngap_copy_peer_addr(ogs_sockaddr_t *dst,
        const ogs_sockaddr_t *from, const ogs_sock_t *sock)
{
    ogs_assert(dst);

    if (ngap_sockaddr_valid(from)) {
        memcpy(dst, from, sizeof(ogs_sockaddr_t));
    } else if (sock && ngap_sockaddr_valid(&sock->remote_addr)) {
        memcpy(dst, &sock->remote_addr, sizeof(ogs_sockaddr_t));
    } else {
        memset(dst, 0, sizeof(ogs_sockaddr_t));
    }
}

static ogs_sockopt_t ngap_default_sockopt;
static bool ngap_default_sockopt_ready = false;

static ogs_sockopt_t *ngap_default_option(void)
{
    if (!ngap_default_sockopt_ready) {
        ogs_sockopt_init(&ngap_default_sockopt);
        ngap_default_sockopt_ready = true;
    }
    return &ngap_default_sockopt;
}

static ogs_sockopt_t *amf_ngap_server_option(ogs_sock_t *listen)
{
    ogs_socknode_t *node = NULL;

    if (!listen)
        return ngap_default_option();

    ogs_list_for_each(&amf_self()->ngap_list, node) {
        if (node->sock == listen)
            return node->option ? node->option : ngap_default_option();
    }
    ogs_list_for_each(&amf_self()->ngap_list6, node) {
        if (node->sock == listen)
            return node->option ? node->option : ngap_default_option();
    }

    return ngap_default_option();
}

ogs_sock_t *ngap_server(ogs_socknode_t *node)
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
    /* the accept loop drains the backlog until EAGAIN */
    ogs_nonblocking(sock->fd);
    poll = ogs_pollset_add(ogs_app()->pollset,
            OGS_POLLIN, sock->fd, lksctp_accept_handler, sock);
    ogs_assert(poll);

    node->poll = poll;
#endif

    node->sock = sock;
    node->cleanup = ogs_sctp_destroy;

    ogs_info("ngap_server() [%s]:%d",
            OGS_ADDR(node->addr, buf), OGS_PORT(node->addr));

    return sock;
}

void ngap_recv_upcall(short when, ogs_socket_t fd, void *data)
{
    ogs_sock_t *sock = NULL;

    ogs_assert(fd != INVALID_SOCKET);
    sock = data;
    ogs_assert(sock);

    /*
     * The pollset is level-triggered: on main, one message per wakeup
     * keeps NGAP interleaved with SBI replies the way the procedures
     * expect (e.g. a UL NAS PDU session request followed by a
     * mobility registration). RX workers own nothing but the socket,
     * so they drain it.
     */
    if (!ogs_worker_self()) {
        ngap_recv_handler(sock);
        return;
    }

    while (ngap_recv_handler(sock) > 0)
        ;
}

#if HAVE_USRSCTP
static void usrsctp_recv_handler(struct socket *socket, void *data, int flags)
{
    int events;

    while ((events = usrsctp_get_events(socket)) &&
           (events & SCTP_EVENT_READ)) {
        if (ngap_recv_handler((ogs_sock_t *)socket) <= 0)
            break;
    }
}
#else
static void lksctp_accept_handler(short when, ogs_socket_t fd, void *data)
{
    ogs_assert(data);
    ogs_assert(fd != INVALID_SOCKET);

    while (ngap_accept_handler(data) > 0)
        ;
}
#endif

static int ngap_accept_handler(ogs_sock_t *sock)
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

    /*
     * Accepted one-to-one sockets inherit neither O_NONBLOCK nor the
     * SCTP event subscription (without it COMM_LOST never reaches us).
     * The recv loop and the IO thread both need non-blocking fds.
     */
    if (ogs_sctp_tune_connected(new, amf_ngap_server_option(sock)) != OGS_OK) {
        ogs_error("ogs_sctp_tune_connected() failed");
        ogs_sock_destroy(new);
        return -1;
    }

    addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));
    ogs_assert(addr);
    memcpy(addr, &new->remote_addr, sizeof(ogs_sockaddr_t));

    ogs_info("gNB-N2 accepted[%s]:%d in ng-path module",
            OGS_ADDR(addr, buf), OGS_PORT(addr));

    ngap_event_push(AMF_EVENT_NGAP_LO_ACCEPT, new, addr, NULL, 0, 0);
    return 1;
}

static void ngap_push_connrefused(ogs_sock_t *sock, ogs_sockaddr_t *from)
{
    ogs_sockaddr_t *addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));

    if (!addr)
        return;
    ngap_copy_peer_addr(addr, from, sock);
    ngap_event_push(AMF_EVENT_NGAP_LO_CONNREFUSED, sock, addr, NULL, 0, 0);
}

static int ngap_recv_handler(ogs_sock_t *sock)
{
    ogs_pkbuf_t *pkbuf;
    int size;
    ogs_sockaddr_t *addr = NULL;
    ogs_sockaddr_t from;
    ogs_sctp_info_t sinfo;
    int flags = 0;

    ogs_assert(sock);

    memset(&from, 0, sizeof(from));

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
                    ngap_copy_peer_addr(addr, &from, sock);

                    ngap_event_push(AMF_EVENT_NGAP_LO_SCTP_COMM_UP,
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

                ngap_push_connrefused(sock, &from);
            }
            break;
        case SCTP_SHUTDOWN_EVENT :
            ogs_debug("SCTP_SHUTDOWN_EVENT:[T:%d, F:0x%x, L:%d]",
                    not->sn_shutdown_event.sse_type,
                    not->sn_shutdown_event.sse_flags,
                    not->sn_shutdown_event.sse_length);
            ngap_push_connrefused(sock, &from);
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
            /*
             * With the IO thread the kernel's failure to deliver a PDU
             * is the stall signal: drop NG so the IO backlog clears
             * and UEs stop retry-flooding (same as the ETIMEDOUT path).
             */
            if (ngap_io_active())
                ngap_push_connrefused(sock, &from);
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
        ngap_copy_peer_addr(addr, &from, sock);

        if (ogs_worker_self()) {
            /*
             * NGAP RX worker: APER decode here, off the main thread.
             * On decode failure fall through with the raw pkbuf: main
             * re-decodes, fails identically and sends the Error
             * Indication from its own context.
             */
            ogs_ngap_message_t *pdu = ogs_calloc(1, sizeof(*pdu));
            ogs_assert(pdu);

            if (ogs_ngap_decode(pdu, pkbuf) == OGS_OK) {
                ngap_event_push_decoded(sock, addr, pkbuf, pdu);
                return 1;
            }

            ogs_ngap_free(pdu);
            ogs_free(pdu);
        }

        ngap_event_push(AMF_EVENT_NGAP_MESSAGE, sock, addr, pkbuf, 0, 0);
        return 1;
    } else if (size == 0) {
        /*
         * One-to-one SCTP: recv returning 0 is peer shutdown. Do not
         * consult errno; a stale EAGAIN would leave a dead association
         * on the poll loop.
         */
        ogs_pkbuf_free(pkbuf);
        ogs_warn("SCTP recv returned 0 (peer shutdown)");
        ngap_push_connrefused(sock, &from);
        return -1;
    } else {
        ogs_error("ogs_sctp_recvmsg(%d) failed(%d:%s-0x%x)",
                size, errno, strerror(errno), flags);
        ogs_pkbuf_free(pkbuf);
        return -1;
    }
}
