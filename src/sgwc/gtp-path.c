/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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

#include "gtp-path.h"
#include "pfcp-path.h"
#include "gn-build.h"
#include "metrics.h"
#include "sgwc-workers.h"
#include "event.h"

/*
 * Deliver a GTP event to the owning shard (or the main queue when
 * workers are off / message is node-local Echo).
 */
static int sgwc_gtp_deliver(sgwc_event_t *e, ogs_pkbuf_t *pkbuf)
{
    int rv;
    int wid = -1;
    bool to_main = false;
    uint32_t fallback_key = 0;
    ogs_gtp2_header_t *h2;
    ogs_gtp1_header_t *h1;
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN + 1];

    ogs_assert(e);
    ogs_assert(pkbuf);

    if (!sgwc_workers_active()) {
        /* trypush: RX runs on the same thread that drains this queue */
        rv = ogs_queue_trypush(ogs_app()->queue, e);
        if (rv != OGS_OK) {
            ogs_error("ogs_queue_trypush() failed:%d", (int)rv);
            ogs_pkbuf_free(pkbuf);
            e->pkbuf = NULL;
            sgwc_event_free(e);
            return -1;
        }
        return 1;
    }

    if (e->id == SGWC_EVT_GN_MESSAGE) {
        if (pkbuf->len < sizeof(ogs_gtp1_header_t)) {
            ogs_pkbuf_free(pkbuf);
            e->pkbuf = NULL;
            sgwc_event_free(e);
            return -1;
        }
        h1 = (ogs_gtp1_header_t *)pkbuf->data;
        if (h1->type == OGS_GTP1_ECHO_REQUEST_TYPE ||
                h1->type == OGS_GTP1_ECHO_RESPONSE_TYPE) {
            to_main = true; /* node-level, main owns the peer FSMs */
        } else if (h1->teid) {
            fallback_key = be32toh(h1->teid);
            wid = sgwc_shard_from_teid(fallback_key);
        } else {
            /* Create PDP etc. without TEID: fall back to worker 0 */
            wid = 0;
        }
    } else {
        if (pkbuf->len < 8) {
            ogs_pkbuf_free(pkbuf);
            e->pkbuf = NULL;
            sgwc_event_free(e);
            return -1;
        }
        h2 = (ogs_gtp2_header_t *)pkbuf->data;
        if (h2->type == OGS_GTP2_ECHO_REQUEST_TYPE ||
                h2->type == OGS_GTP2_ECHO_RESPONSE_TYPE) {
            to_main = true; /* node-level, main owns the peer FSMs */
        } else if (h2->teid_presence && h2->teid != 0) {
            fallback_key = be32toh(h2->teid);
            wid = sgwc_shard_from_teid(fallback_key);
        } else if (h2->type == OGS_GTP2_CREATE_SESSION_REQUEST_TYPE &&
                sgwc_gtpv2_peek_imsi_bcd(pkbuf, imsi_bcd,
                    sizeof(imsi_bcd)) == OGS_OK) {
            wid = sgwc_shard_from_imsi_bcd(imsi_bcd);
        } else {
            /* teid 0 / absent: route by SQN shard bits (xid partition) */
            uint32_t sqn_be = h2->teid_presence ? h2->sqn : h2->sqn_only;
            fallback_key = OGS_GTP2_SQN_TO_XID(sqn_be);
            wid = sgwc_shard_from_xid(fallback_key);
        }
    }

    if (to_main) {
        rv = ogs_queue_trypush(ogs_app()->queue, e);
        if (rv != OGS_OK) {
            ogs_error("ogs_queue_trypush() failed:%d", (int)rv);
            ogs_pkbuf_free(pkbuf);
            e->pkbuf = NULL;
            sgwc_event_free(e);
            return -1;
        }
        return 1;
    }

    /*
     * Session messages must NEVER go to main: with workers active main
     * owns no UEs and its event-loop thread never ran sgwc_context_init
     * (TLS hashes are NULL there — observed as ogs_hash_get assert).
     * Shard bits that don't name a live worker (stale TEID from a
     * previous run, main-encoded id 0, garbage) go to a deterministic
     * worker instead, which replies "Context not found" normally.
     */
    if (wid < 0 || wid >= sgwc_workers_count())
        wid = (int)(fallback_key % (uint32_t)sgwc_workers_count());

    return sgwc_event_push_to_worker(wid, e) == OGS_OK ? 1 : -1;
}

/*
 * PGW peers are normally learned from Create Session F-TEID. Home PGW may
 * reply from a different source IP than the F-TEID address, so classify
 * by GTP message type before defaulting unknown peers to S11 (MME).
 */
static bool sgwc_gtpc_is_s5_pgw_message(uint8_t type)
{
    switch (type) {
    case OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE:
    case OGS_GTP2_MODIFY_BEARER_RESPONSE_TYPE:
    case OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE:
    case OGS_GTP2_CREATE_BEARER_REQUEST_TYPE:
    case OGS_GTP2_UPDATE_BEARER_REQUEST_TYPE:
    case OGS_GTP2_DELETE_BEARER_REQUEST_TYPE:
    case OGS_GTP2_DELETE_BEARER_FAILURE_INDICATION_TYPE:
    case OGS_GTP2_BEARER_RESOURCE_FAILURE_INDICATION_TYPE:
        return true;
    default:
        return false;
    }
}

static int sgwc_gn_queue_message(ogs_sock_t *sock, ogs_pkbuf_t *pkbuf,
        ogs_sockaddr_t *from)
{
    sgwc_event_t *e = NULL;
    int rv;
    ogs_gtp_node_t *gnode = NULL;
    char frombuf[OGS_ADDRSTRLEN];

    ogs_assert(sock);
    ogs_assert(pkbuf);
    ogs_assert(from);

    sgwc_peers_lock();
    gnode = ogs_gtp_node_find_by_addr(sgwc_sgsn_gn_list(), from);
    if (!gnode) {
        gnode = ogs_gtp_node_add_by_addr(sgwc_sgsn_gn_list(), from);
        if (!gnode) {
            sgwc_peers_unlock();
            ogs_error("Failed to create SGSN gnode [%s]:%u",
                    OGS_ADDR(from, frombuf), OGS_PORT(from));
            ogs_pkbuf_free(pkbuf);
            return -1;
        }
        gnode->sock = sock;
        rv = ogs_gtp_connect(ogs_gtp_self()->gtpc_sock,
                ogs_gtp_self()->gtpc_sock6, gnode);
        if (rv != OGS_OK)
            ogs_error("ogs_gtp_connect() failed for SGSN [%s]:%u",
                    OGS_ADDR(from, frombuf), OGS_PORT(from));
        sgwc_sgsn_peer_setup(gnode);
    }
    sgwc_peers_unlock();

    e = sgwc_event_new(SGWC_EVT_GN_MESSAGE);
    ogs_assert(e);
    e->gnode = gnode;
    e->pkbuf = pkbuf;

    return sgwc_gtp_deliver(e, pkbuf);
}

static int sgwc_gn_recv_one(ogs_sock_t *sock)
{
    ssize_t size;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;

    ogs_assert(sock);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    size = ogs_recvfrom(sock->fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_pkbuf_free(pkbuf);
        if (size < 0 && ogs_socket_errno_would_block())
            return 0;
        return -1;
    }

    ogs_pkbuf_trim(pkbuf, size);
    return sgwc_gn_queue_message(sock, pkbuf, &from);
}

static void _gtpv1_c_recv_cb(short when, ogs_socket_t fd, void *data)
{
    ogs_sock_t *sock = data;

    ogs_assert(sock);

    while (sgwc_gn_recv_one(sock) > 0)
        ;
}

static int sgwc_gtpc_recv_one(ogs_sock_t *sock)
{
    sgwc_event_t *e = NULL;
    int rv;
    ssize_t size;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;
    ogs_gtp_node_t *gnode = NULL;
    char frombuf[OGS_ADDRSTRLEN];

    ogs_assert(sock);
    ogs_assert(sock->fd != INVALID_SOCKET);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    size = ogs_recvfrom(sock->fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_pkbuf_free(pkbuf);
        if (size < 0 && ogs_socket_errno_would_block())
            return 0;
        if (size < 0) {
            ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                    "ogs_recvfrom() failed");
        }
        return -1;
    }

    ogs_pkbuf_trim(pkbuf, size);

    if (pkbuf->len >= sizeof(ogs_gtp1_header_t)) {
        uint8_t gtp_ver = ((ogs_gtp1_header_t *)pkbuf->data)->version;

        if (gtp_ver == 1 && sgwc_self()->gn_enabled)
            return sgwc_gn_queue_message(sock, pkbuf, &from);

        if (gtp_ver != 2) {
            ogs_debug("Ignoring GTPv%u on GTPC socket", gtp_ver);
            ogs_pkbuf_free(pkbuf);
            return 0;
        }
    }

    /*
     * 5.5.2 in spec 29.274
     *
     * If a peer's TEID is not available, the TEID field still shall be
     * present in the header and its value shall be set to "0" in the
     * following messages:
     *
     * - Create Session Request message on S2a/S2b/S5/S8
     *
     * - Create Session Request message on S4/S11, if for a given UE,
     *   the SGSN/MME has not yet obtained the Control TEID of the SGW.
     *
     * - If a node receives a message and the TEID-C in the GTPv2 header of
     *   the received message is not known, it shall respond with
     *   "Context not found" Cause in the corresponding response message
     *   to the sender, the TEID used in the GTPv2-C header in the response
     *   message shall be then set to zero.
     *
     * - If a node receives a request message containing protocol error,
     *   e.g. Mandatory IE missing, which requires the receiver to reject
     *   the message as specified in clause 7.7, it shall reject
     *   the request message. For the response message, the node should
     *   look up the remote peer's TEID and accordingly set the GTPv2-C
     *   header TEID and the message cause code. As an implementation
     *   option, the node may not look up the remote peer's TEID and
     *   set the GTPv2-C header TEID to zero in the response message.
     *   However in this case, the cause code shall not be set to
     *   "Context not found".
     */
    sgwc_peers_lock();
    gnode = ogs_gtp_node_find_by_addr(sgwc_pgw_s5c_list(), &from);
    if (!gnode) {
        uint8_t msg_type = 0;

        if (pkbuf->len >= sizeof(ogs_gtp2_header_t))
            msg_type = ((ogs_gtp2_header_t *)pkbuf->data)->type;

        if (sgwc_gtpc_is_s5_pgw_message(msg_type)) {
            gnode = ogs_gtp_node_add_by_addr(
                    sgwc_pgw_s5c_list(), &from);
            if (!gnode) {
                sgwc_peers_unlock();
                ogs_error("Failed to create PGW gnode(%s:%u), mempool full, "
                        "ignoring msg!",
                        OGS_ADDR(&from, frombuf), OGS_PORT(&from));
                ogs_pkbuf_free(pkbuf);
                return -1;
            }
            gnode->sock = sock;
            ogs_info("PGW S5-C peer learned [%s]:%u (GTP type %u)",
                    OGS_ADDR(&from, frombuf), OGS_PORT(&from), msg_type);

            if (sgwc_self()->inbound_roam_gtpc_source_port) {
                rv = ogs_gtp_connect(sgwc_self()->roam_gtpc_sock,
                        sgwc_self()->roam_gtpc_sock6, gnode);
            } else {
                rv = ogs_gtp_connect(ogs_gtp_self()->gtpc_sock,
                        ogs_gtp_self()->gtpc_sock6, gnode);
            }
            if (rv != OGS_OK) {
                ogs_error("ogs_gtp_connect() failed for learned PGW [%s]:%u",
                        OGS_ADDR(&from, frombuf), OGS_PORT(&from));
            }
            sgwc_pgw_peer_setup(gnode);
        }
    }

    if (gnode) {
        e = sgwc_event_new(SGWC_EVT_S5C_MESSAGE);
        ogs_assert(e);
        e->gnode = gnode;
        sgwc_peers_unlock();
    } else {
        if (sgwc_self()->gn_enabled &&
                ogs_gtp_node_find_by_addr(
                    sgwc_sgsn_gn_list(), &from)) {
            sgwc_peers_unlock();
            ogs_debug("Ignoring GTPv2 from known Gn SGSN [%s]:%u",
                    OGS_ADDR(&from, frombuf), OGS_PORT(&from));
            ogs_pkbuf_free(pkbuf);
            return 0;
        }

        gnode = ogs_gtp_node_find_by_addr(sgwc_mme_s11_list(), &from);
        if (!gnode) {
            gnode = ogs_gtp_node_add_by_addr(sgwc_mme_s11_list(), &from);
            if (!gnode) {
                uint8_t msg_type = 0;

                sgwc_peers_unlock();
                if (pkbuf->len >= sizeof(ogs_gtp2_header_t))
                    msg_type = ((ogs_gtp2_header_t *)pkbuf->data)->type;
                ogs_error("Failed to create MME gnode [%s]:%u mempool full "
                        "GTPv2 type[%u] — ignoring",
                        OGS_ADDR(&from, frombuf), OGS_PORT(&from), msg_type);
                ogs_pkbuf_free(pkbuf);
                return -1;
            }
            gnode->sock = sock;
        }
        sgwc_mme_peer_setup(gnode);
        sgwc_peers_unlock();
        e = sgwc_event_new(SGWC_EVT_S11_MESSAGE);
        ogs_assert(e);
        e->gnode = gnode;
    }

    e->pkbuf = pkbuf;

    return sgwc_gtp_deliver(e, pkbuf);
}

static void _gtpv2_c_recv_cb(short when, ogs_socket_t fd, void *data)
{
    ogs_sock_t *sock = data;

    ogs_assert(fd != INVALID_SOCKET);
    ogs_assert(sock);

    while (sgwc_gtpc_recv_one(sock) > 0)
        ;
}

static ogs_sockaddr_t *sgwc_gtpc_sa_with_port(
        ogs_sockaddr_t *src, uint16_t port)
{
    ogs_sockaddr_t *dst = NULL;
    ogs_sockaddr_t *p = NULL;

    ogs_assert(src);
    ogs_assert(port);

    ogs_assert(OGS_OK == ogs_copyaddrinfo(&dst, src));
    for (p = dst; p; p = p->next) {
        if (p->ogs_sa_family == AF_INET)
            p->sin.sin_port = htobe16(port);
        else if (p->ogs_sa_family == AF_INET6)
            p->sin6.sin6_port = htobe16(port);
    }

    return dst;
}

static int sgwc_roam_gtpc_open(void)
{
    char buf[OGS_ADDRSTRLEN];
    uint16_t port = sgwc_self()->inbound_roam_gtpc_source_port;
    ogs_sockaddr_t *sa_list = NULL;
    ogs_sockaddr_t *sa_list6 = NULL;
    ogs_sock_t *sock = NULL;

    if (!port)
        return OGS_OK;

    if (port == ogs_gtp_self()->gtpc_port) {
        ogs_warn("inbound_roam.gtpc.source_port == gtpc.server.port (%u); "
                "single socket mode", port);
        return OGS_OK;
    }

    if (ogs_gtp_self()->gtpc_addr) {
        sa_list = sgwc_gtpc_sa_with_port(ogs_gtp_self()->gtpc_addr, port);
        ogs_assert(sa_list);
        sock = ogs_udp_server(sa_list, NULL);
        ogs_freeaddrinfo(sa_list);
        if (!sock) {
            ogs_error("roam GTP-C IPv4 bind failed port %u", port);
            return OGS_ERROR;
        }
        sgwc_self()->roam_gtpc_sock = sock;
        sgwc_self()->roam_gtpc_addr = &sock->local_addr;
        ogs_info("roam GTP-C bind [%s]:%u (S5 local source; PGW dest port %u)",
                OGS_ADDR(sgwc_self()->roam_gtpc_addr, buf), port,
                ogs_gtp_self()->gtpc_port);
        sgwc_self()->roam_gtpc_poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, _gtpv2_c_recv_cb, sock);
        ogs_assert(sgwc_self()->roam_gtpc_poll);
    }

    if (ogs_gtp_self()->gtpc_addr6) {
        sa_list6 = sgwc_gtpc_sa_with_port(ogs_gtp_self()->gtpc_addr6, port);
        ogs_assert(sa_list6);
        sock = ogs_udp_server(sa_list6, NULL);
        ogs_freeaddrinfo(sa_list6);
        if (!sock) {
            ogs_error("roam GTP-C IPv6 bind failed port %u", port);
            return OGS_ERROR;
        }
        sgwc_self()->roam_gtpc_sock6 = sock;
        sgwc_self()->roam_gtpc_addr6 = &sock->local_addr;
        ogs_info("roam GTP-C bind [%s]:%u (S5 local source; PGW dest port %u)",
                OGS_ADDR(sgwc_self()->roam_gtpc_addr6, buf), port,
                ogs_gtp_self()->gtpc_port);
        sgwc_self()->roam_gtpc_poll6 = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, _gtpv2_c_recv_cb, sock);
        ogs_assert(sgwc_self()->roam_gtpc_poll6);
    }

    if (!sgwc_self()->roam_gtpc_sock && !sgwc_self()->roam_gtpc_sock6) {
        ogs_error("inbound_roam.gtpc.source_port %u: no roam socket", port);
        return OGS_ERROR;
    }

    return OGS_OK;
}

bool sgwc_gtpc_roam_port_enabled(void)
{
    uint16_t port = sgwc_self()->inbound_roam_gtpc_source_port;

    if (!port || port == ogs_gtp_self()->gtpc_port)
        return false;

    return sgwc_self()->roam_gtpc_sock != NULL ||
        sgwc_self()->roam_gtpc_sock6 != NULL;
}

static bool sgwc_gtpc_use_roam_socket(sgwc_sess_t *sess)
{
    ogs_assert(sess);
    return sgwc_gtpc_roam_port_enabled() &&
        sgwc_sess_is_inbound_roam(sess);
}

void sgwc_gtpc_f_teid_addr(
        sgwc_sess_t *sess,
        ogs_sockaddr_t **addr, ogs_sockaddr_t **addr6)
{
    ogs_assert(addr);
    ogs_assert(addr6);

    if (sgwc_gtpc_use_roam_socket(sess)) {
        *addr = sgwc_self()->roam_gtpc_addr;
        *addr6 = sgwc_self()->roam_gtpc_addr6;
    } else {
        *addr = ogs_gtp_self()->gtpc_addr;
        *addr6 = ogs_gtp_self()->gtpc_addr6;
    }
}

int sgwc_gtp_connect_peer(sgwc_sess_t *sess, ogs_gtp_node_t *gnode)
{
    ogs_sock_t *sock = NULL;
    ogs_sock_t *sock6 = NULL;

    ogs_assert(gnode);

    if (sgwc_gtpc_use_roam_socket(sess)) {
        sock = sgwc_self()->roam_gtpc_sock;
        sock6 = sgwc_self()->roam_gtpc_sock6;
    } else {
        sock = ogs_gtp_self()->gtpc_sock;
        sock6 = ogs_gtp_self()->gtpc_sock6;
    }

    return ogs_gtp_connect(sock, sock6, gnode);
}

int sgwc_gtp_open(void)
{
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;

    ogs_list_for_each(&ogs_gtp_self()->gtpc_list, node) {
        sock = ogs_gtp_server(node);
        if (!sock) return OGS_ERROR;

        node->poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, _gtpv2_c_recv_cb, sock);
        ogs_assert(node->poll);
    }
    ogs_list_for_each(&ogs_gtp_self()->gtpc_list6, node) {
        sock = ogs_gtp_server(node);
        if (!sock) return OGS_ERROR;

        node->poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, _gtpv2_c_recv_cb, sock);
        ogs_assert(node->poll);
    }

    OGS_SETUP_GTPC_SERVER;
    ogs_assert(ogs_gtp_self()->gtpc_sock || ogs_gtp_self()->gtpc_sock6);
    ogs_assert(ogs_gtp_self()->gtpc_addr || ogs_gtp_self()->gtpc_addr6);

    if (sgwc_self()->gn_enabled) {
        ogs_socknode_t *node = NULL;
        ogs_sock_t *gn_sock = NULL;

        if (!ogs_list_empty(&sgwc_self()->gn_server_list) ||
                !ogs_list_empty(&sgwc_self()->gn_server_list6)) {
            ogs_list_for_each(&sgwc_self()->gn_server_list, node) {
                gn_sock = ogs_gtp_server(node);
                if (!gn_sock)
                    return OGS_ERROR;
                node->poll = ogs_pollset_add(ogs_app()->pollset,
                        OGS_POLLIN, gn_sock->fd, _gtpv1_c_recv_cb, gn_sock);
                ogs_assert(node->poll);
            }
            ogs_list_for_each(&sgwc_self()->gn_server_list6, node) {
                gn_sock = ogs_gtp_server(node);
                if (!gn_sock)
                    return OGS_ERROR;
                node->poll = ogs_pollset_add(ogs_app()->pollset,
                        OGS_POLLIN, gn_sock->fd, _gtpv1_c_recv_cb, gn_sock);
                ogs_assert(node->poll);
            }
        }

        sgwc_self()->gn_addr = ogs_gtp_self()->gtpc_addr;
        sgwc_self()->gn_addr6 = ogs_gtp_self()->gtpc_addr6;
        if (gn_sock) {
            if (gn_sock->local_addr.ogs_sa_family == AF_INET)
                sgwc_self()->gn_addr = &gn_sock->local_addr;
            else
                sgwc_self()->gn_addr6 = &gn_sock->local_addr;
        }
    }

    return sgwc_roam_gtpc_open();
}

void sgwc_gtp_send_mme_echo(ogs_gtp_node_t *gnode)
{
    ogs_assert(gnode);
    ogs_gtp2_send_echo_request(
            gnode, sgwc_self()->gtpc_recovery, 0);
}

void sgwc_gtp_send_sgsn_echo(ogs_gtp_node_t *gnode)
{
    ogs_assert(gnode);
    ogs_gtp1_send_echo_request(gnode);
}

void sgwc_timer_sgsn_echo(void *data)
{
    sgwc_sgsn_peer_t *peer = data;

    ogs_assert(peer);
    ogs_assert(peer->gnode);

    sgwc_gtp_send_sgsn_echo(peer->gnode);
    sgwc_sgsn_echo_schedule(peer);
}

/* Stored in sgwc_event_t.timer_id for SGWC_EVT_PEER_ECHO_SETUP */
enum {
    SGWC_PEER_ECHO_KIND_PGW = 1,
    SGWC_PEER_ECHO_KIND_MME = 2,
    SGWC_PEER_ECHO_KIND_SGSN = 3,
};

static int sgwc_peer_echo_defer_to_main(ogs_gtp_node_t *gnode, int kind)
{
    sgwc_event_t *e;
    int rv;

    ogs_assert(gnode);

    e = sgwc_event_new(SGWC_EVT_PEER_ECHO_SETUP);
    ogs_assert(e);
    e->gnode = gnode;
    e->timer_id = kind;

    rv = ogs_queue_trypush(ogs_app()->queue, e);
    if (rv == OGS_OK)
        ogs_pollset_notify(ogs_app()->pollset);
    else
        sgwc_event_free(e);

    return rv;
}

void sgwc_sgsn_peer_start_echo(ogs_gtp_node_t *gnode)
{
    sgwc_sgsn_peer_t *peer = NULL;

    ogs_assert(gnode);

    peer = sgwc_sgsn_peer_get(gnode);
    ogs_assert(peer);

    if (peer->t_echo)
        return;

    /* Main timer_mgr is not SMP-safe — never mutate it from a worker. */
    if (ogs_worker_self()) {
        if (!peer->echo_pending) {
            peer->echo_pending = true;
            if (sgwc_peer_echo_defer_to_main(
                        gnode, SGWC_PEER_ECHO_KIND_SGSN) != OGS_OK)
                peer->echo_pending = false;
        }
        return;
    }

    peer->echo_pending = false;
    peer->t_echo = ogs_timer_add(
            ogs_app()->timer_mgr, sgwc_timer_sgsn_echo, peer);
    ogs_assert(peer->t_echo);

    sgwc_gtp_send_sgsn_echo(gnode);
    sgwc_sgsn_echo_schedule(peer);
}

void sgwc_timer_mme_echo(void *data)
{
    sgwc_mme_peer_t *peer = data;

    ogs_assert(peer);
    ogs_assert(peer->gnode);

    sgwc_gtp_send_mme_echo(peer->gnode);
    sgwc_mme_echo_schedule(peer);
}

void sgwc_mme_peer_setup(ogs_gtp_node_t *gnode)
{
    sgwc_mme_peer_t *peer = NULL;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(gnode);

    sgwc_peers_lock();
    sgwc_mme_peer_attach(gnode);
    peer = sgwc_mme_peer_get(gnode);
    ogs_assert(peer);

    if (peer->t_echo) {
        sgwc_peers_unlock();
        return;
    }

    if (ogs_worker_self()) {
        if (!peer->echo_pending) {
            peer->echo_pending = true;
            sgwc_peers_unlock();
            if (sgwc_peer_echo_defer_to_main(
                        gnode, SGWC_PEER_ECHO_KIND_MME) != OGS_OK) {
                sgwc_peers_lock();
                peer = sgwc_mme_peer_get(gnode);
                if (peer)
                    peer->echo_pending = false;
                sgwc_peers_unlock();
            }
        } else {
            sgwc_peers_unlock();
        }
        return;
    }

    peer->echo_pending = false;
    peer->t_echo = ogs_timer_add(
            ogs_app()->timer_mgr, sgwc_timer_mme_echo, peer);
    ogs_assert(peer->t_echo);

    ogs_info("SGWC S11 MME peer: [%s]:%d",
            OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));

    sgwc_gtp_send_mme_echo(gnode);
    sgwc_mme_echo_schedule(peer);
    sgwc_peers_unlock();
}

void sgwc_gtp_send_pgw_echo(ogs_gtp_node_t *gnode)
{
    ogs_assert(gnode);
    ogs_gtp2_send_echo_request(
            gnode, sgwc_self()->gtpc_recovery, 0);
}

void sgwc_timer_pgw_echo(void *data)
{
    sgwc_pgw_peer_t *peer = data;

    ogs_assert(peer);
    ogs_assert(peer->gnode);

    sgwc_gtp_send_pgw_echo(peer->gnode);
    sgwc_pgw_echo_schedule(peer);
}

void sgwc_pgw_peer_setup(ogs_gtp_node_t *gnode)
{
    sgwc_pgw_peer_t *peer = NULL;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(gnode);

    sgwc_peers_lock();
    sgwc_pgw_peer_attach(gnode);
    peer = sgwc_pgw_peer_get(gnode);
    ogs_assert(peer);

    if (peer->t_echo) {
        sgwc_peers_unlock();
        return;
    }

    if (ogs_worker_self()) {
        if (!peer->echo_pending) {
            peer->echo_pending = true;
            sgwc_peers_unlock();
            if (sgwc_peer_echo_defer_to_main(
                        gnode, SGWC_PEER_ECHO_KIND_PGW) != OGS_OK) {
                sgwc_peers_lock();
                peer = sgwc_pgw_peer_get(gnode);
                if (peer)
                    peer->echo_pending = false;
                sgwc_peers_unlock();
            }
        } else {
            sgwc_peers_unlock();
        }
        return;
    }

    peer->echo_pending = false;
    peer->t_echo = ogs_timer_add(
            ogs_app()->timer_mgr, sgwc_timer_pgw_echo, peer);
    ogs_assert(peer->t_echo);

    ogs_info("SGWC S5 PGW peer: [%s]:%d",
            OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));

    sgwc_gtp_send_pgw_echo(gnode);
    sgwc_pgw_echo_schedule(peer);
    sgwc_peers_unlock();
}

/* Main-thread only: finish deferred echo timer setup for a GTP peer. */
void sgwc_peer_echo_setup_on_main(ogs_gtp_node_t *gnode, int kind)
{
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(gnode);
    ogs_assert(!ogs_worker_self());

    sgwc_peers_lock();

    switch (kind) {
    case SGWC_PEER_ECHO_KIND_PGW: {
        sgwc_pgw_peer_t *peer = sgwc_pgw_peer_get(gnode);

        if (!peer) {
            sgwc_peers_unlock();
            return;
        }
        peer->echo_pending = false;
        if (peer->t_echo) {
            sgwc_peers_unlock();
            return;
        }
        peer->t_echo = ogs_timer_add(
                ogs_app()->timer_mgr, sgwc_timer_pgw_echo, peer);
        ogs_assert(peer->t_echo);
        ogs_info("SGWC S5 PGW peer: [%s]:%d",
                OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));
        sgwc_gtp_send_pgw_echo(gnode);
        sgwc_pgw_echo_schedule(peer);
        break;
    }
    case SGWC_PEER_ECHO_KIND_MME: {
        sgwc_mme_peer_t *peer = sgwc_mme_peer_get(gnode);

        if (!peer) {
            sgwc_peers_unlock();
            return;
        }
        peer->echo_pending = false;
        if (peer->t_echo) {
            sgwc_peers_unlock();
            return;
        }
        peer->t_echo = ogs_timer_add(
                ogs_app()->timer_mgr, sgwc_timer_mme_echo, peer);
        ogs_assert(peer->t_echo);
        ogs_info("SGWC S11 MME peer: [%s]:%d",
                OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));
        sgwc_gtp_send_mme_echo(gnode);
        sgwc_mme_echo_schedule(peer);
        break;
    }
    case SGWC_PEER_ECHO_KIND_SGSN: {
        sgwc_sgsn_peer_t *peer = sgwc_sgsn_peer_get(gnode);

        if (!peer) {
            sgwc_peers_unlock();
            return;
        }
        peer->echo_pending = false;
        if (peer->t_echo) {
            sgwc_peers_unlock();
            return;
        }
        peer->t_echo = ogs_timer_add(
                ogs_app()->timer_mgr, sgwc_timer_sgsn_echo, peer);
        ogs_assert(peer->t_echo);
        sgwc_gtp_send_sgsn_echo(gnode);
        sgwc_sgsn_echo_schedule(peer);
        break;
    }
    default:
        ogs_error("SGWC_EVT_PEER_ECHO_SETUP: unknown kind %d", kind);
        break;
    }

    sgwc_peers_unlock();
}

int sgwc_gtp_send_s5c_delete_session_request(sgwc_sess_t *sess)
{
    int rv;
    sgwc_bearer_t *bearer = NULL;

    ogs_gtp2_message_t gtp_message;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(sess);

    if (!sess->gnode)
        return OGS_OK;

    bearer = sgwc_default_bearer_in_sess(sess);
    if (!bearer) {
        ogs_error("No bearer for S5 Delete Session Request");
        return OGS_ERROR;
    }

    memset(&gtp_message, 0, sizeof(ogs_gtp2_message_t));
    gtp_message.h.type = OGS_GTP2_DELETE_SESSION_REQUEST_TYPE;
    gtp_message.h.teid = sess->pgw_s5c_teid;
    gtp_message.delete_session_request.linked_eps_bearer_id.presence = 1;
    gtp_message.delete_session_request.linked_eps_bearer_id.u8 = bearer->ebi;

    pkbuf = ogs_gtp2_build_msg(&gtp_message);
    if (!pkbuf) {
        ogs_error("ogs_gtp2_build_msg() failed");
        return OGS_ERROR;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DELETE_SESSION_REQUEST_TYPE;
    h.teid = sess->pgw_s5c_teid;

    xact = ogs_gtp_xact_local_create(
            sess->gnode, &h, pkbuf, NULL, OGS_UINT_TO_POINTER(sess->id));
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    xact->local_teid = sess->sgw_s5c_teid;

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgwc_gtp_send_network_delete_session(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess)
{
    int rv;
    sgwc_bearer_t *bearer = NULL;

    ogs_gtp2_message_t gtp_message;
    ogs_gtp2_delete_session_request_t *req = NULL;

    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(sgwc_ue);
    ogs_assert(sess);

    if (!sgwc_ue->gnode) {
        ogs_error("[%s] No S11 peer for network Delete Session Request",
                sgwc_ue->imsi_bcd);
        return OGS_ERROR;
    }

    bearer = sgwc_default_bearer_in_sess(sess);
    if (!bearer) {
        ogs_error("[%s] No bearer for network Delete Session Request",
                sgwc_ue->imsi_bcd);
        return OGS_ERROR;
    }

    memset(&gtp_message, 0, sizeof(ogs_gtp2_message_t));
    req = &gtp_message.delete_session_request;
    req->linked_eps_bearer_id.presence = 1;
    req->linked_eps_bearer_id.u8 = bearer->ebi;

    gtp_message.h.type = OGS_GTP2_DELETE_SESSION_REQUEST_TYPE;

    pkbuf = ogs_gtp2_build_msg(&gtp_message);
    if (!pkbuf) {
        ogs_error("ogs_gtp2_build_msg() failed");
        return OGS_ERROR;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DELETE_SESSION_REQUEST_TYPE;
    h.teid = sgwc_ue->mme_s11_teid;

    xact = ogs_gtp_xact_local_create(
            sgwc_ue->gnode, &h, pkbuf, NULL, NULL);
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        return OGS_ERROR;
    }
    xact->local_teid = sgwc_ue->sgw_s11_teid;

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

/*
 * Timeout for an admin-initiated Delete Bearer Request to MME: MME did not
 * respond.  Log a warning and force a PFCP session deletion so the local
 * context and SGW-U tunnel are cleaned up despite the silent MME.
 */
static void admin_delete_bearer_timeout(ogs_gtp_xact_t *xact, void *data)
{
    ogs_pool_id_t bearer_id = OGS_INVALID_POOL_ID;
    sgwc_bearer_t *bearer = NULL;
    sgwc_sess_t *sess = NULL;
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_assert(xact);

    if (!data) {
        ogs_error("admin_delete_bearer_timeout: no bearer data");
        return;
    }
    bearer_id = OGS_POINTER_TO_UINT(data);
    bearer = sgwc_bearer_find_by_id(bearer_id);
    if (!bearer) {
        ogs_warn("admin_delete_bearer_timeout: bearer [%d] already gone",
                 (int)bearer_id);
        return;
    }
    sess = sgwc_sess_find_by_id(bearer->sess_id);
    if (!sess) {
        ogs_warn("admin_delete_bearer_timeout: session already gone");
        return;
    }
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);

    ogs_warn("[%s] No Delete Bearer Response from MME (admin delete) "
             "-- forcing local SGW-U PFCP cleanup",
             sgwc_ue ? sgwc_ue->imsi_bcd : "-");

    /* Best-effort PFCP session deletion; SXA cleanup will free the session. */
    ogs_assert(OGS_OK ==
        sgwc_pfcp_send_session_deletion_request(
            sess, OGS_INVALID_POOL_ID, NULL));
}

int sgwc_gtp_send_delete_bearer_request_to_mme(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess,
        ogs_pool_id_t s5c_xact_id)
{
    int rv;
    sgwc_bearer_t *bearer = NULL;

    ogs_gtp2_message_t gtp_message;
    ogs_gtp2_delete_bearer_request_t *req = NULL;

    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *s11_xact = NULL;

    ogs_assert(sgwc_ue);
    ogs_assert(sess);

    if (!sgwc_ue->gnode) {
        ogs_error("[%s] No S11 peer for Delete Bearer Request",
                sgwc_ue->imsi_bcd);
        return OGS_ERROR;
    }

    bearer = sgwc_default_bearer_in_sess(sess);
    if (!bearer) {
        ogs_error("[%s] No default bearer for Delete Bearer Request",
                sgwc_ue->imsi_bcd);
        return OGS_ERROR;
    }

    memset(&gtp_message, 0, sizeof(gtp_message));
    req = &gtp_message.delete_bearer_request;

    req->linked_eps_bearer_id.presence = 1;
    req->linked_eps_bearer_id.u8 = bearer->ebi;

    /* Must set gtp_message.h.type so ogs_gtp2_build_msg picks the right serializer. */
    gtp_message.h.type = OGS_GTP2_DELETE_BEARER_REQUEST_TYPE;
    gtp_message.h.teid = sgwc_ue->mme_s11_teid;

    pkbuf = ogs_gtp2_build_msg(&gtp_message);
    if (!pkbuf) {
        ogs_error("ogs_gtp2_build_msg() failed");
        return OGS_ERROR;
    }

    /*
     * Use bearer_timeout as the fallback so a non-responding MME is handled
     * gracefully (same path as the PGW-originated Delete Bearer Request).
     */
    s11_xact = ogs_gtp_xact_local_create(
            sgwc_ue->gnode, &gtp_message.h, pkbuf,
            admin_delete_bearer_timeout, OGS_UINT_TO_POINTER(bearer->id));
    if (!s11_xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        return OGS_ERROR;
    }
    s11_xact->local_teid = sgwc_ue->sgw_s11_teid;

    /* Record which bearer this belongs to (used by the response handler). */
    s11_xact->data = OGS_UINT_TO_POINTER(bearer->id);

    /*
     * Associate the S5C transaction when there is one (PGW-forwarded path).
     * For admin-initiated calls pass OGS_INVALID_POOL_ID — the response
     * handler detects the absence and handles local cleanup instead of
     * forwarding to PGW.
     */
    if (s5c_xact_id != OGS_INVALID_POOL_ID) {
        ogs_gtp_xact_t *s5c_xact = ogs_gtp_xact_find_by_id(s5c_xact_id);
        if (s5c_xact)
            ogs_gtp_xact_associate(s5c_xact, s11_xact);
    }

    ogs_info("[%s] Delete Bearer Request -> MME EBI=%d APN=%s "
             "(admin=%s)",
             sgwc_ue->imsi_bcd, bearer->ebi,
             sgwc_default_bearer_in_sess(sess) &&
                     sess->session.name ? sess->session.name : "-",
             s5c_xact_id == OGS_INVALID_POOL_ID ? "yes" : "no");

    rv = ogs_gtp_xact_commit(s11_xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

void sgwc_gtp_close(void)
{
    if (sgwc_self()->roam_gtpc_poll) {
        ogs_pollset_remove(sgwc_self()->roam_gtpc_poll);
        sgwc_self()->roam_gtpc_poll = NULL;
    }
    if (sgwc_self()->roam_gtpc_sock) {
        ogs_sock_destroy(sgwc_self()->roam_gtpc_sock);
        sgwc_self()->roam_gtpc_sock = NULL;
        sgwc_self()->roam_gtpc_addr = NULL;
    }
    if (sgwc_self()->roam_gtpc_poll6) {
        ogs_pollset_remove(sgwc_self()->roam_gtpc_poll6);
        sgwc_self()->roam_gtpc_poll6 = NULL;
    }
    if (sgwc_self()->roam_gtpc_sock6) {
        ogs_sock_destroy(sgwc_self()->roam_gtpc_sock6);
        sgwc_self()->roam_gtpc_sock6 = NULL;
        sgwc_self()->roam_gtpc_addr6 = NULL;
    }

    ogs_socknode_remove_all(&ogs_gtp_self()->gtpc_list);
    ogs_socknode_remove_all(&ogs_gtp_self()->gtpc_list6);
    ogs_socknode_remove_all(&sgwc_self()->gn_server_list);
    ogs_socknode_remove_all(&sgwc_self()->gn_server_list6);
}

int sgwc_gtp_send_create_pdp_context_response(
        sgwc_sess_t *sess, ogs_gtp_xact_t *gn_xact,
        ogs_gtp2_create_session_response_t *s5_rsp)
{
    int rv;
    sgwc_ue_t *sgwc_ue = NULL;
    ogs_gtp1_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(gn_xact);
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);

    pkbuf = sgwc_gn_build_create_pdp_context_response(
            OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE, sess, s5_rsp);
    if (!pkbuf) {
        ogs_error("sgwc_gn_build_create_pdp_context_response() failed");
        return OGS_ERROR;
    }

    memset(&h, 0, sizeof(h));
    h.type = OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE;
    h.teid = sgwc_ue->mme_s11_teid;

    rv = ogs_gtp1_xact_update_tx(gn_xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_commit(gn_xact);
    ogs_expect(rv == OGS_OK);
    return rv;
}

int sgwc_gtp_send_delete_pdp_context_response(
        sgwc_sess_t *sess, ogs_gtp_xact_t *gn_xact, uint8_t gtp1_cause)
{
    int rv;
    sgwc_ue_t *sgwc_ue = NULL;
    ogs_gtp1_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(gn_xact);

    if (sess)
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);

    pkbuf = sgwc_gn_build_delete_pdp_context_response(
            OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE, sess, gtp1_cause);
    if (!pkbuf) {
        ogs_error("sgwc_gn_build_delete_pdp_context_response() failed");
        return OGS_ERROR;
    }

    memset(&h, 0, sizeof(h));
    h.type = OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE;
    h.teid = sgwc_ue ? sgwc_ue->mme_s11_teid : 0;

    rv = ogs_gtp1_xact_update_tx(gn_xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_commit(gn_xact);
    ogs_expect(rv == OGS_OK);
    return rv;
}

int sgwc_gtp_send_update_pdp_context_response(
        ogs_gtp_xact_t *gn_xact, uint32_t sgsn_teid, ogs_pkbuf_t *pkbuf)
{
    int rv;
    ogs_gtp1_header_t h;

    ogs_assert(gn_xact);
    ogs_assert(pkbuf);

    memset(&h, 0, sizeof(h));
    h.type = OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE;
    h.teid = sgsn_teid;

    rv = ogs_gtp1_xact_update_tx(gn_xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_commit(gn_xact);
    ogs_expect(rv == OGS_OK);
    return rv;
}

static void bearer_timeout(ogs_gtp_xact_t *xact, void *data)
{
    sgwc_bearer_t *bearer = data;
    ogs_pool_id_t bearer_id = OGS_INVALID_POOL_ID;
    sgwc_sess_t *sess = NULL;
    sgwc_ue_t *sgwc_ue = NULL;
    uint8_t type = 0;

    ogs_assert(xact);
    type = xact->seq[0].type;

    ogs_assert(data);
    bearer_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(bearer_id >= OGS_MIN_POOL_ID && bearer_id <= OGS_MAX_POOL_ID);

    bearer = sgwc_bearer_find_by_id(bearer_id);
    if (!bearer) {
        ogs_error("Bearer[%d] has already been removed [%d]", bearer_id, type);
        return;
    }

    sess = sgwc_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);

    switch (type) {
    case OGS_GTP2_DOWNLINK_DATA_NOTIFICATION_TYPE:
        ogs_warn("[%s] No Downlink Data Notification ACK", sgwc_ue->imsi_bcd);
        break;
    default:
        ogs_error("GTP Timeout : IMSI[%s] Message-Type[%d]",
                sgwc_ue->imsi_bcd, type);
    }
}

int sgwc_gtp_send_create_session_response(
    sgwc_sess_t *sess, ogs_gtp_xact_t *xact)
{
    int rv;

    sgwc_ue_t *sgwc_ue = NULL;

    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);
    ogs_assert(xact);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE;
    h.teid = sgwc_ue->mme_s11_teid;

    pkbuf = sgwc_s11_build_create_session_response(h.type, sess);
    if (!pkbuf) {
        ogs_error("sgwc_s11_build_create_session_response() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    if (rv == OGS_OK)
        sgwc_metrics_create_session_success(sgwc_ue);

    return rv;
}

int sgwc_gtp_send_downlink_data_notification(
    uint8_t cause_value, sgwc_bearer_t *bearer)
{
    int rv;

    sgwc_ue_t *sgwc_ue = NULL;
    sgwc_sess_t *sess = NULL;

    ogs_gtp_xact_t *gtp_xact = NULL;

    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(bearer);

    sess = sgwc_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    sgwc_ue = sgwc_ue_find_by_id(bearer->sgwc_ue_id);
    ogs_assert(sgwc_ue);
    ogs_assert(sgwc_ue->gnode);

    ogs_info("Downlink Data Notification [%d]", bearer->id);
    ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
        sgwc_ue->mme_s11_teid, sgwc_ue->sgw_s11_teid);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DOWNLINK_DATA_NOTIFICATION_TYPE;
    h.teid = sgwc_ue->mme_s11_teid;

    pkbuf = sgwc_s11_build_downlink_data_notification(cause_value, bearer);
    if (!pkbuf) {
        ogs_error("sgwc_s11_build_downlink_data_notification() failed");
        return OGS_ERROR;
    }

    gtp_xact = ogs_gtp_xact_local_create(
            sgwc_ue->gnode, &h, pkbuf, bearer_timeout,
            OGS_UINT_TO_POINTER(bearer->id));
    if (!gtp_xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        return OGS_ERROR;
    }
    gtp_xact->local_teid = sgwc_ue->sgw_s11_teid;

    rv = ogs_gtp_xact_commit(gtp_xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}
