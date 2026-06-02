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

static void _gtpv2_c_recv_cb(short when, ogs_socket_t fd, void *data)
{
    sgwc_event_t *e = NULL;
    int rv;
    ssize_t size;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;
    ogs_gtp_node_t *gnode = NULL;
    char frombuf[OGS_ADDRSTRLEN];

    ogs_assert(fd != INVALID_SOCKET);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ogs_recvfrom() failed");
        ogs_pkbuf_free(pkbuf);
        return;
    }

    ogs_pkbuf_trim(pkbuf, size);

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
    gnode = ogs_gtp_node_find_by_addr(&sgwc_self()->pgw_s5c_list, &from);
    if (gnode) {
        e = sgwc_event_new(SGWC_EVT_S5C_MESSAGE);
        ogs_assert(e);
        e->gnode = gnode;
    } else {
        gnode = ogs_gtp_node_find_by_addr(&sgwc_self()->mme_s11_list, &from);
        if (!gnode) {
            gnode = ogs_gtp_node_add_by_addr(&sgwc_self()->mme_s11_list, &from);
            if (!gnode) {
                ogs_error("Failed to create new gnode(%s:%u), mempool full, ignoring msg!",
                          OGS_ADDR(&from, frombuf), OGS_PORT(&from));
                ogs_pkbuf_free(pkbuf);
                return;
            }
            gnode->sock = data;
        }
        e = sgwc_event_new(SGWC_EVT_S11_MESSAGE);
        ogs_assert(e);
        e->gnode = gnode;
    }

    e->pkbuf = pkbuf;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        ogs_pkbuf_free(e->pkbuf);
        sgwc_event_free(e);
    }
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

    return sgwc_roam_gtpc_open();
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
