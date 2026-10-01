/*
 * Copyright (C) 2019-2024 by Sukchan Lee <acetcom@gmail.com>
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

#include "context.h"

#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#if HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#include "event.h"
#include "gtp-path.h"
#include "pfcp-path.h"
#include "s5c-build.h"
#include "gn-build.h"
#include "smf-li.h"
#include "smf-trace.h"
#include "metrics.h"
#include "smf-workers.h"

static bool check_if_router_solicit(ogs_pkbuf_t *pkbuf);
static void send_router_advertisement(smf_sess_t *sess, uint8_t *ip6_dst);

static void bearer_timeout(ogs_gtp_xact_t *xact, void *data);

/*
 * Dedicated GTP-C RX helper (smf.gtpc_rx_thread). Not a protocol shard:
 * it only reads, classifies and routes; it never parses into a context.
 */
static ogs_worker_t *gtpc_rx_worker = NULL;
static uint64_t gtpc_rx_drop_count = 0;

#define SMF_GTPC_RECV_BUDGET    512

uint64_t smf_gtpc_rx_drops(void)
{
    return __atomic_load_n(&gtpc_rx_drop_count, __ATOMIC_RELAXED);
}

/*
 * Pick the shard for a raw GTP-C datagram. Only the header (and the
 * IMSI IE of a TEID-less create) is used; the shard re-checks ownership
 * after the full parse (smf_worker_rehome_gtp2/1).
 */
static int smf_gtp_route(ogs_pkbuf_t *pkbuf, uint8_t gtp_ver)
{
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN + 1];
    uint32_t key = 0;
    int shard;

    if (!smf_workers_active())
        return 0;

    if (gtp_ver == 1) {
        ogs_gtp1_header_t *h1 = (ogs_gtp1_header_t *)pkbuf->data;

        if (h1->type == OGS_GTP1_ECHO_REQUEST_TYPE ||
                h1->type == OGS_GTP1_ECHO_RESPONSE_TYPE)
            return 0;

        shard = ogs_gtp1_rx_reply_shard(pkbuf->data, pkbuf->len);
        if (shard >= 0)
            return smf_shard_clamp(shard, be16toh(h1->sqn));

        if (h1->teid) {
            key = be32toh(h1->teid);
            return smf_shard_clamp(smf_shard_from_teid(key), key);
        }

        if (smf_gtpv1_peek_imsi_bcd(pkbuf, imsi_bcd,
                    sizeof(imsi_bcd)) == OGS_OK) {
            uint8_t imsi[OGS_MAX_IMSI_LEN];
            int imsi_len = 0;

            ogs_bcd_to_buffer(imsi_bcd, imsi, &imsi_len);
            shard = smf_ue_owner_shard_by_imsi(imsi, imsi_len);
            return shard >= 0 ? shard : smf_shard_for_new_imsi(imsi_bcd);
        }
        return 1;
    } else {
        ogs_gtp2_header_t *h2 = (ogs_gtp2_header_t *)pkbuf->data;
        uint32_t sqn = h2->teid_presence ? h2->sqn : h2->sqn_only;

        if (h2->type == OGS_GTP2_ECHO_REQUEST_TYPE ||
                h2->type == OGS_GTP2_ECHO_RESPONSE_TYPE)
            return 0;

        /* Reply to OUR request: deliver to the thread holding the xact. */
        shard = ogs_gtp2_rx_reply_shard(pkbuf->data, pkbuf->len);
        if (shard >= 0)
            return smf_shard_clamp(shard, OGS_GTP2_SQN_TO_XID(sqn));

        if (h2->teid_presence && h2->teid &&
                pkbuf->len >= OGS_GTPV2C_HEADER_LEN) {
            key = be32toh(h2->teid);
            /* An S11 CSR may carry a sibling PDN's TEID: same UE owner. */
            return smf_shard_clamp(smf_shard_from_teid(key), key);
        }

        if (h2->type == OGS_GTP2_CREATE_SESSION_REQUEST_TYPE &&
                smf_gtpv2_peek_imsi_bcd(pkbuf, imsi_bcd,
                    sizeof(imsi_bcd)) == OGS_OK) {
            uint8_t imsi[OGS_MAX_IMSI_LEN];
            int imsi_len = 0;

            ogs_bcd_to_buffer(imsi_bcd, imsi, &imsi_len);
            shard = smf_ue_owner_shard_by_imsi(imsi, imsi_len);
            return shard >= 0 ? shard : smf_shard_for_new_imsi(imsi_bcd);
        }

        key = OGS_GTP2_SQN_TO_XID(sqn);
        return smf_shard_clamp(smf_shard_from_xid(key), key);
    }
}

static int smf_gtpc_recv_one(ogs_sock_t *sock)
{
    smf_event_t *e = NULL;
    int rv, shard;
    ssize_t size;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;
    ogs_gtp_node_t *gnode = NULL;
    smf_gtp_node_t *smf_gnode = NULL;
    uint8_t gtp_ver;
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
        if (size < 0)
            ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                    "ogs_recvfrom() failed");
        return -1;
    }

    ogs_pkbuf_trim(pkbuf, size);

    if (pkbuf->len < 8) {
        ogs_warn("Rx short GTP-C datagram (%d bytes)", (int)pkbuf->len);
        ogs_pkbuf_free(pkbuf);
        return 1;
    }

    gtp_ver = ((ogs_gtp2_header_t *)pkbuf->data)->version;
    if (gtp_ver != 1 && gtp_ver != 2) {
        ogs_warn("Rx unexpected GTP version %u", gtp_ver);
        ogs_pkbuf_free(pkbuf);
        return 1;
    }

    /*
     * Match SGW/SGSN by IP first. Some peers (and NAT) send GTP-C from
     * ephemeral UDP source ports; keying on IP:port created one gnode per
     * port and exhausted smf_gtp_node_pool (live: 5.x.x.x:12xxx mempool full
     * while gtp_peers_active sat at 64). Refresh gnode->addr so replies
     * follow the latest source port.
     */
    smf_peers_lock();
    gnode = ogs_gtp_node_find_by_addr(&smf_self()->sgw_s5c_list, &from);
    if (!gnode)
        gnode = ogs_gtp_node_find_by_addr_only(
                &smf_self()->sgw_s5c_list, &from);
    if (gnode) {
        if (!ogs_sockaddr_is_equal(&gnode->addr, &from)) {
            memcpy(&gnode->addr, &from, sizeof(gnode->addr));
            gnode->addr.next = NULL;
        }
        gnode->sock = sock;
        if (!gnode->data_ptr) {
            /* Peer existed without SMF wrapper (prior alloc failure / cleanup). */
            if (!smf_gtp_node_new(gnode)) {
                smf_peers_unlock();
                ogs_error("Failed to attach smf_gnode(%s:%u), "
                          "smf_gtp_node pool full (capacity=%llu); "
                          "ignoring msg",
                          OGS_ADDR(&from, frombuf), OGS_PORT(&from),
                          (unsigned long long)ogs_app()->pool.gtp_node);
                ogs_pkbuf_free(pkbuf);
                return 1;
            }
        }
    } else {
        gnode = ogs_gtp_node_add_by_addr(&smf_self()->sgw_s5c_list, &from);
        if (!gnode) {
            smf_peers_unlock();
            ogs_error("Failed to create new gnode(%s:%u), "
                      "libgtp node pool full (capacity=%llu); ignoring msg",
                      OGS_ADDR(&from, frombuf), OGS_PORT(&from),
                      (unsigned long long)ogs_app()->pool.gtp_node);
            ogs_pkbuf_free(pkbuf);
            return 1;
        }
        gnode->sock = sock;
        if (!smf_gtp_node_new(gnode)) {
            ogs_gtp_node_remove(&smf_self()->sgw_s5c_list, gnode);
            smf_peers_unlock();
            ogs_error("Failed to create smf_gnode(%s:%u), "
                      "smf_gtp_node pool full (capacity=%llu) — "
                      "new peer IP (not just a new UDP port); ignoring msg",
                      OGS_ADDR(&from, frombuf), OGS_PORT(&from),
                      (unsigned long long)ogs_app()->pool.gtp_node);
            ogs_pkbuf_free(pkbuf);
            return 1;
        }
        smf_metrics_inst_global_inc(SMF_METR_GLOB_GAUGE_GTP_PEERS_ACTIVE);
    }
    smf_gnode = gnode->data_ptr;
    smf_peers_unlock();

    if (!smf_gnode) {
        ogs_error("S5C/Gn RX without smf_gnode (%s:%u) — dropping ver[%u]",
                  OGS_ADDR(&from, frombuf), OGS_PORT(&from), gtp_ver);
        ogs_pkbuf_free(pkbuf);
        return 1;
    }

    e = smf_event_new(gtp_ver == 1 ?
            SMF_EVT_GN_MESSAGE : SMF_EVT_S5C_MESSAGE);
    e->gnode = smf_gnode;
    e->pkbuf = pkbuf;

    shard = smf_gtp_route(pkbuf, gtp_ver);
    rv = smf_event_push_shard(shard, e);
    if (rv != OGS_OK) {
        __atomic_fetch_add(&gtpc_rx_drop_count, 1, __ATOMIC_RELAXED);
        return -1;
    }
    return 1;
}

static void _gtpv1v2_c_recv_cb(short when, ogs_socket_t fd, void *data)
{
    ogs_sock_t *sock = data;
    int budget = SMF_GTPC_RECV_BUDGET;

    ogs_assert(fd != INVALID_SOCKET);
    ogs_assert(sock);

    while (budget-- > 0 && smf_gtpc_recv_one(sock) > 0)
        ;
}

static void gtpc_rx_dispatch(ogs_worker_t *worker, void *data)
{
    (void)worker;
    (void)data;
}

static void gtpc_rx_thread_init(ogs_worker_t *worker)
{
    ogs_socknode_t *node = NULL;

    ogs_list_for_each(&ogs_gtp_self()->gtpc_list, node) {
        ogs_assert(node->sock);
        node->poll = ogs_pollset_add(worker->pollset,
                OGS_POLLIN, node->sock->fd, _gtpv1v2_c_recv_cb, node->sock);
        ogs_assert(node->poll);
    }
    ogs_list_for_each(&ogs_gtp_self()->gtpc_list6, node) {
        ogs_assert(node->sock);
        node->poll = ogs_pollset_add(worker->pollset,
                OGS_POLLIN, node->sock->fd, _gtpv1v2_c_recv_cb, node->sock);
        ogs_assert(node->poll);
    }

    ogs_info("SMF GTP-C RX thread started");
}

static void gtpc_rx_thread_fini(ogs_worker_t *worker)
{
    ogs_socknode_t *node = NULL;

    (void)worker;

    ogs_list_for_each(&ogs_gtp_self()->gtpc_list, node) {
        if (node->poll) {
            ogs_pollset_remove(node->poll);
            node->poll = NULL;
        }
    }
    ogs_list_for_each(&ogs_gtp_self()->gtpc_list6, node) {
        if (node->poll) {
            ogs_pollset_remove(node->poll);
            node->poll = NULL;
        }
    }
}

int smf_gtpc_rx_start(void)
{
    if (!smf_self()->gtpc_rx_thread)
        return OGS_OK;
    if (ogs_list_empty(&ogs_gtp_self()->gtpc_list) &&
            ogs_list_empty(&ogs_gtp_self()->gtpc_list6))
        return OGS_OK;

    ogs_assert(!gtpc_rx_worker);

    gtpc_rx_worker = ogs_worker_create(0, 64, 8, 64,
            gtpc_rx_dispatch, NULL);
    ogs_assert(gtpc_rx_worker);
    ogs_worker_hooks(gtpc_rx_worker,
            gtpc_rx_thread_init, gtpc_rx_thread_fini);
    ogs_worker_set_name(gtpc_rx_worker, "smf-gtpc-rx");
    ogs_worker_start(gtpc_rx_worker);

    return OGS_OK;
}

void smf_gtpc_rx_stop(void)
{
    if (!gtpc_rx_worker)
        return;

    ogs_worker_destroy(gtpc_rx_worker);
    gtpc_rx_worker = NULL;
}

bool smf_gtpc_rx_active(void)
{
    return gtpc_rx_worker != NULL;
}

static void _gtpv1_u_recv_cb(short when, ogs_socket_t fd, void *data)
{
    int len;
    ssize_t size;
    char buf[OGS_ADDRSTRLEN];

    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;

    ogs_gtp2_header_t *gtp_h = NULL;
    ogs_gtp2_header_desc_t header_desc;

    ogs_assert(fd != INVALID_SOCKET);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_PKT_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, OGS_MAX_PKT_LEN);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ogs_recv() failed");
        goto cleanup;
    }

    ogs_pkbuf_trim(pkbuf, size);

    ogs_assert(pkbuf);
    ogs_assert(pkbuf->len);

    gtp_h = (ogs_gtp2_header_t *)pkbuf->data;
    if (gtp_h->version != OGS_GTP2_VERSION_1) {
        ogs_error("[DROP] Invalid GTPU version [%d]", gtp_h->version);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    len = ogs_gtpu_parse_header(&header_desc, pkbuf);
    if (len < 0) {
        ogs_error("[DROP] Cannot decode GTPU packet");
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }
    if (header_desc.type == OGS_GTPU_MSGTYPE_ECHO_REQ) {
        ogs_pkbuf_t *echo_rsp;

        ogs_debug("[RECV] Echo Request from [%s]", OGS_ADDR(&from, buf));
        echo_rsp = ogs_gtp2_handle_echo_req(pkbuf);
        ogs_expect(echo_rsp);
        if (echo_rsp) {
            ssize_t sent;

            /* Echo reply */
            ogs_debug("[SEND] Echo Response to [%s]", OGS_ADDR(&from, buf));

            sent = ogs_sendto(fd, echo_rsp->data, echo_rsp->len, 0, &from);
            if (sent < 0 || sent != echo_rsp->len) {
                ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                        "ogs_sendto() failed");
            }
            ogs_pkbuf_free(echo_rsp);
        }
        goto cleanup;
    }
    if (header_desc.type != OGS_GTPU_MSGTYPE_END_MARKER &&
        pkbuf->len <= len) {
        ogs_error("[DROP] Small GTPU packet(type:%d len:%d)",
                header_desc.type, len);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    ogs_debug("[RECV] GPU-U Type [%d] from [%s] : TEID[0x%x]",
            header_desc.type, OGS_ADDR(&from, buf), header_desc.teid);

    /* Remove GTP header and send packets to TUN interface */
    ogs_assert(ogs_pkbuf_pull(pkbuf, len));

    if (header_desc.type == OGS_GTPU_MSGTYPE_GPDU) {
        ogs_pfcp_far_t *far = NULL;
        ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;
        uint8_t dst_if = 0;
        smf_event_t *e = NULL;

        if (header_desc.qos_flow_identifier) {
            ogs_error("QFI[%d] Found", header_desc.qos_flow_identifier);
            goto cleanup;
        }

        /*
         * The FAR and its session belong to the owning shard; copy what
         * we need under the PFCP object lock (FAR removal takes it too)
         * and let the owner answer.
         */
        ogs_pfcp_object_lock();
        far = ogs_pfcp_far_find_by_teid(header_desc.teid);
        if (far) {
            dst_if = far->dst_if;
            if (far->sess) {
                smf_sess_t *far_sess = SMF_SESS(far->sess);
                sess_id = far_sess->id;
            }
        }
        ogs_pfcp_object_unlock();

        if (!far) {
            ogs_error("No FAR for TEID [%d]", header_desc.teid);
            goto cleanup;
        }

        if (dst_if != OGS_PFCP_INTERFACE_CP_FUNCTION) {
            ogs_error("Invalid Destination Interface [%d]", dst_if);
            goto cleanup;
        }

        if (sess_id == OGS_INVALID_POOL_ID ||
                check_if_router_solicit(pkbuf) != true)
            goto cleanup;

        e = smf_event_new(SMF_EVT_ROUTER_SOLICIT);
        e->sess_id = sess_id;
        e->pkbuf = pkbuf;
        pkbuf = NULL;
        smf_event_push_shard(smf_workers_active() ?
                ogs_max(smf_sess_owner_shard_by_id(sess_id), 0) : 0, e);
    } else {
        ogs_error("[DROP] Invalid GTPU Type [%d]", header_desc.type);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
    }

cleanup:
    if (pkbuf)
        ogs_pkbuf_free(pkbuf);
}

void smf_gtp_handle_router_solicit(smf_event_t *e)
{
    smf_sess_t *sess = NULL;
    struct ip6_hdr *ip6_h = NULL;

    ogs_assert(e);
    ogs_assert(e->pkbuf);

    sess = smf_sess_find_active_by_id(e->sess_id);
    if (sess && sess->ipv6) {
        ip6_h = (struct ip6_hdr *)e->pkbuf->data;
        send_router_advertisement(sess, ip6_h->ip6_src.s6_addr);
    }

    ogs_pkbuf_free(e->pkbuf);
    e->pkbuf = NULL;
}

int smf_gtp_open(void)
{
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;

    /* With smf.gtpc_rx_thread the RX helper registers the polls. */
    bool rx_offload = smf_self()->gtpc_rx_thread;

    ogs_list_for_each(&ogs_gtp_self()->gtpc_list, node) {
        sock = ogs_gtp_server(node);
        if (!sock) return OGS_ERROR;

        if (!rx_offload) {
            node->poll = ogs_pollset_add(ogs_app()->pollset,
                    OGS_POLLIN, sock->fd, _gtpv1v2_c_recv_cb, sock);
            ogs_assert(node->poll);
        }
    }
    ogs_list_for_each(&ogs_gtp_self()->gtpc_list6, node) {
        sock = ogs_gtp_server(node);
        if (!sock) return OGS_ERROR;

        if (!rx_offload) {
            node->poll = ogs_pollset_add(ogs_app()->pollset,
                    OGS_POLLIN, sock->fd, _gtpv1v2_c_recv_cb, sock);
            ogs_assert(node->poll);
        }
    }

    OGS_SETUP_GTPC_SERVER;
    /* If we only use 5G, we don't need GTP-C, so there is no check routine. */
    if (!ogs_gtp_self()->gtpc_sock  && !ogs_gtp_self()->gtpc_sock6)
        ogs_warn("No GTP-C configuration");

    ogs_list_for_each(&ogs_gtp_self()->gtpu_list, node) {
        sock = ogs_gtp_server(node);
        if (!sock) return OGS_ERROR;

        if (sock->family == AF_INET)
            ogs_gtp_self()->gtpu_sock = sock;
        else if (sock->family == AF_INET6)
            ogs_gtp_self()->gtpu_sock6 = sock;

        node->poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, _gtpv1_u_recv_cb, sock);
        ogs_assert(node->poll);
    }

    OGS_SETUP_GTPU_SERVER;

    /* Fetch link-local address for router advertisement */
    if (ogs_gtp_self()->link_local_addr)
        ogs_freeaddrinfo(ogs_gtp_self()->link_local_addr);
    if (ogs_gtp_self()->gtpu_addr6)
        ogs_gtp_self()->link_local_addr =
            ogs_link_local_addr_by_sa(ogs_gtp_self()->gtpu_addr6);

    return OGS_OK;
}

void smf_gtp_close(void)
{
    if (ogs_gtp_self()->link_local_addr)
        ogs_freeaddrinfo(ogs_gtp_self()->link_local_addr);

    ogs_socknode_remove_all(&ogs_gtp_self()->gtpc_list);
    ogs_socknode_remove_all(&ogs_gtp_self()->gtpc_list6);

    ogs_socknode_remove_all(&ogs_gtp_self()->gtpu_list);
}

int smf_gtp1_send_create_pdp_context_response(
        smf_sess_t *sess, ogs_gtp_xact_t *xact)
{
    int rv;
    ogs_gtp1_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(xact);

    memset(&h, 0, sizeof(ogs_gtp1_header_t));
    h.type = OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE;
    h.teid = sess->sgw_s5c_teid;

    pkbuf = smf_gn_build_create_pdp_context_response(h.type, sess);
    if (!pkbuf) {
        ogs_error("smf_gn_build_create_pdp_context_response() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp1_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return OGS_ERROR;
    }

    {


        smf_ue_t *_tue = smf_ue_find_by_id(sess->smf_ue_id);


        smf_trace_bind_gtp(xact, _tue);


    }


    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int smf_gtp1_send_delete_pdp_context_response(
        smf_sess_t *sess, ogs_gtp_xact_t *xact)
{
    int rv;
    ogs_gtp1_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(xact);

    memset(&h, 0, sizeof(ogs_gtp1_header_t));
    h.type = OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE;
    h.teid = sess->sgw_s5c_teid;

    pkbuf = smf_gn_build_delete_pdp_context_response(h.type, sess);
    if (!pkbuf) {
        ogs_error("smf_gn_build_delete_pdp_context_response() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp1_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return OGS_ERROR;
    }

    {


        smf_ue_t *_tue = smf_ue_find_by_id(sess->smf_ue_id);


        smf_trace_bind_gtp(xact, _tue);


    }


    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

#if 0
int smf_gtp1_send_update_pdp_context_request(
        smf_bearer_t *bearer, uint8_t pti, uint8_t cause_value)
{
    int rv;

    ogs_gtp_xact_t *xact = NULL;
    ogs_gtp1_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    smf_sess_t *sess = NULL;

    ogs_assert(bearer);
    sess = smf_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    memset(&h, 0, sizeof(ogs_gtp1_header_t));
    h.type = OGS_GTP1_UPDATE_PDP_CONTEXT_REQUEST_TYPE;
    h.teid = sess->sgw_s5c_teid;

    pkbuf = smf_gn_build_update_pdp_context_request(
                h.type, bearer, pti, cause_value);
    if (!pkbuf) {
        ogs_error("smf_gn_build_update_pdp_context_request() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp1_xact_local_create(
            sess->gnode, &h, pkbuf, bearer_timeout,
            OGS_UINT_TO_POINTER(bearer->id));
    if (!xact) {
        ogs_error("ogs_gtp1_xact_local_create() failed");
        return OGS_ERROR;
    }

    {


        smf_ue_t *_tue = smf_ue_find_by_id(sess->smf_ue_id);


        smf_trace_bind_gtp(xact, _tue);


    }


    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}
#endif

int smf_gtp1_send_update_pdp_context_response(
        smf_bearer_t *bearer, ogs_gtp_xact_t *xact)
{
    int rv;

    ogs_gtp1_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    smf_sess_t *sess = NULL;

    ogs_assert(bearer);
    ogs_assert(xact);
    sess = smf_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    memset(&h, 0, sizeof(ogs_gtp1_header_t));
    h.type = OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE;
    h.teid = sess->sgw_s5c_teid;

    pkbuf = smf_gn_build_update_pdp_context_response(
                h.type, sess, bearer);
    if (!pkbuf) {
        ogs_error("smf_gn_build_update_pdp_context_response() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp1_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return OGS_ERROR;
    }

    {


        smf_ue_t *_tue = smf_ue_find_by_id(sess->smf_ue_id);


        smf_trace_bind_gtp(xact, _tue);


    }


    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int smf_gtp2_send_create_session_response(
        smf_sess_t *sess, ogs_gtp_xact_t *xact)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(xact);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE;
    h.teid = sess->sgw_s5c_teid;

    pkbuf = smf_s5c_build_create_session_response(h.type, sess);
    if (!pkbuf) {
        ogs_error("smf_s5c_build_create_session_response() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_update_tx() failed");
        return OGS_ERROR;
    }

    {


        smf_ue_t *_tue = smf_ue_find_by_id(sess->smf_ue_id);


        smf_trace_bind_gtp(xact, _tue);


    }


    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    if (rv == OGS_OK)
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_S5C_TX_CREATESESSIONSUCC);

    ogs_info("S5 Create Session Response sent SGW_S5C_TEID=0x%x",
            sess->sgw_s5c_teid);

    if (rv == OGS_OK)
        smf_li_report_sess(sess, OGS_LI_EVENT_PDN_SESSION_ESTABLISH,
                "create-session-response");

    return rv;
}

int smf_gtp2_send_modify_bearer_response(
        smf_sess_t *sess, ogs_gtp_xact_t *xact,
        ogs_gtp2_modify_bearer_request_t *req, bool sgw_relocation)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(xact);
    ogs_assert(req);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_MODIFY_BEARER_RESPONSE_TYPE;
    h.teid = sess->sgw_s5c_teid;

    pkbuf = smf_s5c_build_modify_bearer_response(
                h.type, sess, req, sgw_relocation);
    if (!pkbuf) {
        ogs_error("smf_s5c_build_modify_bearer_response() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_update_tx() failed");
        return OGS_ERROR;
    }

    {


        smf_ue_t *_tue = smf_ue_find_by_id(sess->smf_ue_id);


        smf_trace_bind_gtp(xact, _tue);


    }


    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int smf_gtp2_send_delete_session_response(
        smf_sess_t *sess, ogs_gtp_xact_t *xact)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(xact);
    ogs_assert(sess);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE;
    h.teid = sess->sgw_s5c_teid;

    pkbuf = smf_s5c_build_delete_session_response(h.type, sess);
    if (!pkbuf) {
        ogs_error("smf_s5c_build_delete_session_response() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_update_tx() failed");
        return OGS_ERROR;
    }

    {


        smf_ue_t *_tue = smf_ue_find_by_id(sess->smf_ue_id);


        smf_trace_bind_gtp(xact, _tue);


    }


    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    if (rv == OGS_OK)
        smf_li_report_sess(sess, OGS_LI_EVENT_PDN_SESSION_RELEASE,
                "delete-session-response");

    return rv;
}

int smf_gtp2_send_delete_bearer_request(
        smf_bearer_t *bearer, uint8_t pti, uint8_t cause_value)
{
    int rv;

    ogs_gtp_xact_t *xact = NULL;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    smf_sess_t *sess = NULL;

    ogs_assert(bearer);
    sess = smf_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DELETE_BEARER_REQUEST_TYPE;
    h.teid = sess->sgw_s5c_teid;

    pkbuf = smf_s5c_build_delete_bearer_request(
                h.type, bearer, pti, cause_value);
    if (!pkbuf) {
        ogs_error("smf_s5c_build_delete_bearer_request() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp_xact_local_create(
            sess->gnode, &h, pkbuf, bearer_timeout,
            OGS_UINT_TO_POINTER(bearer->id));
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        return OGS_ERROR;
    }
    xact->local_teid = sess->smf_n4_teid;

    {


        smf_ue_t *_tue = smf_ue_find_by_id(sess->smf_ue_id);


        smf_trace_bind_gtp(xact, _tue);


    }


    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

static bool check_if_router_solicit(ogs_pkbuf_t *pkbuf)
{
    struct ip *ip_h = NULL;

    ogs_assert(pkbuf);
    ogs_assert(pkbuf->len);
    ogs_assert(pkbuf->data);

    ip_h = (struct ip *)pkbuf->data;
    if (ip_h->ip_v == 6) {
        struct ip6_hdr *ip6_h = (struct ip6_hdr *)pkbuf->data;
        if (ip6_h->ip6_nxt == IPPROTO_ICMPV6) {
            struct icmp6_hdr *icmp_h =
                (struct icmp6_hdr *)(pkbuf->data + sizeof(struct ip6_hdr));
            if (icmp_h->icmp6_type == ND_ROUTER_SOLICIT) {
                ogs_debug("      Router Solict");
                return true;
            }
        }
    }

    return false;
}

static void send_router_advertisement(smf_sess_t *sess, uint8_t *ip6_dst)
{
    int rv;

    ogs_pkbuf_t *pkbuf = NULL;

    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_ue_ip_t *ue_ip = NULL;
    ogs_pfcp_subnet_t *subnet = NULL;
    char ipstr[OGS_ADDRSTRLEN];

    ogs_ipsubnet_t src_ipsub;
    uint16_t plen = 0;
    uint8_t nxt = 0;
    uint8_t *p = NULL;
    struct ip6_hdr *ip6_h =  NULL;
    struct nd_router_advert *advert_h = NULL;
    struct nd_opt_prefix_info *prefix = NULL;

    ogs_assert(sess);
    ue_ip = sess->ipv6;
    ogs_assert(ue_ip);
    subnet = ue_ip->subnet;
    if (!subnet) {
        ogs_error("Cannot build Router Advertisement: no IPv6 subnet");
        return;
    }

    /* Fetch link-local address for router advertisement */
    if (ogs_gtp_self()->link_local_addr) {
        OGS_ADDR(ogs_gtp_self()->link_local_addr, ipstr);
        rv = ogs_ipsubnet(&src_ipsub, ipstr, NULL);
        if (rv != OGS_OK) {
            ogs_error("ogs_ipsubnet() failed");
            return;
        }
    } else {
        /* For the case of loopback used for GTPU link-local address is not
         * available, hence set the source IP to fe80::1
        */
        memset(src_ipsub.sub, 0, sizeof(src_ipsub.sub));
        src_ipsub.sub[0] = htobe32(0xfe800000);
        src_ipsub.sub[3] = htobe32(0x00000001);
    }

    ogs_debug("      Build Router Advertisement");

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_GTPV1U_5GC_HEADER_LEN+200);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_GTPV1U_5GC_HEADER_LEN);
    ogs_pkbuf_put(pkbuf, 200);
    memset(pkbuf->data, 0, pkbuf->len);

    p = (uint8_t *)pkbuf->data;
    ip6_h = (struct ip6_hdr *)p;
    advert_h = (struct nd_router_advert *)((uint8_t *)ip6_h + sizeof *ip6_h);
    prefix = (struct nd_opt_prefix_info *)
        ((uint8_t*)advert_h + sizeof *advert_h);

    advert_h->nd_ra_type = ND_ROUTER_ADVERT;
    advert_h->nd_ra_code = 0;
    advert_h->nd_ra_curhoplimit = 64;
    advert_h->nd_ra_flags_reserved = 0;
    advert_h->nd_ra_router_lifetime = htobe16(64800);  /* 64800s */
    advert_h->nd_ra_reachable = 0;
    advert_h->nd_ra_retransmit = 0;

    prefix->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
    prefix->nd_opt_pi_len = 4; /* 32bytes */
    prefix->nd_opt_pi_prefix_len = OGS_IPV6_DEFAULT_PREFIX_LEN;
    prefix->nd_opt_pi_flags_reserved =
        ND_OPT_PI_FLAG_ONLINK|ND_OPT_PI_FLAG_AUTO;
    prefix->nd_opt_pi_valid_time = htobe32(0xffffffff); /* Infinite */
    prefix->nd_opt_pi_preferred_time = htobe32(0xffffffff); /* Infinite */
    memcpy(prefix->nd_opt_pi_prefix.s6_addr,
            ue_ip->addr, (OGS_IPV6_DEFAULT_PREFIX_LEN >> 3));

    /* For IPv6 Pseudo-Header */
    plen = sizeof *advert_h + sizeof *prefix;
    nxt = IPPROTO_ICMPV6;

    if (smf_self()->mtu) {
        struct nd_opt_mtu *mtu =
            (struct nd_opt_mtu *)((uint8_t*)prefix + sizeof *prefix);

        mtu->nd_opt_mtu_type = ND_OPT_MTU;
        mtu->nd_opt_mtu_len = 1; /* 8bytes */
        mtu->nd_opt_mtu_mtu = htobe32(smf_self()->mtu);

        plen += sizeof *mtu;
    }

    pkbuf->len = sizeof *ip6_h + plen;

    memcpy(p, src_ipsub.sub, sizeof src_ipsub.sub);
    p += sizeof src_ipsub.sub;
    memcpy(p, ip6_dst, OGS_IPV6_LEN);
    p += OGS_IPV6_LEN;
    p += 2; plen = htobe16(plen); memcpy(p, &plen, 2); p += 2;
    p += 3; *p = nxt; p += 1;

    advert_h->nd_ra_cksum = ogs_in_cksum((uint16_t *)pkbuf->data, pkbuf->len);

    ip6_h->ip6_flow = htobe32(0x60000001);
    ip6_h->ip6_plen = plen;
    ip6_h->ip6_nxt = nxt;  /* ICMPv6 */
    ip6_h->ip6_hlim = 0xff;
    memcpy(ip6_h->ip6_src.s6_addr, src_ipsub.sub, sizeof src_ipsub.sub);
    memcpy(ip6_h->ip6_dst.s6_addr, ip6_dst, OGS_IPV6_LEN);

    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CP_FUNCTION && pdr->gnode) {
            ogs_gtp2_header_desc_t header_desc;
            ogs_gtp_node_t *gnode = pdr->gnode;
            ogs_assert(gnode);
            ogs_assert(gnode->sock);

            memset(&header_desc, 0, sizeof(header_desc));
            header_desc.type = OGS_GTPU_MSGTYPE_GPDU;

            ogs_gtp2_encapsulate_header(&header_desc, pkbuf);

            ogs_gtp_send_with_teid(
                    gnode->sock, pkbuf, pdr->f_teid.teid, &gnode->addr);

            ogs_debug("      Send Router Advertisement");
            break;
        }
    }

    ogs_pkbuf_free(pkbuf);
}

static void bearer_timeout(ogs_gtp_xact_t *xact, void *data)
{
    smf_bearer_t *bearer = NULL;
    ogs_pool_id_t bearer_id = OGS_INVALID_POOL_ID;
    smf_sess_t *sess = NULL;
    smf_ue_t *smf_ue = NULL;
    uint8_t type = 0;

    ogs_assert(xact);
    type = xact->seq[0].type;

    ogs_assert(data);
    bearer_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(bearer_id >= OGS_MIN_POOL_ID && bearer_id <= OGS_MAX_POOL_ID);

    bearer = smf_bearer_find_by_id(bearer_id);
    if (!bearer) {
        ogs_error("Bearer has already been removed [%d]", type);
        return;
    }

    sess = smf_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    switch (type) {
    case OGS_GTP2_DELETE_BEARER_REQUEST_TYPE: {
        char sgw_peer[OGS_ADDRSTRLEN];
        char upf_peer[OGS_ADDRSTRLEN];

        smf_log_sgw_peer(sgw_peer, sizeof(sgw_peer), sess);
        smf_log_upf_peer(upf_peer, sizeof(upf_peer), sess);
        ogs_error("[%s] S5 timeout: no Delete Bearer Response "
                "APN[%s] EBI[%d] SGW[%s] UPF[%s]",
                smf_log_id(smf_ue),
                sess->session.name ? sess->session.name : "-",
                bearer->ebi,
                sgw_peer[0] ? sgw_peer : "-",
                upf_peer[0] ? upf_peer : "-");
        ogs_assert(OGS_OK ==
            smf_epc_pfcp_send_one_bearer_modification_request(
                bearer, OGS_INVALID_POOL_ID, OGS_PFCP_MODIFY_REMOVE,
                OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED,
                OGS_GTP2_CAUSE_UNDEFINED_VALUE));
        break;
    }
    default: {
        char sgw_peer[OGS_ADDRSTRLEN];

        smf_log_sgw_peer(sgw_peer, sizeof(sgw_peer), sess);
        ogs_error("[%s] S5 timeout: message-type[%d] APN[%s] SGW[%s]",
                smf_log_id(smf_ue), type,
                sess->session.name ? sess->session.name : "-",
                sgw_peer[0] ? sgw_peer : "-");
        break;
    }
    }
}
