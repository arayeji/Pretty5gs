/*
 * Copyright (C) 2019-2025 by Sukchan Lee <acetcom@gmail.com>
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

#include "pfcp-path.h"
#include "context.h"
#include "gtp-path.h"
#include "s11-handler.h"
#include "gn-handler.h"
#include "sgwc-trace.h"
#include "event.h"
#include "sgwc-workers.h"

/*
 * Dedicated PFCP RX helper (sgwc.pfcp_rx_thread). Not a protocol shard.
 */
static ogs_worker_t *pfcp_rx_worker = NULL;
static uint64_t pfcp_rx_drop_count = 0;

static void sgwc_pfcp_rx_drop(void)
{
    __atomic_fetch_add(&pfcp_rx_drop_count, 1, __ATOMIC_RELAXED);
}

uint64_t sgwc_pfcp_rx_drops(void)
{
    return __atomic_load_n(&pfcp_rx_drop_count, __ATOMIC_RELAXED);
}

static void pfcp_node_fsm_init(ogs_pfcp_node_t *node, bool try_to_associate)
{
    sgwc_event_t e;

    ogs_assert(node);

    memset(&e, 0, sizeof(e));
    e.pfcp_node = node;

    if (try_to_associate == true) {
        node->t_association = ogs_timer_add(ogs_app()->timer_mgr,
                sgwc_timer_pfcp_association, node);
        ogs_assert(node->t_association);
    }

    ogs_fsm_init(&node->sm, sgwc_pfcp_state_initial, sgwc_pfcp_state_final, &e);
}

static void pfcp_node_fsm_fini(ogs_pfcp_node_t *node)
{
    sgwc_event_t e;

    ogs_assert(node);

    memset(&e, 0, sizeof(e));
    e.pfcp_node = node;

    ogs_fsm_fini(&node->sm, &e);

    if (node->t_association)
        ogs_timer_delete(node->t_association);
}

/*
 * Read ONE PFCP datagram; returns 1 if a datagram was consumed (keep
 * draining), 0 when the socket is empty / on error (stop for this wakeup).
 */
static int sgwc_pfcp_recv_one(ogs_socket_t fd)
{
    int rv;

    sgwc_event_t *e = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;
    ogs_pfcp_node_t *node = NULL;
    ogs_pfcp_message_t *message = NULL;

    ogs_pfcp_status_e pfcp_status;;
    ogs_pfcp_node_id_t node_id;

    ogs_assert(fd != INVALID_SOCKET);

    pkbuf = ogs_pfcp_recvfrom(fd, &from);
    if (!pkbuf) {
        /* empty socket (EAGAIN) or receive/parse error; either way stop —
         * a level-triggered pollset re-fires if datagrams remain */
        return 0;
    }

    e = sgwc_event_new(SGWC_EVT_SXA_MESSAGE);
    ogs_assert(e);

    /*
     * Issue #1911
     *
     * Because ogs_pfcp_message_t is over 80kb in size,
     * it can cause stack overflow.
     * To avoid this, the pfcp_message structure uses heap memory.
     */
    if ((message = ogs_pfcp_parse_msg(pkbuf)) == NULL) {
        ogs_error("ogs_pfcp_parse_msg() failed");
        ogs_pkbuf_free(pkbuf);
        sgwc_event_free(e);
        return 1;
    }

    pfcp_status = ogs_pfcp_extract_node_id(message, &node_id);
    switch (pfcp_status) {
    case OGS_PFCP_STATUS_SUCCESS:
    case OGS_PFCP_STATUS_NODE_ID_NONE:
    case OGS_PFCP_STATUS_NODE_ID_OPTIONAL_ABSENT:
        ogs_debug("ogs_pfcp_extract_node_id() "
                "type [%d] pfcp_status [%d] node_id [%s] from %s",
                message->h.type, pfcp_status,
                pfcp_status == OGS_PFCP_STATUS_SUCCESS ?
                    ogs_pfcp_node_id_to_string_static(&node_id) :
                    "NULL",
                ogs_sockaddr_to_string_static(&from));
        break;

    case OGS_PFCP_ERROR_SEMANTIC_INCORRECT_MESSAGE:
    case OGS_PFCP_ERROR_NODE_ID_NOT_PRESENT:
    case OGS_PFCP_ERROR_NODE_ID_NOT_FOUND:
    case OGS_PFCP_ERROR_UNKNOWN_MESSAGE:
        ogs_error("ogs_pfcp_extract_node_id() failed "
                "type [%d] pfcp_status [%d] from %s",
                message->h.type, pfcp_status,
                ogs_sockaddr_to_string_static(&from));
        goto cleanup;

    default:
        ogs_error("Unexpected pfcp_status "
                "type [%d] pfcp_status [%d] from %s",
                message->h.type, pfcp_status,
                ogs_sockaddr_to_string_static(&from));
        goto cleanup;
    }

    node = ogs_pfcp_node_find(&ogs_pfcp_self()->pfcp_peer_list,
            pfcp_status == OGS_PFCP_STATUS_SUCCESS ? &node_id : NULL, &from);
    if (!node) {
        if (message->h.type == OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE ||
            message->h.type == OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE) {
            ogs_assert(pfcp_status == OGS_PFCP_STATUS_SUCCESS);
            node = ogs_pfcp_node_add(&ogs_pfcp_self()->pfcp_peer_list,
                    &node_id, &from);
            if (!node) {
                ogs_error("No memory: ogs_pfcp_node_add() failed");
                goto cleanup;
            }
            ogs_debug("Added PFCP-Node: addr_list %s",
                    ogs_sockaddr_to_string_static(node->addr_list));

            pfcp_node_fsm_init(node, false);

        } else {
            ogs_error("Cannot find PFCP-Node: type [%d] node_id %s from %s",
                    message->h.type,
                    pfcp_status == OGS_PFCP_STATUS_SUCCESS ?
                        ogs_pfcp_node_id_to_string_static(&node_id) :
                        "NULL",
                    ogs_sockaddr_to_string_static(&from));
            goto cleanup;
        }
    } else {
        ogs_debug("Found PFCP-Node: addr_list %s",
                ogs_sockaddr_to_string_static(node->addr_list));
        ogs_expect(OGS_OK == ogs_pfcp_node_merge(
                    node,
                    pfcp_status == OGS_PFCP_STATUS_SUCCESS ?  &node_id : NULL,
                    &from));
        ogs_debug("Merged PFCP-Node: addr_list %s",
                ogs_sockaddr_to_string_static(node->addr_list));
    }

    e->pfcp_node = node;
    e->pkbuf = pkbuf;
    e->pfcp_message = message;

    if (!sgwc_workers_active()) {
        /* trypush: never block the RX poll thread */
        rv = ogs_queue_trypush(ogs_app()->queue, e);
        if (rv != OGS_OK) {
            ogs_error("ogs_queue_trypush() failed:%d", (int)rv);
            sgwc_pfcp_rx_drop();
            goto cleanup;
        }
        if (pfcp_rx_worker)
            ogs_pollset_notify(ogs_app()->pollset);
        return 1;
    }

    /*
     * Association / heartbeat / node report stay on main.
     * Session messages with SEID route by shard bits; SEID-less
     * session responses route by SQN xid partition.
     */
    {
        int wid = -1;
        bool to_main = false;
        uint32_t fallback_key = 0;
        uint8_t type = message->h.type;

        if (type == OGS_PFCP_HEARTBEAT_REQUEST_TYPE ||
                type == OGS_PFCP_HEARTBEAT_RESPONSE_TYPE ||
                type == OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE ||
                type == OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE ||
                type == OGS_PFCP_ASSOCIATION_UPDATE_REQUEST_TYPE ||
                type == OGS_PFCP_ASSOCIATION_UPDATE_RESPONSE_TYPE ||
                type == OGS_PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE ||
                type == OGS_PFCP_ASSOCIATION_RELEASE_RESPONSE_TYPE ||
                type == OGS_PFCP_NODE_REPORT_REQUEST_TYPE ||
                type == OGS_PFCP_NODE_REPORT_RESPONSE_TYPE ||
                type == OGS_PFCP_PFD_MANAGEMENT_REQUEST_TYPE ||
                type == OGS_PFCP_PFD_MANAGEMENT_RESPONSE_TYPE) {
            to_main = true;
        } else if (message->h.seid_presence && message->h.seid != 0) {
            /* parse_msg converts SEID to host order */
            fallback_key = (uint32_t)message->h.seid;
            wid = sgwc_shard_from_seid(message->h.seid);
        } else {
            /* SQN left in network order; OGS_PFCP_SQN_TO_XID expects that */
            uint32_t sqn_be = message->h.seid_presence ?
                    message->h.sqn : message->h.sqn_only;
            fallback_key = OGS_PFCP_SQN_TO_XID(sqn_be);
            wid = sgwc_shard_from_xid(fallback_key);
        }

        /*
         * wid == -1 means shard 0 = the MAIN thread, which shares the
         * process-global context and handles its own sessions (or
         * answers "Session context not found" for stale SEIDs). Shard
         * bits beyond the live worker count route to a deterministic
         * worker.
         */
        if (wid >= sgwc_workers_count())
            wid = (int)(fallback_key % (uint32_t)sgwc_workers_count());

        if (to_main || wid < 0) {
            /* Association/heartbeat must never block the PFCP RX path. */
            rv = ogs_queue_trypush(ogs_app()->queue, e);
            if (rv != OGS_OK) {
                ogs_error("ogs_queue_trypush() failed:%d", (int)rv);
                sgwc_pfcp_rx_drop();
                goto cleanup;
            }
            if (pfcp_rx_worker)
                ogs_pollset_notify(ogs_app()->pollset);
            return 1;
        }

        if (sgwc_event_push_to_worker(wid, e) != OGS_OK) {
            sgwc_pfcp_rx_drop();
            return 1; /* push_to_worker already freed e + buffers */
        }
        return 1;
    }

cleanup:
    ogs_pkbuf_free(pkbuf);
    ogs_pfcp_message_free(message);
    sgwc_event_free(e);
    return 1;
}

/*
 * Drain the PFCP socket per poll wakeup (bounded) instead of reading one
 * datagram per main-loop iteration — same fix as the MME GTP-C RX path:
 * under a Session Establishment/Modification storm SGW-U answers faster
 * than one-datagram-per-iteration, the kernel socket buffer fills and
 * dropped replies become false PFCP timeouts.
 */
#define SGWC_PFCP_RECV_BUDGET   512

static void pfcp_recv_cb(short when, ogs_socket_t fd, void *data)
{
    int budget = SGWC_PFCP_RECV_BUDGET;

    while (budget-- > 0 && sgwc_pfcp_recv_one(fd) > 0)
        ;
}

int sgwc_pfcp_open(void)
{
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;
    bool rx_offload = sgwc_self()->pfcp_rx_thread != 0;

    /* PFCP Server */
    ogs_list_for_each(&ogs_pfcp_self()->pfcp_list, node) {
        sock = ogs_pfcp_server(node);
        if (!sock) return OGS_ERROR;

        if (!rx_offload) {
            node->poll = ogs_pollset_add(ogs_app()->pollset,
                    OGS_POLLIN, sock->fd, pfcp_recv_cb, sock);
            ogs_assert(node->poll);
        }
    }
    ogs_list_for_each(&ogs_pfcp_self()->pfcp_list6, node) {
        sock = ogs_pfcp_server(node);
        if (!sock) return OGS_ERROR;

        if (!rx_offload) {
            node->poll = ogs_pollset_add(ogs_app()->pollset,
                    OGS_POLLIN, sock->fd, pfcp_recv_cb, sock);
            ogs_assert(node->poll);
        }
    }

    OGS_SETUP_PFCP_SERVER;

    return OGS_OK;
}

static void pfcp_rx_dispatch(ogs_worker_t *worker, void *data)
{
    (void)worker;
    (void)data;
}

static void pfcp_rx_thread_init(ogs_worker_t *worker)
{
    ogs_socknode_t *node = NULL;

    ogs_list_for_each(&ogs_pfcp_self()->pfcp_list, node) {
        ogs_assert(node->sock);
        node->poll = ogs_pollset_add(worker->pollset,
                OGS_POLLIN, node->sock->fd, pfcp_recv_cb, node->sock);
        ogs_assert(node->poll);
    }
    ogs_list_for_each(&ogs_pfcp_self()->pfcp_list6, node) {
        ogs_assert(node->sock);
        node->poll = ogs_pollset_add(worker->pollset,
                OGS_POLLIN, node->sock->fd, pfcp_recv_cb, node->sock);
        ogs_assert(node->poll);
    }

    ogs_info("SGW-C PFCP RX thread started");
}

static void pfcp_rx_thread_fini(ogs_worker_t *worker)
{
    ogs_socknode_t *node = NULL;

    (void)worker;

    ogs_list_for_each(&ogs_pfcp_self()->pfcp_list, node) {
        if (node->poll) {
            ogs_pollset_remove(node->poll);
            node->poll = NULL;
        }
    }
    ogs_list_for_each(&ogs_pfcp_self()->pfcp_list6, node) {
        if (node->poll) {
            ogs_pollset_remove(node->poll);
            node->poll = NULL;
        }
    }
}

int sgwc_pfcp_rx_start(void)
{
    if (!sgwc_self()->pfcp_rx_thread)
        return OGS_OK;

    ogs_assert(!pfcp_rx_worker);

    pfcp_rx_worker = ogs_worker_create(0, 64, 8, 64,
            pfcp_rx_dispatch, NULL);
    ogs_assert(pfcp_rx_worker);
    ogs_worker_hooks(pfcp_rx_worker,
            pfcp_rx_thread_init, pfcp_rx_thread_fini);
    ogs_worker_set_name(pfcp_rx_worker, "pfcp-rx");
    ogs_worker_start(pfcp_rx_worker);

    return OGS_OK;
}

bool sgwc_pfcp_rx_active(void)
{
    return pfcp_rx_worker != NULL;
}

void sgwc_pfcp_close(void)
{
    ogs_pfcp_node_t *pfcp_node = NULL;

    if (pfcp_rx_worker) {
        ogs_worker_destroy(pfcp_rx_worker);
        pfcp_rx_worker = NULL;
    }

    ogs_list_for_each(&ogs_pfcp_self()->pfcp_peer_list, pfcp_node)
        pfcp_node_fsm_fini(pfcp_node);

    ogs_freeaddrinfo(ogs_pfcp_self()->pfcp_advertise);
    ogs_freeaddrinfo(ogs_pfcp_self()->pfcp_advertise6);

    ogs_socknode_remove_all(&ogs_pfcp_self()->pfcp_list);
    ogs_socknode_remove_all(&ogs_pfcp_self()->pfcp_list6);
}

static void sess_timeout(ogs_pfcp_xact_t *xact, void *data)
{
    sgwc_sess_t *sess = NULL;
    ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;
    uint8_t type;

    ogs_assert(xact);
    type = xact->seq[0].type;

    ogs_assert(data);
    sess_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(sess_id >= OGS_MIN_POOL_ID && sess_id <= OGS_MAX_POOL_ID);

    sess = sgwc_sess_find_by_id(sess_id);
    if (!sess) {
        ogs_error("Session has already been removed [%d]", type);
        return;
    }

    /*
     * Pool ids are recycled after sgwc_sess_remove(). If this session was
     * torn down by another path (e.g. an S11 Delete racing a graceful
     * maintenance drain) while our PFCP xact was still in flight, sess_id
     * may now resolve to a brand-new, unrelated session. The CP SEID is
     * unique per session and was captured in xact->local_seid at send
     * time, so a mismatch proves the id was recycled — acting on this
     * session would tear down the wrong PDN context (crash/UAF).
     */
    if (xact->local_seid && sess->sgwc_sxa_seid != xact->local_seid) {
        ogs_error("PFCP timeout [%d]: sess_id[%d] was recycled "
                "(xact SEID[0x%llx] != sess SEID[0x%llx]); ignoring",
                type, sess_id,
                (unsigned long long)xact->local_seid,
                (unsigned long long)sess->sgwc_sxa_seid);
        return;
    }

    switch (type) {
    case OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE: {
        sgwc_ue_t *sgwc_ue = NULL;
        ogs_gtp_xact_t *s11_xact = NULL;

        /* Establish gave up: release the admission in-flight slot */
        sgwc_admission_establish_done(sess);

        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        if (sess->pfcp_node) {
            char sgwu_peer[OGS_ADDRSTRLEN];

            sgwc_log_sgwu_peer(sgwu_peer, sizeof(sgwu_peer), sess);
            ogs_error("[%s] Sxa timeout: no PFCP Session Establishment "
                    "Response from SGW-U %s sess_id[%d] sx_seid[0x%llx] "
                    "s11_xact[%u]",
                    sgwc_log_imsi(sgwc_ue),
                    sgwu_peer[0] ? sgwu_peer : "(unknown)",
                    sess->id, (unsigned long long)sess->sgwc_sxa_seid,
                    xact->assoc_xact_id);
        } else {
            ogs_error("[%s] Sxa timeout: no PFCP Session Establishment "
                    "Response from SGW-U sess_id[%d] sx_seid[0x%llx] "
                    "s11_xact[%u]",
                    sgwc_log_imsi(sgwc_ue), sess->id,
                    (unsigned long long)sess->sgwc_sxa_seid,
                    xact->assoc_xact_id);
        }

        s11_xact = ogs_gtp_xact_find_by_id(xact->assoc_xact_id);
        if (sgwc_ue && s11_xact) {
            if (sess->gn) {
                sgwc_gn_send_create_reject(sess, sgwc_ue, s11_xact,
                        OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
                sgwc_ue_remove_if_empty(sgwc_ue);
                break;
            }
            /*
             * reject_and_cleanup() frees sess and, if that was the UE's last
             * session, the UE itself. Do NOT touch sgwc_ue afterwards: a
             * second sgwc_ue_remove_if_empty() on the freed pointer corrupts
             * sgw_ue_list (stale-pointer unlink) and double-frees the pool
             * node.
             */
            sgwc_create_session_reject_and_cleanup(sess, sgwc_ue, s11_xact,
                    OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
        } else if (xact->assoc_xact_id == OGS_INVALID_POOL_ID) {
            /* PFCP restoration path — SGW-U slow to respond; keep the
             * session so the UE can continue after SGW-U recovers.
             * The UE will re-attach or the session will be aged out. */
            ogs_warn("[%s] PFCP restoration timeout sess_id[%d] — "
                    "keeping session pending SGW-U recovery",
                    sgwc_log_imsi(sgwc_ue), sess->id);
        } else {
            /* s11_xact already gone — normal session timeout, clean up */
            sgwc_sess_abort_create(sess);
            sgwc_ue_remove_if_empty(sgwc_ue);
        }
        break;
    }
    case OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE: {
        sgwc_ue_t *sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        ogs_gtp_xact_t *s11_xact = NULL;
        char sgwu_peer[OGS_ADDRSTRLEN];

        sgwc_log_sgwu_peer(sgwu_peer, sizeof(sgwu_peer), sess);
        ogs_error("[%s] Sxa timeout: no PFCP Session Modification Response "
                "from SGW-U %s sess_id[%d] sx_seid[0x%llx]",
                sgwc_log_imsi(sgwc_ue),
                sgwu_peer[0] ? sgwu_peer : "(unknown)",
                sess->id, (unsigned long long)sess->sgwc_sxa_seid);

        s11_xact = ogs_gtp_xact_find_by_id(xact->assoc_xact_id);
        if (sgwc_ue && s11_xact &&
                (xact->modify_flags & OGS_PFCP_MODIFY_UL_ONLY)) {
            /* reject_and_cleanup() frees sess and the UE if it was the last
             * session; no further sgwc_ue access allowed (see above). */
            sgwc_create_session_reject_and_cleanup(sess, sgwc_ue, s11_xact,
                    OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
        } else if (sgwc_ue &&
                (xact->modify_flags & OGS_PFCP_MODIFY_UL_ONLY)) {
            /*
             * S11 GTP transaction already expired before the PFCP modification
             * timed out.  MME has already given up on this bearer, so there is
             * no S11 reply to send; just tear down the downstream sessions
             * (S5 + PFCP) that were created during this attach attempt.
             */
            sgwc_sess_abort_create(sess);
            sgwc_ue_remove_if_empty(sgwc_ue);
        }
        break;
    }
    case OGS_PFCP_SESSION_DELETION_REQUEST_TYPE: {
        sgwc_ue_t *sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        ogs_gtp_xact_t *s11_xact = NULL;
        char sgwu_peer[OGS_ADDRSTRLEN];

        sgwc_log_sgwu_peer(sgwu_peer, sizeof(sgwu_peer), sess);
        ogs_error("[%s] Sxa timeout: no PFCP Session Deletion Response "
                "from SGW-U %s sess_id[%d] sgwu_seid[0x%llx]",
                sgwc_log_imsi(sgwc_ue),
                sgwu_peer[0] ? sgwu_peer : "(unknown)",
                sess->id, (unsigned long long)sess->sgwu_sxa_seid);
        if (sgwc_ue && sgwc_ue->csr_replace_sess_id == sess->id) {
            if (sess->gn)
                sgwc_gn_csr_replace_continue(sgwc_ue, sess, false);
            else
                sgwc_csr_replace_continue(sgwc_ue, sess, false);
            return;
        }

        /*
         * SGW-U never answered the deletion after all PFCP retransmissions
         * (e.g. an unresponsive or broken user plane that does not emit
         * Session Deletion Responses). The SGW-C session and UE were freed
         * only in the Session Deletion *Response* handler, so a silent SGW-U
         * left the SGW-C context (and the sgwc_ue_active gauge) leaking
         * forever. Stop waiting on the user plane: acknowledge the pending
         * S11/Gn peer so the MME/SGSN can finish detach, then drop the
         * session and release the UE if this was its last PDN connection.
         * sgwu_sxa_seid is cleared first so sgwc_sess_remove() does not queue
         * yet another (already-timed-out) orphan purge toward the dead SGW-U.
         */
        s11_xact = ogs_gtp_xact_find_by_id(xact->assoc_xact_id);
        if (sgwc_ue && s11_xact) {
            if (sess->gn)
                sgwc_gtp_send_delete_pdp_context_response(
                        sess, s11_xact, OGS_GTP1_CAUSE_REQUEST_ACCEPTED);
            else
                ogs_gtp_send_error_message(
                        s11_xact, sgwc_ue->mme_s11_teid,
                        OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE,
                        OGS_GTP2_CAUSE_REQUEST_ACCEPTED);
        }

        sess->sgwu_sxa_seid = 0;
        sgwc_sess_remove(sess);
        sgwc_ue_remove_if_empty(sgwc_ue);
        return;
    }
    default:
        ogs_error("Not implemented [type:%d]", type);
        break;
    }
}

static void bearer_timeout(ogs_pfcp_xact_t *xact, void *data)
{
    sgwc_bearer_t *bearer = NULL;
    ogs_pool_id_t bearer_id = OGS_INVALID_POOL_ID;
    uint8_t type;

    ogs_assert(xact);
    type = xact->seq[0].type;

    ogs_assert(data);
    bearer_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(bearer_id >= OGS_MIN_POOL_ID && bearer_id <= OGS_MAX_POOL_ID);

    bearer = sgwc_bearer_find_by_id(bearer_id);
    if (!bearer) {
        ogs_error("Bearer has already been removed [%d]", type);
        return;
    }

    switch (type) {
    case OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE:
        ogs_error("No PFCP session modification response");
        break;
    default:
        ogs_error("Not implemented [type:%d]", type);
        break;
    }
}

void sgwc_bearer_unlink_to_modify(
        sgwc_bearer_t *bearer, ogs_pfcp_node_t *node)
{
    ogs_pfcp_xact_t *xact = NULL;

    ogs_assert(bearer);
    if (!node)
        return;

    ogs_list_for_each(&node->local_list[ogs_worker_self_id()], xact) {
        if (ogs_list_exists(&xact->bearer_to_modify_list,
                    &bearer->to_modify_node)) {
            ogs_list_remove(&xact->bearer_to_modify_list,
                    &bearer->to_modify_node);
            ogs_warn("Unlinked bearer_id[%d] EBI[%d] from in-flight PFCP "
                    "modify xid=%u flags=0x%llx before new link",
                    bearer->id, bearer->ebi, xact->xid,
                    (unsigned long long)xact->modify_flags);
            return; /* single embedded lnode: at most one list */
        }
    }
}

/*
 * True when this session already has a Session Modification in flight
 * on the owning shard (session-scoped or bearer-scoped). Used to defer
 * background DROP/REARM/DROBU so they do not steal to_modify_node from
 * an ACTIVATE/DEACTIVATE that a GTP peer is waiting on.
 */
static bool sgwc_sess_pfcp_modify_in_flight(sgwc_sess_t *sess)
{
    ogs_pfcp_xact_t *xact = NULL;

    ogs_assert(sess);
    if (!sess->pfcp_node)
        return false;

    ogs_list_for_each(&sess->pfcp_node->local_list[ogs_worker_self_id()],
            xact) {
        sgwc_bearer_t *bearer = NULL;

        if (xact->seq[0].type !=
                OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE)
            continue;

        if (xact->modify_flags & OGS_PFCP_MODIFY_SESSION) {
            ogs_pool_id_t sess_id = OGS_POINTER_TO_UINT(xact->data);

            if (sess_id == sess->id)
                return true;
            continue;
        }

        ogs_list_for_each(&sess->bearer_list, bearer) {
            if (ogs_list_exists(&xact->bearer_to_modify_list,
                        &bearer->to_modify_node))
                return true;
        }
    }

    return false;
}

#define SGWC_PFCP_MODIFY_SOFT \
    (OGS_PFCP_MODIFY_DROP|OGS_PFCP_MODIFY_REARM|OGS_PFCP_MODIFY_DROBU)

int sgwc_pfcp_send_bearer_to_modify_list(
        sgwc_sess_t *sess, ogs_pfcp_xact_t *xact)
{
    int rv;
    ogs_pkbuf_t *sxabuf = NULL;
    ogs_pfcp_header_t h;

    ogs_assert(sess);
    ogs_assert(xact);

    sgwc_sess_sync_pfcp_pdr_nwi(sess);

    xact->local_seid = sess->sgwc_sxa_seid;
    ogs_debug("PFCP Session Modification xact: "
            "sess_id=%d xact=%p local_seid=0x%llx bearer_to_modify_count=%d",
            sess->id, xact, (unsigned long long)xact->local_seid,
            ogs_list_count(&xact->bearer_to_modify_list));

    memset(&h, 0, sizeof(ogs_pfcp_header_t));
    h.type = OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE;
    h.seid = sess->sgwu_sxa_seid;

    sxabuf = sgwc_sxa_build_bearer_to_modify_list(h.type, sess, xact);
    if (!sxabuf) {
        ogs_error("sgwc_sxa_build_bearer_to_modify_list() failed");
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_update_tx(xact, &h, sxabuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_pfcp_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgwc_pfcp_send_session_establishment_request(
        sgwc_sess_t *sess, ogs_pool_id_t gtp_xact_id, ogs_pkbuf_t *gtpbuf,
        uint64_t flags)
{
    int rv;
    ogs_pkbuf_t *sxabuf = NULL;
    ogs_pfcp_header_t h;
    ogs_pfcp_xact_t *xact = NULL;

    ogs_assert(sess);

    sgwc_sess_sync_pfcp_pdr_nwi(sess);

    xact = ogs_pfcp_xact_local_create(
            sess->pfcp_node, sess_timeout, OGS_UINT_TO_POINTER(sess->id));
    if (!xact) {
        ogs_error("ogs_pfcp_xact_local_create() failed");
        return OGS_ERROR;
    }

    xact->assoc_xact_id = gtp_xact_id;
    if (gtpbuf) {
        xact->gtpbuf = ogs_pkbuf_copy(gtpbuf);
        if (!xact->gtpbuf) {
            ogs_error("ogs_pkbuf_copy() failed");
            ogs_pfcp_xact_delete(xact);
            return OGS_ERROR;
        }
    }
    xact->local_seid = sess->sgwc_sxa_seid;
    xact->create_flags = flags;

    memset(&h, 0, sizeof(ogs_pfcp_header_t));
    h.type = OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE;

/*
 * 7.2.2.4.2 Conditions for Sending SEID=0 in PFCP Header
 *
 * If a peer's SEID is not available, the SEID field shall still be present
 * in the header and its value shall be set to "0" in the following messages:
 *
 * - PFCP Session Establishment Request message on Sxa/Sxb/Sxc/N4;
 *
 * - If a node receives a message for which it has no session, i.e.
 *   if SEID in the PFCP header is not known, it shall respond
 *   with "Session context not found" cause in the corresponding
 *   response message to the sender, the SEID used in the PFCP header
 *   in the response message shall be then set to "0";
 *
 * - If a node receives a request message containing protocol error,
 *   e.g. Mandatory IE missing, which requires the receiver
 *   to reject the message as specified in clause 7.6, it shall reject
 *   the request message. For the response message, the node should look up
 *   the remote peer's SEID and accordingly set SEID in the PFCP header
 *   and the message cause code. As an implementation option,
 *   the node may not look up the remote peer's SEID and
 *   set the PFCP header SEID to "0" in the response message.
 *   However in this case, the cause value shall not be set
 *   to "Session not found".
 *
 * - When the UP function sends PFCP Session Report Request message
 *   over N4 towards another SMF or another PFCP entity in the SMF
 *   as specified in clause 5.22.2 and clause 5.22.3.
 */
    h.seid = sess->sgwu_sxa_seid;

    sxabuf = sgwc_sxa_build_session_establishment_request(h.type, sess);
    if (!sxabuf) {
        ogs_error("sgwc_sxa_build_session_establishment_request() failed");
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_update_tx(xact, &h, sxabuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_pfcp_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    /*
     * Count toward the admission in-flight cap only for real Create
     * Sessions (a GTP transaction is waiting); PFCP restoration
     * re-establishes (no S11/Gn xact) must not starve new attaches.
     */
    if (rv == OGS_OK && gtp_xact_id != OGS_INVALID_POOL_ID)
        sgwc_admission_establish_started(sess);

    return rv;
}

int sgwc_pfcp_send_session_modification_request(
        sgwc_sess_t *sess, ogs_pool_id_t gtp_xact_id,
        ogs_pkbuf_t *gtpbuf, uint64_t flags)
{
    ogs_pfcp_xact_t *xact = NULL;
    sgwc_bearer_t *bearer = NULL;

    ogs_assert(sess);
    ogs_assert(ogs_list_count(&sess->bearer_list));
    ogs_debug("PFCP Session Modification from session: "
            "sess_id=%d gtp_xact_id=%d flags=0x%llx",
            sess->id, gtp_xact_id, (unsigned long long)flags);

    /*
     * Background FAR maintenance (DROP / REARM / DROBU) must not race an
     * in-flight GTP-driven modify: both paths share bearer->to_modify_node.
     * Return OGS_RETRY so callers leave CP state alone; buffer_idle /
     * holddown sweep will try again.
     */
    if ((flags & SGWC_PFCP_MODIFY_SOFT) &&
            sgwc_sess_pfcp_modify_in_flight(sess)) {
        ogs_info("Defer PFCP soft-modify flags=0x%llx sess_id[%d]: "
                "modify already in flight",
                (unsigned long long)flags, sess->id);
        return OGS_RETRY;
    }

    xact = ogs_pfcp_xact_local_create(
            sess->pfcp_node, sess_timeout, OGS_UINT_TO_POINTER(sess->id));
    if (!xact) {
        ogs_error("ogs_pfcp_xact_local_create() failed");
        return OGS_ERROR;
    }

    xact->assoc_xact_id = gtp_xact_id;
    xact->modify_flags = flags | OGS_PFCP_MODIFY_SESSION;
    if (gtpbuf) {
        xact->gtpbuf = ogs_pkbuf_copy(gtpbuf);
        if (!xact->gtpbuf) {
            ogs_error("ogs_pkbuf_copy() failed");
            ogs_pfcp_xact_delete(xact);
            return OGS_ERROR;
        }
    }
    xact->local_seid = sess->sgwc_sxa_seid;

    ogs_list_for_each(&sess->bearer_list, bearer) {
        sgwc_bearer_unlink_to_modify(bearer, sess->pfcp_node);
        ogs_list_add(&xact->bearer_to_modify_list, &bearer->to_modify_node);
    }

    return sgwc_pfcp_send_bearer_to_modify_list(sess, xact);
}

int sgwc_pfcp_send_bearer_modification_request(
        sgwc_bearer_t *bearer, ogs_pool_id_t gtp_xact_id,
        ogs_pkbuf_t *gtpbuf, uint64_t flags)
{
    int rv;
    ogs_pkbuf_t *sxabuf = NULL;
    ogs_pfcp_header_t h;
    ogs_pfcp_xact_t *xact = NULL;
    sgwc_sess_t *sess = NULL;

    ogs_assert(bearer);
    sess = sgwc_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    ogs_debug("PFCP Session Modification from bearer: "
            "bearer_id=%d sess_id=%d gtp_xact_id=%d flags=0x%llx",
            bearer->id, sess->id, gtp_xact_id, (unsigned long long)flags);

    xact = ogs_pfcp_xact_local_create(
            sess->pfcp_node, bearer_timeout, OGS_UINT_TO_POINTER(bearer->id));
    if (!xact) {
        ogs_error("ogs_pfcp_xact_local_create() failed");
        return OGS_ERROR;
    }

    xact->assoc_xact_id = gtp_xact_id;
    xact->modify_flags = flags;
    if (gtpbuf) {
        xact->gtpbuf = ogs_pkbuf_copy(gtpbuf);
        if (!xact->gtpbuf) {
            ogs_error("ogs_pkbuf_copy() failed");
            ogs_pfcp_xact_delete(xact);
            return OGS_ERROR;
        }
    }
    xact->local_seid = sess->sgwc_sxa_seid;

    sgwc_bearer_unlink_to_modify(bearer, sess->pfcp_node);
    ogs_list_add(&xact->bearer_to_modify_list, &bearer->to_modify_node);

    sgwc_sess_sync_pfcp_pdr_nwi(sess);

    memset(&h, 0, sizeof(ogs_pfcp_header_t));
    h.type = OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE;
    h.seid = sess->sgwu_sxa_seid;

    sxabuf = sgwc_sxa_build_bearer_to_modify_list(h.type, sess, xact);
    if (!sxabuf) {
        ogs_error("sgwc_sxa_build_bearer_to_modify_list() failed");
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_update_tx(xact, &h, sxabuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_pfcp_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int sgwc_pfcp_send_session_deletion_request(
        sgwc_sess_t *sess, ogs_pool_id_t gtp_xact_id, ogs_pkbuf_t *gtpbuf)
{
    int rv;
    ogs_pkbuf_t *sxabuf = NULL;
    ogs_pfcp_header_t h;
    ogs_pfcp_xact_t *xact = NULL;

    ogs_assert(sess);

    xact = ogs_pfcp_xact_local_create(
            sess->pfcp_node, sess_timeout, OGS_UINT_TO_POINTER(sess->id));
    if (!xact) {
        ogs_error("ogs_pfcp_xact_local_create() failed");
        return OGS_ERROR;
    }

    xact->assoc_xact_id = gtp_xact_id;
    if (gtpbuf) {
        xact->gtpbuf = ogs_pkbuf_copy(gtpbuf);
        if (!xact->gtpbuf) {
            ogs_error("ogs_pkbuf_copy() failed");
            ogs_pfcp_xact_delete(xact);
            return OGS_ERROR;
        }
    }
    xact->local_seid = sess->sgwc_sxa_seid;

    memset(&h, 0, sizeof(ogs_pfcp_header_t));
    h.type = OGS_PFCP_SESSION_DELETION_REQUEST_TYPE;
    h.seid = sess->sgwu_sxa_seid;

    sxabuf = sgwc_sxa_build_session_deletion_request(h.type, sess);
    if (!sxabuf) {
        ogs_error("sgwc_sxa_build_session_deletion_request() failed");
        ogs_pfcp_xact_delete(xact);
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_update_tx(xact, &h, sxabuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_pfcp_xact_update_tx() failed");
        ogs_pfcp_xact_delete(xact);
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

static void sgwc_pfcp_orphan_purge_timeout(ogs_pfcp_xact_t *xact, void *data)
{
    (void)data;

    ogs_assert(xact);
    ogs_debug("orphan PFCP session purge finished (type=%u)",
            xact->seq[0].type);
}

static int sgwc_pfcp_send_orphan_session_purge(
        sgwc_sess_t *sess, uint64_t sgwu_sxa_seid)
{
    int rv;
    ogs_pkbuf_t *sxabuf = NULL;
    ogs_pfcp_header_t h;
    ogs_pfcp_xact_t *xact = NULL;

    ogs_assert(sess);
    ogs_assert(sess->pfcp_node);
    ogs_assert(sgwu_sxa_seid);

    xact = ogs_pfcp_xact_local_create(
            sess->pfcp_node, sgwc_pfcp_orphan_purge_timeout, NULL);
    if (!xact) {
        ogs_error("ogs_pfcp_xact_local_create() failed");
        return OGS_ERROR;
    }

    xact->delete_trigger = OGS_PFCP_DELETE_TRIGGER_ORPHAN_PURGE;
    xact->assoc_xact_id = OGS_INVALID_POOL_ID;
    xact->local_seid = 0;

    memset(&h, 0, sizeof(ogs_pfcp_header_t));
    h.type = OGS_PFCP_SESSION_DELETION_REQUEST_TYPE;
    h.seid = sgwu_sxa_seid;

    sxabuf = sgwc_sxa_build_session_deletion_request(h.type, sess);
    if (!sxabuf) {
        ogs_error("sgwc_sxa_build_session_deletion_request() failed");
        ogs_pfcp_xact_delete(xact);
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_update_tx(xact, &h, sxabuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_pfcp_xact_update_tx() failed");
        ogs_pfcp_xact_delete(xact);
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

void sgwc_sess_purge_upf(sgwc_sess_t *sess)
{
    sgwc_ue_t *sgwc_ue = NULL;
    uint64_t sgwu_seid = 0;

    if (!sess || !sess->sgwu_sxa_seid || !sess->pfcp_node)
        return;

    sgwu_seid = sess->sgwu_sxa_seid;
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    sess->sgwu_sxa_seid = 0;

    if (sgwc_pfcp_send_orphan_session_purge(sess, sgwu_seid) != OGS_OK) {
        ogs_warn("[%s] Orphan PFCP session purge failed (SGWU-SEID=0x%llx)",
                sgwc_ue ? sgwc_ue->imsi_bcd : "-",
                (unsigned long long)sgwu_seid);
    }
}

int sgwc_pfcp_purge_seid_node(ogs_pfcp_node_t *pfcp_node, uint64_t up_seid)
{
    int rv;
    ogs_pkbuf_t *sxabuf = NULL;
    ogs_pfcp_message_t *pfcp_message = NULL;
    ogs_pfcp_header_t h;
    ogs_pfcp_xact_t *xact = NULL;

    if (!pfcp_node || !up_seid) {
        ogs_error("purge-seid: node and SEID are required");
        return OGS_ERROR;
    }

    xact = ogs_pfcp_xact_local_create(
            pfcp_node, sgwc_pfcp_orphan_purge_timeout, NULL);
    if (!xact) {
        ogs_error("purge-seid: ogs_pfcp_xact_local_create() failed");
        return OGS_ERROR;
    }

    xact->delete_trigger = OGS_PFCP_DELETE_TRIGGER_ORPHAN_PURGE;
    xact->assoc_xact_id = OGS_INVALID_POOL_ID;
    xact->local_seid = 0;

    memset(&h, 0, sizeof(ogs_pfcp_header_t));
    h.type = OGS_PFCP_SESSION_DELETION_REQUEST_TYPE;
    h.seid = up_seid;

    /* Session Deletion Request body is empty; just the SEID in the header. */
    pfcp_message = ogs_calloc(1, sizeof(*pfcp_message));
    if (!pfcp_message) {
        ogs_error("purge-seid: ogs_calloc() failed");
        ogs_pfcp_xact_delete(xact);
        return OGS_ERROR;
    }
    pfcp_message->h.type = h.type;
    sxabuf = ogs_pfcp_build_msg(pfcp_message);
    ogs_free(pfcp_message);
    if (!sxabuf) {
        ogs_error("purge-seid: ogs_pfcp_build_msg() failed");
        ogs_pfcp_xact_delete(xact);
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_update_tx(xact, &h, sxabuf);
    if (rv != OGS_OK) {
        ogs_error("purge-seid: ogs_pfcp_xact_update_tx() failed");
        ogs_pfcp_xact_delete(xact);
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    ogs_warn("purge-seid: sent PFCP Session Deletion to SGW-U %s "
            "SEID=0x%llx",
            ogs_sockaddr_to_string_static(pfcp_node->addr_list),
            (unsigned long long)up_seid);

    return rv;
}

int sgwc_pfcp_purge_seid(ogs_sockaddr_t *upf_addr, uint64_t up_seid)
{
    ogs_pfcp_node_t *pfcp_node = NULL, *iter = NULL;
    char buf[OGS_ADDRSTRLEN];

    if (!up_seid) {
        ogs_error("purge-seid: SEID must be non-zero");
        return OGS_ERROR;
    }

    /*
     * Resolve the target SGW-U. With an explicit address, match it; without
     * one, use the sole associated peer. Refuse to guess when several SGW-U
     * peers are associated -- the NMS must name the one that owns the SEID.
     */
    ogs_list_for_each(&ogs_pfcp_self()->pfcp_peer_list, iter) {
        if (!OGS_FSM_CHECK(&iter->sm, sgwc_pfcp_state_associated))
            continue;
        if (upf_addr) {
            ogs_sockaddr_t *a = NULL;
            bool match = false;
            for (a = iter->addr_list; a; a = a->next) {
                if (ogs_sockaddr_is_equal_addr(a, upf_addr)) {
                    match = true;
                    break;
                }
            }
            if (match) {
                pfcp_node = iter;
                break;
            }
        } else if (!pfcp_node) {
            pfcp_node = iter;
        } else {
            ogs_error("purge-seid: multiple SGW-U peers associated; "
                    "specify ?ip=<sgwu-addr>");
            return OGS_ERROR;
        }
    }

    if (!pfcp_node) {
        ogs_error("purge-seid: no matching associated SGW-U peer%s%s",
                upf_addr ? " for " : "",
                upf_addr ? OGS_ADDR(upf_addr, buf) : "");
        return OGS_ERROR;
    }

    return sgwc_pfcp_purge_seid_node(pfcp_node, up_seid);
}

int sgwc_pfcp_send_session_report_response(
        ogs_pfcp_xact_t *xact, sgwc_sess_t *sess, uint8_t cause)
{
    int rv;
    ogs_pkbuf_t *sxabuf = NULL;
    ogs_pfcp_header_t h;

    memset(&h, 0, sizeof(ogs_pfcp_header_t));
    h.type = OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE;
    h.seid = sess->sgwu_sxa_seid;

    sxabuf = ogs_pfcp_build_session_report_response(h.type, cause);
    if (!sxabuf) {
        ogs_error("ogs_pfcp_build_session_report_response() failed");
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_update_tx(xact, &h, sxabuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_pfcp_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_pfcp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

ogs_pfcp_node_t *sgwc_pfcp_admin_add_sgwu_peer(
        ogs_sockaddr_t *addr,
        const char **dnns, int num_of_dnns)
{
    ogs_pfcp_node_t *node = NULL;
    int i;

    ogs_assert(addr);

    ogs_pfcp_peer_lock();
    node = ogs_pfcp_node_new(addr);
    if (!node) {
        ogs_pfcp_peer_unlock();
        ogs_error("sgwc_pfcp_admin_add_sgwu_peer: node_new failed");
        return NULL;
    }

    ogs_list_add(&ogs_pfcp_self()->pfcp_peer_list, node);
    ogs_pfcp_peer_unlock();

    if (dnns && num_of_dnns > 0) {
        if (num_of_dnns > OGS_MAX_NUM_OF_DNN)
            num_of_dnns = OGS_MAX_NUM_OF_DNN;
        for (i = 0; i < num_of_dnns; i++) {
            if (dnns[i])
                node->dnn[i] = ogs_strdup(dnns[i]);
        }
        node->num_of_dnn = num_of_dnns;
    }

    pfcp_node_fsm_init(node, true);

    ogs_info("sgwc_pfcp_admin_add_sgwu_peer: added SGW-U peer "
            "(num_of_dnn=%u)", (unsigned)node->num_of_dnn);

    return node;
}

bool sgwc_pfcp_remove_sgwu_peer(ogs_pfcp_node_t *node)
{
    ogs_assert(node);

    if (sgwc_pfcp_peer_in_use(node))
        return false;

    pfcp_node_fsm_fini(node);
    ogs_pfcp_node_remove(&ogs_pfcp_self()->pfcp_peer_list, node);
    return true;
}

void sgwc_pfcp_request_reassociation(ogs_pfcp_node_t *node)
{
    int rv;
    sgwc_event_t *e = NULL;

    ogs_assert(node);

    e = sgwc_event_new(SGWC_EVT_SXA_REASSOCIATE);
    e->pfcp_node = node;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        sgwc_event_free(e);
    }
}
