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
#include "gtp-path.h"
#include "s11-handler.h"
#include "gn-handler.h"
#include "sgwc-trace.h"
#include "event.h"

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

static void pfcp_recv_cb(short when, ogs_socket_t fd, void *data)
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
        ogs_error("ogs_pfcp_recvfrom() failed");
        return;
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
        return;
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

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        goto cleanup;
    }

    return;

cleanup:
    ogs_pkbuf_free(pkbuf);
    ogs_pfcp_message_free(message);
    sgwc_event_free(e);
}

int sgwc_pfcp_open(void)
{
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;

    /* PFCP Server */
    ogs_list_for_each(&ogs_pfcp_self()->pfcp_list, node) {
        sock = ogs_pfcp_server(node);
        if (!sock) return OGS_ERROR;

        node->poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, pfcp_recv_cb, sock);
        ogs_assert(node->poll);
    }
    ogs_list_for_each(&ogs_pfcp_self()->pfcp_list6, node) {
        sock = ogs_pfcp_server(node);
        if (!sock) return OGS_ERROR;

        node->poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, pfcp_recv_cb, sock);
        ogs_assert(node->poll);
    }

    OGS_SETUP_PFCP_SERVER;

    return OGS_OK;
}

void sgwc_pfcp_close(void)
{
    ogs_pfcp_node_t *pfcp_node = NULL;

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

    switch (type) {
    case OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE: {
        sgwc_ue_t *sgwc_ue = NULL;
        ogs_gtp_xact_t *s11_xact = NULL;

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
                break;
            }
            ogs_gtp_send_error_message(
                    s11_xact, sgwc_ue->mme_s11_teid,
                    OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                    OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING);
        }

        sgwc_sess_remove(sess);
        break;
    }
    case OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE: {
        sgwc_ue_t *sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        char sgwu_peer[OGS_ADDRSTRLEN];

        sgwc_log_sgwu_peer(sgwu_peer, sizeof(sgwu_peer), sess);
        ogs_error("[%s] Sxa timeout: no PFCP Session Modification Response "
                "from SGW-U %s sess_id[%d] sx_seid[0x%llx]",
                sgwc_log_imsi(sgwc_ue),
                sgwu_peer[0] ? sgwu_peer : "(unknown)",
                sess->id, (unsigned long long)sess->sgwc_sxa_seid);
        break;
    }
    case OGS_PFCP_SESSION_DELETION_REQUEST_TYPE: {
        sgwc_ue_t *sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        char sgwu_peer[OGS_ADDRSTRLEN];

        sgwc_log_sgwu_peer(sgwu_peer, sizeof(sgwu_peer), sess);
        ogs_error("[%s] Sxa timeout: no PFCP Session Deletion Response "
                "from SGW-U %s sess_id[%d] sgwu_seid[0x%llx]",
                sgwc_log_imsi(sgwc_ue),
                sgwu_peer[0] ? sgwu_peer : "(unknown)",
                sess->id, (unsigned long long)sess->sgwu_sxa_seid);
        if (sgwc_ue && sgwc_ue->csr_replace_sess_id == sess->id) {
            sgwc_csr_replace_continue(sgwc_ue, sess, false);
            return;
        }
        break;
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

    ogs_list_for_each(&sess->bearer_list, bearer)
        ogs_list_add(&xact->bearer_to_modify_list, &bearer->to_modify_node);

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

    node = ogs_pfcp_node_new(addr);
    if (!node) {
        ogs_error("sgwc_pfcp_admin_add_sgwu_peer: node_new failed");
        return NULL;
    }

    ogs_list_add(&ogs_pfcp_self()->pfcp_peer_list, node);

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
