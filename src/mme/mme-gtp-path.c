/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
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

#include "ogs-gtp.h"

#include "mme-event.h"
#include "mme-timer.h"
#include "mme-gn-build.h"
#include "mme-gtp-path.h"
#include "mme-trace.h"
#include "mme-path.h"
#include "mme-inbound-roam-apn.h"
#include "s1ap-path.h"
#include "mme-s11-build.h"
#include "mme-sm.h"
#include "mme-workers.h"
#include "metrics.h"

static const char *mme_gtp2_message_type_name(uint8_t type)
{
    switch (type) {
    case OGS_GTP2_CREATE_SESSION_REQUEST_TYPE:
        return "Create Session Request";
    case OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE:
        return "Create Session Response";
    case OGS_GTP2_DELETE_SESSION_REQUEST_TYPE:
        return "Delete Session Request";
    case OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE:
        return "Delete Session Response";
    case OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE:
        return "Modify Bearer Request";
    case OGS_GTP2_MODIFY_BEARER_RESPONSE_TYPE:
        return "Modify Bearer Response";
    case OGS_GTP2_RELEASE_ACCESS_BEARERS_REQUEST_TYPE:
        return "Release Access Bearers Request";
    case OGS_GTP2_RELEASE_ACCESS_BEARERS_RESPONSE_TYPE:
        return "Release Access Bearers Response";
    case OGS_GTP2_BEARER_RESOURCE_COMMAND_TYPE:
        return "Bearer Resource Command";
    case OGS_GTP2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
        return "Create Indirect Data Forwarding Tunnel Request";
    case OGS_GTP2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
        return "Delete Indirect Data Forwarding Tunnel Request";
    default:
        return "Unknown";
    }
}

static void _gtpv1v2_c_recv_cb(short when, ogs_socket_t fd, void *data)
{
    int rv;
    char buf[OGS_ADDRSTRLEN];

    ssize_t size;
    mme_event_t *e = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;
    mme_sgw_t *sgw = NULL;
    mme_sgsn_t *sgsn = NULL;
    uint8_t gtp_ver;

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

    gtp_ver = ((ogs_gtp2_header_t *)pkbuf->data)->version;
    switch (gtp_ver) {
    case 1:
        sgsn = mme_sgsn_find_by_addr(&from);
        if (!sgsn) {
            ogs_error("Unknown SGSN : %s", OGS_ADDR(&from, buf));
            ogs_pkbuf_free(pkbuf);
            return;
        }
        ogs_assert(sgsn);
        e = mme_event_new(MME_EVENT_GN_MESSAGE);
        ogs_assert(e);
        e->gnode = &sgsn->gnode;
        break;
    case 2:
        sgw = mme_sgw_find_by_addr(&from);
        if (!sgw) {
            uint8_t gtp_type = 0;
            uint32_t teid = 0;
            mme_ue_t *hint_ue = NULL;
            const char *imsi = "-";

            if (pkbuf->len >= sizeof(ogs_gtp2_header_t)) {
                ogs_gtp2_header_t *h = (ogs_gtp2_header_t *)pkbuf->data;

                gtp_type = h->type;
                teid = be32toh(h->teid);
                if (teid)
                    hint_ue = mme_ue_find_by_s11_local_teid(teid);
            }
            if (hint_ue)
                imsi = mme_log_imsi(hint_ue);

            ogs_error("Unknown SGW [%s]:%d IMSI[%s] GTPv2 type[%u:%s] "
                    "TEID[0x%x] (check mme.gtpc.client.sgwc / roam port)",
                    OGS_ADDR(&from, buf), OGS_PORT(&from), imsi,
                    gtp_type, mme_gtp2_message_type_name(gtp_type), teid);
            ogs_pkbuf_free(pkbuf);
            return;
        }
        ogs_assert(sgw);
        e = mme_event_new(MME_EVENT_S11_MESSAGE);
        ogs_assert(e);
        e->gnode = &sgw->gnode;
        break;
    default:
        ogs_warn("Rx unexpected GTP version %u", gtp_ver);
        ogs_pkbuf_free(pkbuf);
        return;
    }

    e->pkbuf = pkbuf;

    /*
     * Echo stays on main (peer housekeeping). Other S11 messages bounce
     * to the UE shard when mme.workers > 0.
     */
    if (gtp_ver == 2 && pkbuf->len >= 1) {
        uint8_t type = ((ogs_gtp2_header_t *)pkbuf->data)->type;
        if (type == OGS_GTP2_ECHO_REQUEST_TYPE ||
                type == OGS_GTP2_ECHO_RESPONSE_TYPE) {
            rv = ogs_queue_push(ogs_app()->queue, e);
            if (rv != OGS_OK) {
                ogs_error("ogs_queue_push() failed:%d", (int)rv);
                ogs_pkbuf_free(e->pkbuf);
                mme_event_free(e);
            } else {
                ogs_pollset_notify(ogs_app()->pollset);
            }
            return;
        }
    }

    rv = mme_event_push_to_ue_owner(e);
    if (rv != OGS_OK)
        ogs_error("S11 event push failed:%d", (int)rv);
}

static void timeout(ogs_gtp_xact_t *xact, void *data)
{
    int r;
    mme_ue_t *mme_ue = NULL;
    ogs_pool_id_t mme_ue_id = OGS_INVALID_POOL_ID;
    enb_ue_t *enb_ue = NULL;
    mme_sess_t *sess = NULL;
    ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;
    mme_bearer_t *bearer = NULL;
    ogs_pool_id_t bearer_id = OGS_INVALID_POOL_ID;
    uint8_t type = 0;

    ogs_assert(xact);
    type = xact->seq[0].type;

    switch (type) {
    case OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE:
    case OGS_GTP2_RELEASE_ACCESS_BEARERS_REQUEST_TYPE:
    case OGS_GTP2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
    case OGS_GTP2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
        mme_ue_id = OGS_POINTER_TO_UINT(data);
        ogs_assert(mme_ue_id >= OGS_MIN_POOL_ID &&
                mme_ue_id <= OGS_MAX_POOL_ID);
        mme_ue = mme_ue_find_by_id(mme_ue_id);
        if (!mme_ue) {
            char peer[OGS_ADDRSTRLEN];

            ogs_error("GTP timeout: MME-UE[%u] removed type[%u:%s] SGW[%s]:%d",
                    mme_ue_id, type, mme_gtp2_message_type_name(type),
                    xact && xact->gnode ?
                        OGS_ADDR(&xact->gnode->addr, peer) : "-",
                    xact && xact->gnode ? OGS_PORT(&xact->gnode->addr) : 0);
            return;
        }
        break;
    case OGS_GTP2_CREATE_SESSION_REQUEST_TYPE:
    case OGS_GTP2_DELETE_SESSION_REQUEST_TYPE:
        sess_id = OGS_POINTER_TO_UINT(data);
        ogs_assert(sess_id >= OGS_MIN_POOL_ID && sess_id <= OGS_MAX_POOL_ID);
        sess = mme_sess_find_by_id(sess_id);
        if (!sess) {
            char peer[OGS_ADDRSTRLEN];

            ogs_error("GTP timeout: Session[%u] removed type[%u:%s] "
                    "SGW[%s]:%d",
                    sess_id, type, mme_gtp2_message_type_name(type),
                    xact && xact->gnode ?
                        OGS_ADDR(&xact->gnode->addr, peer) : "-",
                    xact && xact->gnode ? OGS_PORT(&xact->gnode->addr) : 0);
            return;
        }
        mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
        ogs_assert(mme_ue);
        break;
    case OGS_GTP2_BEARER_RESOURCE_COMMAND_TYPE:
        bearer_id = OGS_POINTER_TO_UINT(data);
        ogs_assert(bearer_id >= OGS_MIN_POOL_ID &&
                bearer_id <= OGS_MAX_POOL_ID);
        bearer = mme_bearer_find_by_id(bearer_id);
        if (!bearer) {
            char peer[OGS_ADDRSTRLEN];

            ogs_error("GTP timeout: Bearer[%u] removed type[%u:%s] "
                    "SGW[%s]:%d",
                    bearer_id, type, mme_gtp2_message_type_name(type),
                    xact && xact->gnode ?
                        OGS_ADDR(&xact->gnode->addr, peer) : "-",
                    xact && xact->gnode ? OGS_PORT(&xact->gnode->addr) : 0);
            return;
        }
        sess = mme_sess_find_by_id(bearer->sess_id);
        ogs_assert(sess);
        mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
        ogs_assert(mme_ue);
        break;
    default:
        ogs_error("Invalid GTP timeout type [%d]", type);
        return;
    }

    ogs_assert(mme_ue);
    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

    switch (type) {
    case OGS_GTP2_DELETE_SESSION_REQUEST_TYPE:
        /*
         * If SESSION_CONTEXT_WILL_DELETED(MME_UE) is not cleared,
         * The MME cannot send Delete-Session-Request to the SGW-C.
         * As such, it could be the infinite loop occurred in EMM state machine.
         *
         * To prevent this situation,
         * force clearing SESSION_CONTEXT_WILL_DELETED variable
         * when MME does not receive Delete-Session-Response message from SGW-C.
         */
        CLEAR_SESSION_CONTEXT(mme_ue);

        if (enb_ue) {
            r = s1ap_send_ue_context_release_command(enb_ue,
                    S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
                    S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
        } else {
            uint16_t tac = 0;
            uint32_t cell_id = 0, enb_id = 0;

            mme_log_radio(mme_ue, enb_ue, &tac, &cell_id, &enb_id);
            ogs_warn("[%s] GTP timeout: no S1 context type[%u:%s] "
                    "TAC[0x%04x] eNB_ID[0x%x] cell[0x%x]",
                    mme_log_imsi(mme_ue), type,
                    mme_gtp2_message_type_name(type), tac, enb_id, cell_id);
        }
        break;
    case OGS_GTP2_BEARER_RESOURCE_COMMAND_TYPE:
        /* Nothing to do */
        break;
    default:
        if (enb_ue)
            mme_send_delete_session_or_mme_ue_context_release(enb_ue, mme_ue);
        else {
            uint16_t tac = 0;
            uint32_t cell_id = 0, enb_id = 0;

            mme_log_radio(mme_ue, enb_ue, &tac, &cell_id, &enb_id);
            ogs_warn("[%s] GTP timeout: no S1 context type[%u:%s] "
                    "TAC[0x%04x] eNB_ID[0x%x] cell[0x%x]; "
                    "starting mobile reachable timer",
                    mme_log_imsi(mme_ue), type,
                    mme_gtp2_message_type_name(type), tac, enb_id, cell_id);
            mme_mobile_reachable_start(mme_ue);
        }
        break;
    }

    {
        char peer[OGS_ADDRSTRLEN];
        sgw_ue_t *sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
        const char *type_name = mme_gtp2_message_type_name(type);
        const char *peer_addr = "unknown";
        int peer_port = 0;

        if (xact && xact->gnode) {
            peer_addr = OGS_ADDR(&xact->gnode->addr, peer);
            peer_port = OGS_PORT(&xact->gnode->addr);
        }

        mme_ue_error(mme_ue, enb_ue, "s11", NULL,
                "GTP Timeout S11 [%s]:%d Message-Type[%d:%s] "
                "SGW_S11_TEID[0x%x]",
                peer_addr, peer_port, type, type_name,
                sgw_ue ? sgw_ue->sgw_s11_teid : 0);
    }
}

static void gn_sgsn_context_timeout(ogs_gtp_xact_t *xact, void *data)
{
    int rv;
    mme_event_t *e = NULL;
    ogs_pool_id_t mme_ue_id = OGS_INVALID_POOL_ID;
    char peer[OGS_ADDRSTRLEN];

    ogs_assert(xact);
    ogs_assert(data);

    mme_ue_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(mme_ue_id >= OGS_MIN_POOL_ID &&
            mme_ue_id <= OGS_MAX_POOL_ID);

    if (!mme_ue_find_by_id(mme_ue_id))
        return;

    ogs_warn("Gn SGSN Context Response timeout MME-UE[%u] peer [%s]:%d",
            mme_ue_id,
            xact->gnode ? OGS_ADDR(&xact->gnode->addr, peer) : "-",
            xact->gnode ? OGS_PORT(&xact->gnode->addr) : 0);

    e = mme_event_new(MME_EVENT_GN_TIMER);
    if (!e) {
        ogs_error("mme_event_new() failed");
        return;
    }

    e->timer_id = MME_TIMER_GN_SGSN_CONTEXT;
    e->mme_ue_id = mme_ue_id;

    /* The timeout path can remove the UE: run it on the owner shard. */
    rv = mme_event_push_to_ue_owner(e);
    if (rv != OGS_OK)
        ogs_error("Gn SGSN-context timer push failed:%d", (int)rv);
}

int mme_gtp_open(void)
{
    int rv;
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;
    mme_sgw_t *sgw = NULL;
    mme_sgsn_t *sgsn = NULL;

    ogs_list_for_each(&ogs_gtp_self()->gtpc_list, node) {
        sock = ogs_gtp_server(node);
        if (!sock) return OGS_ERROR;

        node->poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, _gtpv1v2_c_recv_cb, sock);
        ogs_assert(node->poll);
    }
    ogs_list_for_each(&ogs_gtp_self()->gtpc_list6, node) {
        sock = ogs_gtp_server(node);
        if (!sock) return OGS_ERROR;

        node->poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, _gtpv1v2_c_recv_cb, sock);
        ogs_assert(node->poll);
    }

    OGS_SETUP_GTPC_SERVER;
    ogs_assert(ogs_gtp_self()->gtpc_sock || ogs_gtp_self()->gtpc_sock6);
    ogs_assert(ogs_gtp_self()->gtpc_addr || ogs_gtp_self()->gtpc_addr6);

    mme_self()->pgw_addr = mme_pgw_addr_find_by_apn_enb(
            &mme_self()->pgw_list, AF_INET, NULL);
    mme_self()->pgw_addr6 = mme_pgw_addr_find_by_apn_enb(
            &mme_self()->pgw_list, AF_INET6, NULL);

    ogs_list_for_each(&mme_self()->sgw_list, sgw) {
        char buf[OGS_ADDRSTRLEN];

        rv = ogs_gtp_connect(
                ogs_gtp_self()->gtpc_sock, ogs_gtp_self()->gtpc_sock6,
                &sgw->gnode);
        if (rv != OGS_OK) {
            ogs_error("gtp_connect() failed for SGW [%s]:%d",
                    OGS_ADDR(sgw->gnode.sa_list, buf),
                    OGS_PORT(sgw->gnode.sa_list));
            return OGS_ERROR;
        }
        ogs_info("MME S11 peer configured: [%s]:%d",
                OGS_ADDR(&sgw->gnode.addr, buf), OGS_PORT(&sgw->gnode.addr));

        mme_gtp_send_sgw_echo(sgw);
        mme_sgw_echo_schedule(sgw);
    }

    ogs_list_for_each(&mme_self()->sgsn_list, sgsn) {
        rv = ogs_gtp_connect(
                ogs_gtp_self()->gtpc_sock, ogs_gtp_self()->gtpc_sock6,
                &sgsn->gnode);
        ogs_assert(rv == OGS_OK);
    }

    return OGS_OK;
}

void mme_gtp_close(void)
{
    ogs_socknode_remove_all(&ogs_gtp_self()->gtpc_list);
    ogs_socknode_remove_all(&ogs_gtp_self()->gtpc_list6);
}

void mme_gtp_send_sgw_echo(mme_sgw_t *sgw)
{
    ogs_assert(sgw);
    ogs_gtp2_send_echo_request(
            &sgw->gnode, mme_self()->gtpc_recovery, 0);
}

void mme_timer_sgw_echo(void *data)
{
    mme_sgw_t *sgw = data;

    ogs_assert(sgw);
    mme_gtp_send_sgw_echo(sgw);
    mme_sgw_echo_schedule(sgw);
}

int mme_gtp_send_create_session_request(
        enb_ue_t *enb_ue, mme_sess_t *sess, int create_action)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *xact = NULL;
    mme_ue_t *mme_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;

    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    ogs_assert(mme_ue);

    if (sess->session && sess->session->name &&
            !mme_inbound_roam_apn_allowed(mme_ue, sess->session->name)) {
        ogs_warn("[%s] inbound roam APN policy: block Create Session APN[%s] "
                "esm_cause=%u create_action=%d",
                mme_ue->imsi_bcd, sess->session->name,
                mme_inbound_roam_apn_esm_cause(mme_ue, sess->session->name),
                create_action);
        return OGS_ERROR;
    }

    if (mme_self()->maintenance_mode &&
            create_action != OGS_GTP_CREATE_IN_PATH_SWITCH_REQUEST) {
        ogs_warn("[%s] Create Session blocked: MME maintenance mode",
                mme_log_imsi(mme_ue));
        return OGS_ERROR;
    }

    if (create_action != OGS_GTP_CREATE_IN_PATH_SWITCH_REQUEST)
        mme_sgw_reselect_for_ue_if_needed(mme_ue);

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (!sgw_ue) {
        ogs_error("[%s] Create Session Request: SGW-UE gone "
                "(create_action=%d)", mme_ue->imsi_bcd, create_action);
        return OGS_ERROR;
    }

    if (create_action == OGS_GTP_CREATE_IN_PATH_SWITCH_REQUEST) {
        sgw_ue = sgw_ue_find_by_id(sgw_ue->target_ue_id);
        if (!sgw_ue) {
            ogs_error("[%s] Create Session Request: target SGW-UE gone "
                    "(path switch)", mme_ue->imsi_bcd);
            return OGS_ERROR;
        }
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_CREATE_SESSION_REQUEST_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    pkbuf = mme_s11_build_create_session_request(h.type, sess, create_action);
    if (!pkbuf) {
        char sgw_peer[OGS_ADDRSTRLEN];
        char pgw_peer[64];
        const char *apn = sess->session ? sess->session->name : "-";

        mme_log_pgw_peer(pgw_peer, sizeof(pgw_peer), sess);
        ogs_error("[%s] mme_s11_build_create_session_request() failed "
                "APN[%s] SGW[%s]:%d PGW[%s] create_action[%d]",
                mme_log_imsi(mme_ue), apn,
                OGS_ADDR(&sgw_ue->gnode->addr, sgw_peer),
                OGS_PORT(&sgw_ue->gnode->addr),
                pgw_peer[0] ? pgw_peer : "-", create_action);
        return OGS_ERROR;
    }

    {
        char buf[OGS_ADDRSTRLEN];
        ogs_gtp_node_t *gnode = sgw_ue->gnode;

        if (!gnode || !gnode->sock) {
            ogs_error("[%s] S11 Create Session not sent: "
                    "SGW GTP node not connected",
                    MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
            ogs_pkbuf_free(pkbuf);
            mme_ue_progress(mme_ue, "create_session_req_fail");
            return OGS_ERROR;
        }

        if (OGS_PORT(&gnode->addr) == 0) {
            rv = ogs_gtp_connect(
                    ogs_gtp_self()->gtpc_sock, ogs_gtp_self()->gtpc_sock6,
                    gnode);
            if (rv != OGS_OK) {
                ogs_error("[%s] S11 Create Session not sent: "
                        "ogs_gtp_connect() failed SGW[%s]:%d",
                        mme_log_imsi(mme_ue),
                        OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));
                ogs_pkbuf_free(pkbuf);
                mme_ue_progress(mme_ue, "create_session_req_fail");
                return OGS_ERROR;
            }
        }

        ogs_info("[%s] S11 Create Session -> [%s]:%d",
                MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-",
                OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));
    }

    xact = ogs_gtp_xact_local_create(
            sgw_ue->gnode, &h, pkbuf, timeout,
            OGS_UINT_TO_POINTER(sess->id));
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        ogs_pkbuf_free(pkbuf);
        mme_ue_progress(mme_ue, "create_session_req_fail");
        return OGS_ERROR;
    }
    xact->create_action = create_action;
    xact->local_teid = mme_ue->gn.mme_gn_teid;
    if (enb_ue)
        xact->enb_ue_id = enb_ue->id;
    else
        xact->enb_ue_id = OGS_INVALID_POOL_ID;

    rv = ogs_gtp_xact_commit(xact);
    if (rv != OGS_OK) {
        ogs_error("[%s] S11 Create Session commit failed",
                MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-");
        mme_ue_progress(mme_ue, "create_session_req_fail");
        return OGS_ERROR;
    }

    mme_ue_progress(mme_ue, "create_session_req");

    mme_metrics_s11_create_session_attempt(mme_ue);

    return OGS_OK;
}

int mme_gtp_send_modify_bearer_request(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        int uli_presence, int modify_action)
{
    int rv;

    ogs_gtp_xact_t *xact = NULL;
    sgw_ue_t *sgw_ue = NULL;

    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(mme_ue);
    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    ogs_assert(sgw_ue);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    pkbuf = mme_s11_build_modify_bearer_request(h.type, mme_ue, uli_presence);
    if (!pkbuf) {
        ogs_error("mme_s11_build_modify_bearer_request() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp_xact_local_create(
            sgw_ue->gnode, &h, pkbuf, timeout,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    xact->modify_action = modify_action;
    xact->local_teid = mme_ue->gn.mme_gn_teid;
    if (enb_ue)
        xact->enb_ue_id = enb_ue->id;
    else
        xact->enb_ue_id = OGS_INVALID_POOL_ID;

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    if (mme_ue->nas_eps.type == MME_EPS_TYPE_SERVICE_REQUEST) {
        enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

        if (rv == OGS_OK) {
            char buf[OGS_ADDRSTRLEN];

            mme_ue_service_info(mme_ue, enb_ue,
                    "S11 Modify Bearer -> at [%s]:%d",
                    OGS_ADDR(&sgw_ue->gnode->addr, buf),
                    OGS_PORT(&sgw_ue->gnode->addr));
            mme_ue_service_progress(mme_ue, enb_ue, "mbr_req");
        } else {
            mme_ue_service_progress(mme_ue, enb_ue, "mbr_req_fail");
        }
    }

    return rv;
}

int mme_gtp_send_delete_session_request(
        enb_ue_t *enb_ue, sgw_ue_t *sgw_ue, mme_sess_t *sess, int action)
{
    int rv;
    ogs_pkbuf_t *s11buf = NULL;
    ogs_gtp2_header_t h;
    ogs_gtp_xact_t *xact = NULL;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(action);
    ogs_assert(sess);
    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    ogs_assert(mme_ue);
    ogs_assert(sgw_ue);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DELETE_SESSION_REQUEST_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    s11buf = mme_s11_build_delete_session_request(h.type, sess, action);
    if (!s11buf) {
        ogs_error("mme_s11_build_delete_session_request() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp_xact_local_create(
            sgw_ue->gnode, &h, s11buf, timeout,
            OGS_UINT_TO_POINTER(sess->id));
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        ogs_pkbuf_free(s11buf);
        return OGS_ERROR;
    }
    xact->delete_action = action;
    xact->local_teid = mme_ue->gn.mme_gn_teid;
    if (enb_ue)
        xact->enb_ue_id = enb_ue->id;
    else
        xact->enb_ue_id = OGS_INVALID_POOL_ID;
    ogs_debug("delete_session_request - xact:%p, sess:%p", xact, sess);

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

void mme_gtp_send_delete_all_sessions(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue, int action)
{
    mme_sess_t *sess = NULL, *next_sess = NULL;
    sgw_ue_t *sgw_ue = NULL;

    ogs_assert(mme_ue);
    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    ogs_assert(action);

    if (!sgw_ue) {
        ogs_list_for_each_safe(&mme_ue->sess_list, next_sess, sess)
            MME_SESS_CLEAR(sess);
        return;
    }

    ogs_list_for_each_safe(&mme_ue->sess_list, next_sess, sess) {
        if (MME_HAVE_SGW_S1U_PATH(sess)) {
            mme_gtp_send_delete_session_request(enb_ue, sgw_ue, sess, action);
        } else {
            MME_SESS_CLEAR(sess);
        }
    }
}

int mme_gtp_send_create_bearer_response(
        mme_bearer_t *bearer, uint8_t cause_value)
{
    int rv;

    ogs_gtp_xact_t *xact = NULL;
    mme_ue_t *mme_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;

    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(bearer);
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    ogs_assert(mme_ue);

    if (bearer->create.xact_id < OGS_MIN_POOL_ID ||
            bearer->create.xact_id > OGS_MAX_POOL_ID) {
        mme_ue_warn(mme_ue, NULL, "s11", NULL,
                "Create Bearer Response: no saved GTP transaction");
        return OGS_OK;
    }

    xact = ogs_gtp_xact_find_by_id(bearer->create.xact_id);
    bearer->create.xact_id = OGS_INVALID_POOL_ID;
    if (!xact) {
        mme_ue_warn(mme_ue, NULL, "s11", NULL,
                "GTP transaction(CREATE) has already been removed");
        return OGS_OK;
    }
    if (xact->org != OGS_GTP_REMOTE_ORIGINATOR ||
            xact->seq[0].type != OGS_GTP2_CREATE_BEARER_REQUEST_TYPE) {
        mme_ue_warn(mme_ue, NULL, "s11", NULL,
                "Create Bearer Response: saved xact id now belongs to "
                "another transaction (org=%d type=%d); dropping",
                xact->org, xact->seq[0].type);
        return OGS_OK;
    }
    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (!sgw_ue) {
        ogs_error("[%s] Create Bearer Response: SGW UE context gone",
                mme_ue->imsi_bcd);
        return OGS_ERROR;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_CREATE_BEARER_RESPONSE_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    pkbuf = mme_s11_build_create_bearer_response(h.type, bearer, cause_value);
    if (!pkbuf) {
        ogs_error("mme_s11_build_create_bearer_response() failed");
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

int mme_gtp_send_update_bearer_response(
        mme_bearer_t *bearer, uint8_t cause_value)
{
    int rv;

    ogs_gtp_xact_t *xact = NULL;
    mme_ue_t *mme_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;

    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(bearer);
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    ogs_assert(mme_ue);
    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    ogs_assert(sgw_ue);

    /*
     * Issues #3240
     *
     * SMF->SGW-C->MME: First Update Bearer Request
     * MME->UE:         First Modify EPS bearer context request
     * SMF->SGW-C->MME: Second Update Bearer Request
     * MME->UE:         Second Modify EPS bearer context request
     * UE->MME:         First Modify EPS bearer context accept
     * MME->SGW-C->SMF: First Update Bearer Response
     * UE->MME:         Second Modify EPS bearer context accept
     * MME->SGW-C->SMF: Second Update Bearer Response
     *
     * Pop the oldest pending Update xact (FIFO, validated against the
     * xact pool — stale IDs are skipped).
     */
    xact = mme_bearer_update_xact_pop(bearer);
    if (!xact) {
        ogs_warn("GTP transaction(UPDATE) has already been removed");
        return OGS_OK;
    }

    /*
     * eNB sends Modify EPS Bearer Accept to the MME
     * MME can send Update Bearer Response to the SGW-C,
     * so stop the peer waiting timer
     */
    if (xact->tm_peer)
        ogs_timer_stop(xact->tm_peer);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_UPDATE_BEARER_RESPONSE_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    pkbuf = mme_s11_build_update_bearer_response(h.type, bearer, cause_value);
    if (!pkbuf) {
        ogs_error("mme_s11_build_update_bearer_response() failed");
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

int mme_gtp_send_delete_bearer_response(
        mme_bearer_t *bearer, uint8_t cause_value)
{
    int rv;

    ogs_gtp_xact_t *xact = NULL;
    mme_ue_t *mme_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;

    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(bearer);
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    ogs_assert(mme_ue);

    /*
     * Deactivate Accept can arrive with no pending Delete Bearer
     * Request (e.g. UE-initiated PDN disconnect after Delete Session,
     * duplicate Accept, or xact already consumed). Asserting here
     * previously crashed the MME at 03:07.
     */
    if (bearer->delete.xact_id < OGS_MIN_POOL_ID ||
            bearer->delete.xact_id > OGS_MAX_POOL_ID) {
        mme_ue_warn(mme_ue, NULL, "s11", NULL,
                "Delete Bearer Response: no saved GTP transaction "
                "(UE-initiated or already acknowledged)");
        return OGS_OK;
    }

    xact = ogs_gtp_xact_find_by_id(bearer->delete.xact_id);
    bearer->delete.xact_id = OGS_INVALID_POOL_ID;
    if (!xact) {
        mme_ue_warn(mme_ue, NULL, "s11", NULL,
                "GTP transaction(DELETE) has already been removed");
        return OGS_OK;
    }
    if (xact->org != OGS_GTP_REMOTE_ORIGINATOR ||
            xact->seq[0].type != OGS_GTP2_DELETE_BEARER_REQUEST_TYPE) {
        mme_ue_warn(mme_ue, NULL, "s11", NULL,
                "Delete Bearer Response: saved xact id now belongs to "
                "another transaction (org=%d type=%d); dropping",
                xact->org, xact->seq[0].type);
        return OGS_OK;
    }
    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (!sgw_ue) {
        ogs_error("[%s] Delete Bearer Response: SGW UE context gone",
                mme_ue->imsi_bcd);
        return OGS_ERROR;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DELETE_BEARER_RESPONSE_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    pkbuf = mme_s11_build_delete_bearer_response(h.type, bearer, cause_value);
    if (!pkbuf) {
        ogs_error("mme_s11_build_delete_bearer_response() failed");
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

int mme_gtp_send_release_access_bearers_request(
        ogs_pool_id_t enb_ue_id, mme_ue_t *mme_ue, int action)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *xact = NULL;
    sgw_ue_t *sgw_ue = NULL;

    ogs_assert(action);
    ogs_assert(mme_ue);

    /*
     * Create the xact on the UE owner shard: the response handler
     * clears bearer S1-U state and restarts UE timers, which must not
     * run on main while the owner is live (S1AP release request / S1
     * reset paths call us from the main thread).
     */
    if (mme_workers_active() &&
            mme_worker_post_rel_ab(action, enb_ue_id, mme_ue) == OGS_OK)
        return OGS_OK;

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (!sgw_ue) {
        ogs_error("[%s] Release Access Bearers: SGW-UE gone (action=%d)",
                mme_ue->imsi_bcd, action);
        return OGS_ERROR;
    }

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_RELEASE_ACCESS_BEARERS_REQUEST_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    pkbuf = mme_s11_build_release_access_bearers_request(h.type);
    if (!pkbuf) {
        ogs_error("mme_s11_build_release_access_bearers_request() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp_xact_local_create(
            sgw_ue->gnode, &h, pkbuf, timeout,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    xact->release_action = action;
    xact->local_teid = mme_ue->gn.mme_gn_teid;
    xact->enb_ue_id = enb_ue_id;

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

/*
 * Paced Release Access Bearers Request sender for eNB-level mass release
 * (SCTP CONNREFUSED / fast reconnect).
 *
 * When an eNB association dies, every UE on it needs a Release Access
 * Bearers Request toward the SGW-C. Doing that synchronously was fine for
 * one eNB, but a site-wide flap (hundreds of eNBs, hundreds of thousands
 * of UEs) burst-allocated one GTP transaction + retransmit timer per UE
 * in a single event, monopolised the main thread for seconds and could
 * exhaust the transaction pool (the ogs_assert on the send aborted the
 * daemon). Instead, the S1 context teardown stays synchronous (it must
 * finish before the eNB context is freed) and only the S11 sends are
 * queued here and paced in batches.
 *
 * Safety: entries hold pool ids only. At send time the UE is re-resolved;
 * if it is gone, or has re-attached (ECM-CONNECTED again - a new Modify
 * Bearer Request already told the SGW about the new eNB, so a late RABR
 * would wrongly release the live S1-U), the entry is dropped.
 */
#define MME_RABR_RELEASE_BATCH      512
#define MME_RABR_RELEASE_INTERVAL   ogs_time_from_msec(50)

typedef struct mme_pending_release_s {
    ogs_lnode_t     lnode;
    ogs_pool_id_t   mme_ue_id;
    ogs_pool_id_t   enb_ue_id;  /* already removed; kept for xact bookkeeping */
    int             action;
} mme_pending_release_t;

static OGS_LIST(pending_release_list);
static ogs_timer_t *t_pending_release = NULL;

static void mme_gtp_pending_release_step(void);

static void pending_release_timer_cb(void *data)
{
    (void)data;
    mme_gtp_pending_release_step();
}

static void mme_gtp_pending_release_enqueue(
        ogs_pool_id_t mme_ue_id, ogs_pool_id_t enb_ue_id, int action)
{
    mme_pending_release_t *entry = NULL;

    entry = ogs_calloc(1, sizeof(*entry));
    ogs_assert(entry);

    entry->mme_ue_id = mme_ue_id;
    entry->enb_ue_id = enb_ue_id;
    entry->action = action;

    ogs_list_add(&pending_release_list, entry);
}

static void mme_gtp_pending_release_step(void)
{
    mme_pending_release_t *entry = NULL;
    int sent = 0, skipped = 0;

    while (sent < MME_RABR_RELEASE_BATCH &&
            (entry = ogs_list_first(&pending_release_list)) != NULL) {
        mme_ue_t *mme_ue = NULL;
        sgw_ue_t *sgw_ue = NULL;

        ogs_list_remove(&pending_release_list, entry);

        mme_ue = mme_ue_find_by_id(entry->mme_ue_id);
        if (!mme_ue || ECM_CONNECTED(mme_ue)) {
            /* Removed meanwhile, or re-attached: RABR no longer valid. */
            skipped++;
            ogs_free(entry);
            continue;
        }

        sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
        if (!sgw_ue) {
            skipped++;
            ogs_free(entry);
            continue;
        }

        if (mme_gtp_send_release_access_bearers_request(
                entry->enb_ue_id, mme_ue, entry->action) != OGS_OK)
            ogs_error("Deferred Release Access Bearers Request failed "
                    "[IMSI:%s]", mme_ue->imsi_bcd);

        sent++;
        ogs_free(entry);
    }

    if (ogs_list_first(&pending_release_list)) {
        if (!t_pending_release) {
            t_pending_release = ogs_timer_add(
                    ogs_app()->timer_mgr, pending_release_timer_cb, NULL);
            ogs_assert(t_pending_release);
        }
        ogs_timer_start(t_pending_release, MME_RABR_RELEASE_INTERVAL);
    } else if (sent || skipped) {
        ogs_info("eNB mass-release: paced sender drained "
                "(last batch sent=%d skipped=%d)", sent, skipped);
    }
}

void mme_gtp_pending_release_final(void)
{
    mme_pending_release_t *entry = NULL, *next = NULL;

    ogs_list_for_each_safe(&pending_release_list, next, entry) {
        ogs_list_remove(&pending_release_list, entry);
        ogs_free(entry);
    }

    if (t_pending_release) {
        ogs_timer_delete(t_pending_release);
        t_pending_release = NULL;
    }
}

void mme_gtp_send_release_all_ue_in_enb(mme_enb_t *enb, int action)
{
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL, *next = NULL;
    int deferred = 0;

    ogs_list_for_each_safe(&enb->enb_ue_list, next, enb_ue) {
        mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);

        if (mme_ue) {
            ogs_pool_id_t enb_ue_id = enb_ue->id;

            if (action == OGS_GTP_RELEASE_S1_CONTEXT_REMOVE_BY_LO_CONNREFUSED) {
                /*
                 * https://github.com/open5gs/open5gs/pull/1497
                 *
                 * 1. eNB, SGW-U and UPF go offline at the same time.
                 * 2. MME sends Release Access Bearer Request to SGW-C
                 * 3. SGW-C/SMF sends PFCP modification,
                 *    but SGW-U/UPF does not respond.
                 * 4. MME does not receive Release Access Bearer Response.
                 * 5. timeout()
                 * 6. MME sends Delete Session Request to the SGW-C/SMF
                 * 7. No SGW-U/UPF, so timeout()
                 * 8. MME sends UEContextReleaseRequest enb_ue.
                 * 9. But there is no enb_ue, so MME crashed.
                 *
                 * To solve this situation,
                 * Execute enb_ue_unlink(mme_ue) and enb_ue_remove(enb_ue)
                 * before mme_gtp_send_release_access_bearers_request().
                 * enb_ue_id is saved above before the free to avoid
                 * use-after-free when setting xact->enb_ue_id.
                 */
                enb_ue_deassociate_mme_ue(enb_ue, mme_ue);
                enb_ue_remove(enb_ue);
                enb_ue = NULL;

                /*
                 * S11 send deferred to the paced sender (see above).
                 * The S1 side is already torn down at this point.
                 */
                mme_gtp_pending_release_enqueue(mme_ue->id, enb_ue_id, action);
                deferred++;
                continue;
            }

            if (mme_gtp_send_release_access_bearers_request(
                    enb_ue_id, mme_ue, action) != OGS_OK)
                ogs_error("[%s] Release Access Bearers failed "
                        "(action=%d)", mme_ue->imsi_bcd, action);
        } else {
            ogs_warn("mme_gtp_send_release_all_ue_in_enb()");
            ogs_warn("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d] Action[%d]",
                enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id, action);

            if (action == OGS_GTP_RELEASE_S1_CONTEXT_REMOVE_BY_LO_CONNREFUSED ||
                action == OGS_GTP_RELEASE_S1_CONTEXT_REMOVE_BY_RESET_ALL) {
                enb_ue_remove(enb_ue);
            } else {
                /* At this point, it does not support other action */
                ogs_assert_if_reached();
            }
        }
    }

    if (deferred) {
        ogs_info("eNB mass-release: %d Release Access Bearers Request(s) "
                "queued for paced sending (batch=%d interval=%dms, "
                "%d already pending)",
                deferred, MME_RABR_RELEASE_BATCH,
                (int)ogs_time_to_msec(MME_RABR_RELEASE_INTERVAL),
                ogs_list_count(&pending_release_list) - deferred);
        mme_gtp_pending_release_step();
    }
}

int mme_gtp_send_downlink_data_notification_ack(
        mme_bearer_t *bearer, uint8_t cause_value)
{
    int rv;
    mme_ue_t *mme_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;
    ogs_gtp_xact_t *xact = NULL;

    ogs_gtp2_header_t h;
    ogs_pkbuf_t *s11buf = NULL;

    ogs_assert(bearer);
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    ogs_assert(mme_ue);

    if (bearer->notify.xact_id < OGS_MIN_POOL_ID ||
            bearer->notify.xact_id > OGS_MAX_POOL_ID) {
        mme_ue_warn(mme_ue, NULL, "s11", NULL,
                "DDN Ack: no saved GTP transaction (already acknowledged?)");
        return OGS_OK;
    }

    xact = ogs_gtp_xact_find_by_id(bearer->notify.xact_id);
    /* One ack per DDN: never reuse a stale id - after the holding
     * timer frees the transaction the pool slot can be recycled by an
     * unrelated transaction, and update_tx on it would fail (this
     * previously crashed the MME via ogs_assert in the callers). */
    bearer->notify.xact_id = OGS_INVALID_POOL_ID;
    if (!xact) {
        mme_ue_warn(mme_ue, NULL, "s11", NULL,
                "GTP transaction(NOTIFY) has already been removed");
        return OGS_OK;
    }
    if (xact->org != OGS_GTP_REMOTE_ORIGINATOR ||
            xact->seq[0].type != OGS_GTP2_DOWNLINK_DATA_NOTIFICATION_TYPE) {
        mme_ue_warn(mme_ue, NULL, "s11", NULL,
                "DDN Ack: saved xact id now belongs to another "
                "transaction (org=%d type=%d); dropping ack",
                xact->org, xact->seq[0].type);
        return OGS_OK;
    }
    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (!sgw_ue) {
        ogs_error("[%s] DDN Ack: SGW UE context gone", mme_ue->imsi_bcd);
        return OGS_ERROR;
    }

    /* Build Downlink data notification ack */
    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    s11buf = mme_s11_build_downlink_data_notification_ack(h.type, cause_value);
    if (!s11buf) {
        ogs_error("mme_s11_build_downlink_data_notification_ack() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_update_tx(xact, &h, s11buf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int mme_gtp_send_create_indirect_data_forwarding_tunnel_request(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *xact = NULL;
    sgw_ue_t *sgw_ue = NULL;

    ogs_assert(enb_ue);
    ogs_assert(mme_ue);
    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    ogs_assert(sgw_ue);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    pkbuf = mme_s11_build_create_indirect_data_forwarding_tunnel_request(
            h.type, mme_ue);
    if (!pkbuf) {
        ogs_error("mme_s11_build_create_indirect_data_forwarding_"
                "tunnel_request() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp_xact_local_create(
            sgw_ue->gnode, &h, pkbuf, timeout,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    xact->local_teid = mme_ue->gn.mme_gn_teid;
    xact->enb_ue_id = enb_ue->id;

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int mme_gtp_send_delete_indirect_data_forwarding_tunnel_request(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue, int action)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *xact = NULL;
    sgw_ue_t *sgw_ue = NULL;

    ogs_assert(enb_ue);
    ogs_assert(action);
    ogs_assert(mme_ue);
    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    ogs_assert(sgw_ue);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_TLV_MAX_HEADROOM);
    if (!pkbuf) {
        ogs_error("ogs_pkbuf_alloc() failed");
        return OGS_ERROR;
    }
    ogs_pkbuf_reserve(pkbuf, OGS_TLV_MAX_HEADROOM);

    xact = ogs_gtp_xact_local_create(
            sgw_ue->gnode, &h, pkbuf, timeout,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    xact->delete_indirect_action = action;
    xact->local_teid = mme_ue->gn.mme_gn_teid;
    xact->enb_ue_id = enb_ue->id;

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int mme_gtp_send_bearer_resource_command(
        mme_bearer_t *bearer, ogs_nas_eps_message_t *nas_message)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *xact = NULL;

    mme_ue_t *mme_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;

    ogs_assert(bearer);
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    ogs_assert(mme_ue);
    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    ogs_assert(sgw_ue);

    memset(&h, 0, sizeof(ogs_gtp2_header_t));
    h.type = OGS_GTP2_BEARER_RESOURCE_COMMAND_TYPE;
    h.teid = sgw_ue->sgw_s11_teid;

    pkbuf = mme_s11_build_bearer_resource_command(h.type, bearer, nas_message);
    if (!pkbuf) {
        ogs_error("mme_s11_build_bearer_resource_command() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp_xact_local_create(
            sgw_ue->gnode, &h, pkbuf, timeout,
            OGS_UINT_TO_POINTER(bearer->id));
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    xact->xid |= OGS_GTP_CMD_XACT_ID;
    xact->local_teid = mme_ue->gn.mme_gn_teid;

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

/*************************
 * GTPv1C (Gn interface):
 *************************/

int mme_gtp1_send_sgsn_context_request(
        mme_sgsn_t *sgsn, mme_ue_t *mme_ue, const ogs_nas_p_tmsi_signature_t *ptmsi_sig)
{
    int rv;
    ogs_gtp1_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(sgsn);
    ogs_assert(mme_ue);

    memset(&h, 0, sizeof(ogs_gtp1_header_t));
    h.type = OGS_GTP1_SGSN_CONTEXT_REQUEST_TYPE;
    h.teid = 0;

    pkbuf = mme_gn_build_sgsn_context_request(mme_ue, ptmsi_sig);
    if (!pkbuf) {
        ogs_error("mme_gn_build_sgsn_context_request() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp1_xact_local_create(&sgsn->gnode, &h, pkbuf,
            gn_sgsn_context_timeout, OGS_UINT_TO_POINTER(mme_ue->id));
    if (!xact) {
        ogs_error("ogs_gtp1_xact_local_create() failed");
        return OGS_ERROR;
    }
    /* TS 29.060 8.2: GTP header TEID is zero; local_teid correlates the reply. */
    xact->local_teid = mme_ue->gn.mme_gn_teid;

    mme_ue->gn.sgsn_context_pending = true;

    rv = ogs_gtp_xact_commit(xact);
    if (rv != OGS_OK) {
        mme_ue->gn.sgsn_context_pending = false;
        ogs_error("ogs_gtp_xact_commit() failed");
        return OGS_ERROR;
    }

    return rv;
}

int mme_gtp1_send_sgsn_context_response(
        mme_ue_t *mme_ue, uint8_t cause, ogs_gtp_xact_t *xact)
{
    int rv;
    ogs_gtp1_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    memset(&h, 0, sizeof(ogs_gtp1_header_t));
    h.type = OGS_GTP1_SGSN_CONTEXT_RESPONSE_TYPE;
    h.teid = mme_ue ? mme_ue->gn.sgsn_gn_teid : 0;

    pkbuf = mme_gn_build_sgsn_context_response(mme_ue, cause);
    if (!pkbuf) {
        ogs_error("mme_gn_build_sgsn_context_response() failed");
        return OGS_ERROR;
    }
    xact->local_teid = mme_ue ? mme_ue->gn.mme_gn_teid : 0;

    rv = ogs_gtp1_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int mme_gtp1_send_sgsn_context_ack(
        mme_ue_t *mme_ue, uint8_t cause, ogs_gtp_xact_t *xact)
{
    int rv;
    ogs_gtp1_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(mme_ue);

    memset(&h, 0, sizeof(ogs_gtp1_header_t));
    h.type = OGS_GTP1_SGSN_CONTEXT_ACKNOWLEDGE_TYPE;
    h.teid = mme_ue->gn.sgsn_gn_teid;

    pkbuf = mme_gn_build_sgsn_context_ack(mme_ue, cause);
    if (!pkbuf) {
        ogs_error("mme_gn_build_sgsn_context_response() failed");
        return OGS_ERROR;
    }
    xact->local_teid = mme_ue->gn.mme_gn_teid;

    rv = ogs_gtp1_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int mme_gtp1_send_ran_information_relay(
        mme_sgsn_t *sgsn, const uint8_t *buf, size_t len,
        const ogs_nas_rai_t *rai, uint16_t cell_id)
{
    int rv;
    ogs_gtp1_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(sgsn);
    ogs_assert(buf);

    memset(&h, 0, sizeof(ogs_gtp1_header_t));
    h.type = OGS_GTP1_RAN_INFORMATION_RELAY_TYPE;
    h.teid = 0;

    pkbuf = mme_gn_build_ran_information_relay(h.type, buf, len, rai, cell_id);
    if (!pkbuf) {
        ogs_error("mme_gn_build_ran_information_relay() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp1_xact_local_create(&sgsn->gnode, &h, pkbuf, NULL, NULL);
    if (!xact) {
        ogs_error("ogs_gtp1_xact_local_create() failed");
        return OGS_ERROR;
    }
    /* TS 29.060 8.2: "The RAN Information Relay message, where the Tunnel
     * Endpoint Identifier shall be set to all zeroes." */
    xact->local_teid = 0;

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}
