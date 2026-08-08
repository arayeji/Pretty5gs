/*
 * Copyright (C) 2019,2026 by Sukchan Lee <acetcom@gmail.com>
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

#include "s11-handler.h"
#include "s5c-handler.h"
#include "gn-handler.h"
#include "context.h"
#include "sgwc-reload-lists.h"
#include "sgwc-workers.h"

#include "gtp-path.h"
#include "pfcp-path.h"
#include "metrics.h"

static void sgwc_handle_echo_request(
        ogs_gtp_xact_t *xact, ogs_gtp2_echo_request_t *req)
{
    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("[SGW] Receiving Echo Request");
    ogs_gtp2_send_echo_response(xact, sgwc_self()->gtpc_recovery, 0);
}

static void sgwc_handle_echo_response(
        ogs_gtp_xact_t *s11_xact, ogs_gtp2_echo_response_t *rsp)
{
    ogs_assert(s11_xact);
    ogs_assert(rsp);

    ogs_debug("[SGW] Receiving Echo Response");
}

/*
 * Batched /admin/maintenance/drain.
 *
 * The old implementation tore down every session in one main-thread pass:
 * up to three messages per session (Delete Bearer toward MME, PFCP
 * deletion toward SGW-U, Delete Session toward SMF). With hundreds of
 * thousands of sessions this blocked the main loop for seconds and
 * burst-flooded all three peers. Instead, process fixed-size UE batches
 * paced by a timer so other traffic keeps flowing in between (same
 * pattern as the MME drain).
 *
 * SMP: the drain ROUND (generation, force flag, active flag) is set up
 * once by the main thread; each shard — main included — then steps
 * through only the UEs it owns, on its own pacing timer. The round ends
 * when the last shard finishes.
 */
#define SGWC_ADMIN_DRAIN_BATCH      256 /* UEs per batch */
#define SGWC_ADMIN_DRAIN_INTERVAL   ogs_time_from_msec(100)

/* Per-thread stepper state; the timer lives on this thread's timer_mgr. */
static OGS_THREAD_LOCAL ogs_timer_t *t_admin_drain = NULL;
static OGS_THREAD_LOCAL bool drain_self_active = false;

/* Number of shards still stepping the current round (atomic). */
static int drain_shards_running = 0;

static void sgwc_admin_drain_step(void);

static void admin_drain_timer_cb(void *data)
{
    (void)data;
    sgwc_admin_drain_step();
}

/* Main thread only: open a new process-wide drain round. */
static void sgwc_admin_drain_round_start(bool force)
{
    int ue_count;

    sgwc_self()->drain_generation++;
    if (sgwc_self()->drain_generation == 0)
        sgwc_self()->drain_generation = 1;
    sgwc_self()->drain_force = force;
    sgwc_self()->drain_active = true;
    __atomic_store_n(&sgwc_self()->drain_processed, 0, __ATOMIC_RELAXED);

    sgwc_ctx_lock();
    ue_count = ogs_list_count(&sgwc_self()->sgw_ue_list);
    sgwc_ctx_unlock();

    ogs_info("admin maintenance drain: start mode=%s ue_count=%d "
            "batch=%d interval=%dms",
            force ? "force" : "graceful", ue_count,
            SGWC_ADMIN_DRAIN_BATCH,
            (int)ogs_time_to_msec(SGWC_ADMIN_DRAIN_INTERVAL));
}

/* Start (or keep running) this shard's stepper for the current round. */
static void sgwc_admin_drain_begin(void)
{
    if (drain_self_active) {
        /* Already stepping; the new generation is picked up as we go. */
        return;
    }
    drain_self_active = true;
    __atomic_add_fetch(&drain_shards_running, 1, __ATOMIC_RELAXED);

    sgwc_admin_drain_step();
}

static void sgwc_admin_drain_step(void)
{
    sgwc_sess_t *sess = NULL, *next_sess = NULL;
    int ues = 0, sessions = 0;
    bool more = false;
    int rv;
    ogs_pool_id_t *ids = NULL;
    int count = 0, i;

    if (!drain_self_active)
        return;

    ids = sgwc_ue_ids_collect_owned(&count);

    for (i = 0; i < count; i++) {
        sgwc_ue_t *ue = sgwc_ue_find_by_id(ids[i]);

        if (!ue || !sgwc_ue_owned_by_self(ue))
            continue;
        if (ue->drain_generation == sgwc_self()->drain_generation)
            continue;
        if (ues >= SGWC_ADMIN_DRAIN_BATCH) {
            more = true;
            break;
        }
        ue->drain_generation = sgwc_self()->drain_generation;
        ues++;

        ogs_list_for_each_safe(&ue->sess_list, next_sess, sess) {
            rv = sgwc_gtp_send_network_delete_session(ue, sess);
            ogs_expect(rv == OGS_OK);

            if (sess->gnode)
                sgwc_gtp_send_s5c_delete_session_request(sess);

            if (sgwc_self()->drain_force) {
                /*
                 * Force-local teardown: do not use
                 * sgwc_pfcp_send_session_deletion_request() here.  Its PFCP
                 * xact stores sess->id; freeing the session while that xact is
                 * still in flight lets a recycled pool id make sess_timeout()
                 * operate on the wrong PDN context (crash/UAF).  Orphan purge
                 * uses a NULL xact callback instead.
                 */
                sgwc_sess_purge_upf(sess);
                sgwc_sess_remove(sess);
            } else {
                if (sess->pfcp_node && sess->sgwu_sxa_seid) {
                    rv = sgwc_pfcp_send_session_deletion_request(
                            sess, OGS_INVALID_POOL_ID, NULL);
                    ogs_expect(rv == OGS_OK);
                }
            }
            sessions++;
        }
        if (sgwc_self()->drain_force && ogs_list_empty(&ue->sess_list))
            sgwc_ue_remove(ue);
    }

    if (ids)
        ogs_free(ids);

    __atomic_add_fetch(&sgwc_self()->drain_processed, sessions,
            __ATOMIC_RELAXED);

    if (more) {
        if (!t_admin_drain) {
            t_admin_drain = ogs_timer_add(
                    ogs_worker_timer_mgr(ogs_app()->timer_mgr),
                    admin_drain_timer_cb, NULL);
            ogs_assert(t_admin_drain);
        }
        ogs_timer_start(t_admin_drain, SGWC_ADMIN_DRAIN_INTERVAL);
        return;
    }

    /* This shard is done; the last one out closes the round. */
    drain_self_active = false;
    if (t_admin_drain)
        ogs_timer_stop(t_admin_drain);

    if (__atomic_sub_fetch(&drain_shards_running, 1, __ATOMIC_RELAXED) == 0) {
        sgwc_self()->drain_active = false;
        ogs_info("admin maintenance drain: %s %u session(s)",
                sgwc_self()->drain_force ?
                    "removed" : "initiated teardown for",
                __atomic_load_n(&sgwc_self()->drain_processed,
                        __ATOMIC_RELAXED));
    }
}

static void sgwc_admin_drain_timer_stop(void)
{
    if (drain_self_active) {
        drain_self_active = false;
        if (__atomic_sub_fetch(&drain_shards_running, 1,
                __ATOMIC_RELAXED) == 0)
            sgwc_self()->drain_active = false;
    }

    if (!t_admin_drain)
        return;

    ogs_timer_delete(t_admin_drain);
    t_admin_drain = NULL;
}

static void sgwc_admin_detach_ue_sessions(sgwc_ue_t *ue, int admin_force)
{
    sgwc_sess_t *sess = NULL, *next_sess = NULL;
    int count = 0;
    int rv;

    ogs_assert(ue);
    ogs_list_for_each_safe(&ue->sess_list, next_sess, sess) {
        /* Notify MME via Delete Bearer Request (3GPP TS 23.401 §5.4.4). */
        rv = sgwc_gtp_send_delete_bearer_request_to_mme(
                ue, sess, OGS_INVALID_POOL_ID);
        ogs_expect(rv == OGS_OK);

        if (sess->gnode)
            sgwc_gtp_send_s5c_delete_session_request(sess);

        if (admin_force) {
            sgwc_sess_purge_upf(sess);
            sgwc_sess_remove(sess);
        } else if (sess->pfcp_node && sess->sgwu_sxa_seid) {
            rv = sgwc_pfcp_send_session_deletion_request(
                    sess, OGS_INVALID_POOL_ID, NULL);
            ogs_expect(rv == OGS_OK);
        }
        count++;
    }
    if (admin_force && ogs_list_empty(&ue->sess_list))
        sgwc_ue_remove(ue);

    ogs_info("admin session detach: %s %d session(s) for imsi=%s",
            admin_force ? "removed" : "initiated for", count, ue->imsi_bcd);
}


void sgwc_state_initial(ogs_fsm_t *s, sgwc_event_t *e)
{
    sgwc_sm_debug(e);

    ogs_assert(s);

    /*
     * The periodic orphan sweep is driven by ONE timer on the main
     * thread; when it fires, main fans the sweep event to every worker
     * and each shard (main included) sweeps only the UEs it owns.
     */
    if (!ogs_worker_self()) {
        sgwc_orphan_timer_start();
        sgwc_buffer_idle_timer_start();
    }

    OGS_FSM_TRAN(s, &sgwc_state_operational);
}

void sgwc_state_final(ogs_fsm_t *s, sgwc_event_t *e)
{
    sgwc_sm_debug(e);

    ogs_assert(s);

    sgwc_orphan_timer_stop();
    sgwc_buffer_idle_timer_stop();
    sgwc_admin_drain_timer_stop();
}

void sgwc_state_operational(ogs_fsm_t *s, sgwc_event_t *e)
{
    int rv;

    ogs_pkbuf_t *recvbuf = NULL;
    sgwc_ue_t *sgwc_ue = NULL;
    sgwc_sess_t *sess = NULL;

    ogs_gtp_xact_t *gtp_xact = NULL;
    ogs_gtp2_message_t gtp_message;
    ogs_gtp1_message_t gtp1_message;
    ogs_gtp_node_t *gnode = NULL;

    ogs_pfcp_node_t *pfcp_node = NULL;
    ogs_pfcp_xact_t *pfcp_xact = NULL;
    ogs_pfcp_message_t *pfcp_message = NULL;

    sgwc_sm_debug(e);

    ogs_assert(s);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;

    case OGS_FSM_EXIT_SIG:
        break;

    case SGWC_EVT_SXA_MESSAGE:
        ogs_assert(e);
        recvbuf = e->pkbuf;
        ogs_assert(recvbuf);
        ogs_trace_packet_bind_rx("pfcp", recvbuf->data, recvbuf->len);
        pfcp_message = e->pfcp_message;
        ogs_assert(pfcp_message);
        pfcp_node = e->pfcp_node;
        ogs_assert(pfcp_node);
        /*
         * RX may have added the peer without FSM init; that deferred
         * init is main-only. Shard workers only see session messages
         * for already-associated peers — never call ensure_fsm here
         * (ogs_assert(!ogs_worker_self()) would abort the process).
         */
        if (!ogs_worker_self())
            sgwc_pfcp_node_ensure_fsm(pfcp_node);
        ogs_assert(OGS_FSM_STATE(&pfcp_node->sm));

        rv = ogs_pfcp_xact_receive(pfcp_node, &pfcp_message->h, &pfcp_xact);
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            ogs_pfcp_message_free(pfcp_message);
            break;
        }

        e->pfcp_xact_id = pfcp_xact ? pfcp_xact->id : OGS_INVALID_POOL_ID;

        e->gtp_message = NULL;
        if (pfcp_xact->gtpbuf) {
            rv = ogs_gtp2_parse_msg(&gtp_message, pfcp_xact->gtpbuf);
            if (rv != OGS_OK) {
                ogs_error("ogs_gtp2_parse_msg() failed on PFCP CSR buffer");
            } else {
                e->gtp_message = &gtp_message;
            }
        }

        ogs_fsm_dispatch(&pfcp_node->sm, e);
        if (OGS_FSM_CHECK(&pfcp_node->sm, sgwc_pfcp_state_exception)) {
            ogs_error("PFCP state machine exception");
        }

        /*
         * Must NULL after free: an in-flight PFCP modify xact can be
         * found again by a Modify Bearer retransmit (step >= 1) which
         * frees xact->gtpbuf before replacing it. Leaving a dangling
         * pointer here caused talloc "access after free" under load.
         */
        if (pfcp_xact->gtpbuf) {
            ogs_pkbuf_free(pfcp_xact->gtpbuf);
            pfcp_xact->gtpbuf = NULL;
        }
        ogs_pkbuf_free(recvbuf);
        ogs_pfcp_message_free(pfcp_message);
        break;

    case SGWC_EVT_SXA_TIMER:
    case SGWC_EVT_SXA_NO_HEARTBEAT:
    case SGWC_EVT_SXA_REASSOCIATE:
        ogs_assert(e);
        pfcp_node = e->pfcp_node;
        ogs_assert(pfcp_node);
        ogs_assert(OGS_FSM_STATE(&pfcp_node->sm));

        ogs_fsm_dispatch(&pfcp_node->sm, e);
        break;

    case SGWC_EVT_S11_MESSAGE:
        ogs_assert(e);
        recvbuf = e->pkbuf;
        ogs_assert(recvbuf);
        ogs_trace_packet_bind_rx("gtp", recvbuf->data, recvbuf->len);

        if (recvbuf->len >= sizeof(ogs_gtp1_header_t)) {
            uint8_t gtp_ver = ((ogs_gtp1_header_t *)recvbuf->data)->version;

            if (gtp_ver != 2) {
                ogs_debug("Ignoring GTPv%u on S11 queue (type %u)",
                        gtp_ver, ((ogs_gtp1_header_t *)recvbuf->data)->type);
                ogs_pkbuf_free(recvbuf);
                break;
            }
        }

        if (ogs_gtp2_parse_msg(&gtp_message, recvbuf) != OGS_OK) {
            ogs_error("ogs_gtp2_parse_msg() failed");
            ogs_pkbuf_free(recvbuf);
            break;
        }

        gnode = e->gnode;
        ogs_assert(gnode);

        /* Foreign-shard UE: bounce BEFORE creating the per-shard xact.
         * rehome takes the pkbuf; do not free it here. */
        if (sgwc_worker_rehome_gtp2(e, &gtp_message))
            break;

        rv = ogs_gtp_xact_receive(gnode, &gtp_message.h, &gtp_xact);
        if (rv == OGS_RETRY) {
            ogs_debug("S11 GTP duplicate request ignored (type=%u)",
                    gtp_message.h.type);
            ogs_pkbuf_free(recvbuf);
            break;
        }
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        sgwc_s11_check_peer_recovery(gnode, &gtp_message);

        if (gtp_message.h.teid_presence && gtp_message.h.teid != 0)
            /* Cause is not "Context not found" */
            sgwc_ue = sgwc_ue_find_by_teid(gtp_message.h.teid);

        if (!sgwc_ue && gtp_xact->local_teid) /* rx no TEID or TEID=0 */
            /* 3GPP TS 29.274 5.5.2: we receive TEID=0 under some
             * conditions, such as cause "Session context not found". In those
             * cases, we still want to identify the local session which
             * originated the message, so try harder by using the TEID we
             * locally stored in xact when sending the original request: */
            sgwc_ue = sgwc_ue_find_by_teid(gtp_xact->local_teid);

        if (sgwc_ue)
            OGS_SETUP_GTP_NODE(sgwc_ue, gnode);

        /* Prefer TEID-resolved IMSI for PACKET dumps (handlers may return
         * early before ogs_sgwc_trace_set / on_imsi). */
        if (sgwc_ue && sgwc_ue->imsi_bcd[0]) {
            ogs_gtp_xact_set_imsi(gtp_xact, sgwc_ue->imsi_bcd);
            ogs_trace_packet(sgwc_ue->imsi_bcd, "gtp", "rx",
                    recvbuf->data, recvbuf->len);
            ogs_trace_packet_bind_rx(NULL, NULL, 0);
        }

        switch(gtp_message.h.type) {
        case OGS_GTP2_ECHO_REQUEST_TYPE:
            sgwc_handle_echo_request(gtp_xact, &gtp_message.echo_request);
            break;
        case OGS_GTP2_ECHO_RESPONSE_TYPE:
            sgwc_handle_echo_response(gtp_xact, &gtp_message.echo_response);
            break;
        case OGS_GTP2_CREATE_SESSION_REQUEST_TYPE:
            if (gtp_message.h.teid == 0) {
                if (!sgwc_ue &&
                        gtp_message.create_session_request.imsi.presence &&
                        gtp_message.create_session_request.imsi.data &&
                        gtp_message.create_session_request.imsi.len > 0) {
                    sgwc_ue = sgwc_ue_find_by_imsi(
                            gtp_message.create_session_request.imsi.data,
                            gtp_message.create_session_request.imsi.len);
                }
                if (!sgwc_ue)
                    sgwc_ue = sgwc_ue_add_by_message(&gtp_message);
            }
            if (sgwc_ue)
                OGS_SETUP_GTP_NODE(sgwc_ue, gnode);
            /* Create Session often arrives with TEID=0; dump after UE exists. */
            if (sgwc_ue && sgwc_ue->imsi_bcd[0]) {
                ogs_gtp_xact_set_imsi(gtp_xact, sgwc_ue->imsi_bcd);
                ogs_trace_packet(sgwc_ue->imsi_bcd, "gtp", "rx",
                        recvbuf->data, recvbuf->len);
                ogs_trace_packet_bind_rx(NULL, NULL, 0);
            }
            sgwc_s11_handle_create_session_request(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE:
            sgwc_s11_handle_modify_bearer_request(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_DELETE_SESSION_REQUEST_TYPE:
            sgwc_s11_handle_delete_session_request(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_CREATE_BEARER_RESPONSE_TYPE:
            if (!gtp_message.h.teid_presence) ogs_error("No TEID");
            sgwc_s11_handle_create_bearer_response(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_UPDATE_BEARER_RESPONSE_TYPE:
            if (!gtp_message.h.teid_presence) ogs_error("No TEID");
            sgwc_s11_handle_update_bearer_response(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_DELETE_BEARER_RESPONSE_TYPE:
            if (!gtp_message.h.teid_presence) ogs_error("No TEID");
            sgwc_s11_handle_delete_bearer_response(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_RELEASE_ACCESS_BEARERS_REQUEST_TYPE:
            sgwc_s11_handle_release_access_bearers_request(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE_TYPE:
            sgwc_s11_handle_downlink_data_notification_ack(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
            sgwc_s11_handle_create_indirect_data_forwarding_tunnel_request(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
            sgwc_s11_handle_delete_indirect_data_forwarding_tunnel_request(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_BEARER_RESOURCE_COMMAND_TYPE:
            sgwc_s11_handle_bearer_resource_command(
                    sgwc_ue, gtp_xact, recvbuf, &gtp_message);
            break;
        default:
            ogs_warn("Not implemented(type:%d)", gtp_message.h.type);
            break;
        }
        ogs_pkbuf_free(recvbuf);
        break;

    case SGWC_EVT_GN_MESSAGE:
        ogs_assert(e);
        recvbuf = e->pkbuf;
        ogs_assert(recvbuf);

        gnode = e->gnode;
        ogs_assert(gnode);

        if (sgwc_gn_handle_known_request(gnode, recvbuf)) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        if (ogs_gtp1_parse_msg(&gtp1_message, recvbuf) != OGS_OK) {
            ogs_error("ogs_gtp1_parse_msg() failed");
            ogs_pkbuf_free(recvbuf);
            break;
        }

        /* Foreign-shard session: bounce BEFORE creating the per-shard
         * xact. rehome takes the pkbuf; do not free it here. */
        if (sgwc_worker_rehome_gtp1(e, &gtp1_message))
            break;

        if (gtp1_message.h.teid != 0)
            sess = sgwc_sess_find_by_teid(gtp1_message.h.teid);

        rv = ogs_gtp1_xact_receive(gnode, &gtp1_message.h, &gtp_xact);
        if (rv == OGS_RETRY) {
            ogs_debug("Gn GTP duplicate request ignored (type=%u)",
                    gtp1_message.h.type);
            ogs_pkbuf_free(recvbuf);
            break;
        }
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        if (!sgwc_ue && sess)
            sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);

        if (gtp1_message.h.type == OGS_GTP1_CREATE_PDP_CONTEXT_REQUEST_TYPE &&
                gtp1_message.h.teid == 0 &&
                gtp1_message.create_pdp_context_request.imsi.presence &&
                gtp1_message.create_pdp_context_request.imsi.data &&
                gtp1_message.create_pdp_context_request.imsi.len > 0) {
            sgwc_ue = sgwc_ue_find_by_imsi(
                    gtp1_message.create_pdp_context_request.imsi.data,
                    gtp1_message.create_pdp_context_request.imsi.len);
        }

        if (sgwc_ue)
            OGS_SETUP_GTP_NODE(sgwc_ue, gnode);

        switch (gtp1_message.h.type) {
        case OGS_GTP1_ECHO_REQUEST_TYPE:
            sgwc_gn_handle_echo_request(gtp_xact, &gtp1_message.echo_request);
            break;
        case OGS_GTP1_ECHO_RESPONSE_TYPE:
            ogs_debug("[SGW] Gn Echo Response received");
            break;
        case OGS_GTP1_CREATE_PDP_CONTEXT_REQUEST_TYPE:
            sgwc_gn_handle_create_pdp_context_request(
                    sgwc_ue, gtp_xact, recvbuf, &gtp1_message);
            break;
        case OGS_GTP1_DELETE_PDP_CONTEXT_REQUEST_TYPE:
            sgwc_gn_handle_delete_pdp_context_request(
                    sgwc_ue, sess, gtp_xact, recvbuf, &gtp1_message);
            break;
        case OGS_GTP1_UPDATE_PDP_CONTEXT_REQUEST_TYPE:
            sgwc_gn_handle_update_pdp_context_request(
                    sgwc_ue, sess, gtp_xact, recvbuf, &gtp1_message);
            break;
        default:
            ogs_warn("Gn not implemented(type:%d)", gtp1_message.h.type);
            break;
        }
        ogs_pkbuf_free(recvbuf);
        break;

    case SGWC_EVT_S5C_MESSAGE:
        ogs_assert(e);
        recvbuf = e->pkbuf;
        ogs_assert(recvbuf);

        if (ogs_gtp2_parse_msg(&gtp_message, recvbuf) != OGS_OK) {
            ogs_error("ogs_gtp2_parse_msg() failed");
            ogs_pkbuf_free(recvbuf);
            break;
        }

        gnode = e->gnode;
        ogs_assert(gnode);

        /* Foreign-shard session (e.g. truncated S5 TEID routed to
         * main): bounce BEFORE creating the per-shard xact. */
        if (sgwc_worker_rehome_gtp2(e, &gtp_message))
            break;

        rv = ogs_gtp_xact_receive(gnode, &gtp_message.h, &gtp_xact);
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        sgwc_s5_check_peer_recovery(gnode, &gtp_message);

        if (gtp_message.h.teid_presence && gtp_message.h.teid != 0)
            sess = sgwc_sess_find_by_teid(gtp_message.h.teid);

        if (!sess && gtp_xact->local_teid) /* rx no TEID or TEID=0 */
            /* 3GPP TS 29.274 5.5.2: we receive TEID=0 under some
             * conditions, such as cause "Session context not found". In those
             * cases, we still want to identify the local session which
             * originated the message, so try harder by using the TEID we
             * locally stored in xact when sending the original request: */
            sess = sgwc_sess_find_by_teid(gtp_xact->local_teid);

        switch(gtp_message.h.type) {
        case OGS_GTP2_ECHO_REQUEST_TYPE:
            sgwc_handle_echo_request(gtp_xact, &gtp_message.echo_request);
            break;
        case OGS_GTP2_ECHO_RESPONSE_TYPE:
            sgwc_handle_echo_response(gtp_xact, &gtp_message.echo_response);
            break;
        case OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE:
            if (!gtp_message.h.teid_presence) ogs_error("No TEID");
            sgwc_s5c_handle_create_session_response(
                    sess, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_MODIFY_BEARER_RESPONSE_TYPE:
            if (!gtp_message.h.teid_presence) ogs_error("No TEID");
            sgwc_s5c_handle_modify_bearer_response(
                    sess, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE:
            if (!gtp_message.h.teid_presence) ogs_error("No TEID");
            sgwc_s5c_handle_delete_session_response(
                    sess, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_CREATE_BEARER_REQUEST_TYPE:
            sgwc_s5c_handle_create_bearer_request(
                    sess, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_UPDATE_BEARER_REQUEST_TYPE:
            sgwc_s5c_handle_update_bearer_request(
                    sess, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_DELETE_BEARER_REQUEST_TYPE:
            sgwc_s5c_handle_delete_bearer_request(
                    sess, gtp_xact, recvbuf, &gtp_message);
            break;
        case OGS_GTP2_BEARER_RESOURCE_FAILURE_INDICATION_TYPE:
            if (!gtp_message.h.teid_presence) ogs_error("No TEID");
            sgwc_s5c_handle_bearer_resource_failure_indication(
                    sess, gtp_xact, recvbuf, &gtp_message);
            break;
        default:
            ogs_warn("Not implemented(type:%d)", gtp_message.h.type);
            break;
        }
        ogs_pkbuf_free(recvbuf);
        break;
    case SGWC_EVT_PEER_ECHO_SETUP:
        /* Workers must not touch main timer_mgr; finish echo setup here. */
        if (ogs_worker_self()) {
            ogs_error("SGWC_EVT_PEER_ECHO_SETUP delivered to worker");
            break;
        }
        if (!e->gnode) {
            ogs_error("SGWC_EVT_PEER_ECHO_SETUP: no gnode");
            break;
        }
        sgwc_peer_echo_setup_on_main(e->gnode, e->timer_id);
        break;

    case SGWC_EVT_CONFIG_RELOAD:
        /* Context is process-global: main applies the reload once for
         * every shard (list swaps happen under sgwc_ctx_lock). */
        if (ogs_worker_self()) {
            ogs_error("SGWC_EVT_CONFIG_RELOAD delivered to worker");
            break;
        }
        sgwc_context_reload_runtime();
        break;

    case SGWC_EVT_ADMIN_MAINTENANCE_ENABLE:
        /* Context is shared: one write is visible to every shard. */
        sgwc_self()->maintenance_mode = true;
        ogs_info("admin maintenance: enabled");
        break;

    case SGWC_EVT_ADMIN_MAINTENANCE_DISABLE:
        sgwc_self()->maintenance_mode = false;
        ogs_info("admin maintenance: disabled");
        break;

    case SGWC_EVT_ADMIN_MAINTENANCE_DRAIN:
        sgwc_self()->maintenance_mode = true;
        if (!ogs_worker_self()) {
            /* Main opens the round, then every shard (main included)
             * steps through the UEs it owns. */
            sgwc_admin_drain_round_start(e->admin_force ? true : false);
            if (sgwc_workers_active())
                sgwc_event_fanout_workers(SGWC_EVT_ADMIN_MAINTENANCE_DRAIN,
                        e->admin_force);
        }
        sgwc_admin_drain_begin();
        break;

    case SGWC_EVT_ADMIN_DETACH_SESSION:
        if (e->admin_imsi_bcd[0])
            sgwc_ue = sgwc_ue_find_by_imsi_bcd(e->admin_imsi_bcd);
        else
            sgwc_ue = sgwc_ue_find_by_id(e->sgwc_ue_id);
        if (sgwc_ue) {
            ogs_info("admin session detach: imsi=%s mode=%s",
                    sgwc_ue->imsi_bcd,
                    e->admin_force ? "force" : "graceful");
            sgwc_admin_detach_ue_sessions(sgwc_ue, e->admin_force);
        } else {
            ogs_warn("admin session detach: UE already gone");
        }
        break;

    case SGWC_EVT_ADMIN_DETACH_SESS_ONE: {
        sgwc_sess_t *sess = sgwc_sess_find_by_id(e->admin_sess_id);
        if (sess) {
            sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
            ogs_info("admin session delete: imsi=%s apn=%s mode=%s",
                    sgwc_ue ? sgwc_ue->imsi_bcd : "-",
                    sess->session.name,
                    e->admin_force ? "force" : "graceful");

            /* Always notify MME via Delete Bearer Request (§5.4.4). */
            if (sgwc_ue)
                sgwc_gtp_send_delete_bearer_request_to_mme(
                        sgwc_ue, sess, OGS_INVALID_POOL_ID);

            if (e->admin_force) {
                /*
                 * Force: tear down downstream (SGW-U + SMF) and remove
                 * locally immediately. The Delete Bearer Request above is
                 * fire-and-forget; if MME responds after the session is
                 * gone, the response handler handles the missing context
                 * gracefully.
                 */
                sgwc_sess_abort_create(sess);
                if (sgwc_ue)
                    sgwc_ue_remove_if_empty(sgwc_ue);
            } else {
                /* Graceful: send signalling, keep local context for responses */
                if (sess->pfcp_node && sess->sgwu_sxa_seid)
                    sgwc_pfcp_send_session_deletion_request(
                            sess, OGS_INVALID_POOL_ID, NULL);
                if (sess->gnode)
                    sgwc_gtp_send_s5c_delete_session_request(sess);
                /*
                 * Local context stays alive; cleanup cascades via the
                 * Delete Bearer Response → PFCP deletion → sxa cleanup path.
                 */
            }
        } else {
            ogs_warn("admin session delete: session already gone");
        }
        break;
    }

    case SGWC_EVT_ADMIN_PURGE_ORPHANS: {
        int purged = 0, remaining;

        /* Every shard purges its own orphans; main also sweeps below. */
        if (!ogs_worker_self() && sgwc_workers_active())
            sgwc_event_fanout_workers(SGWC_EVT_ADMIN_PURGE_ORPHANS, 0);
        /*
         * Admin-triggered purge. Reuse the shared sweep with the same grace as
         * the periodic task so a manual purge never aborts an attach that is
         * still in flight. The grace keeps freshly created sessions (which
         * legitimately have sgwu_sxa_seid==0 / not yet metrics-counted) alive.
         */
        remaining = sgwc_orphan_sweep(true,
                ogs_time_from_sec(sgwc_self()->orphan.grace_s), &purged);
        ogs_info("admin purge-orphans: removed %d session(s), "
                 "%d orphan(s) remaining on this shard", purged, remaining);
        break;
    }

    case SGWC_EVT_ADMIN_PURGE_SEID:
        ogs_info("admin purge-seid: SGW-U SEID=0x%llx",
                (unsigned long long)e->admin_seid);
        if (sgwc_pfcp_purge_seid(e->admin_upf_addr, e->admin_seid) != OGS_OK)
            ogs_error("admin purge-seid: failed for SEID=0x%llx",
                    (unsigned long long)e->admin_seid);
        break;

    case SGWC_EVT_ORPHAN_SWEEP: {
        int purged = 0, remaining;

        /* Main's timer drives the round: fan a copy to every worker,
         * then sweep the main-owned shard below. */
        if (!ogs_worker_self() && sgwc_workers_active())
            sgwc_event_fanout_workers(SGWC_EVT_ORPHAN_SWEEP, 0);

        remaining = sgwc_orphan_sweep(sgwc_self()->orphan.purge,
                ogs_time_from_sec(sgwc_self()->orphan.grace_s), &purged);

        if (purged)
            ogs_warn("orphan sweep: purged %d session(s), %d remaining",
                    purged, remaining);
        else
            ogs_debug("orphan sweep: %d orphan(s)", remaining);

        /* Re-arm for the next interval (timer is one-shot, main only). */
        if (!ogs_worker_self() &&
                sgwc_self()->orphan.enabled && sgwc_self()->orphan.t_sweep)
            ogs_timer_start(sgwc_self()->orphan.t_sweep,
                    ogs_time_from_sec(sgwc_self()->orphan.interval_s));
        break;
    }

    case SGWC_EVT_BUFFER_IDLE_SWEEP: {
        int dropped = 0, remaining;

        if (!ogs_worker_self() && sgwc_workers_active())
            sgwc_event_fanout_workers(SGWC_EVT_BUFFER_IDLE_SWEEP, 0);

        remaining = sgwc_buffer_idle_sweep(&dropped);
        if (dropped)
            ogs_warn("buffer_idle sweep: DROPped %d session(s), "
                    "%d still buffering on this shard",
                    dropped, remaining);
        else
            ogs_debug("buffer_idle sweep: %d session(s) buffering", remaining);

        if (!ogs_worker_self() &&
                sgwc_self()->buffer_idle.enabled &&
                sgwc_self()->buffer_idle.t_sweep)
            ogs_timer_start(sgwc_self()->buffer_idle.t_sweep,
                    ogs_time_from_sec(sgwc_self()->buffer_idle.interval_s));
        break;
    }

    case SGWC_EVT_PEER_RESTART_PURGE:
        if (!e->gnode) {
            ogs_error("SGWC_EVT_PEER_RESTART_PURGE: no gnode");
            break;
        }
        sgwc_peer_restart_purge_owned(e->gnode, e->timer_id);
        break;

    case SGWC_EVT_SXA_RESTORE:
        if (!e->pfcp_node) {
            ogs_error("SGWC_EVT_SXA_RESTORE: no pfcp_node");
            break;
        }
        sgwc_pfcp_restoration_owned(e->pfcp_node);
        break;

    default:
        ogs_error("No handler for event %s", sgwc_event_get_name(e));
        break;
    }
}
