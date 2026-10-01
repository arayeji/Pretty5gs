/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef SMF_EVENT_H
#define SMF_EVENT_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ogs_gtp_node_s ogs_gtp_node_t;
typedef struct ogs_gtp_xact_s ogs_gtp_xact_t;
typedef struct ogs_gtp1_message_s ogs_gtp1_message_t;
typedef struct ogs_gtp2_message_s ogs_gtp2_message_t;
typedef struct ogs_pfcp_node_s ogs_pfcp_node_t;
typedef struct ogs_pfcp_xact_s ogs_pfcp_xact_t;
typedef struct ogs_pfcp_message_s ogs_pfcp_message_t;
typedef struct ogs_diam_gx_message_s ogs_diam_gx_message_t;
typedef struct ogs_diam_gy_message_s ogs_diam_gy_message_t;
typedef struct ogs_diam_s6b_message_s ogs_diam_s6b_message_t;
typedef struct smf_sess_s smf_sess_t;
typedef struct smf_upf_s smf_upf_t;
typedef struct smf_gtp_node_s smf_gtp_node_t;
typedef struct ogs_nas_5gs_message_s ogs_nas_5gs_message_t;
typedef struct NGAP_NGAP_PDU ogs_ngap_message_t;
typedef long NGAP_ProcedureCode_t;

typedef enum {
    SMF_EVT_BASE = OGS_MAX_NUM_OF_PROTO_EVENT,

    SMF_EVT_S5C_MESSAGE,
    SMF_EVT_S6B_MESSAGE,
    SMF_EVT_GN_MESSAGE,
    SMF_EVT_GX_MESSAGE,
    SMF_EVT_GY_MESSAGE,
    SMF_EVT_GX_PEER_CONNECT,

    SMF_EVT_N4_MESSAGE,
    SMF_EVT_N4_TIMER,
    SMF_EVT_N4_NO_HEARTBEAT,
    SMF_EVT_N4_REASSOCIATE,

    SMF_EVT_NGAP_MESSAGE,
    SMF_EVT_NGAP_TIMER,

    SMF_EVT_5GSM_MESSAGE,
    SMF_EVT_5GSM_TIMER,

    SMF_EVT_SESSION_RELEASE,

    SMF_EVT_CONFIG_RELOAD,

    SMF_EVT_ADMIN_MAINTENANCE_ENABLE,
    SMF_EVT_ADMIN_MAINTENANCE_DISABLE,
    SMF_EVT_ADMIN_MAINTENANCE_DRAIN,
    SMF_EVT_ADMIN_DETACH_SESSION,
    SMF_EVT_ADMIN_DETACH_SESS_ONE,  /* one PDN/APN (admin_sess_id) */
    SMF_EVT_ADMIN_PURGE_SEID,       /* delete one stale UPF SEID (NMS audit) */

    SMF_EVT_ORPHAN_SWEEP,           /* periodic orphan metric + optional purge */

    /*
     * SMP cross-shard events (smf-workers.c). Fan-outs reach every shard
     * (workers + main); each acts only on the UEs it owns.
     */
    SMF_EVT_N4_RESTORE,             /* fan-out: pfcp_node, timer_id=kind */
    SMF_EVT_SGW_RESTART_PURGE,      /* fan-out: gnode restarted          */
    SMF_EVT_GX_RESTORE,             /* fan-out: Gx peer (re)connected    */
    SMF_EVT_ROUTER_SOLICIT,         /* to owner: sess_id, pkbuf=IPv6 RS  */
    SMF_EVT_RADIUS_POD,             /* to owner: sess_id                 */
    SMF_EVT_XSHARD_COLLISION,       /* to owner of old sess: release it  */
    SMF_EVT_MAIN_CALL,              /* to main: smf_main_call() record   */
    SMF_EVT_SBI_SEND,               /* to main: response for a stream    */

    SMF_EVT_TOP,

} smf_event_e;

typedef struct smf_event_s {
    ogs_event_t h;

    ogs_pkbuf_t *pkbuf;

    smf_gtp_node_t *gnode;
    ogs_pool_id_t gtp_xact_id;

    ogs_pfcp_node_t *pfcp_node;
    ogs_pool_id_t pfcp_xact_id;
    ogs_pfcp_message_t *pfcp_message;

    union {
        ogs_gtp1_message_t *gtp1_message;
        ogs_gtp2_message_t *gtp2_message;
    };

    union {
        ogs_diam_gx_message_t *gx_message;
        ogs_diam_gy_message_t *gy_message;
        ogs_diam_s6b_message_t *s6b_message;
    };

    struct {
        int type;
        ogs_ngap_message_t *message;
    } ngap;

    struct {
        uint8_t type;
        ogs_nas_5gs_message_t *message;
    } nas;

    struct {
        int trigger;
    } release;

    ogs_pool_id_t sess_id;

    /* SMF_EVT_ADMIN_MAINTENANCE_DRAIN / DETACH_*: 0=graceful, 1=force */
    int admin_force;
    ogs_pool_id_t smf_ue_id;
    /* SMF_EVT_ADMIN_DETACH_SESS_ONE: specific session */
    ogs_pool_id_t admin_sess_id;

    /* SMF_EVT_ADMIN_PURGE_SEID: raw UPF F-SEID to delete + optional UPF
     * address filter (NULL -> the single associated UPF peer). The handler
     * owns and frees admin_upf_addr. */
    uint64_t admin_seid;
    ogs_sockaddr_t *admin_upf_addr;

    /*
     * SMF_EVT_XSHARD_COLLISION: shard that parked the new request and
     * wants the old session gone (reply target), 0 = main.
     */
    int reply_shard;
    /* S5C CSR already went through the cross-shard collision handshake. */
    bool xshard_done;

    /*
     * SMF_EVT_SGW_RESTART_PURGE: only sessions created at or before this
     * wall-clock time are purged (a fresh session from the restarted SGW
     * may already exist when a shard dequeues its copy).
     */
    ogs_time_t cutoff;

    /* Monotonic enqueue time for the event-lag estimator; 0 = unknown. */
    ogs_time_t created_at;

    /*
     * PACKET RX dump bound by the receiving thread, re-bound by the
     * thread that dispatches the event. NULL unless a trace filter is on.
     */
    struct smf_event_trace_rx_s *trace_rx;

    /*
     * SBI event handed by main to the 5GC session owner (sbi-relay.c).
     * The worker owns h.sbi.request (a copy) / h.sbi.response; main has
     * already done the xact part, sbi_stream_id is its assoc stream.
     */
    bool sbi_relayed;
    ogs_pool_id_t sbi_stream_id;
} smf_event_t;

OGS_STATIC_ASSERT(OGS_EVENT_SIZE >= sizeof(smf_event_t));

smf_event_t *smf_event_new(int id);
/* Frees the event and any pkbuf / PFCP message / admin address it owns. */
void smf_event_free(smf_event_t *e);

/*
 * SMP delivery (all non-blocking; each frees the event on failure):
 *  - push_main:  main app queue (trypush + pollset wake).
 *  - push_local: the calling thread's own queue (worker or main).
 */
int smf_event_push_main(smf_event_t *e);
int smf_event_push_local(smf_event_t *e);

void smf_event_lag_observe(const smf_event_t *e);
ogs_time_t smf_event_lag(void);

/* Move this thread's ogs_trace_packet_bind_rx() buffer into the event. */
void smf_event_trace_rx_capture(smf_event_t *e);
/* On the dispatching thread: re-bind (and release) the captured buffer. */
void smf_event_trace_rx_restore(smf_event_t *e);

const char *smf_event_get_name(smf_event_t *e);

#ifdef __cplusplus
}
#endif

#endif /* SMF_EVENT_H */
