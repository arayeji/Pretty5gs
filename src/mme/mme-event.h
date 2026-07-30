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

#ifndef MME_EVENT_H
#define MME_EVENT_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* forward declaration */
typedef enum {
    MME_EVENT_BASE = OGS_MAX_NUM_OF_PROTO_EVENT,

    MME_EVENT_S1AP_MESSAGE,
    MME_EVENT_S1AP_TIMER,
    MME_EVENT_S1AP_LO_ACCEPT,
    MME_EVENT_S1AP_LO_SCTP_COMM_UP,
    MME_EVENT_S1AP_LO_CONNREFUSED,
    /* RX worker confirmed poll removal: main may destroy e->sock */
    MME_EVENT_S1AP_RX_SOCK_CLOSED,
    /* RX worker could not watch e->sock (fd died in the accept->watch
     * race); main tears down the half-created eNB */
    MME_EVENT_S1AP_RX_WATCH_FAILED,
    /* TX worker finished encoding a downlink PDU (e->pkbuf, may be
     * NULL on encode failure); main sends it and flushes the eNB's
     * hold list (see s1ap-tx.c) */
    MME_EVENT_S1AP_TX_READY,
    /* IO thread confirmed it dropped every reference to e->sock
     * (write queue + POLLOUT). Main may destroy the socket once all
     * registered confirmations arrive (see s1ap-io.c close registry) */
    MME_EVENT_S1AP_IO_DRAINED,
    /*
     * IO thread heartbeat: e->sock's write queue is above the
     * congestion watermark, depth in e->io_wq_depth. Repeated once a
     * second while it lasts; main treats it as a short lease
     * (s1ap-overload.c). Safe to drop — the next one arrives in 1 s.
     */
    MME_EVENT_S1AP_IO_CONGESTED,

    MME_EVENT_EMM_MESSAGE,
    MME_EVENT_EMM_TIMER,
    MME_EVENT_ESM_MESSAGE,
    MME_EVENT_ESM_TIMER,
    MME_EVENT_S11_MESSAGE,
    MME_EVENT_S11_TIMER,
    MME_EVENT_S6A_MESSAGE,
    MME_EVENT_S6A_TIMER,

    MME_EVENT_SGSAP_MESSAGE,
    MME_EVENT_SGSAP_TIMER,
    MME_EVENT_SGSAP_LO_SCTP_COMM_UP,
    MME_EVENT_SGSAP_LO_CONNREFUSED,

    MME_EVENT_GN_MESSAGE,
    MME_EVENT_GN_TIMER,

    MME_EVENT_CONFIG_RELOAD,

    /*
     * Admin operations injected by the Prometheus HTTP admin
     * endpoints (POST /admin/...). The HTTP handler runs on the
     * MHD worker thread; posting these events bounces the actual
     * mutation to the MME main thread so we don't race S1AP
     * processing in mme_enb_t / mme_ue_t internals.
     */
    MME_EVENT_ADMIN_DETACH_ENB,
    MME_EVENT_ADMIN_DETACH_UE,
    MME_EVENT_ADMIN_PAGE_UE,
    /*
     * Silent local UE reclaim on the OWNER shard
     * (mme_ue_enter_ue_context_will_remove): posted by the orphan
     * sweep and the SGW-recovery purge, which run on other threads
     * and must not drive the UE FSM / mme_ue_remove themselves.
     */
    MME_EVENT_ADMIN_PURGE_UE,
    MME_EVENT_ADMIN_TAC_ADD,
    MME_EVENT_ADMIN_MAINTENANCE_ENABLE,
    MME_EVENT_ADMIN_MAINTENANCE_DISABLE,
    MME_EVENT_ADMIN_MAINTENANCE_DRAIN,

    MME_EVENT_ORPHAN_SWEEP,

    /*
     * S1AP procedure tail deferred to the UE owner shard
     * (mme.workers): everything that mutates shard-owned mme_ue /
     * bearer state or creates a GTP xact must run on the owner
     * thread — both to avoid the main-vs-shard write race and so
     * the S11 response routes back to the xact's shard.
     * e->ho_kind selects the tail.
     */
    MME_EVENT_S1AP_HO_TAIL,

    MAX_NUM_OF_MME_EVENT,

} mme_event_e;

/* MME_EVENT_S1AP_HO_TAIL discriminators (mme_event_t.ho_kind) */
#define MME_HO_TAIL_PATH_SWITCH     1
#define MME_HO_TAIL_HANDOVER_NOTIFY 2
#define MME_HO_TAIL_ICS_RSP         3
/*
 * UE Context Release Complete tail: the eNB-side bookkeeping
 * (enb_ue_remove, HO peer unlink) ran on main; the mme_ue-side
 * (mobile-reachable timer, will-remove, mme_ue_remove, indirect-tunnel
 * teardown, paging) runs here on the owner. e->enb_ue_id carries the
 * id of the ALREADY-REMOVED enb_ue (for stale-link comparison only —
 * never resolve it), e->rel_action the S1AP_UE_CTX_REL_* action and
 * e->rel_flags the MME_UE_REL_F_* bits.
 */
#define MME_HO_TAIL_UE_REL          4
/*
 * Release Access Bearers send bounced to the UE owner shard so the
 * xact — and therefore the S11 response with its CLEAR_ENB_S1U_PATH /
 * mobile-reachable tail — lives on the owner. e->enb_ue_id may name an
 * already-removed enb_ue (mass eNB release paths); e->rel_action is
 * the OGS_GTP_RELEASE_* action.
 */
#define MME_HO_TAIL_REL_AB          5

#define MME_UE_REL_F_HO_PEER_GONE   0x1

/*
 * MME_HO_TAIL_ICS_RSP payload, carried in e->pkbuf (freed with the
 * event). The E-RAB Setup items are snapshotted on main from the
 * decoded ASN.1 message; the owner shard applies them to the bearers
 * (bearer->enb_s1u_teid/ip are shard-owned; TSAN: ICS-Response vs
 * Create-Bearer-Request paging race).
 */
typedef struct mme_ics_rsp_erab_s {
    uint8_t     ebi;
    uint32_t    enb_s1u_teid;       /* host byte order */
    ogs_ip_t    enb_s1u_ip;
} mme_ics_rsp_erab_t;

typedef struct mme_ics_rsp_tail_s {
    bool        erab_present;       /* E_RABSetupListCtxtSURes IE present */
    int         num_of_erab;
    mme_ics_rsp_erab_t erab[];
} mme_ics_rsp_tail_t;

typedef long S1AP_ProcedureCode_t;
typedef struct S1AP_S1AP_PDU ogs_s1ap_message_t;
typedef struct ogs_nas_eps_message_s ogs_nas_eps_message_t;
typedef struct ogs_diam_s6a_message_s ogs_diam_s6a_message_t;
typedef struct mme_vlr_s mme_vlr_t;
typedef struct mme_enb_s mme_enb_t;
typedef struct enb_ue_s enb_ue_t;
typedef struct sgw_ue_s sgw_ue_t;
typedef struct mme_ue_s mme_ue_t;
typedef struct mme_sess_s mme_sess_t;
typedef struct mme_bearer_s mme_bearer_t;
typedef struct ogs_gtp_node_s ogs_gtp_node_t;

typedef struct mme_event_s {
    int id;
    int timer_id;

    ogs_pkbuf_t *pkbuf;

    ogs_sock_t *sock;
    ogs_sockaddr_t *addr;

    uint16_t max_num_of_istreams;
    uint16_t max_num_of_ostreams;

    S1AP_ProcedureCode_t s1ap_code;
    ogs_s1ap_message_t *s1ap_message;
    /* s1ap_message was heap-decoded by an S1AP RX worker; the main
     * loop skips its own decode and frees pdu+struct after dispatch */
    bool s1ap_rx_decoded;

    ogs_gtp_node_t *gnode;

    /* MME_EVENT_S1AP_TX_READY: SCTP stream for the encoded pkbuf */
    uint16_t tx_stream_no;

    /* MME_EVENT_S1AP_IO_CONGESTED: per-eNB write-queue depth */
    int io_wq_depth;

    uint8_t nas_type;
    int create_action;
    ogs_nas_eps_message_t *nas_message;

    /*
     * TAI/E-CGI snapshot taken on main from enb_ue->saved when the EMM
     * event is created (s1ap_send_to_nas). With mme.workers the owner
     * shard applies it to mme_ue; main must not write shard-owned UE
     * fields (TSAN: uplink-NAS vs attach-request location race).
     */
    ogs_eps_tai_t nas_tai;
    ogs_e_cgi_t nas_e_cgi;
    bool nas_location_present;

    ogs_diam_s6a_message_t *s6a_message;

    mme_vlr_t *vlr;
    ogs_pool_id_t enb_id;
    ogs_pool_id_t enb_ue_id;
    ogs_pool_id_t sgw_ue_id;
    ogs_pool_id_t mme_ue_id;
    ogs_pool_id_t bearer_id;
    ogs_pool_id_t gtp_xact_id;

    ogs_timer_t *timer;

    /*
     * Set on MME_EVENT_ADMIN_DETACH_* events to request the abrupt
     * cleanup path (no NAS Detach Request, no S1 Reset PDU). Comes
     * from ?force=1 on the admin HTTP endpoint. Default 0 ->
     * standard 3GPP detach signalling (UE/eNB are notified).
     */
    int admin_force;

    /* MME_EVENT_ADMIN_TAC_ADD: hot-add served TAI from admin watcher */
    char admin_mcc[4];
    char admin_mnc[4];
    int admin_tac;

    /* Set at creation; the dispatching thread turns it into queue lag */
    ogs_time_t created_at;

    /* MME_EVENT_S1AP_HO_TAIL: MME_HO_TAIL_* discriminator */
    int ho_kind;
    /* MME_HO_TAIL_UE_REL: S1AP_UE_CTX_REL_* action + MME_UE_REL_F_* */
    int rel_action;
    int rel_flags;

} mme_event_t;

OGS_STATIC_ASSERT(OGS_EVENT_SIZE >= sizeof(mme_event_t));

void mme_event_term(void);

/*
 * The mme_main() thread is the ONLY consumer of ogs_app()->queue. A
 * blocking ogs_queue_push() issued from that same thread (poll callback,
 * timer callback, signal handler) therefore waits on a drain that can
 * never happen: mme_main() stops polling, every socket it owns stops
 * being read, and the S11 UDP Recv-Q overflows until all GTP
 * transactions time out. Push through mme_queue_push_main() instead --
 * it never blocks the main thread and only retries briefly elsewhere.
 *
 * Returns OGS_OK (queued, pollset notified), OGS_RETRY (queue full,
 * caller must drop and free the event) or OGS_DONE (queue terminated).
 */
void mme_event_mark_main_thread(void);
bool mme_event_on_main_thread(void);
int mme_queue_push_main(void *event);

/*
 * S1AP CONNREFUSED side-channel: teardowns must not compete with a
 * full S1AP message queue. Init before RX/IO workers start; main
 * drains via mme_event_s1ap_connrefused_trypop() before the app queue.
 */
void mme_event_s1ap_connrefused_init(void);
void mme_event_s1ap_connrefused_final(void);
int mme_event_s1ap_connrefused_trypop(mme_event_t **e);

mme_event_t *mme_event_new(mme_event_e id);
void mme_event_free(mme_event_t *e);

/*
 * Event-queue lag: how long a dispatched event waited between creation and
 * dispatch. Timers whose budget is smaller than this are measuring the MME's
 * own backlog rather than the peer, so retransmitting on them is wrong.
 * Observed by every dispatching thread, read from anywhere.
 */
void mme_event_lag_observe(const mme_event_t *e);
ogs_time_t mme_event_lag(void);

/*
 * Drop queued events targeting a MME-UE that is being removed (main app
 * queue and, when mme.workers > 0, the owner shard queue).
 */
void mme_event_purge_mme_ue(ogs_pool_id_t mme_ue_id);

void mme_event_timeout(void *data);

const char *mme_event_get_name(mme_event_t *e);

/* Push a pre-decoded S1AP message from an RX worker. Takes ownership
 * of addr, pkbuf and pdu; main frees pdu after dispatch. */
void s1ap_event_push_decoded(void *sock, ogs_sockaddr_t *addr,
        ogs_pkbuf_t *pkbuf, ogs_s1ap_message_t *pdu);

void mme_sctp_event_push(mme_event_e id,
        void *sock, ogs_sockaddr_t *addr, ogs_pkbuf_t *pkbuf,
        uint16_t max_num_of_istreams, uint16_t max_num_of_ostreams);

/* IO thread -> main: TX congestion heartbeat for sock (see s1ap-io.c) */
void s1ap_io_congestion_event_push(void *sock, int wq_depth);

#ifdef __cplusplus
}
#endif

#endif /* MME_EVENT_H */
