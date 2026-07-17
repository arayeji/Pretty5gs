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

#ifndef SGWC_EVENT_H
#define SGWC_EVENT_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ogs_gtp_node_s ogs_gtp_node_t;
typedef struct ogs_gtp2_message_s ogs_gtp2_message_t;
typedef struct ogs_gtp1_message_s ogs_gtp1_message_t;
typedef struct ogs_pfcp_node_s ogs_pfcp_node_t;
typedef struct ogs_pfcp_xact_s ogs_pfcp_xact_t;
typedef struct ogs_pfcp_message_s ogs_pfcp_message_t;
typedef struct sgwc_bearer_s sgwc_bearer_t;

typedef enum {
    SGWC_EVT_BASE = OGS_MAX_NUM_OF_PROTO_EVENT,

    SGWC_EVT_S11_MESSAGE,
    SGWC_EVT_S5C_MESSAGE,
    SGWC_EVT_GN_MESSAGE,

    SGWC_EVT_SXA_MESSAGE,
    SGWC_EVT_SXA_TIMER,
    SGWC_EVT_SXA_NO_HEARTBEAT,
    SGWC_EVT_SXA_REASSOCIATE,

    SGWC_EVT_CONFIG_RELOAD,

    SGWC_EVT_ADMIN_MAINTENANCE_ENABLE,
    SGWC_EVT_ADMIN_MAINTENANCE_DISABLE,
    SGWC_EVT_ADMIN_MAINTENANCE_DRAIN,
    SGWC_EVT_ADMIN_DETACH_SESSION,
    SGWC_EVT_ADMIN_DETACH_SESS_ONE,   /* detach one specific session (sgwc_sess_id) */
    SGWC_EVT_ADMIN_PURGE_ORPHANS,     /* delete all orphan sessions                 */
    SGWC_EVT_ADMIN_PURGE_SEID,        /* delete one stale SGW-U SEID (NMS audit)    */

    SGWC_EVT_ORPHAN_SWEEP,            /* periodic orphan metric + optional purge    */

    /* Worker deferred: create GTP peer echo timer on main timer_mgr (e->gnode). */
    SGWC_EVT_PEER_ECHO_SETUP,

    /* Peer restart (recovery counter advanced): each thread purges the
     * sessions IT OWNS toward that peer (e->gnode, e->timer_id = kind). */
    SGWC_EVT_PEER_RESTART_PURGE,

    /* PFCP association re-established with restoration_required: each
     * thread re-establishes ITS OWN sessions on that SGW-U (e->pfcp_node). */
    SGWC_EVT_SXA_RESTORE,

    SGWC_EVT_TOP,

} sgwc_event_e;

typedef struct sgwc_event_s {
    int id;
    int timer_id;

    ogs_pkbuf_t *pkbuf;

    ogs_gtp_node_t *gnode;
    ogs_gtp2_message_t *gtp_message;
    ogs_gtp1_message_t *gtp1_message;

    ogs_pfcp_node_t *pfcp_node;
    ogs_pool_id_t pfcp_xact_id;
    ogs_pfcp_message_t *pfcp_message;

    /* SGWC_EVT_ADMIN_MAINTENANCE_DRAIN / DETACH_SESSION: 0=graceful, 1=force */
    int admin_force;
    ogs_pool_id_t sgwc_ue_id;
    ogs_pool_id_t admin_sess_id;  /* SGWC_EVT_ADMIN_DETACH_SESS_ONE: specific session */
    char admin_imsi_bcd[OGS_MAX_IMSI_BCD_LEN + 1]; /* shard-routed detach */

    /* SGWC_EVT_ADMIN_PURGE_SEID: raw SGW-U F-SEID to delete + optional
     * SGW-U address filter (NULL -> the single associated SGW-U peer). */
    uint64_t admin_seid;
    ogs_sockaddr_t *admin_upf_addr;
} sgwc_event_t;

OGS_STATIC_ASSERT(OGS_EVENT_SIZE >= sizeof(sgwc_event_t));

void sgwc_event_init(void);
void sgwc_event_term(void);
void sgwc_event_final(void);

sgwc_event_t *sgwc_event_new(sgwc_event_e id);
void sgwc_event_free(sgwc_event_t *e);

/* Deliver an event to the calling thread's own loop: the current SMP
 * worker's queue, or the app queue on the main thread. Frees the event
 * and returns the push result on failure. */
int sgwc_event_push_local(sgwc_event_t *e);

const char *sgwc_event_get_name(sgwc_event_t *e);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_EVENT_H */
