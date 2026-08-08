/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Pretty-Trace passive EPC/5GC probe — shared types.
 */

#if !defined(PTRACE_H)
#define PTRACE_H

#include "ogs-app.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PTRACE_MAX_IFACES           16
#define PTRACE_MAX_WORKERS          32
#define PTRACE_MAX_DEV_LEN          64
#define PTRACE_MAX_PATH_LEN         256
#define PTRACE_MAX_ID_LEN           32
#define PTRACE_MAX_MSG_LEN          64
#define PTRACE_MAX_APN_LEN          64
#define PTRACE_MAX_REF_LEN          128
#define PTRACE_MAX_FIELDS_LEN       512
#define PTRACE_MAX_PACKET           8192
#define PTRACE_MAX_EVENTS_PER_PKT   8
#define PTRACE_ID_POOL_SIZE         16384
#define PTRACE_UE_IDLE_SEC          600
#define PTRACE_UE_NO_IMSI_IDLE_SEC  120
#define PTRACE_MAX_UE_TEIDS         16
#define PTRACE_MAX_UE_SEIDS         8
#define PTRACE_MAX_UE_IPS           8
#define PTRACE_MAX_UE_SESSIONS      8
#define PTRACE_MAX_PDN_SESSIONS     8
#define PTRACE_MAX_SESSION_LEN      128
#define PTRACE_SESS_STALE_SEC       120
#define PTRACE_MAX_RULES            256
#define PTRACE_MAX_TRACES           128
#define PTRACE_MAX_TIMELINE         512
#define PTRACE_MAX_PCAP_REFS        4096
#define PTRACE_MAX_JSON             65536

typedef enum {
    PTRACE_ROLE_UNKNOWN = 0,
    PTRACE_ROLE_S1MME,
    PTRACE_ROLE_S1U,
    PTRACE_ROLE_S11,
    PTRACE_ROLE_S5,
    PTRACE_ROLE_S8,
    PTRACE_ROLE_N3,
    PTRACE_ROLE_N4,
    PTRACE_ROLE_DIAMETER,
} ptrace_role_e;

typedef enum {
    PTRACE_PROTO_UNKNOWN = 0,
    PTRACE_PROTO_S1AP,
    PTRACE_PROTO_NAS,
    PTRACE_PROTO_GTPC,
    PTRACE_PROTO_GTPU,
    PTRACE_PROTO_PFCP,
    PTRACE_PROTO_DIAMETER,
} ptrace_proto_e;

typedef enum {
    PTRACE_BACKEND_PCAP = 0,
    PTRACE_BACKEND_AFPACKET,
    PTRACE_BACKEND_PFRING,
    PTRACE_BACKEND_DPDK,
} ptrace_backend_e;

typedef struct ptrace_ids_s {
    char imsi[PTRACE_MAX_ID_LEN];
    char msisdn[PTRACE_MAX_ID_LEN];
    char imei[PTRACE_MAX_ID_LEN];
    char guti[PTRACE_MAX_ID_LEN];
    char m_tmsi[PTRACE_MAX_ID_LEN];
    char ue_ip[PTRACE_MAX_ID_LEN];
    char apn[PTRACE_MAX_APN_LEN];
    char session_id[PTRACE_MAX_SESSION_LEN];
    uint32_t teid;
    uint32_t teids[PTRACE_MAX_UE_TEIDS];
    int num_teids;
    uint64_t seid;
    uint32_t enb_ue_s1ap_id;
    uint32_t mme_ue_s1ap_id;
    uint16_t tac;
    uint32_t cell_id;
    uint8_t bearer_id;
    uint32_t diam_hbh;
    bool has_teid;
    bool has_seid;
    bool has_enb_ue_s1ap_id;
    bool has_mme_ue_s1ap_id;
    bool has_tac;
    bool has_cell_id;
    bool has_bearer_id;
    bool has_diam_hbh;
} ptrace_ids_t;

typedef struct ptrace_packet_s {
    ogs_lnode_t lnode;
    ogs_time_t ts;              /* usec */
    ptrace_role_e role;
    char iface[PTRACE_MAX_DEV_LEN];
    uint16_t len;
    uint8_t data[PTRACE_MAX_PACKET];
    char packet_ref[PTRACE_MAX_REF_LEN];
} ptrace_packet_t;

/* Compact identity event — no full frame copy. */
typedef struct ptrace_id_event_s {
    ogs_lnode_t lnode;
    ogs_time_t ts;
    ptrace_proto_e protocol;
    ptrace_role_e role;
    char message[PTRACE_MAX_MSG_LEN];
    char src_ip[PTRACE_MAX_ID_LEN];
    char dst_ip[PTRACE_MAX_ID_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    ptrace_ids_t ids;
    char packet_ref[PTRACE_MAX_REF_LEN];
    uint16_t raw_len;
} ptrace_id_event_t;

typedef struct ptrace_event_s {
    ogs_lnode_t lnode;
    uint64_t id;
    ogs_time_t ts;
    ptrace_proto_e protocol;
    ptrace_role_e role;
    char message[PTRACE_MAX_MSG_LEN];
    uint8_t msg_type;
    uint32_t cause_code;
    char cause[PTRACE_MAX_MSG_LEN];
    char src_ip[PTRACE_MAX_ID_LEN];
    char dst_ip[PTRACE_MAX_ID_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    ptrace_ids_t ids;
    char fields[PTRACE_MAX_FIELDS_LEN];
    char packet_ref[PTRACE_MAX_REF_LEN];
    uint16_t raw_len;
    uint64_t ue_id;             /* correlated UE root (0 = unknown) */
} ptrace_event_t;

typedef struct ptrace_iface_s {
    char dev[PTRACE_MAX_DEV_LEN];
    ptrace_role_e role;
} ptrace_iface_t;

static inline const char *ptrace_role_str(ptrace_role_e role)
{
    switch (role) {
    case PTRACE_ROLE_S1MME: return "s1mme";
    case PTRACE_ROLE_S1U: return "s1u";
    case PTRACE_ROLE_S11: return "s11";
    case PTRACE_ROLE_S5: return "s5";
    case PTRACE_ROLE_S8: return "s8";
    case PTRACE_ROLE_N3: return "n3";
    case PTRACE_ROLE_N4: return "n4";
    case PTRACE_ROLE_DIAMETER: return "diameter";
    default: return "unknown";
    }
}

static inline const char *ptrace_proto_str(ptrace_proto_e p)
{
    switch (p) {
    case PTRACE_PROTO_S1AP: return "s1ap";
    case PTRACE_PROTO_NAS: return "nas";
    case PTRACE_PROTO_GTPC: return "gtpc";
    case PTRACE_PROTO_GTPU: return "gtpu";
    case PTRACE_PROTO_PFCP: return "pfcp";
    case PTRACE_PROTO_DIAMETER: return "diameter";
    default: return "unknown";
    }
}

static inline ptrace_role_e ptrace_role_parse(const char *s)
{
    if (!s) return PTRACE_ROLE_UNKNOWN;
    if (!strcmp(s, "s1mme")) return PTRACE_ROLE_S1MME;
    if (!strcmp(s, "s1u")) return PTRACE_ROLE_S1U;
    if (!strcmp(s, "s11")) return PTRACE_ROLE_S11;
    if (!strcmp(s, "s5")) return PTRACE_ROLE_S5;
    if (!strcmp(s, "s8")) return PTRACE_ROLE_S8;
    if (!strcmp(s, "n3")) return PTRACE_ROLE_N3;
    if (!strcmp(s, "n4")) return PTRACE_ROLE_N4;
    if (!strcmp(s, "diameter")) return PTRACE_ROLE_DIAMETER;
    return PTRACE_ROLE_UNKNOWN;
}

/* Record every TEID seen on a message (eNB + SGW S1-U, S11, S5, …). */
static inline void ptrace_ids_add_teid(ptrace_ids_t *ids, uint32_t teid)
{
    int i;
    if (!ids || !teid)
        return;
    ids->teid = teid;
    ids->has_teid = true;
    for (i = 0; i < ids->num_teids; i++) {
        if (ids->teids[i] == teid)
            return;
    }
    if (ids->num_teids < PTRACE_MAX_UE_TEIDS)
        ids->teids[ids->num_teids++] = teid;
}

static inline bool ptrace_ids_has_subscriber(const ptrace_ids_t *ids)
{
    if (!ids)
        return false;
    return ids->imsi[0] || ids->guti[0] || ids->msisdn[0] || ids->imei[0] ||
            ids->session_id[0];
}

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_H */
