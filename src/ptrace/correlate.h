/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_CORRELATE_H)
#define PTRACE_CORRELATE_H

#include "ptrace.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PTRACE_SESS_ACTIVE = 0,
    PTRACE_SESS_STALE = 1,
    PTRACE_SESS_RELEASED = 2,
} ptrace_sess_state_e;

/* One PDN/PDU session under a UE (multi-APN, re-attach overlap). */
typedef struct ptrace_pdn_sess_s {
    uint64_t id;
    ptrace_sess_state_e state;
    char apn[PTRACE_MAX_APN_LEN];
    char ue_ip[PTRACE_MAX_ID_LEN];
    uint32_t teids[8];
    int num_teids;
    uint64_t seids[4];
    int num_seids;
    uint32_t enb_ue_s1ap_id;
    uint32_t mme_ue_s1ap_id;
    bool has_enb;
    bool has_mme;
    ogs_time_t created;
    ogs_time_t last_seen;
    ogs_time_t stale_until;
} ptrace_pdn_sess_t;

typedef struct ptrace_ue_s {
    ogs_lnode_t lnode;
    uint64_t ue_id;
    char imsi[PTRACE_MAX_ID_LEN];
    char msisdn[PTRACE_MAX_ID_LEN];
    char imei[PTRACE_MAX_ID_LEN];
    char guti[PTRACE_MAX_ID_LEN];
    char m_tmsi[PTRACE_MAX_ID_LEN];
    char ue_ips[PTRACE_MAX_UE_IPS][PTRACE_MAX_ID_LEN];
    int num_ue_ips;
    uint32_t teids[PTRACE_MAX_UE_TEIDS];
    int num_teids;
    uint64_t seids[PTRACE_MAX_UE_SEIDS];
    int num_seids;
    uint32_t enb_ue_s1ap_ids[8];
    int num_enb;
    uint32_t mme_ue_s1ap_ids[8];
    int num_mme;
    uint16_t tacs[4];
    int num_tac;
    char sessions[PTRACE_MAX_UE_SESSIONS][PTRACE_MAX_SESSION_LEN];
    int num_sessions;
    char apn[PTRACE_MAX_APN_LEN]; /* latest/primary APN (compat) */
    ptrace_pdn_sess_t pdn[PTRACE_MAX_PDN_SESSIONS];
    int num_pdn;
    ogs_time_t last_seen;
    /* After merge, drop nodes keep this redirect instead of being freed
     * so concurrent /ue and trace lookups cannot UAF. */
    struct ptrace_ue_s *canonical;
} ptrace_ue_t;

int ptrace_correlate_init(void);
void ptrace_correlate_final(void);
uint64_t ptrace_correlate_event(ptrace_event_t *evt);
ptrace_ue_t *ptrace_correlate_find(const char *key);
int ptrace_correlate_ue_count(void);
int ptrace_correlate_ue_json(ptrace_ue_t *ue, char *buf, size_t buflen);
bool ptrace_correlate_event_matches_ue(const ptrace_event_t *evt,
        const ptrace_ue_t *ue);
/* Evict idle roots: no-IMSI sooner, IMSI after cache window. */
int ptrace_correlate_expire(void);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_CORRELATE_H */
