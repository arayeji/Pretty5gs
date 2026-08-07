/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_CORRELATE_H)
#define PTRACE_CORRELATE_H

#include "ptrace.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    uint32_t enb_ue_s1ap_ids[4];
    int num_enb;
    uint32_t mme_ue_s1ap_ids[4];
    int num_mme;
    uint16_t tacs[4];
    int num_tac;
    char apn[PTRACE_MAX_APN_LEN];
    ogs_time_t last_seen;
} ptrace_ue_t;

int ptrace_correlate_init(void);
void ptrace_correlate_final(void);
uint64_t ptrace_correlate_event(ptrace_event_t *evt);
ptrace_ue_t *ptrace_correlate_find(const char *key);
int ptrace_correlate_ue_json(ptrace_ue_t *ue, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_CORRELATE_H */
