/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Active trace targets only — no global UE table.
 * Per-target session keys (TEID/HBH/GUTI/…) stitch follow-ups.
 */

#if !defined(PTRACE_TARGET_H)
#define PTRACE_TARGET_H

#include "ptrace.h"
#include "correlate.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PTRACE_MAX_TARGETS          64
#define PTRACE_TARGET_MAX_TEIDS     16
#define PTRACE_TARGET_MAX_HBH       16
#define PTRACE_TARGET_MAX_SEIDS     8
#define PTRACE_TARGET_MAX_SESS      8
#define PTRACE_TARGET_DEFAULT_SEC   600

typedef struct ptrace_target_s {
    ogs_lnode_t lnode;
    uint64_t id;                /* used as evt->ue_id / cache pin */
    char imsi[PTRACE_MAX_ID_LEN];
    char msisdn[PTRACE_MAX_ID_LEN];
    char imei[PTRACE_MAX_ID_LEN];
    char guti[PTRACE_MAX_ID_LEN];
    char m_tmsi[PTRACE_MAX_ID_LEN];
    char ue_ips[PTRACE_MAX_UE_IPS][PTRACE_MAX_ID_LEN];
    int num_ue_ips;
    char sessions[PTRACE_TARGET_MAX_SESS][PTRACE_MAX_SESSION_LEN];
    int num_sessions;
    uint32_t teids[PTRACE_TARGET_MAX_TEIDS];
    int num_teids;
    uint64_t seids[PTRACE_TARGET_MAX_SEIDS];
    int num_seids;
    uint32_t hbhs[PTRACE_TARGET_MAX_HBH];
    int num_hbhs;
    ogs_time_t created;
    ogs_time_t until;
    ogs_time_t last_seen;
    bool active;
    /* API-compatible UE view (points at this target's fields). */
    ptrace_ue_t ue;
} ptrace_target_t;

int ptrace_target_init(void);
void ptrace_target_final(void);

/* Activate / refresh a target by IMSI, MSISDN, or IMEI digits. */
ptrace_target_t *ptrace_target_activate(const char *key, int duration_sec);
bool ptrace_target_deactivate(const char *key);
ptrace_target_t *ptrace_target_find(const char *key);
int ptrace_target_count(void);
bool ptrace_target_any_active(void);

/* Hot path: true if ids belong to an active target; learns session keys. */
uint64_t ptrace_target_match_learn(ptrace_ids_t *ids, ogs_time_t ts);

/* Expire finished targets. */
int ptrace_target_expire(void);

/* Fill ptrace_ue_t view for JSON (ue points into target — do not free). */
ptrace_ue_t *ptrace_target_ue(ptrace_target_t *t);
int ptrace_target_ue_json(ptrace_target_t *t, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_TARGET_H */
