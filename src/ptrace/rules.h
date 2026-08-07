/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_RULES_H)
#define PTRACE_RULES_H

#include "ptrace.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ptrace_rule_s {
    ogs_lnode_t lnode;
    char id[PTRACE_MAX_ID_LEN];
    char imsi[PTRACE_MAX_ID_LEN];
    char msisdn[PTRACE_MAX_ID_LEN];
    char imei[PTRACE_MAX_ID_LEN];
    char ue_ip[PTRACE_MAX_ID_LEN];
    uint32_t teid;
    uint64_t seid;
    uint16_t tac;
    uint32_t cell_id;
    bool has_teid;
    bool has_seid;
    bool has_tac;
    bool has_cell;
    bool capture_full_packet;
    ogs_time_t expires;
} ptrace_rule_t;

int ptrace_rules_init(void);
void ptrace_rules_final(void);
ptrace_rule_t *ptrace_rules_add(ptrace_rule_t *in);
bool ptrace_rules_delete(const char *id);
ptrace_rule_t *ptrace_rules_get(const char *id);
ptrace_rule_t *ptrace_rules_match(const ptrace_event_t *evt);
void ptrace_rules_expire(void);
int ptrace_rules_json(char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_RULES_H */
