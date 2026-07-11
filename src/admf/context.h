/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(ADMF_CONTEXT_H)
#define ADMF_CONTEXT_H

#include "ogs-li.h"
#include "ogs-app.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ADMF_MAX_X1_PEERS   8

typedef struct admf_x1_peer_s {
    char name[16];
    ogs_li_mdf_peer_t peer;
} admf_x1_peer_t;

typedef struct admf_context_s {
    ogs_li_target_set_t targets;

    ogs_sockaddr_t *hi1_addr;
    uint16_t hi1_port;

    char hi2_spool_dir[OGS_LI_MAX_SPOOL_PATH];

    admf_x1_peer_t x1_peers[ADMF_MAX_X1_PEERS];
    int num_x1_peers;
} admf_context_t;

admf_context_t *admf_self(void);

int admf_initialize(void);
void admf_terminate(void);

int admf_context_init(void);
void admf_context_final(void);
int admf_context_parse_config(void);

#ifdef __cplusplus
}
#endif

#endif /* ADMF_CONTEXT_H */
