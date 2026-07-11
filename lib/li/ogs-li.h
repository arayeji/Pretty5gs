/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Lawful Interception shared types (lab profile: JSON X2/HI2 transport).
 * Standards: 3GPP TS 33.127/33.128, ETSI TS 102 232, ETSI TS 103 221.
 */

#if !defined(OGS_LI_H)
#define OGS_LI_H

#include <stdbool.h>
#include "ogs-core.h"
#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_LI_MAX_TARGETS          256
#define OGS_LI_MAX_LIID_LEN         64
#define OGS_LI_MAX_MSISDN_LEN       24
#define OGS_LI_MAX_JSON             4096
#define OGS_LI_MAX_SPOOL_PATH       512

typedef enum {
    OGS_LI_EVENT_UNKNOWN = 0,
    OGS_LI_EVENT_EPS_ATTACH,
    OGS_LI_EVENT_EPS_DETACH,
    OGS_LI_EVENT_EPS_TAU,
    OGS_LI_EVENT_EPS_BEARER_ACTIVATE,
    OGS_LI_EVENT_EPS_BEARER_DEACTIVATE,
    OGS_LI_EVENT_PDN_SESSION_ESTABLISH,
    OGS_LI_EVENT_PDN_SESSION_RELEASE,
    OGS_LI_EVENT_PDN_SESSION_MODIFY,
} ogs_li_event_e;

typedef enum {
    OGS_LI_POI_MME = 1,
    OGS_LI_POI_SMF = 2,
    OGS_LI_POI_SGW = 3,
    OGS_LI_POI_UPF = 4,
} ogs_li_poi_e;

typedef struct ogs_li_target_s {
    ogs_lnode_t lnode;
    char liid[OGS_LI_MAX_LIID_LEN + 1];
    char imsi[OGS_MAX_IMSI_BCD_LEN + 1];
    char msisdn[OGS_LI_MAX_MSISDN_LEN + 1];
    uint32_t cin;
    bool active;
} ogs_li_target_t;

typedef struct ogs_li_target_set_s {
    ogs_list_t list;
    OGS_POOL(pool, ogs_li_target_t);
    uint32_t next_cin;
} ogs_li_target_set_t;

typedef struct ogs_li_mdf_peer_s {
    ogs_sockaddr_t *addr;
    char host[OGS_ADDRSTRLEN];
    uint16_t port;
} ogs_li_mdf_peer_t;

typedef struct ogs_li_config_s {
    bool enabled;
    ogs_li_mdf_peer_t mdf;
    char hi2_spool_dir[OGS_LI_MAX_SPOOL_PATH];
} ogs_li_config_t;

void ogs_li_target_set_init(ogs_li_target_set_t *set, int max_targets);
void ogs_li_target_set_final(ogs_li_target_set_t *set);

ogs_li_target_t *ogs_li_target_add(
        ogs_li_target_set_t *set, const char *liid, const char *imsi,
        const char *msisdn);
bool ogs_li_target_remove_by_liid(ogs_li_target_set_t *set, const char *liid);
bool ogs_li_target_remove_by_imsi(ogs_li_target_set_t *set, const char *imsi);
ogs_li_target_t *ogs_li_target_find_by_imsi(
        const ogs_li_target_set_t *set, const char *imsi);
ogs_li_target_t *ogs_li_target_find_by_liid(
        const ogs_li_target_set_t *set, const char *liid);

uint32_t ogs_li_target_alloc_cin(ogs_li_target_set_t *set);

int ogs_li_x2_encode_json(char *buf, size_t buflen,
        ogs_li_poi_e poi, ogs_li_event_e event,
        const char *liid, uint32_t cin, const char *imsi,
        const char *msisdn, const char *detail);

int ogs_li_hi2_write_spool(const char *spool_dir, const char *hi2_json);

int ogs_li_http_post_json(const ogs_li_mdf_peer_t *peer,
        const char *path, const char *json_body, int timeout_ms);

int ogs_li_http_get(const ogs_li_mdf_peer_t *peer,
        const char *path, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* OGS_LI_H */
