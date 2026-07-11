#ifndef SGWC_METRICS_H
#define SGWC_METRICS_H

#include "ogs-metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sgwc_ue_s sgwc_ue_t;
typedef struct sgwc_sess_s sgwc_sess_t;

typedef enum sgwc_metric_type_global_s {
    SGWC_METR_GLOB_GAUGE_SESSIONS_ORPHAN = 0,
    SGWC_METR_GLOB_GAUGE_UE_ORPHAN,
    SGWC_METR_GLOB_GAUGE_PFCP_PEERS_ACTIVE,
    _SGWC_METR_GLOB_MAX,
} sgwc_metric_type_global_t;

typedef enum sgwc_metric_type_pfcp_peer_s {
    SGWC_METR_PFCP_PEER_GAUGE_UP = 0,
    _SGWC_METR_PFCP_PEER_MAX,
} sgwc_metric_type_pfcp_peer_t;

typedef enum sgwc_metric_type_by_plmn_s {
    SGWC_METR_BY_PLMN_GAUGE_UE_ACTIVE = 0,
    SGWC_METR_BY_PLMN_CTR_CREATE_SESSION_ATTEMPT,
    SGWC_METR_BY_PLMN_CTR_CREATE_SESSION_SUCCESS,
    _SGWC_METR_BY_PLMN_MAX,
} sgwc_metric_type_by_plmn_t;

typedef enum sgwc_metric_type_by_plmn_cause_s {
    SGWC_METR_BY_PLMN_CAUSE_CTR_CREATE_SESSION_FAIL = 0,
    _SGWC_METR_BY_PLMN_CAUSE_MAX,
} sgwc_metric_type_by_plmn_cause_t;

typedef enum sgwc_metric_type_by_plmn_pgw_s {
    SGWC_METR_BY_PLMN_PGW_GAUGE_SESSION_ACTIVE = 0,
    _SGWC_METR_BY_PLMN_PGW_MAX,
} sgwc_metric_type_by_plmn_pgw_t;

typedef enum sgwc_metric_type_by_plmn_apn_s {
    SGWC_METR_BY_PLMN_APN_GAUGE_SESSION_ACTIVE = 0,
    _SGWC_METR_BY_PLMN_APN_MAX,
} sgwc_metric_type_by_plmn_apn_t;

typedef enum sgwc_metric_type_by_rat_s {
    SGWC_METR_GAUGE_SESSIONNBR_BY_RAT = 0,
    _SGWC_METR_BY_RAT_MAX,
} sgwc_metric_type_by_rat_t;

void sgwc_metrics_inst_by_rat_add(
    const char *rat, const char *gtp_if,
    sgwc_metric_type_by_rat_t t, int val);

extern ogs_metrics_spec_t *sgwc_metrics_spec_global[_SGWC_METR_GLOB_MAX];
extern ogs_metrics_inst_t *sgwc_metrics_inst_global[_SGWC_METR_GLOB_MAX];

void sgwc_metrics_global_set(sgwc_metric_type_global_t t, int val);

static inline void sgwc_metrics_inst_global_inc(sgwc_metric_type_global_t t)
{
    if (t < _SGWC_METR_GLOB_MAX && sgwc_metrics_inst_global[t])
        ogs_metrics_inst_inc(sgwc_metrics_inst_global[t]);
}

static inline void sgwc_metrics_inst_global_dec(sgwc_metric_type_global_t t)
{
    if (t < _SGWC_METR_GLOB_MAX && sgwc_metrics_inst_global[t])
        ogs_metrics_inst_dec(sgwc_metrics_inst_global[t]);
}

void sgwc_metrics_pfcp_peer_up(const char *addr, int up);

void sgwc_metrics_create_session_attempt(sgwc_ue_t *sgwc_ue);
void sgwc_metrics_create_session_success(sgwc_ue_t *sgwc_ue);
void sgwc_metrics_create_session_fail(sgwc_ue_t *sgwc_ue, uint8_t gtp_cause);

void sgwc_metrics_ue_active_inc(sgwc_ue_t *sgwc_ue);
void sgwc_metrics_ue_active_dec(sgwc_ue_t *sgwc_ue);
void sgwc_metrics_session_active_inc(sgwc_sess_t *sess);
void sgwc_metrics_session_active_dec(sgwc_sess_t *sess);

void sgwc_metrics_init(void);
void sgwc_metrics_final(void);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_METRICS_H */
