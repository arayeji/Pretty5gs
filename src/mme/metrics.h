#ifndef MME_METRICS_H
#define MME_METRICS_H

#include "ogs-metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mme_ue_s mme_ue_t;
typedef struct mme_sess_s mme_sess_t;
typedef struct sgw_ue_s sgw_ue_t;
typedef struct enb_ue_s enb_ue_t;

/* GLOBAL */
typedef enum mme_metric_type_global_s {
    MME_METR_GLOB_GAUGE_ENB_UE,
    MME_METR_GLOB_GAUGE_MME_SESS,
    MME_METR_GLOB_GAUGE_ENB,
    _MME_METR_GLOB_MAX,
} mme_metric_type_global_t;
extern ogs_metrics_inst_t *mme_metrics_inst_global[_MME_METR_GLOB_MAX];

int mme_metrics_init_inst_global(void);
int mme_metrics_free_inst_global(void);

static inline void mme_metrics_inst_global_set(mme_metric_type_global_t t, int val)
{ ogs_metrics_inst_set(mme_metrics_inst_global[t], val); }
static inline void mme_metrics_inst_global_add(mme_metric_type_global_t t, int val)
{ ogs_metrics_inst_add(mme_metrics_inst_global[t], val); }
static inline void mme_metrics_inst_global_inc(mme_metric_type_global_t t)
{ ogs_metrics_inst_inc(mme_metrics_inst_global[t]); }
static inline void mme_metrics_inst_global_dec(mme_metric_type_global_t t)
{ ogs_metrics_inst_dec(mme_metrics_inst_global[t]); }

/* BY PLMN */
typedef enum mme_metric_type_by_plmn_s {
    MME_METR_BY_PLMN_CTR_ATTACH_ATTEMPT = 0,
    MME_METR_BY_PLMN_CTR_ATTACH_SUCCESS,
    MME_METR_BY_PLMN_CTR_AUTH_REQUEST,
    MME_METR_BY_PLMN_CTR_AUTH_SUCCESS,
    MME_METR_BY_PLMN_CTR_AUTH_FAIL,
    MME_METR_BY_PLMN_GAUGE_UE_REGISTERED,
    _MME_METR_BY_PLMN_MAX,
} mme_metric_type_by_plmn_t;

/* BY PLMN and CAUSE */
typedef enum mme_metric_type_by_plmn_cause_s {
    MME_METR_BY_PLMN_CAUSE_CTR_ATTACH_REJECT = 0,
    MME_METR_BY_PLMN_CAUSE_CTR_ESM_REJECT,
    _MME_METR_BY_PLMN_CAUSE_MAX,
} mme_metric_type_by_plmn_cause_t;

/* BY REASON */
typedef enum mme_metric_type_by_reason_s {
    MME_METR_BY_REASON_CTR_UE_LOST = 0,
    _MME_METR_BY_REASON_MAX,
} mme_metric_type_by_reason_t;

/* BY SGW, IMSI PLMN and APN */
typedef enum mme_metric_type_by_sgw_plmn_apn_s {
    MME_METR_BY_SGW_PLMN_APN_GAUGE_SESS_ACTIVE = 0,
    _MME_METR_BY_SGW_PLMN_APN_MAX,
} mme_metric_type_by_sgw_plmn_apn_t;

/* BY SGW and IMSI PLMN */
typedef enum mme_metric_type_by_sgw_plmn_s {
    MME_METR_BY_SGW_PLMN_GAUGE_UE_ACTIVE = 0,
    _MME_METR_BY_SGW_PLMN_MAX,
} mme_metric_type_by_sgw_plmn_t;

void mme_metrics_attach_attempt(mme_ue_t *mme_ue);
void mme_metrics_attach_success(mme_ue_t *mme_ue);
void mme_metrics_attach_reject(mme_ue_t *mme_ue, uint8_t emm_cause);
void mme_metrics_esm_reject(mme_ue_t *mme_ue, uint8_t esm_cause);
void mme_metrics_auth_request(mme_ue_t *mme_ue);
void mme_metrics_auth_success(mme_ue_t *mme_ue);
void mme_metrics_auth_fail(mme_ue_t *mme_ue);
void mme_metrics_ue_registered_inc(mme_ue_t *mme_ue);
void mme_metrics_on_ue_remove(mme_ue_t *mme_ue);

void mme_metrics_sess_active_update(mme_sess_t *sess);
void mme_metrics_on_sess_remove(mme_sess_t *sess);

void mme_metrics_enb_ue_connected_update(enb_ue_t *enb_ue);
void mme_metrics_enb_ue_connected_clear(enb_ue_t *enb_ue);

void mme_metrics_init(void);
void mme_metrics_final(void);

#ifdef __cplusplus
}
#endif

#endif /* MME_METRICS_H */
