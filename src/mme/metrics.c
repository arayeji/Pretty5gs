#include "ogs-app.h"
#include "mme-context.h"

#include "metrics.h"

typedef struct mme_metrics_spec_def_s {
    unsigned int type;
    const char *name;
    const char *description;
    int initial_val;
    unsigned int num_labels;
    const char **labels;
} mme_metrics_spec_def_t;

/* Helper generic functions: */
static int mme_metrics_init_inst(ogs_metrics_inst_t **inst, ogs_metrics_spec_t **specs,
        unsigned int len, unsigned int num_labels, const char **labels)
{
    unsigned int i;
    for (i = 0; i < len; i++)
        inst[i] = ogs_metrics_inst_new(specs[i], num_labels, labels);
    return OGS_OK;
}

static int mme_metrics_free_inst(ogs_metrics_inst_t **inst,
        unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i++)
        ogs_metrics_inst_free(inst[i]);
    memset(inst, 0, sizeof(inst[0]) * len);
    return OGS_OK;
}

static int mme_metrics_init_spec(ogs_metrics_context_t *ctx,
        ogs_metrics_spec_t **dst, mme_metrics_spec_def_t *src, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i++) {
        dst[i] = ogs_metrics_spec_new(ctx, src[i].type,
                src[i].name, src[i].description,
                src[i].initial_val, src[i].num_labels, src[i].labels,
                NULL);
    }
    return OGS_OK;
}

typedef struct mme_metric_key_by_plmn_s {
    ogs_plmn_id_t               plmn_id;
    mme_metric_type_by_plmn_t   t;
} mme_metric_key_by_plmn_t;

typedef struct mme_metric_key_by_plmn_cause_s {
    ogs_plmn_id_t                   plmn_id;
    uint8_t                         cause;
    mme_metric_type_by_plmn_cause_t t;
} mme_metric_key_by_plmn_cause_t;

typedef struct mme_metric_key_by_reason_s {
    char                            reason[16];
    mme_metric_type_by_reason_t     t;
} mme_metric_key_by_reason_t;

typedef struct mme_metric_key_by_sgw_plmn_apn_s {
    char                                sgw_addr[OGS_ADDRSTRLEN];
    ogs_plmn_id_t                       plmn_id;
    char                                apn[OGS_MAX_APN_LEN+1];
    mme_metric_type_by_sgw_plmn_apn_t   t;
} mme_metric_key_by_sgw_plmn_apn_t;

typedef struct mme_metric_key_by_sgw_plmn_s {
    char                            sgw_addr[OGS_ADDRSTRLEN];
    ogs_plmn_id_t                   plmn_id;
    mme_metric_type_by_sgw_plmn_t   t;
} mme_metric_key_by_sgw_plmn_t;

typedef struct mme_metric_key_by_plmn_ho_s {
    ogs_plmn_id_t                   plmn_id;
    char                            ho_type[16];
    char                            cause_group[16];
    long                            cause_value;
    mme_metric_type_by_plmn_ho_t    t;
} mme_metric_key_by_plmn_ho_t;

#define MME_METRICS_HO_CAUSE_GROUP_NONE "none"
#define MME_METRICS_HO_CAUSE_VALUE_NONE 0

typedef struct mme_metric_key_by_plmn_origin_s {
    ogs_plmn_id_t                       plmn_id;
    char                                origin[16];
    mme_metric_type_by_plmn_origin_t    t;
} mme_metric_key_by_plmn_origin_t;

extern ogs_metrics_spec_t *mme_metrics_spec_by_plmn[_MME_METR_BY_PLMN_MAX];
extern ogs_hash_t *metrics_hash_by_plmn;
extern mme_metrics_spec_def_t mme_metrics_spec_def_by_plmn[_MME_METR_BY_PLMN_MAX];
extern ogs_metrics_spec_t *mme_metrics_spec_by_plmn_cause[_MME_METR_BY_PLMN_CAUSE_MAX];
extern ogs_hash_t *metrics_hash_by_plmn_cause;
extern mme_metrics_spec_def_t mme_metrics_spec_def_by_plmn_cause[_MME_METR_BY_PLMN_CAUSE_MAX];
extern ogs_metrics_spec_t *mme_metrics_spec_by_reason[_MME_METR_BY_REASON_MAX];
extern ogs_hash_t *metrics_hash_by_reason;
extern mme_metrics_spec_def_t mme_metrics_spec_def_by_reason[_MME_METR_BY_REASON_MAX];
extern ogs_metrics_spec_t
    *mme_metrics_spec_by_sgw_plmn_apn[_MME_METR_BY_SGW_PLMN_APN_MAX];
extern ogs_hash_t *metrics_hash_by_sgw_plmn_apn;
extern mme_metrics_spec_def_t
    mme_metrics_spec_def_by_sgw_plmn_apn[_MME_METR_BY_SGW_PLMN_APN_MAX];
extern ogs_metrics_spec_t
    *mme_metrics_spec_by_sgw_plmn[_MME_METR_BY_SGW_PLMN_MAX];
extern ogs_hash_t *metrics_hash_by_sgw_plmn;
extern mme_metrics_spec_def_t
    mme_metrics_spec_def_by_sgw_plmn[_MME_METR_BY_SGW_PLMN_MAX];
extern ogs_metrics_spec_t *mme_metrics_spec_by_plmn_ho[_MME_METR_BY_PLMN_HO_MAX];
extern ogs_hash_t *metrics_hash_by_plmn_ho;
extern mme_metrics_spec_def_t
    mme_metrics_spec_def_by_plmn_ho[_MME_METR_BY_PLMN_HO_MAX];
extern ogs_metrics_spec_t
    *mme_metrics_spec_by_plmn_origin[_MME_METR_BY_PLMN_ORIGIN_MAX];
extern ogs_hash_t *metrics_hash_by_plmn_origin;
extern mme_metrics_spec_def_t
    mme_metrics_spec_def_by_plmn_origin[_MME_METR_BY_PLMN_ORIGIN_MAX];

static bool mme_metrics_plmn_from_ue(mme_ue_t *mme_ue, ogs_plmn_id_t *plmn_id)
{
    ogs_assert(mme_ue);
    ogs_assert(plmn_id);

    if (!mme_ue->imsi_len)
        return false;

    mme_home_plmn_from_imsi_bcd(mme_ue->imsi_bcd, plmn_id);
    return true;
}

static void mme_metrics_inst_by_plmn_add(ogs_plmn_id_t *plmn,
        mme_metric_type_by_plmn_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    mme_metric_key_by_plmn_t *plmn_key;
    char plmn_id[OGS_PLMNIDSTRLEN] = "";

    ogs_assert(plmn);
    if (!metrics_hash_by_plmn)
        return;

    plmn_key = ogs_calloc(1, sizeof(*plmn_key));
    ogs_assert(plmn_key);

    plmn_key->plmn_id = *plmn;
    plmn_key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_plmn,
            plmn_key, sizeof(*plmn_key));

    if (!metrics) {
        ogs_plmn_id_to_string(plmn, plmn_id);

        metrics = ogs_metrics_inst_new(mme_metrics_spec_by_plmn[t],
                mme_metrics_spec_def_by_plmn->num_labels,
                (const char *[]){ plmn_id });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_plmn,
                plmn_key, sizeof(*plmn_key), metrics);
    } else {
        ogs_free(plmn_key);
    }

    ogs_metrics_inst_add(metrics, val);
}

static void mme_metrics_inst_by_plmn_cause_add(ogs_plmn_id_t *plmn,
        uint8_t cause, mme_metric_type_by_plmn_cause_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    mme_metric_key_by_plmn_cause_t *key;
    char plmn_id[OGS_PLMNIDSTRLEN] = "";
    char cause_str[4];

    ogs_assert(plmn);
    if (!metrics_hash_by_plmn_cause)
        return;

    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);

    key->plmn_id = *plmn;
    key->cause = cause;
    key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_plmn_cause,
            key, sizeof(*key));

    if (!metrics) {
        ogs_plmn_id_to_string(plmn, plmn_id);
        ogs_snprintf(cause_str, sizeof(cause_str), "%d", cause);

        metrics = ogs_metrics_inst_new(mme_metrics_spec_by_plmn_cause[t],
                mme_metrics_spec_def_by_plmn_cause->num_labels,
                (const char *[]){ plmn_id, cause_str });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_plmn_cause,
                key, sizeof(*key), metrics);
    } else {
        ogs_free(key);
    }

    ogs_metrics_inst_add(metrics, val);
}

static void mme_metrics_inst_by_plmn_ho_add(ogs_plmn_id_t *plmn,
        const char *ho_type, const char *cause_group, long cause_value,
        mme_metric_type_by_plmn_ho_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    mme_metric_key_by_plmn_ho_t *key;
    char plmn_id[OGS_PLMNIDSTRLEN] = "";
    char cause_value_str[16];
    const char *type_label = ho_type ? ho_type : "unknown";
    const char *group_label = cause_group ? cause_group :
        MME_METRICS_HO_CAUSE_GROUP_NONE;

    ogs_assert(plmn);
    if (!metrics_hash_by_plmn_ho)
        return;

    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);

    key->plmn_id = *plmn;
    ogs_cpystrn(key->ho_type, type_label, sizeof(key->ho_type));
    ogs_cpystrn(key->cause_group, group_label, sizeof(key->cause_group));
    key->cause_value = cause_value;
    key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_plmn_ho,
            key, sizeof(*key));

    if (!metrics) {
        ogs_plmn_id_to_string(plmn, plmn_id);
        ogs_snprintf(cause_value_str, sizeof(cause_value_str), "%ld",
                cause_value);

        metrics = ogs_metrics_inst_new(mme_metrics_spec_by_plmn_ho[t],
                mme_metrics_spec_def_by_plmn_ho[t].num_labels,
                (const char *[]){
                    plmn_id, key->ho_type, key->cause_group, cause_value_str });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_plmn_ho,
                key, sizeof(*key), metrics);
    } else {
        ogs_free(key);
    }

    ogs_metrics_inst_add(metrics, val);
}

static void mme_metrics_inst_by_plmn_origin_add(ogs_plmn_id_t *plmn,
        const char *origin, mme_metric_type_by_plmn_origin_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    mme_metric_key_by_plmn_origin_t *key;
    char plmn_id[OGS_PLMNIDSTRLEN] = "";

    ogs_assert(plmn);
    ogs_assert(origin);
    if (!metrics_hash_by_plmn_origin)
        return;

    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);

    key->plmn_id = *plmn;
    ogs_cpystrn(key->origin, origin, sizeof(key->origin));
    key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_plmn_origin,
            key, sizeof(*key));

    if (!metrics) {
        ogs_plmn_id_to_string(plmn, plmn_id);

        metrics = ogs_metrics_inst_new(mme_metrics_spec_by_plmn_origin[t],
                mme_metrics_spec_def_by_plmn_origin->num_labels,
                (const char *[]){ plmn_id, key->origin });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_plmn_origin,
                key, sizeof(*key), metrics);
    } else {
        ogs_free(key);
    }

    ogs_metrics_inst_add(metrics, val);
}

static void mme_metrics_inst_by_reason_add(const char *reason,
        mme_metric_type_by_reason_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    mme_metric_key_by_reason_t *key;

    ogs_assert(reason);
    if (!metrics_hash_by_reason)
        return;

    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);

    ogs_cpystrn(key->reason, reason, sizeof(key->reason));
    key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_reason,
            key, sizeof(*key));

    if (!metrics) {
        metrics = ogs_metrics_inst_new(mme_metrics_spec_by_reason[t],
                mme_metrics_spec_def_by_reason->num_labels,
                (const char *[]){ key->reason });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_reason,
                key, sizeof(*key), metrics);
    } else {
        ogs_free(key);
    }

    ogs_metrics_inst_add(metrics, val);
}

static void mme_metrics_inst_by_sgw_plmn_apn_add(
        const char *sgw_addr, const ogs_plmn_id_t *plmn, const char *apn,
        mme_metric_type_by_sgw_plmn_apn_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    mme_metric_key_by_sgw_plmn_apn_t *key;
    char plmn_id[OGS_PLMNIDSTRLEN] = "";

    ogs_assert(sgw_addr);
    ogs_assert(plmn);
    ogs_assert(apn);
    if (!metrics_hash_by_sgw_plmn_apn)
        return;

    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);

    ogs_cpystrn(key->sgw_addr, sgw_addr, sizeof(key->sgw_addr));
    key->plmn_id = *plmn;
    ogs_cpystrn(key->apn, apn, sizeof(key->apn));
    key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_sgw_plmn_apn,
            key, sizeof(*key));

    if (!metrics) {
        ogs_plmn_id_to_string(&key->plmn_id, plmn_id);

        metrics = ogs_metrics_inst_new(mme_metrics_spec_by_sgw_plmn_apn[t],
                mme_metrics_spec_def_by_sgw_plmn_apn->num_labels,
                (const char *[]){ key->sgw_addr, plmn_id, key->apn });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_sgw_plmn_apn,
                key, sizeof(*key), metrics);
    } else {
        ogs_free(key);
    }

    ogs_metrics_inst_add(metrics, val);
}

static void mme_metrics_inst_by_sgw_plmn_add(
        const char *sgw_addr, const ogs_plmn_id_t *plmn,
        mme_metric_type_by_sgw_plmn_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    mme_metric_key_by_sgw_plmn_t *key;
    char plmn_id[OGS_PLMNIDSTRLEN] = "";

    ogs_assert(sgw_addr);
    ogs_assert(plmn);
    if (!metrics_hash_by_sgw_plmn)
        return;

    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);

    ogs_cpystrn(key->sgw_addr, sgw_addr, sizeof(key->sgw_addr));
    key->plmn_id = *plmn;
    key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_sgw_plmn,
            key, sizeof(*key));

    if (!metrics) {
        ogs_plmn_id_to_string(&key->plmn_id, plmn_id);

        metrics = ogs_metrics_inst_new(mme_metrics_spec_by_sgw_plmn[t],
                mme_metrics_spec_def_by_sgw_plmn->num_labels,
                (const char *[]){ key->sgw_addr, plmn_id });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_sgw_plmn,
                key, sizeof(*key), metrics);
    } else {
        ogs_free(key);
    }

    ogs_metrics_inst_add(metrics, val);
}

void mme_metrics_attach_attempt(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_ATTACH_ATTEMPT, 1);
}

void mme_metrics_attach_success(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_ATTACH_SUCCESS, 1);
}

void mme_metrics_attach_reject(mme_ue_t *mme_ue, uint8_t emm_cause)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue)
        return;

    if (!mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_cause_add(&plmn_id, emm_cause,
            MME_METR_BY_PLMN_CAUSE_CTR_ATTACH_REJECT, 1);
}

void mme_metrics_esm_reject(mme_ue_t *mme_ue, uint8_t esm_cause)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue)
        return;

    if (!mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_cause_add(&plmn_id, esm_cause,
            MME_METR_BY_PLMN_CAUSE_CTR_ESM_REJECT, 1);
}

void mme_metrics_tau_attempt(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_TAU_ATTEMPT, 1);
}

void mme_metrics_tau_success(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_TAU_SUCCESS, 1);
}

void mme_metrics_tau_reject(mme_ue_t *mme_ue, uint8_t emm_cause)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_cause_add(&plmn_id, emm_cause,
            MME_METR_BY_PLMN_CAUSE_CTR_TAU_REJECT, 1);
}

void mme_metrics_service_request_attempt(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_SERVICE_REQUEST_ATTEMPT, 1);
}

void mme_metrics_service_request_success(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_SERVICE_REQUEST_SUCCESS, 1);
}

void mme_metrics_service_reject(mme_ue_t *mme_ue, uint8_t emm_cause)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_cause_add(&plmn_id, emm_cause,
            MME_METR_BY_PLMN_CAUSE_CTR_SERVICE_REJECT, 1);
}

void mme_metrics_pdn_connectivity_attempt(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_PDN_CONNECTIVITY_ATTEMPT, 1);
}

void mme_metrics_pdn_connectivity_success(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_PDN_CONNECTIVITY_SUCCESS, 1);
}

void mme_metrics_s11_create_session_attempt(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_S11_CREATE_SESSION_ATTEMPT, 1);
}

void mme_metrics_s11_create_session_success(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_S11_CREATE_SESSION_SUCCESS, 1);
}

void mme_metrics_s11_create_session_fail(mme_ue_t *mme_ue, uint8_t gtp_cause)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_cause_add(&plmn_id, gtp_cause,
            MME_METR_BY_PLMN_CAUSE_CTR_S11_CREATE_SESSION_FAIL, 1);
}

void mme_metrics_paging_attempt(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_PAGING_ATTEMPT, 1);
}

void mme_metrics_paging_success(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_PAGING_SUCCESS, 1);
}

void mme_metrics_ho_attempt(mme_ue_t *mme_ue, const char *ho_type)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_ho_add(&plmn_id, ho_type,
            MME_METRICS_HO_CAUSE_GROUP_NONE, MME_METRICS_HO_CAUSE_VALUE_NONE,
            MME_METR_BY_PLMN_HO_CTR_ATTEMPT, 1);
}

void mme_metrics_ho_success(mme_ue_t *mme_ue, const char *ho_type)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_ho_add(&plmn_id, ho_type,
            MME_METRICS_HO_CAUSE_GROUP_NONE, MME_METRICS_HO_CAUSE_VALUE_NONE,
            MME_METR_BY_PLMN_HO_CTR_SUCCESS, 1);
}

void mme_metrics_ho_fail(mme_ue_t *mme_ue, const char *ho_type,
        const char *cause_group, long cause_value)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_ho_add(&plmn_id, ho_type, cause_group, cause_value,
            MME_METR_BY_PLMN_HO_CTR_FAIL, 1);
}

void mme_metrics_detach(mme_ue_t *mme_ue, const char *origin)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_ue || !origin || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_origin_add(&plmn_id, origin,
            MME_METR_BY_PLMN_ORIGIN_CTR_DETACH, 1);
}

void mme_metrics_auth_request(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_AUTH_REQUEST, 1);
}

void mme_metrics_auth_success(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_AUTH_SUCCESS, 1);

    if (MME_UE_HAVE_IMSI(mme_ue) && ECM_CONNECTED(mme_ue)) {
        enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

        if (enb_ue)
            mme_metrics_enb_ue_connected_update(enb_ue);
    }
}

void mme_metrics_auth_fail(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_CTR_AUTH_FAIL, 1);
}

void mme_metrics_ue_registered_inc(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t plmn_id;

    if (!mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    mme_metrics_inst_by_plmn_add(&plmn_id,
            MME_METR_BY_PLMN_GAUGE_UE_REGISTERED, 1);

    /*
     * Remember the exact label we incremented so the decrement in
     * mme_metrics_on_ue_remove() hits the same PLMN even if the
     * context is later re-keyed to a different IMSI by
     * mme_ue_set_imsi() (GUTI collision after GUTI reuse).
     */
    mme_ue->metrics_plmn_id = plmn_id;
    mme_ue->metrics_plmn_valid = true;
}

static const char *mme_metrics_detach_reason(mme_ue_t *mme_ue)
{
    switch (mme_ue->detach_type) {
    case MME_DETACH_TYPE_REQUEST_FROM_UE:
        return "ue_detach";
    case MME_DETACH_TYPE_MME_EXPLICIT:
        return "mme_explicit";
    case MME_DETACH_TYPE_HSS_EXPLICIT:
        return "hss_explicit";
    case MME_DETACH_TYPE_MME_IMPLICIT:
        return "mme_implicit";
    case MME_DETACH_TYPE_HSS_IMPLICIT:
        return "hss_implicit";
    default:
        return "other";
    }
}

void mme_metrics_on_ue_remove(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    if (!mme_ue->metrics_registered)
        return;

    /*
     * Decrement the PLMN label recorded at increment time. Re-deriving
     * the PLMN from mme_ue->imsi_bcd here underflowed the gauge when
     * the context had been re-keyed to an IMSI of another PLMN between
     * registration and removal.
     */
    if (mme_ue->metrics_plmn_valid) {
        mme_metrics_inst_by_plmn_add(&mme_ue->metrics_plmn_id,
                MME_METR_BY_PLMN_GAUGE_UE_REGISTERED, -1);
        mme_ue->metrics_plmn_valid = false;
    }

    mme_metrics_inst_by_reason_add(mme_metrics_detach_reason(mme_ue),
            MME_METR_BY_REASON_CTR_UE_LOST, 1);
}

static bool mme_metrics_sgw_plmn_from_ue(
        mme_ue_t *mme_ue, char *sgw_addr, int sgw_addr_len,
        ogs_plmn_id_t *plmn_id)
{
    sgw_ue_t *sgw_ue = NULL;

    ogs_assert(mme_ue);
    ogs_assert(sgw_addr);
    ogs_assert(plmn_id);

    if (!mme_metrics_plmn_from_ue(mme_ue, plmn_id))
        return false;

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (!sgw_ue || !sgw_ue->sgw || !sgw_ue->sgw->gnode.sa_list)
        return false;

    OGS_ADDR(sgw_ue->sgw->gnode.sa_list, sgw_addr);
    return sgw_addr[0] != '\0';
}

/*
 * Count one enb_ue S1 context (same population as global enb_ue) under
 * the owning UE's selected SGW and IMSI home PLMN.
 */
void mme_metrics_enb_ue_connected_update(enb_ue_t *enb_ue)
{
    mme_ue_t *mme_ue = NULL;
    char sgw_addr[OGS_ADDRSTRLEN] = "";
    ogs_plmn_id_t plmn_id;

    if (!enb_ue)
        return;

    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (!mme_ue)
        return;

    if (!mme_metrics_sgw_plmn_from_ue(mme_ue, sgw_addr, sizeof(sgw_addr),
            &plmn_id))
        return;

    if (enb_ue->metrics_sgw_counted) {
        if (strcmp(enb_ue->metrics_sgw_addr, sgw_addr) == 0 &&
            memcmp(&enb_ue->metrics_plmn_id, &plmn_id,
                sizeof(plmn_id)) == 0)
            return;

        mme_metrics_inst_by_sgw_plmn_add(
                enb_ue->metrics_sgw_addr, &enb_ue->metrics_plmn_id,
                MME_METR_BY_SGW_PLMN_GAUGE_UE_ACTIVE, -1);
    }

    mme_metrics_inst_by_sgw_plmn_add(sgw_addr, &plmn_id,
            MME_METR_BY_SGW_PLMN_GAUGE_UE_ACTIVE, 1);

    ogs_cpystrn(enb_ue->metrics_sgw_addr, sgw_addr,
            sizeof(enb_ue->metrics_sgw_addr));
    enb_ue->metrics_plmn_id = plmn_id;
    enb_ue->metrics_sgw_counted = true;
}

void mme_metrics_enb_ue_connected_clear(enb_ue_t *enb_ue)
{
    if (!enb_ue || !enb_ue->metrics_sgw_counted)
        return;

    mme_metrics_inst_by_sgw_plmn_add(
            enb_ue->metrics_sgw_addr, &enb_ue->metrics_plmn_id,
            MME_METR_BY_SGW_PLMN_GAUGE_UE_ACTIVE, -1);
    enb_ue->metrics_sgw_counted = false;
}

/*
 * (Re-)count an established PDN session under the currently selected
 * SGW / IMSI home PLMN / APN. Called on Create Session Response success;
 * safe to call again after SGW relocation - the previous label set is
 * decremented and the new one incremented.
 */
void mme_metrics_sess_active_update(mme_sess_t *sess)
{
    mme_ue_t *mme_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;
    ogs_plmn_id_t plmn_id;
    char sgw_addr[OGS_ADDRSTRLEN] = "";
    const char *apn = NULL;

    ogs_assert(sess);

    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    if (!mme_ue || !mme_metrics_plmn_from_ue(mme_ue, &plmn_id))
        return;

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (!sgw_ue || !sgw_ue->sgw || !sgw_ue->sgw->gnode.sa_list)
        return;

    OGS_ADDR(sgw_ue->sgw->gnode.sa_list, sgw_addr);

    apn = (sess->session && sess->session->name) ?
            sess->session->name : "unknown";

    if (sess->metrics_sess_counted) {
        if (strcmp(sess->metrics_sgw_addr, sgw_addr) == 0 &&
            memcmp(&sess->metrics_plmn_id, &plmn_id,
                sizeof(plmn_id)) == 0 &&
            strcmp(sess->metrics_apn, apn) == 0)
            return;

        mme_metrics_inst_by_sgw_plmn_apn_add(
                sess->metrics_sgw_addr, &sess->metrics_plmn_id,
                sess->metrics_apn,
                MME_METR_BY_SGW_PLMN_APN_GAUGE_SESS_ACTIVE, -1);
    }

    mme_metrics_inst_by_sgw_plmn_apn_add(sgw_addr, &plmn_id, apn,
            MME_METR_BY_SGW_PLMN_APN_GAUGE_SESS_ACTIVE, 1);

    ogs_cpystrn(sess->metrics_sgw_addr, sgw_addr,
            sizeof(sess->metrics_sgw_addr));
    sess->metrics_plmn_id = plmn_id;
    ogs_cpystrn(sess->metrics_apn, apn, sizeof(sess->metrics_apn));
    sess->metrics_sess_counted = true;
}

void mme_metrics_on_sess_remove(mme_sess_t *sess)
{
    ogs_assert(sess);

    if (!sess->metrics_sess_counted)
        return;

    mme_metrics_inst_by_sgw_plmn_apn_add(
            sess->metrics_sgw_addr, &sess->metrics_plmn_id,
            sess->metrics_apn,
            MME_METR_BY_SGW_PLMN_APN_GAUGE_SESS_ACTIVE, -1);
    sess->metrics_sess_counted = false;
}

/* GLOBAL */
ogs_metrics_spec_t *mme_metrics_spec_global[_MME_METR_GLOB_MAX];
ogs_metrics_inst_t *mme_metrics_inst_global[_MME_METR_GLOB_MAX];
mme_metrics_spec_def_t mme_metrics_spec_def_global[_MME_METR_GLOB_MAX] = {
/* Global Gauges: */
[MME_METR_GLOB_GAUGE_ENB_UE] = {
    .type = OGS_METRICS_METRIC_TYPE_GAUGE,
    .name = "enb_ue",
    .description = "Number of UEs connected to eNodeBs",
},
[MME_METR_GLOB_GAUGE_MME_SESS] = {
    .type = OGS_METRICS_METRIC_TYPE_GAUGE,
    .name = "mme_session",
    .description = "MME Sessions",
},
[MME_METR_GLOB_GAUGE_ENB] = {
    .type = OGS_METRICS_METRIC_TYPE_GAUGE,
    .name = "enb",
    .description = "eNodeBs",
},
};
int mme_metrics_init_inst_global(void)
{
    return mme_metrics_init_inst(mme_metrics_inst_global, mme_metrics_spec_global,
                _MME_METR_GLOB_MAX, 0, NULL);
}
int mme_metrics_free_inst_global(void)
{
    return mme_metrics_free_inst(mme_metrics_inst_global, _MME_METR_GLOB_MAX);
}

/* BY PLMN */
const char *labels_plmn[] = {
    "plmnid"
};

#define MME_METR_BY_PLMN_CTR_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_COUNTER, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_plmn), \
        .labels = labels_plmn, \
    },
#define MME_METR_BY_PLMN_GAUGE_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_GAUGE, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_plmn), \
        .labels = labels_plmn, \
    },

ogs_metrics_spec_t *mme_metrics_spec_by_plmn[_MME_METR_BY_PLMN_MAX];
ogs_hash_t *metrics_hash_by_plmn = NULL;
mme_metrics_spec_def_t mme_metrics_spec_def_by_plmn[_MME_METR_BY_PLMN_MAX] = {
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_ATTACH_ATTEMPT,
    "mme_attach_attempt_total",
    "Attach attempts per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_ATTACH_SUCCESS,
    "mme_attach_success_total",
    "Successful attach procedures per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_AUTH_REQUEST,
    "mme_auth_request_total",
    "Authentication requests sent per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_AUTH_SUCCESS,
    "mme_auth_success_total",
    "Successful authentications per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_AUTH_FAIL,
    "mme_auth_fail_total",
    "Authentication failures per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_TAU_ATTEMPT,
    "mme_tau_attempt_total",
    "Tracking area update attempts per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_TAU_SUCCESS,
    "mme_tau_success_total",
    "Successful tracking area updates per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_SERVICE_REQUEST_ATTEMPT,
    "mme_service_request_attempt_total",
    "Service request attempts per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_SERVICE_REQUEST_SUCCESS,
    "mme_service_request_success_total",
    "Successful service requests per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_PDN_CONNECTIVITY_ATTEMPT,
    "mme_pdn_connectivity_attempt_total",
    "PDN connectivity attempts per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_PDN_CONNECTIVITY_SUCCESS,
    "mme_pdn_connectivity_success_total",
    "Successful PDN connectivity procedures per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_S11_CREATE_SESSION_ATTEMPT,
    "mme_s11_create_session_attempt_total",
    "S11 Create Session attempts per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_S11_CREATE_SESSION_SUCCESS,
    "mme_s11_create_session_success_total",
    "Successful S11 Create Session procedures per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_PAGING_ATTEMPT,
    "mme_paging_attempt_total",
    "Paging attempts per IMSI PLMN")
MME_METR_BY_PLMN_CTR_ENTRY(
    MME_METR_BY_PLMN_CTR_PAGING_SUCCESS,
    "mme_paging_success_total",
    "Successful paging procedures per IMSI PLMN")
MME_METR_BY_PLMN_GAUGE_ENTRY(
    MME_METR_BY_PLMN_GAUGE_UE_REGISTERED,
    "mme_ue_registered",
    "Registered UEs per IMSI PLMN")
};

static void mme_metrics_init_by_plmn(void)
{
    metrics_hash_by_plmn = ogs_hash_make();
    ogs_assert(metrics_hash_by_plmn);
}

/* BY PLMN and CAUSE */
const char *labels_plmn_cause[] = {
    "plmnid",
    "cause"
};

#define MME_METR_BY_PLMN_CAUSE_CTR_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_COUNTER, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_plmn_cause), \
        .labels = labels_plmn_cause, \
    },

ogs_metrics_spec_t *mme_metrics_spec_by_plmn_cause[_MME_METR_BY_PLMN_CAUSE_MAX];
ogs_hash_t *metrics_hash_by_plmn_cause = NULL;
mme_metrics_spec_def_t mme_metrics_spec_def_by_plmn_cause[_MME_METR_BY_PLMN_CAUSE_MAX] = {
MME_METR_BY_PLMN_CAUSE_CTR_ENTRY(
    MME_METR_BY_PLMN_CAUSE_CTR_ATTACH_REJECT,
    "mme_attach_reject_total",
    "Attach rejections per IMSI PLMN and EMM cause")
MME_METR_BY_PLMN_CAUSE_CTR_ENTRY(
    MME_METR_BY_PLMN_CAUSE_CTR_ESM_REJECT,
    "mme_esm_reject_total",
    "ESM rejections per IMSI PLMN and ESM cause")
MME_METR_BY_PLMN_CAUSE_CTR_ENTRY(
    MME_METR_BY_PLMN_CAUSE_CTR_TAU_REJECT,
    "mme_tau_reject_total",
    "TAU rejections per IMSI PLMN and EMM cause")
MME_METR_BY_PLMN_CAUSE_CTR_ENTRY(
    MME_METR_BY_PLMN_CAUSE_CTR_SERVICE_REJECT,
    "mme_service_reject_total",
    "Service rejections per IMSI PLMN and EMM cause")
MME_METR_BY_PLMN_CAUSE_CTR_ENTRY(
    MME_METR_BY_PLMN_CAUSE_CTR_S11_CREATE_SESSION_FAIL,
    "mme_s11_create_session_fail_total",
    "S11 Create Session failures per IMSI PLMN and GTP cause")
};

static void mme_metrics_init_by_plmn_cause(void)
{
    metrics_hash_by_plmn_cause = ogs_hash_make();
    ogs_assert(metrics_hash_by_plmn_cause);
}

/* BY PLMN and HO type (S1AP Cause IE labels per TS 36.413) */
const char *labels_plmn_ho[] = {
    "plmnid",
    "type",
    "cause_group",
    "cause_value"
};

#define MME_METR_BY_PLMN_HO_CTR_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_COUNTER, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_plmn_ho), \
        .labels = labels_plmn_ho, \
    },

ogs_metrics_spec_t *mme_metrics_spec_by_plmn_ho[_MME_METR_BY_PLMN_HO_MAX];
ogs_hash_t *metrics_hash_by_plmn_ho = NULL;
mme_metrics_spec_def_t mme_metrics_spec_def_by_plmn_ho[_MME_METR_BY_PLMN_HO_MAX] = {
MME_METR_BY_PLMN_HO_CTR_ENTRY(
    MME_METR_BY_PLMN_HO_CTR_ATTEMPT,
    "mme_ho_attempt_total",
    "Handover preparation attempts per IMSI PLMN and HO type "
    "(TS 32.410: counted on Handover Required / Path Switch Request)")
MME_METR_BY_PLMN_HO_CTR_ENTRY(
    MME_METR_BY_PLMN_HO_CTR_SUCCESS,
    "mme_ho_success_total",
    "Successful handovers per IMSI PLMN and HO type "
    "(intralte: Handover Notify; path_switch: Path Switch Ack)")
MME_METR_BY_PLMN_HO_CTR_ENTRY(
    MME_METR_BY_PLMN_HO_CTR_FAIL,
    "mme_ho_fail_total",
    "Handover failures per IMSI PLMN, HO type and S1AP Cause IE "
    "(cause_group + cause_value per TS 36.413)")
};

static void mme_metrics_init_by_plmn_ho(void)
{
    metrics_hash_by_plmn_ho = ogs_hash_make();
    ogs_assert(metrics_hash_by_plmn_ho);
}

/* BY PLMN and detach origin */
const char *labels_plmn_origin[] = {
    "plmnid",
    "origin"
};

#define MME_METR_BY_PLMN_ORIGIN_CTR_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_COUNTER, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_plmn_origin), \
        .labels = labels_plmn_origin, \
    },

ogs_metrics_spec_t
    *mme_metrics_spec_by_plmn_origin[_MME_METR_BY_PLMN_ORIGIN_MAX];
ogs_hash_t *metrics_hash_by_plmn_origin = NULL;
mme_metrics_spec_def_t
    mme_metrics_spec_def_by_plmn_origin[_MME_METR_BY_PLMN_ORIGIN_MAX] = {
MME_METR_BY_PLMN_ORIGIN_CTR_ENTRY(
    MME_METR_BY_PLMN_ORIGIN_CTR_DETACH,
    "mme_detach_total",
    "Detach procedures per IMSI PLMN and origin")
};

static void mme_metrics_init_by_plmn_origin(void)
{
    metrics_hash_by_plmn_origin = ogs_hash_make();
    ogs_assert(metrics_hash_by_plmn_origin);
}

/* BY REASON */
const char *labels_reason[] = {
    "reason"
};

#define MME_METR_BY_REASON_CTR_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_COUNTER, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_reason), \
        .labels = labels_reason, \
    },

ogs_metrics_spec_t *mme_metrics_spec_by_reason[_MME_METR_BY_REASON_MAX];
ogs_hash_t *metrics_hash_by_reason = NULL;
mme_metrics_spec_def_t mme_metrics_spec_def_by_reason[_MME_METR_BY_REASON_MAX] = {
MME_METR_BY_REASON_CTR_ENTRY(
    MME_METR_BY_REASON_CTR_UE_LOST,
    "mme_ue_lost_total",
    "UE removals by detach reason")
};

static void mme_metrics_init_by_reason(void)
{
    metrics_hash_by_reason = ogs_hash_make();
    ogs_assert(metrics_hash_by_reason);
}

/* BY SGW, IMSI PLMN and APN */
const char *labels_sgw_plmn_apn[] = {
    "sgw",
    "plmnid",
    "apn"
};

#define MME_METR_BY_SGW_PLMN_APN_GAUGE_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_GAUGE, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_sgw_plmn_apn), \
        .labels = labels_sgw_plmn_apn, \
    },

ogs_metrics_spec_t
    *mme_metrics_spec_by_sgw_plmn_apn[_MME_METR_BY_SGW_PLMN_APN_MAX];
ogs_hash_t *metrics_hash_by_sgw_plmn_apn = NULL;
mme_metrics_spec_def_t
    mme_metrics_spec_def_by_sgw_plmn_apn[_MME_METR_BY_SGW_PLMN_APN_MAX] = {
MME_METR_BY_SGW_PLMN_APN_GAUGE_ENTRY(
    MME_METR_BY_SGW_PLMN_APN_GAUGE_SESS_ACTIVE,
    "mme_session_active_by_sgw",
    "Active MME sessions per selected SGW, IMSI home PLMN and APN")
};

static void mme_metrics_init_by_sgw_plmn_apn(void)
{
    metrics_hash_by_sgw_plmn_apn = ogs_hash_make();
    ogs_assert(metrics_hash_by_sgw_plmn_apn);
}

/* BY SGW and IMSI PLMN */
const char *labels_sgw_plmn[] = {
    "sgw",
    "plmnid"
};

#define MME_METR_BY_SGW_PLMN_GAUGE_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_GAUGE, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_sgw_plmn), \
        .labels = labels_sgw_plmn, \
    },

ogs_metrics_spec_t
    *mme_metrics_spec_by_sgw_plmn[_MME_METR_BY_SGW_PLMN_MAX];
ogs_hash_t *metrics_hash_by_sgw_plmn = NULL;
mme_metrics_spec_def_t
    mme_metrics_spec_def_by_sgw_plmn[_MME_METR_BY_SGW_PLMN_MAX] = {
MME_METR_BY_SGW_PLMN_GAUGE_ENTRY(
    MME_METR_BY_SGW_PLMN_GAUGE_UE_ACTIVE,
    "mme_ue_active_by_sgw",
    "ECM-CONNECTED UEs (active S1, one per enb_ue context) per selected "
    "SGW and IMSI home PLMN; sum <= global enb_ue (contexts mid-attach, "
    "before IMSI/SGW are known, are not yet labelled)")
};

static void mme_metrics_init_by_sgw_plmn(void)
{
    metrics_hash_by_sgw_plmn = ogs_hash_make();
    ogs_assert(metrics_hash_by_sgw_plmn);
}

void mme_metrics_init(void)
{
    ogs_metrics_context_t *ctx = ogs_metrics_self();
    ogs_metrics_context_init();

    mme_metrics_init_spec(ctx, mme_metrics_spec_global, mme_metrics_spec_def_global,
            _MME_METR_GLOB_MAX);
    mme_metrics_init_spec(ctx, mme_metrics_spec_by_plmn,
            mme_metrics_spec_def_by_plmn, _MME_METR_BY_PLMN_MAX);
    mme_metrics_init_spec(ctx, mme_metrics_spec_by_plmn_cause,
            mme_metrics_spec_def_by_plmn_cause, _MME_METR_BY_PLMN_CAUSE_MAX);
    mme_metrics_init_spec(ctx, mme_metrics_spec_by_reason,
            mme_metrics_spec_def_by_reason, _MME_METR_BY_REASON_MAX);
    mme_metrics_init_spec(ctx, mme_metrics_spec_by_sgw_plmn_apn,
            mme_metrics_spec_def_by_sgw_plmn_apn,
            _MME_METR_BY_SGW_PLMN_APN_MAX);
    mme_metrics_init_spec(ctx, mme_metrics_spec_by_sgw_plmn,
            mme_metrics_spec_def_by_sgw_plmn,
            _MME_METR_BY_SGW_PLMN_MAX);
    mme_metrics_init_spec(ctx, mme_metrics_spec_by_plmn_ho,
            mme_metrics_spec_def_by_plmn_ho, _MME_METR_BY_PLMN_HO_MAX);
    mme_metrics_init_spec(ctx, mme_metrics_spec_by_plmn_origin,
            mme_metrics_spec_def_by_plmn_origin,
            _MME_METR_BY_PLMN_ORIGIN_MAX);

    mme_metrics_init_inst_global();
    mme_metrics_init_by_plmn();
    mme_metrics_init_by_plmn_cause();
    mme_metrics_init_by_plmn_ho();
    mme_metrics_init_by_plmn_origin();
    mme_metrics_init_by_reason();
    mme_metrics_init_by_sgw_plmn_apn();
    mme_metrics_init_by_sgw_plmn();
}

void mme_metrics_final(void)
{
    ogs_hash_index_t *hi;

    if (metrics_hash_by_plmn) {
        for (hi = ogs_hash_first(metrics_hash_by_plmn); hi; hi = ogs_hash_next(hi)) {
            mme_metric_key_by_plmn_t *key =
                (mme_metric_key_by_plmn_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_plmn, key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_plmn);
        metrics_hash_by_plmn = NULL;
    }
    if (metrics_hash_by_plmn_cause) {
        for (hi = ogs_hash_first(metrics_hash_by_plmn_cause); hi;
                hi = ogs_hash_next(hi)) {
            mme_metric_key_by_plmn_cause_t *key =
                (mme_metric_key_by_plmn_cause_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_plmn_cause, key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_plmn_cause);
        metrics_hash_by_plmn_cause = NULL;
    }
    if (metrics_hash_by_reason) {
        for (hi = ogs_hash_first(metrics_hash_by_reason); hi; hi = ogs_hash_next(hi)) {
            mme_metric_key_by_reason_t *key =
                (mme_metric_key_by_reason_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_reason, key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_reason);
        metrics_hash_by_reason = NULL;
    }
    if (metrics_hash_by_sgw_plmn_apn) {
        for (hi = ogs_hash_first(metrics_hash_by_sgw_plmn_apn); hi;
                hi = ogs_hash_next(hi)) {
            mme_metric_key_by_sgw_plmn_apn_t *key =
                (mme_metric_key_by_sgw_plmn_apn_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_sgw_plmn_apn,
                    key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_sgw_plmn_apn);
        metrics_hash_by_sgw_plmn_apn = NULL;
    }
    if (metrics_hash_by_sgw_plmn) {
        for (hi = ogs_hash_first(metrics_hash_by_sgw_plmn); hi;
                hi = ogs_hash_next(hi)) {
            mme_metric_key_by_sgw_plmn_t *key =
                (mme_metric_key_by_sgw_plmn_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_sgw_plmn,
                    key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_sgw_plmn);
        metrics_hash_by_sgw_plmn = NULL;
    }
    if (metrics_hash_by_plmn_ho) {
        for (hi = ogs_hash_first(metrics_hash_by_plmn_ho); hi;
                hi = ogs_hash_next(hi)) {
            mme_metric_key_by_plmn_ho_t *key =
                (mme_metric_key_by_plmn_ho_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_plmn_ho, key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_plmn_ho);
        metrics_hash_by_plmn_ho = NULL;
    }
    if (metrics_hash_by_plmn_origin) {
        for (hi = ogs_hash_first(metrics_hash_by_plmn_origin); hi;
                hi = ogs_hash_next(hi)) {
            mme_metric_key_by_plmn_origin_t *key =
                (mme_metric_key_by_plmn_origin_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_plmn_origin, key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_plmn_origin);
        metrics_hash_by_plmn_origin = NULL;
    }

    ogs_metrics_context_final();
}
