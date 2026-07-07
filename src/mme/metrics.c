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

extern ogs_metrics_spec_t *mme_metrics_spec_by_plmn[_MME_METR_BY_PLMN_MAX];
extern ogs_hash_t *metrics_hash_by_plmn;
extern mme_metrics_spec_def_t mme_metrics_spec_def_by_plmn[_MME_METR_BY_PLMN_MAX];
extern ogs_metrics_spec_t *mme_metrics_spec_by_plmn_cause[_MME_METR_BY_PLMN_CAUSE_MAX];
extern ogs_hash_t *metrics_hash_by_plmn_cause;
extern mme_metrics_spec_def_t mme_metrics_spec_def_by_plmn_cause[_MME_METR_BY_PLMN_CAUSE_MAX];
extern ogs_metrics_spec_t *mme_metrics_spec_by_reason[_MME_METR_BY_REASON_MAX];
extern ogs_hash_t *metrics_hash_by_reason;
extern mme_metrics_spec_def_t mme_metrics_spec_def_by_reason[_MME_METR_BY_REASON_MAX];

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
};

static void mme_metrics_init_by_plmn_cause(void)
{
    metrics_hash_by_plmn_cause = ogs_hash_make();
    ogs_assert(metrics_hash_by_plmn_cause);
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

    mme_metrics_init_inst_global();
    mme_metrics_init_by_plmn();
    mme_metrics_init_by_plmn_cause();
    mme_metrics_init_by_reason();
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

    ogs_metrics_context_final();
}
