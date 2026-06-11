#include "ogs-app.h"
#include "context.h"

#include "metrics.h"

typedef struct sgwc_metrics_spec_def_s {
    unsigned int type;
    const char *name;
    const char *description;
    int initial_val;
    unsigned int num_labels;
    const char **labels;
} sgwc_metrics_spec_def_t;

typedef struct sgwc_metric_key_by_plmn_s {
    ogs_plmn_id_t               plmn_id;
    sgwc_metric_type_by_plmn_t  t;
} sgwc_metric_key_by_plmn_t;

typedef struct sgwc_metric_key_by_plmn_pgw_s {
    ogs_plmn_id_t                       plmn_id;
    char                                pgw_addr[OGS_ADDRSTRLEN];
    sgwc_metric_type_by_plmn_pgw_t      t;
} sgwc_metric_key_by_plmn_pgw_t;

extern ogs_metrics_spec_t *sgwc_metrics_spec_by_plmn[_SGWC_METR_BY_PLMN_MAX];
extern ogs_hash_t *metrics_hash_by_plmn;
extern sgwc_metrics_spec_def_t sgwc_metrics_spec_def_by_plmn[_SGWC_METR_BY_PLMN_MAX];
extern ogs_metrics_spec_t *sgwc_metrics_spec_by_plmn_pgw[_SGWC_METR_BY_PLMN_PGW_MAX];
extern ogs_hash_t *metrics_hash_by_plmn_pgw;
extern sgwc_metrics_spec_def_t sgwc_metrics_spec_def_by_plmn_pgw[_SGWC_METR_BY_PLMN_PGW_MAX];

static int sgwc_metrics_init_spec(ogs_metrics_context_t *ctx,
        ogs_metrics_spec_t **dst, sgwc_metrics_spec_def_t *src, unsigned int len)
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

static bool sgwc_metrics_plmn_from_ue(sgwc_ue_t *sgwc_ue, ogs_plmn_id_t *plmn_id)
{
    ogs_assert(sgwc_ue);
    ogs_assert(plmn_id);

    if (!sgwc_ue->imsi_len)
        return false;

    ogs_plmn_id_from_imsi_bcd(sgwc_ue->imsi_bcd, plmn_id);
    return true;
}

static bool sgwc_metrics_plmn_from_sess(sgwc_sess_t *sess, ogs_plmn_id_t *plmn_id)
{
    sgwc_ue_t *sgwc_ue = NULL;
    ogs_plmn_id_t zero_plmn_id;

    ogs_assert(sess);
    ogs_assert(plmn_id);

    memset(&zero_plmn_id, 0, sizeof(zero_plmn_id));
    if (memcmp(&sess->serving_plmn_id, &zero_plmn_id, OGS_PLMN_ID_LEN) != 0) {
        *plmn_id = sess->serving_plmn_id;
        return true;
    }

    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    if (sgwc_ue && sgwc_metrics_plmn_from_ue(sgwc_ue, plmn_id))
        return true;

    return false;
}

static void sgwc_metrics_inst_by_plmn_add(ogs_plmn_id_t *plmn,
        sgwc_metric_type_by_plmn_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    sgwc_metric_key_by_plmn_t *plmn_key;
    char plmn_id[OGS_PLMNIDSTRLEN] = "";

    ogs_assert(plmn);

    plmn_key = ogs_calloc(1, sizeof(*plmn_key));
    ogs_assert(plmn_key);

    plmn_key->plmn_id = *plmn;
    plmn_key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_plmn,
            plmn_key, sizeof(*plmn_key));

    if (!metrics) {
        ogs_plmn_id_to_string(plmn, plmn_id);

        metrics = ogs_metrics_inst_new(sgwc_metrics_spec_by_plmn[t],
                sgwc_metrics_spec_def_by_plmn->num_labels,
                (const char *[]){ plmn_id });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_plmn,
                plmn_key, sizeof(*plmn_key), metrics);
    } else {
        ogs_free(plmn_key);
    }

    ogs_metrics_inst_add(metrics, val);
}

static void sgwc_metrics_inst_by_plmn_pgw_add(ogs_plmn_id_t *plmn,
        const char *pgw_addr, sgwc_metric_type_by_plmn_pgw_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    sgwc_metric_key_by_plmn_pgw_t *key;
    char plmn_id[OGS_PLMNIDSTRLEN] = "";

    ogs_assert(plmn);
    ogs_assert(pgw_addr);

    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);

    key->plmn_id = *plmn;
    ogs_cpystrn(key->pgw_addr, pgw_addr, sizeof(key->pgw_addr));
    key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_plmn_pgw,
            key, sizeof(*key));

    if (!metrics) {
        ogs_plmn_id_to_string(plmn, plmn_id);

        metrics = ogs_metrics_inst_new(sgwc_metrics_spec_by_plmn_pgw[t],
                sgwc_metrics_spec_def_by_plmn_pgw->num_labels,
                (const char *[]){ plmn_id, key->pgw_addr });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_plmn_pgw,
                key, sizeof(*key), metrics);
    } else {
        ogs_free(key);
    }

    ogs_metrics_inst_add(metrics, val);
}

void sgwc_metrics_ue_active_inc(sgwc_ue_t *sgwc_ue)
{
    ogs_plmn_id_t plmn_id;

    ogs_assert(sgwc_ue);

    if (sgwc_ue->metrics_ue_counted)
        return;

    if (!sgwc_metrics_plmn_from_ue(sgwc_ue, &plmn_id))
        return;

    sgwc_metrics_inst_by_plmn_add(&plmn_id,
            SGWC_METR_BY_PLMN_GAUGE_UE_ACTIVE, 1);
    sgwc_ue->metrics_ue_counted = 1;
}

void sgwc_metrics_ue_active_dec(sgwc_ue_t *sgwc_ue)
{
    ogs_plmn_id_t plmn_id;

    ogs_assert(sgwc_ue);

    if (!sgwc_ue->metrics_ue_counted)
        return;

    if (!sgwc_metrics_plmn_from_ue(sgwc_ue, &plmn_id))
        return;

    sgwc_metrics_inst_by_plmn_add(&plmn_id,
            SGWC_METR_BY_PLMN_GAUGE_UE_ACTIVE, -1);
    sgwc_ue->metrics_ue_counted = 0;
}

void sgwc_metrics_session_active_inc(sgwc_sess_t *sess)
{
    ogs_plmn_id_t plmn_id;
    char ipbuf[OGS_ADDRSTRLEN];

    ogs_assert(sess);
    ogs_assert(sess->gnode);

    if (sess->metrics_session_counted)
        return;

    if (!sgwc_metrics_plmn_from_sess(sess, &plmn_id))
        return;

    OGS_ADDR(&sess->gnode->addr, ipbuf);
    sgwc_metrics_inst_by_plmn_pgw_add(&plmn_id, ipbuf,
            SGWC_METR_BY_PLMN_PGW_GAUGE_SESSION_ACTIVE, 1);
    sess->metrics_session_counted = 1;
}

void sgwc_metrics_session_active_dec(sgwc_sess_t *sess)
{
    ogs_plmn_id_t plmn_id;
    char ipbuf[OGS_ADDRSTRLEN];

    ogs_assert(sess);

    if (!sess->metrics_session_counted)
        return;

    if (!sess->gnode) {
        ogs_warn("SGWC session metrics dec skipped: no PGW gnode");
        sess->metrics_session_counted = 0;
        return;
    }

    if (!sgwc_metrics_plmn_from_sess(sess, &plmn_id))
        return;

    OGS_ADDR(&sess->gnode->addr, ipbuf);
    sgwc_metrics_inst_by_plmn_pgw_add(&plmn_id, ipbuf,
            SGWC_METR_BY_PLMN_PGW_GAUGE_SESSION_ACTIVE, -1);
    sess->metrics_session_counted = 0;
}

/* BY PLMN */
const char *labels_plmn[] = {
    "plmnid"
};

#define SGWC_METR_BY_PLMN_GAUGE_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_GAUGE, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_plmn), \
        .labels = labels_plmn, \
    },

ogs_metrics_spec_t *sgwc_metrics_spec_by_plmn[_SGWC_METR_BY_PLMN_MAX];
ogs_hash_t *metrics_hash_by_plmn = NULL;
sgwc_metrics_spec_def_t sgwc_metrics_spec_def_by_plmn[_SGWC_METR_BY_PLMN_MAX] = {
SGWC_METR_BY_PLMN_GAUGE_ENTRY(
    SGWC_METR_BY_PLMN_GAUGE_UE_ACTIVE,
    "sgwc_ue_active",
    "Active UEs per IMSI PLMN on SGWC")
};

static void sgwc_metrics_init_by_plmn(void)
{
    metrics_hash_by_plmn = ogs_hash_make();
    ogs_assert(metrics_hash_by_plmn);
}

/* BY PLMN and PGW */
const char *labels_plmn_pgw[] = {
    "plmnid",
    "pgw_addr"
};

#define SGWC_METR_BY_PLMN_PGW_GAUGE_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_GAUGE, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_plmn_pgw), \
        .labels = labels_plmn_pgw, \
    },

ogs_metrics_spec_t *sgwc_metrics_spec_by_plmn_pgw[_SGWC_METR_BY_PLMN_PGW_MAX];
ogs_hash_t *metrics_hash_by_plmn_pgw = NULL;
sgwc_metrics_spec_def_t sgwc_metrics_spec_def_by_plmn_pgw[_SGWC_METR_BY_PLMN_PGW_MAX] = {
SGWC_METR_BY_PLMN_PGW_GAUGE_ENTRY(
    SGWC_METR_BY_PLMN_PGW_GAUGE_SESSION_ACTIVE,
    "sgwc_session_active",
    "Active sessions per IMSI PLMN and PGW on SGWC")
};

static void sgwc_metrics_init_by_plmn_pgw(void)
{
    metrics_hash_by_plmn_pgw = ogs_hash_make();
    ogs_assert(metrics_hash_by_plmn_pgw);
}

void sgwc_metrics_init(void)
{
    ogs_metrics_context_t *ctx = ogs_metrics_self();
    ogs_metrics_context_init();

    sgwc_metrics_init_spec(ctx, sgwc_metrics_spec_by_plmn,
            sgwc_metrics_spec_def_by_plmn, _SGWC_METR_BY_PLMN_MAX);
    sgwc_metrics_init_spec(ctx, sgwc_metrics_spec_by_plmn_pgw,
            sgwc_metrics_spec_def_by_plmn_pgw, _SGWC_METR_BY_PLMN_PGW_MAX);

    sgwc_metrics_init_by_plmn();
    sgwc_metrics_init_by_plmn_pgw();
}

void sgwc_metrics_final(void)
{
    ogs_hash_index_t *hi;

    if (metrics_hash_by_plmn) {
        for (hi = ogs_hash_first(metrics_hash_by_plmn); hi; hi = ogs_hash_next(hi)) {
            sgwc_metric_key_by_plmn_t *key =
                (sgwc_metric_key_by_plmn_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_plmn, key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_plmn);
    }
    if (metrics_hash_by_plmn_pgw) {
        for (hi = ogs_hash_first(metrics_hash_by_plmn_pgw); hi;
                hi = ogs_hash_next(hi)) {
            sgwc_metric_key_by_plmn_pgw_t *key =
                (sgwc_metric_key_by_plmn_pgw_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_plmn_pgw, key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_plmn_pgw);
    }

    ogs_metrics_context_final();
}
