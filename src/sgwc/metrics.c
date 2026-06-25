#include "ogs-app.h"
#include "context.h"

#include "metrics.h"
#include "pdn-info.h"

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

typedef struct sgwc_metric_key_by_plmn_apn_s {
    ogs_plmn_id_t                       plmn_id;
    char                                apn[OGS_MAX_APN_LEN+1];
    sgwc_metric_type_by_plmn_apn_t      t;
} sgwc_metric_key_by_plmn_apn_t;

typedef struct sgwc_metric_key_by_rat_s {
    char                        rat[16];
    char                        gtp_if[8];
    sgwc_metric_type_by_rat_t   t;
} sgwc_metric_key_by_rat_t;

extern ogs_metrics_spec_t *sgwc_metrics_spec_by_plmn[_SGWC_METR_BY_PLMN_MAX];
extern ogs_hash_t *metrics_hash_by_plmn;
extern sgwc_metrics_spec_def_t sgwc_metrics_spec_def_by_plmn[_SGWC_METR_BY_PLMN_MAX];
extern ogs_metrics_spec_t *sgwc_metrics_spec_by_plmn_pgw[_SGWC_METR_BY_PLMN_PGW_MAX];
extern ogs_hash_t *metrics_hash_by_plmn_pgw;
extern sgwc_metrics_spec_def_t sgwc_metrics_spec_def_by_plmn_pgw[_SGWC_METR_BY_PLMN_PGW_MAX];
extern ogs_metrics_spec_t *sgwc_metrics_spec_by_plmn_apn[_SGWC_METR_BY_PLMN_APN_MAX];
extern ogs_hash_t *metrics_hash_by_plmn_apn;
extern sgwc_metrics_spec_def_t sgwc_metrics_spec_def_by_plmn_apn[_SGWC_METR_BY_PLMN_APN_MAX];
extern ogs_metrics_spec_t *sgwc_metrics_spec_by_rat[_SGWC_METR_BY_RAT_MAX];
extern ogs_hash_t *metrics_hash_by_rat;
extern sgwc_metrics_spec_def_t sgwc_metrics_spec_def_by_rat[_SGWC_METR_BY_RAT_MAX];

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

/* GLOBAL (no labels) */
ogs_metrics_spec_t *sgwc_metrics_spec_global[_SGWC_METR_GLOB_MAX];
ogs_metrics_inst_t *sgwc_metrics_inst_global[_SGWC_METR_GLOB_MAX];
sgwc_metrics_spec_def_t sgwc_metrics_spec_def_global[_SGWC_METR_GLOB_MAX] = {
[SGWC_METR_GLOB_GAUGE_SESSIONS_ORPHAN] = {
    .type = OGS_METRICS_METRIC_TYPE_GAUGE,
    .name = "sgwc_sessions_orphan",
    .description = "SGWC sessions detected as orphan/stuck "
        "(no SGW-U PFCP session or never fully established)",
},
};

void sgwc_metrics_global_set(sgwc_metric_type_global_t t, int val)
{
    if (t >= _SGWC_METR_GLOB_MAX)
        return;
    if (!sgwc_metrics_inst_global[t])
        return;
    ogs_metrics_inst_set(sgwc_metrics_inst_global[t], val);
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

    /*
     * Always prefer IMSI PLMN (home PLMN) so that the metric label matches
     * the subscriber identity, consistent with sgwc_ue_active.
     * serving_plmn_id is the *visited* network's PLMN (derived from the TAI
     * or Serving Network IE) and would label every session with the local
     * operator's PLMN regardless of the subscriber's home network.
     * Fall back to serving_plmn_id only when IMSI is unavailable
     * (e.g. anonymous/emergency sessions).
     */
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    if (sgwc_ue && sgwc_metrics_plmn_from_ue(sgwc_ue, plmn_id))
        return true;

    memset(&zero_plmn_id, 0, sizeof(zero_plmn_id));
    if (memcmp(&sess->serving_plmn_id, &zero_plmn_id, OGS_PLMN_ID_LEN) != 0) {
        *plmn_id = sess->serving_plmn_id;
        return true;
    }

    return false;
}

static void sgwc_metrics_inst_by_plmn_add(ogs_plmn_id_t *plmn,
        sgwc_metric_type_by_plmn_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    sgwc_metric_key_by_plmn_t *plmn_key;
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
    if (!metrics_hash_by_plmn_pgw)
        return;

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

static void sgwc_metrics_inst_by_plmn_apn_add(ogs_plmn_id_t *plmn,
        const char *apn, sgwc_metric_type_by_plmn_apn_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    sgwc_metric_key_by_plmn_apn_t *key;
    char plmn_id[OGS_PLMNIDSTRLEN] = "";

    ogs_assert(plmn);
    ogs_assert(apn);
    if (!metrics_hash_by_plmn_apn)
        return;

    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);

    key->plmn_id = *plmn;
    ogs_cpystrn(key->apn, apn, sizeof(key->apn));
    key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_plmn_apn,
            key, sizeof(*key));

    if (!metrics) {
        ogs_plmn_id_to_string(plmn, plmn_id);

        metrics = ogs_metrics_inst_new(sgwc_metrics_spec_by_plmn_apn[t],
                sgwc_metrics_spec_def_by_plmn_apn->num_labels,
                (const char *[]){ plmn_id, key->apn });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_plmn_apn,
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
    const char *rat = NULL, *gtp_if = NULL;

    ogs_assert(sess);
    ogs_assert(sess->gnode);

    if (sess->metrics_session_counted)
        return;

    if (!sgwc_metrics_plmn_from_sess(sess, &plmn_id))
        return;

    OGS_ADDR(&sess->gnode->addr, ipbuf);
    sgwc_metrics_inst_by_plmn_pgw_add(&plmn_id, ipbuf,
            SGWC_METR_BY_PLMN_PGW_GAUGE_SESSION_ACTIVE, 1);

    if (sess->session.name && sess->session.name[0]) {
        ogs_cpystrn(sess->metrics_apn, sess->session.name,
                sizeof(sess->metrics_apn));
        sess->metrics_apn_labeled = 1;
        sgwc_metrics_inst_by_plmn_apn_add(&plmn_id, sess->metrics_apn,
                SGWC_METR_BY_PLMN_APN_GAUGE_SESSION_ACTIVE, 1);
    }

    if (sgwc_sess_rat_metric_labels(sess, &rat, &gtp_if)) {
        ogs_cpystrn(sess->metrics_rat, rat, sizeof(sess->metrics_rat));
        ogs_cpystrn(sess->metrics_gtp_if, gtp_if,
                sizeof(sess->metrics_gtp_if));
        sess->metrics_rat_labeled = 1;
        sgwc_metrics_inst_by_rat_add(sess->metrics_rat, sess->metrics_gtp_if,
                SGWC_METR_GAUGE_SESSIONNBR_BY_RAT, 1);
    }

    sess->metrics_session_counted = 1;
}

static void sgwc_metrics_session_rat_dec(sgwc_sess_t *sess)
{
    if (!sess->metrics_rat_labeled)
        return;

    sgwc_metrics_inst_by_rat_add(sess->metrics_rat, sess->metrics_gtp_if,
            SGWC_METR_GAUGE_SESSIONNBR_BY_RAT, -1);
    sess->metrics_rat_labeled = 0;
    sess->metrics_rat[0] = '\0';
    sess->metrics_gtp_if[0] = '\0';
}

static void sgwc_metrics_session_apn_dec(sgwc_sess_t *sess,
        ogs_plmn_id_t *plmn_id)
{
    if (!sess->metrics_apn_labeled)
        return;

    sgwc_metrics_inst_by_plmn_apn_add(plmn_id, sess->metrics_apn,
            SGWC_METR_BY_PLMN_APN_GAUGE_SESSION_ACTIVE, -1);
    sess->metrics_apn_labeled = 0;
    sess->metrics_apn[0] = '\0';
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
        sgwc_metrics_session_rat_dec(sess);
        sess->metrics_apn_labeled = 0;
        sess->metrics_session_counted = 0;
        return;
    }

    if (!sgwc_metrics_plmn_from_sess(sess, &plmn_id)) {
        ogs_warn("SGWC session metrics dec skipped: no PLMN");
        sgwc_metrics_session_rat_dec(sess);
        sess->metrics_apn_labeled = 0;
        sess->metrics_session_counted = 0;
        return;
    }

    OGS_ADDR(&sess->gnode->addr, ipbuf);
    sgwc_metrics_inst_by_plmn_pgw_add(&plmn_id, ipbuf,
            SGWC_METR_BY_PLMN_PGW_GAUGE_SESSION_ACTIVE, -1);

    sgwc_metrics_session_apn_dec(sess, &plmn_id);
    sgwc_metrics_session_rat_dec(sess);
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

/* BY PLMN and APN */
const char *labels_plmn_apn[] = {
    "plmnid",
    "apn"
};

#define SGWC_METR_BY_PLMN_APN_GAUGE_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_GAUGE, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_plmn_apn), \
        .labels = labels_plmn_apn, \
    },

ogs_metrics_spec_t *sgwc_metrics_spec_by_plmn_apn[_SGWC_METR_BY_PLMN_APN_MAX];
ogs_hash_t *metrics_hash_by_plmn_apn = NULL;
sgwc_metrics_spec_def_t sgwc_metrics_spec_def_by_plmn_apn[_SGWC_METR_BY_PLMN_APN_MAX] = {
SGWC_METR_BY_PLMN_APN_GAUGE_ENTRY(
    SGWC_METR_BY_PLMN_APN_GAUGE_SESSION_ACTIVE,
    "sgwc_session_active_by_apn",
    "Active sessions per IMSI PLMN and APN on SGWC")
};

static void sgwc_metrics_init_by_plmn_apn(void)
{
    metrics_hash_by_plmn_apn = ogs_hash_make();
    ogs_assert(metrics_hash_by_plmn_apn);
}

/* BY RAT */
const char *labels_rat[] = {
    "rat",
    "gtp_if"
};

#define SGWC_METR_BY_RAT_GAUGE_ENTRY(_id, _name, _desc) \
    [_id] = { \
        .type = OGS_METRICS_METRIC_TYPE_GAUGE, \
        .name = _name, \
        .description = _desc, \
        .num_labels = OGS_ARRAY_SIZE(labels_rat), \
        .labels = labels_rat, \
    },

ogs_metrics_spec_t *sgwc_metrics_spec_by_rat[_SGWC_METR_BY_RAT_MAX];
ogs_hash_t *metrics_hash_by_rat = NULL;
sgwc_metrics_spec_def_t sgwc_metrics_spec_def_by_rat[_SGWC_METR_BY_RAT_MAX] = {
SGWC_METR_BY_RAT_GAUGE_ENTRY(
    SGWC_METR_GAUGE_SESSIONNBR_BY_RAT,
    "sgwc_sessionnbr_by_rat",
    "Active PDN sessions per RAT at the SGWC")
};

static void sgwc_metrics_init_by_rat(void)
{
    metrics_hash_by_rat = ogs_hash_make();
    ogs_assert(metrics_hash_by_rat);
}

void sgwc_metrics_inst_by_rat_add(
        const char *rat, const char *gtp_if,
        sgwc_metric_type_by_rat_t t, int val)
{
    ogs_metrics_inst_t *metrics = NULL;
    sgwc_metric_key_by_rat_t *rat_key;

    ogs_assert(rat);
    if (!metrics_hash_by_rat)
        return;

    rat_key = ogs_calloc(1, sizeof(*rat_key));
    ogs_assert(rat_key);

    ogs_cpystrn(rat_key->rat, rat, sizeof(rat_key->rat));
    ogs_cpystrn(rat_key->gtp_if, gtp_if ? gtp_if : "",
            sizeof(rat_key->gtp_if));
    rat_key->t = t;

    metrics = ogs_hash_get(metrics_hash_by_rat,
            rat_key, sizeof(*rat_key));

    if (!metrics) {
        metrics = ogs_metrics_inst_new(sgwc_metrics_spec_by_rat[t],
                sgwc_metrics_spec_def_by_rat->num_labels,
                (const char *[]){ rat_key->rat, rat_key->gtp_if });

        ogs_assert(metrics);
        ogs_hash_set(metrics_hash_by_rat,
                rat_key, sizeof(*rat_key), metrics);
    } else {
        ogs_free(rat_key);
    }

    ogs_metrics_inst_add(metrics, val);
}

void sgwc_metrics_init(void)
{
    unsigned int i;
    ogs_metrics_context_t *ctx = ogs_metrics_self();
    ogs_metrics_context_init();

    sgwc_metrics_init_spec(ctx, sgwc_metrics_spec_global,
            sgwc_metrics_spec_def_global, _SGWC_METR_GLOB_MAX);
    sgwc_metrics_init_spec(ctx, sgwc_metrics_spec_by_plmn,
            sgwc_metrics_spec_def_by_plmn, _SGWC_METR_BY_PLMN_MAX);
    sgwc_metrics_init_spec(ctx, sgwc_metrics_spec_by_plmn_pgw,
            sgwc_metrics_spec_def_by_plmn_pgw, _SGWC_METR_BY_PLMN_PGW_MAX);
    sgwc_metrics_init_spec(ctx, sgwc_metrics_spec_by_plmn_apn,
            sgwc_metrics_spec_def_by_plmn_apn, _SGWC_METR_BY_PLMN_APN_MAX);
    sgwc_metrics_init_spec(ctx, sgwc_metrics_spec_by_rat,
            sgwc_metrics_spec_def_by_rat, _SGWC_METR_BY_RAT_MAX);

    for (i = 0; i < _SGWC_METR_GLOB_MAX; i++)
        sgwc_metrics_inst_global[i] = ogs_metrics_inst_new(
                sgwc_metrics_spec_global[i], 0, NULL);

    sgwc_metrics_init_by_plmn();
    sgwc_metrics_init_by_plmn_pgw();
    sgwc_metrics_init_by_plmn_apn();
    sgwc_metrics_init_by_rat();
}

void sgwc_metrics_final(void)
{
    ogs_hash_index_t *hi;
    unsigned int i;

    for (i = 0; i < _SGWC_METR_GLOB_MAX; i++) {
        if (sgwc_metrics_inst_global[i]) {
            ogs_metrics_inst_free(sgwc_metrics_inst_global[i]);
            sgwc_metrics_inst_global[i] = NULL;
        }
    }

    if (metrics_hash_by_plmn) {
        for (hi = ogs_hash_first(metrics_hash_by_plmn); hi; hi = ogs_hash_next(hi)) {
            sgwc_metric_key_by_plmn_t *key =
                (sgwc_metric_key_by_plmn_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_plmn, key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_plmn);
        metrics_hash_by_plmn = NULL;
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
        metrics_hash_by_plmn_pgw = NULL;
    }
    if (metrics_hash_by_plmn_apn) {
        for (hi = ogs_hash_first(metrics_hash_by_plmn_apn); hi;
                hi = ogs_hash_next(hi)) {
            sgwc_metric_key_by_plmn_apn_t *key =
                (sgwc_metric_key_by_plmn_apn_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_plmn_apn, key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_plmn_apn);
        metrics_hash_by_plmn_apn = NULL;
    }
    if (metrics_hash_by_rat) {
        for (hi = ogs_hash_first(metrics_hash_by_rat); hi; hi = ogs_hash_next(hi)) {
            sgwc_metric_key_by_rat_t *key =
                (sgwc_metric_key_by_rat_t *)ogs_hash_this_key(hi);

            ogs_hash_set(metrics_hash_by_rat, key, sizeof(*key), NULL);
            ogs_free(key);
        }
        ogs_hash_destroy(metrics_hash_by_rat);
        metrics_hash_by_rat = NULL;
    }

    ogs_metrics_context_final();
}
