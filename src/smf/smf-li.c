/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "smf-li.h"

#include "ogs-metrics.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static ogs_li_config_t smf_li_config;
static ogs_li_target_set_t smf_li_targets;
static bool smf_li_initialized = false;

void smf_li_init(void)
{
    if (smf_li_initialized)
        return;

    memset(&smf_li_config, 0, sizeof(smf_li_config));
    smf_li_config.mdf.port = 9051;
    ogs_li_target_set_init(&smf_li_targets, OGS_LI_MAX_TARGETS);
    smf_li_initialized = true;
}

void smf_li_final(void)
{
    if (!smf_li_initialized)
        return;

    if (smf_li_config.mdf.addr)
        ogs_freeaddrinfo(smf_li_config.mdf.addr);

    ogs_li_target_set_final(&smf_li_targets);
    smf_li_initialized = false;
}

void smf_li_parse_config(ogs_yaml_iter_t *smf_iter)
{
    ogs_yaml_iter_t li_iter;
    const char *li_key = NULL;

    ogs_assert(smf_iter);

    ogs_yaml_iter_recurse(smf_iter, &li_iter);
    while (ogs_yaml_iter_next(&li_iter)) {
        li_key = ogs_yaml_iter_key(&li_iter);
        ogs_assert(li_key);

        if (!strcmp(li_key, "enabled")) {
            smf_li_config.enabled = ogs_yaml_iter_bool(&li_iter);
        } else if (!strcmp(li_key, "mdf")) {
            ogs_yaml_iter_t mdf_iter;
            ogs_yaml_iter_recurse(&li_iter, &mdf_iter);

            while (ogs_yaml_iter_next(&mdf_iter)) {
                const char *mdf_key = ogs_yaml_iter_key(&mdf_iter);
                ogs_assert(mdf_key);

                if (!strcmp(mdf_key, "addr") || !strcmp(mdf_key, "address")) {
                    yaml_node_t *node = yaml_document_get_node(
                            mdf_iter.document, mdf_iter.pair->value);
                    ogs_assert(node);
                    if (node->type == YAML_SCALAR_NODE) {
                        const char *v = (char *)node->data.scalar.value;
                        if (smf_li_config.mdf.addr)
                            ogs_freeaddrinfo(smf_li_config.mdf.addr);
                        ogs_assert(OGS_OK == ogs_addaddrinfo(
                                    &smf_li_config.mdf.addr, AF_UNSPEC,
                                    v, smf_li_config.mdf.port, 0));
                        ogs_cpystrn(smf_li_config.mdf.host, v,
                                sizeof(smf_li_config.mdf.host));
                    }
                } else if (!strcmp(mdf_key, "port")) {
                    const char *v = ogs_yaml_iter_value(&mdf_iter);
                    if (v)
                        smf_li_config.mdf.port = (uint16_t)atoi(v);
                }
            }
        }
    }

    if (smf_li_config.enabled) {
        ogs_info("SMF LI enabled (MDF %s:%u)",
                smf_li_config.mdf.host[0] ?
                    smf_li_config.mdf.host : "127.0.0.1",
                (unsigned)smf_li_config.mdf.port);
    }
}

static void smf_li_send_x2(ogs_li_target_t *target, ogs_li_event_e event,
        const char *detail)
{
    char x2[OGS_LI_MAX_JSON];

    ogs_assert(target);

    if (ogs_li_x2_encode_json(x2, sizeof(x2), OGS_LI_POI_SMF, event,
            target->liid, target->cin, target->imsi,
            target->msisdn[0] ? target->msisdn : NULL,
            detail) <= 0)
        return;

    if (ogs_li_http_post_json(&smf_li_config.mdf, "/mdf/x2", x2, 3000)
            != OGS_OK)
        ogs_warn("SMF LI X2 delivery failed [%s]", target->liid);
}

void smf_li_report_sess(smf_sess_t *sess, ogs_li_event_e event,
        const char *detail)
{
    smf_ue_t *smf_ue = NULL;
    ogs_li_target_t *target = NULL;

    if (!smf_li_initialized || !smf_li_config.enabled)
        return;

    ogs_assert(sess);
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    if (!smf_ue || !smf_ue->imsi_bcd[0])
        return;

    target = ogs_li_target_find_by_imsi(&smf_li_targets, smf_ue->imsi_bcd);
    if (!target)
        return;

    smf_li_send_x2(target, event, detail);
}

int smf_admin_li_target(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    const char *action = q && q->action ? q->action : NULL;
    const char *liid = q && q->liid ? q->liid : NULL;
    const char *imsi = q && q->imsi ? q->imsi : NULL;
    const char *msisdn = q && q->msisdn ? q->msisdn : NULL;
    ogs_li_target_t *target = NULL;
    int n;

    if (!action) {
        n = snprintf(body, body_cap, "{\"error\":\"action required\"}\n");
        *body_len = n > 0 ? (size_t)n : 0;
        return 400;
    }

    if (!strcmp(action, "add")) {
        if (!liid || !imsi) {
            n = snprintf(body, body_cap,
                    "{\"error\":\"liid and imsi required\"}\n");
            *body_len = n > 0 ? (size_t)n : 0;
            return 400;
        }

        target = ogs_li_target_add(&smf_li_targets, liid, imsi, msisdn);
        if (!target) {
            n = snprintf(body, body_cap,
                    "{\"error\":\"target pool full\"}\n");
            *body_len = n > 0 ? (size_t)n : 0;
            return 503;
        }

        n = snprintf(body, body_cap,
                "{\"status\":\"active\",\"liid\":\"%s\",\"imsi\":\"%s\"}\n",
                target->liid, target->imsi);
        *body_len = n > 0 ? (size_t)n : 0;
        return 200;
    }

    if (!strcmp(action, "remove")) {
        bool removed = false;

        if (liid)
            removed = ogs_li_target_remove_by_liid(&smf_li_targets, liid);
        else if (imsi)
            removed = ogs_li_target_remove_by_imsi(&smf_li_targets, imsi);

        if (!removed) {
            n = snprintf(body, body_cap,
                    "{\"error\":\"target not found\"}\n");
            *body_len = n > 0 ? (size_t)n : 0;
            return 404;
        }

        n = snprintf(body, body_cap, "{\"status\":\"removed\"}\n");
        *body_len = n > 0 ? (size_t)n : 0;
        return 200;
    }

    n = snprintf(body, body_cap, "{\"error\":\"unknown action\"}\n");
    *body_len = n > 0 ? (size_t)n : 0;
    return 400;
}
