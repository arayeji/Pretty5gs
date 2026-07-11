/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "mme-li.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static ogs_li_config_t mme_li_config;
static ogs_li_target_set_t mme_li_targets;
static bool mme_li_initialized = false;

void mme_li_init(void)
{
    if (mme_li_initialized)
        return;

    memset(&mme_li_config, 0, sizeof(mme_li_config));
    mme_li_config.mdf.port = 9051;
    ogs_cpystrn(mme_li_config.hi2_spool_dir, "/var/spool/open5gs/hi2",
            sizeof(mme_li_config.hi2_spool_dir));

    ogs_li_target_set_init(&mme_li_targets, OGS_LI_MAX_TARGETS);
    mme_li_initialized = true;
}

void mme_li_final(void)
{
    if (!mme_li_initialized)
        return;

    if (mme_li_config.mdf.addr)
        ogs_freeaddrinfo(mme_li_config.mdf.addr);

    ogs_li_target_set_final(&mme_li_targets);
    mme_li_initialized = false;
}

void mme_li_parse_config(ogs_yaml_iter_t *mme_iter)
{
    ogs_yaml_iter_t li_iter;
    const char *li_key = NULL;

    ogs_assert(mme_iter);

    ogs_yaml_iter_recurse(mme_iter, &li_iter);
    while (ogs_yaml_iter_next(&li_iter)) {
        li_key = ogs_yaml_iter_key(&li_iter);
        ogs_assert(li_key);

        if (!strcmp(li_key, "enabled")) {
            mme_li_config.enabled = ogs_yaml_iter_bool(&li_iter);
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
                        if (mme_li_config.mdf.addr)
                            ogs_freeaddrinfo(mme_li_config.mdf.addr);
                        ogs_assert(OGS_OK == ogs_addaddrinfo(
                                    &mme_li_config.mdf.addr, AF_UNSPEC,
                                    v, mme_li_config.mdf.port, 0));
                        ogs_cpystrn(mme_li_config.mdf.host, v,
                                sizeof(mme_li_config.mdf.host));
                    }
                } else if (!strcmp(mdf_key, "port")) {
                    const char *v = ogs_yaml_iter_value(&mdf_iter);
                    if (v)
                        mme_li_config.mdf.port = (uint16_t)atoi(v);
                }
            }
        }
    }

    if (mme_li_config.enabled) {
        ogs_info("MME LI enabled (MDF %s:%u)",
                mme_li_config.mdf.host[0] ?
                    mme_li_config.mdf.host : "127.0.0.1",
                (unsigned)mme_li_config.mdf.port);
    }
}

static void mme_li_send_x2(ogs_li_poi_e poi, ogs_li_event_e event,
        ogs_li_target_t *target, const char *detail)
{
    char x2[OGS_LI_MAX_JSON];

    ogs_assert(target);

    if (ogs_li_x2_encode_json(x2, sizeof(x2), poi, event,
            target->liid, target->cin, target->imsi,
            target->msisdn[0] ? target->msisdn : NULL,
            detail) <= 0)
        return;

    if (ogs_li_http_post_json(&mme_li_config.mdf, "/mdf/x2", x2, 3000)
            != OGS_OK) {
        ogs_warn("MME LI X2 delivery failed [%s]", target->liid);
    }
}

void mme_li_report(mme_ue_t *mme_ue, ogs_li_event_e event,
        const char *detail)
{
    ogs_li_target_t *target = NULL;

    if (!mme_li_initialized || !mme_li_config.enabled)
        return;

    ogs_assert(mme_ue);
    if (!mme_ue->imsi_bcd[0])
        return;

    target = ogs_li_target_find_by_imsi(&mme_li_targets, mme_ue->imsi_bcd);
    if (!target)
        return;

    mme_li_send_x2(OGS_LI_POI_MME, event, target, detail);
}

int mme_admin_li_target(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    const char *action = q && q->action ? q->action : NULL;
    const char *liid = q && q->liid ? q->liid : NULL;
    const char *imsi = q && q->imsi ? q->imsi : NULL;
    const char *msisdn = q && q->msisdn ? q->msisdn : NULL;
    ogs_li_target_t *target = NULL;
    int n;

    if (!action) {
        n = snprintf(body, body_cap,
                "{\"error\":\"action required\"}\n");
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

        target = ogs_li_target_add(&mme_li_targets, liid, imsi, msisdn);
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
            removed = ogs_li_target_remove_by_liid(&mme_li_targets, liid);
        else if (imsi)
            removed = ogs_li_target_remove_by_imsi(&mme_li_targets, imsi);

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

    if (!strcmp(action, "list")) {
        ogs_li_target_t *t = NULL;
        size_t off = 0;

        n = snprintf(body + off, body_cap - off, "{\"targets\":[");
        if (n > 0)
            off += (size_t)n;

        ogs_list_for_each(&mme_li_targets.list, t) {
            n = snprintf(body + off, body_cap - off,
                    "%s{\"liid\":\"%s\",\"imsi\":\"%s\"}",
                    off > 14 ? "," : "", t->liid, t->imsi);
            if (n <= 0 || (size_t)n >= body_cap - off)
                break;
            off += (size_t)n;
        }

        n = snprintf(body + off, body_cap - off, "]}\n");
        if (n > 0)
            off += (size_t)n;
        *body_len = off;
        return 200;
    }

    n = snprintf(body, body_cap, "{\"error\":\"unknown action\"}\n");
    *body_len = n > 0 ? (size_t)n : 0;
    return 400;
}
