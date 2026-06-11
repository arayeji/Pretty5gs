/*
 * Copyright (C) 2026 by Open5GS contributors
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "runtime-config.h"

#include "ogs-app.h"
#include "ogs-proto.h"
#include "mme-context.h"
#include "mme-timer.h"

#include "sbi/openapi/external/cJSON.h"

#include <string.h>

static cJSON *json_append_trace_imsi(void)
{
    cJSON *arr = cJSON_CreateArray();
    int i, n;
    char prefix[OGS_MAX_IMSI_BCD_LEN + 1];

    ogs_assert(arr);

    n = ogs_trace_filter_count();
    for (i = 0; i < n; i++) {
        if (ogs_trace_filter_get(i, prefix, sizeof(prefix)) != OGS_OK)
            continue;
        cJSON_AddItemToArray(arr, cJSON_CreateString(prefix));
    }
    return arr;
}

static void json_append_timer(cJSON *parent, const char *name, mme_timer_e id)
{
    mme_timer_cfg_t *cfg = mme_timer_cfg(id);
    cJSON *obj;

    if (!cfg || !cfg->have)
        return;

    obj = cJSON_CreateObject();
    ogs_assert(obj);
    cJSON_AddNumberToObject(obj, "value_seconds",
            (double)ogs_time_to_sec(cfg->duration));
    cJSON_AddNumberToObject(obj, "max_count", cfg->max_count);
    cJSON_AddItemToObject(parent, name, obj);
}

static void json_append_served_tai(cJSON *runtime, mme_context_t *ctx)
{
    cJSON *arr = cJSON_CreateArray();
    int i;

    ogs_assert(arr);
    cJSON_AddItemToObject(runtime, "served_tai", arr);
    cJSON_AddNumberToObject(runtime, "served_tai_count", ctx->num_of_served_tai);

    for (i = 0; i < ctx->num_of_served_tai; i++) {
        ogs_eps_tai0_list_t *list0 = ctx->served_tai[i].list0;
        ogs_eps_tai1_list_t *list1 = &ctx->served_tai[i].list1;
        ogs_eps_tai2_list_t *list2 = &ctx->served_tai[i].list2;
        int j, k;

        if (!list0)
            continue;

        for (j = 0; j < (int)ogs_app_max_eps_tai0_partial_list() &&
                list0->tai[j].num; j++) {
            char plmn[OGS_PLMNIDSTRLEN];

            ogs_plmn_id_to_string(&list0->tai[j].plmn_id, plmn);
            for (k = 0; k < list0->tai[j].num; k++) {
                cJSON *entry = cJSON_CreateObject();
                char tac[8];

                ogs_snprintf(tac, sizeof(tac), "%04x", list0->tai[j].tac[k]);
                cJSON_AddStringToObject(entry, "plmn", plmn);
                cJSON_AddStringToObject(entry, "tac", tac);
                cJSON_AddStringToObject(entry, "list_type", "0");
                cJSON_AddItemToArray(arr, entry);
            }
        }

        for (j = 0; list1->tai[j].num; j++) {
            cJSON *entry = cJSON_CreateObject();
            char plmn[OGS_PLMNIDSTRLEN];
            char tac[8];

            ogs_plmn_id_to_string(&list1->tai[j].plmn_id, plmn);
            ogs_snprintf(tac, sizeof(tac), "%04x", list1->tai[j].tac);
            cJSON_AddStringToObject(entry, "plmn", plmn);
            cJSON_AddStringToObject(entry, "tac", tac);
            cJSON_AddStringToObject(entry, "list_type", "1");
            cJSON_AddNumberToObject(entry, "tac_count", list1->tai[j].num);
            cJSON_AddItemToArray(arr, entry);
        }

        if (list2->num) {
            for (j = 0; j < list2->num; j++) {
                cJSON *entry = cJSON_CreateObject();
                char plmn[OGS_PLMNIDSTRLEN];
                char tac[8];

                ogs_plmn_id_to_string(&list2->tai[j].plmn_id, plmn);
                ogs_snprintf(tac, sizeof(tac), "%04x", list2->tai[j].tac);
                cJSON_AddStringToObject(entry, "plmn", plmn);
                cJSON_AddStringToObject(entry, "tac", tac);
                cJSON_AddStringToObject(entry, "list_type", "2");
                cJSON_AddItemToArray(arr, entry);
            }
        }
    }
}

static void json_append_access_control(cJSON *runtime, mme_context_t *ctx)
{
    cJSON *arr = cJSON_CreateArray();
    int i;

    ogs_assert(arr);
    cJSON_AddItemToObject(runtime, "access_control", arr);

    for (i = 0; i < ctx->num_of_access_control; i++) {
        mme_access_control_t *ac = &ctx->access_control[i];
        cJSON *entry = cJSON_CreateObject();
        char plmn[OGS_PLMNIDSTRLEN];

        if (ac->plmn_id_configured)
            ogs_plmn_id_to_string(&ac->plmn_id, plmn);
        else
            plmn[0] = '\0';

        cJSON_AddStringToObject(entry, "plmn", plmn);
        cJSON_AddStringToObject(entry, "imsi_prefix",
                ac->imsi_prefix[0] ? ac->imsi_prefix : "");
        cJSON_AddNumberToObject(entry, "reject_cause", ac->reject_cause);
        cJSON_AddBoolToObject(entry, "tac_configured",
                ac->tac_hash && ogs_hash_count(ac->tac_hash) > 0);
        cJSON_AddBoolToObject(entry, "enb_configured",
                ac->enb_id_hash && ogs_hash_count(ac->enb_id_hash) > 0);
        cJSON_AddItemToArray(arr, entry);
    }
}

static void json_append_peer_list(cJSON *parent, const char *name,
        ogs_list_t *list, bool pgw_style)
{
    cJSON *arr = cJSON_CreateArray();
    const char *addr;

    ogs_assert(arr);
    cJSON_AddItemToObject(parent, name, arr);

    if (pgw_style) {
        mme_pgw_t *pgw = NULL;

        ogs_list_for_each(list, pgw) {
            addr = ogs_sockaddr_to_string_static(pgw->sa_list);
            if (addr && addr[0])
                cJSON_AddItemToArray(arr, cJSON_CreateString(addr));
        }
    } else {
        mme_sgw_t *sgw = NULL;

        ogs_list_for_each(list, sgw) {
            addr = ogs_sockaddr_to_string_static(
                    sgw->gnode.sa_list ? sgw->gnode.sa_list : &sgw->gnode.addr);
            if (addr && addr[0])
                cJSON_AddItemToArray(arr, cJSON_CreateString(addr));
        }
    }
}

char *mme_runtime_config_dump(void)
{
    mme_context_t *ctx = mme_self();
    cJSON *root = cJSON_CreateObject();
    cJSON *runtime = NULL;
    cJSON *time = NULL;
    cJSON *attach = NULL;
    cJSON *ambr = NULL;
    cJSON *idle = NULL;
    cJSON *imsi_acl = NULL;
    cJSON *eplmn = NULL;
    char *out;
    int i;

    ogs_assert(root);

    cJSON_AddStringToObject(root, "nf", "MME");
    cJSON_AddStringToObject(root, "config_file",
            ogs_app()->file ? ogs_app()->file : "");

    ogs_reload_audit_snapshot_to_json(root);

    runtime = cJSON_CreateObject();
    ogs_assert(runtime);
    cJSON_AddItemToObject(root, "runtime", runtime);

    time = cJSON_CreateObject();
    ogs_assert(time);
    cJSON_AddItemToObject(runtime, "time", time);

    cJSON_AddNumberToObject(time, "t3412",
            (double)ogs_time_to_sec(ctx->time.t3412.value));
    cJSON_AddNumberToObject(time, "t3402",
            (double)ogs_time_to_sec(ctx->time.t3402.value));
    cJSON_AddNumberToObject(time, "t3423",
            (double)ogs_time_to_sec(ctx->time.t3423.value));

    json_append_timer(time, "t3413", MME_TIMER_T3413);
    json_append_timer(time, "t3422", MME_TIMER_T3422);

    idle = cJSON_CreateObject();
    ogs_assert(idle);
    cJSON_AddItemToObject(time, "idle", idle);
    cJSON_AddNumberToObject(idle, "mobile_reachable_margin",
            (double)ogs_time_to_sec(ctx->time.idle.mobile_reachable_margin));
    cJSON_AddNumberToObject(idle, "implicit_detach_margin",
            (double)ogs_time_to_sec(ctx->time.idle.implicit_detach_margin));

    cJSON_AddNumberToObject(runtime, "gtpc_echo_interval",
            ctx->gtpc_echo_interval);

    attach = cJSON_CreateObject();
    ogs_assert(attach);
    cJSON_AddItemToObject(runtime, "attach_accept", attach);
    cJSON_AddBoolToObject(attach, "tai_list_serving_only",
            ctx->attach_accept.tai_list_serving_only);
    cJSON_AddBoolToObject(attach, "equivalent_plmn",
            ctx->attach_accept.equivalent_plmn);
    cJSON_AddBoolToObject(attach, "equivalent_plmn_serving_only",
            ctx->attach_accept.equivalent_plmn_serving_only);
    cJSON_AddBoolToObject(attach, "ims_voice_over_ps",
            ctx->attach_accept.ims_voice_over_ps);
    cJSON_AddBoolToObject(attach, "t3402", ctx->attach_accept.t3402);
    cJSON_AddBoolToObject(attach, "esm_cause_pdn_type_mismatch",
            ctx->attach_accept.esm_cause_pdn_type_mismatch);
    cJSON_AddBoolToObject(attach, "legacy_gprs_qos",
            ctx->attach_accept.legacy_gprs_qos);

    ambr = cJSON_CreateObject();
    ogs_assert(ambr);
    cJSON_AddItemToObject(runtime, "ambr_limit", ambr);
    cJSON_AddBoolToObject(ambr, "enabled", ctx->ambr_limit.enabled);
    cJSON_AddBoolToObject(ambr, "force", ctx->ambr_limit.force);
    cJSON_AddNumberToObject(ambr, "downlink_bps", ctx->ambr_limit.downlink_bps);
    cJSON_AddNumberToObject(ambr, "uplink_bps", ctx->ambr_limit.uplink_bps);

    cJSON_AddBoolToObject(runtime, "require_hss_map", ctx->require_hss_map);

    json_append_served_tai(runtime, ctx);
    json_append_access_control(runtime, ctx);

    cJSON_AddNumberToObject(runtime, "imsi_acl_count", ctx->num_of_imsi_acl);
    imsi_acl = cJSON_CreateArray();
    ogs_assert(imsi_acl);
    cJSON_AddItemToObject(runtime, "imsi_acl", imsi_acl);
    for (i = 0; i < ctx->num_of_imsi_acl; i++)
        cJSON_AddItemToArray(imsi_acl,
                cJSON_CreateString(ctx->imsi_acl[i].prefix));

    cJSON_AddNumberToObject(runtime, "eplmn_count", ctx->num_of_eplmn);
    eplmn = cJSON_CreateArray();
    ogs_assert(eplmn);
    cJSON_AddItemToObject(runtime, "eplmn", eplmn);
    for (i = 0; i < ctx->num_of_eplmn; i++) {
        char plmn[OGS_PLMNIDSTRLEN];
        ogs_plmn_id_to_string(&ctx->eplmn[i], plmn);
        cJSON_AddItemToArray(eplmn, cJSON_CreateString(plmn));
    }

    json_append_peer_list(runtime, "sgw_list", &ctx->sgw_list, false);
    json_append_peer_list(runtime, "pgw_list", &ctx->pgw_list, true);

    cJSON_AddItemToObject(runtime, "trace_imsi", json_append_trace_imsi());

    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

size_t mme_dump_runtime_config(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    char *json;
    size_t n;

    (void)page;
    (void)page_size;
    (void)q;

    if (!buf || buflen == 0)
        return 0;

    json = mme_runtime_config_dump();
    if (!json)
        return 0;

    n = strlen(json);
    if (n + 2 < buflen) {
        memcpy(buf, json, n);
        buf[n++] = '\n';
        buf[n] = '\0';
    } else if (buflen > 0) {
        memcpy(buf, json, buflen - 1);
        buf[buflen - 1] = '\0';
        n = buflen - 1;
    }

    ogs_free(json);
    return n;
}
