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
#include "ogs-pfcp.h"
#include "context.h"
#include "sgwc-sm.h"

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

static void json_append_gtp_peers(cJSON *parent, const char *name,
        ogs_list_t *list)
{
    ogs_gtp_node_t *gnode = NULL;
    cJSON *arr = cJSON_CreateArray();
    const char *addr;

    ogs_assert(arr);
    cJSON_AddItemToObject(parent, name, arr);

    ogs_list_for_each(list, gnode) {
        addr = ogs_sockaddr_to_string_static(
                gnode->sa_list ? gnode->sa_list : &gnode->addr);
        if (addr && addr[0])
            cJSON_AddItemToArray(arr, cJSON_CreateString(addr));
    }
}

static void json_append_pfcp_peers(cJSON *parent, const char *name)
{
    ogs_pfcp_node_t *node = NULL;
    cJSON *arr = cJSON_CreateArray();
    const char *addr;

    ogs_assert(arr);
    cJSON_AddItemToObject(parent, name, arr);

    ogs_list_for_each(&ogs_pfcp_self()->pfcp_peer_list, node) {
        cJSON *entry = cJSON_CreateObject();

        addr = ogs_sockaddr_to_string_static(node->addr_list);
        if (!addr || !addr[0])
            continue;

        cJSON_AddStringToObject(entry, "addr", addr);
        cJSON_AddBoolToObject(entry, "associated",
                OGS_FSM_CHECK(&node->sm, sgwc_pfcp_state_associated));
        cJSON_AddItemToArray(arr, entry);
    }
}

char *sgwc_runtime_config_dump(void)
{
    sgwc_context_t *ctx = sgwc_self();
    cJSON *root = cJSON_CreateObject();
    cJSON *runtime = NULL;
    cJSON *gtpu = NULL;
    cJSON *pfcp = NULL;
    cJSON *inbound = NULL;
    cJSON *cdr = NULL;
    cJSON *rules = NULL;
    sgwc_sgwu_nwi_rewrite_rule_t *rule = NULL;
    char *out;

    ogs_assert(root);

    cJSON_AddStringToObject(root, "nf", "SGWC");
    cJSON_AddStringToObject(root, "config_file",
            ogs_app()->file ? ogs_app()->file : "");

    ogs_reload_audit_snapshot_to_json(root);

    runtime = cJSON_CreateObject();
    ogs_assert(runtime);
    cJSON_AddItemToObject(root, "runtime", runtime);

    cJSON_AddNumberToObject(runtime, "gtpc_echo_interval",
            ctx->gtpc_echo_interval);

    gtpu = cJSON_CreateObject();
    ogs_assert(gtpu);
    cJSON_AddItemToObject(runtime, "gtpu", gtpu);
    cJSON_AddBoolToObject(gtpu, "force_cp_teid", ctx->gtpu_force_cp_teid);
    cJSON_AddNumberToObject(gtpu, "teid_offset", ctx->gtpu_teid_offset);
    cJSON_AddNumberToObject(gtpu, "teid_range_indication",
            ctx->gtpu_teid_range_indication);
    cJSON_AddNumberToObject(gtpu, "teid_range", ctx->gtpu_teid_range);

    pfcp = cJSON_CreateObject();
    ogs_assert(pfcp);
    cJSON_AddItemToObject(runtime, "pfcp", pfcp);
    cJSON_AddBoolToObject(pfcp, "send_user_id", ctx->pfcp_send_user_id);

    inbound = cJSON_CreateObject();
    ogs_assert(inbound);
    cJSON_AddItemToObject(runtime, "inbound_roam", inbound);
    cJSON_AddNumberToObject(inbound, "gtpc_source_port",
            ctx->inbound_roam_gtpc_source_port);
    cJSON_AddBoolToObject(inbound, "gtpc_send_recovery_on_s5_csr",
            ctx->inbound_roam_gtpc_send_recovery_on_s5_csr);
    cJSON_AddNumberToObject(inbound, "teid_offset",
            ctx->inbound_roam_teid_offset);
    cJSON_AddBoolToObject(inbound, "gtpu_force_cp_teid",
            ctx->inbound_roam_gtpu_force_cp_teid);
    cJSON_AddNumberToObject(inbound, "gtpu_teid_offset",
            ctx->inbound_roam_gtpu_teid_offset);

    cdr = cJSON_CreateObject();
    ogs_assert(cdr);
    cJSON_AddItemToObject(runtime, "cdr", cdr);
    cJSON_AddBoolToObject(cdr, "enabled", ctx->cdr.enabled);
    cJSON_AddStringToObject(cdr, "spool_dir",
            ctx->cdr.spool_dir ? ctx->cdr.spool_dir : "");

    rules = cJSON_CreateArray();
    ogs_assert(rules);
    cJSON_AddItemToObject(runtime, "sgwu_nwi_rewrite_list", rules);
    ogs_list_for_each(&ctx->sgwu_nwi_rewrite_list, rule) {
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "match", rule->match ? rule->match : "");
        cJSON_AddStringToObject(entry, "replace",
                rule->replace ? rule->replace : "");
        cJSON_AddItemToArray(rules, entry);
    }

    json_append_gtp_peers(runtime, "mme_s11_list", &ctx->mme_s11_list);
    json_append_gtp_peers(runtime, "pgw_s5c_list", &ctx->pgw_s5c_list);
    json_append_pfcp_peers(runtime, "sgwu_pfcp_peers");

    cJSON_AddItemToObject(runtime, "trace_imsi", json_append_trace_imsi());

    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

size_t sgwc_dump_runtime_config(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    char *json;
    size_t n;

    (void)page;
    (void)page_size;
    (void)q;

    if (!buf || buflen == 0)
        return 0;

    json = sgwc_runtime_config_dump();
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
