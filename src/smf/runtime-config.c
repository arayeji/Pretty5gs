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
#include "smf-sm.h"

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

static void json_append_subnets(cJSON *runtime)
{
    ogs_pfcp_subnet_t *subnet = NULL;
    cJSON *arr = cJSON_CreateArray();

    ogs_assert(arr);
    cJSON_AddItemToObject(runtime, "session_subnets", arr);

    ogs_list_for_each(&ogs_pfcp_self()->subnet_list, subnet) {
        cJSON *entry = cJSON_CreateObject();
        cJSON *dnns = cJSON_CreateArray();
        char sub[OGS_ADDRSTRLEN + 8];
        char gw[OGS_ADDRSTRLEN];
        int i;

        if (subnet->family == AF_INET6)
            OGS_INET6_NTOP(&subnet->sub.sub[0], sub);
        else
            OGS_INET_NTOP(&subnet->sub.sub[0], sub);

        ogs_snprintf(sub + strlen(sub), sizeof(sub) - strlen(sub),
                "/%u", subnet->prefixlen);

        if (subnet->family == AF_INET6)
            OGS_INET6_NTOP(&subnet->gw.sub[0], gw);
        else
            OGS_INET_NTOP(&subnet->gw.sub[0], gw);

        cJSON_AddStringToObject(entry, "sub", sub);
        cJSON_AddStringToObject(entry, "gw", gw);
        cJSON_AddStringToObject(entry, "family",
                subnet->family == AF_INET6 ? "ipv6" : "ipv4");

        for (i = 0; i < subnet->num_of_dnn; i++)
            cJSON_AddItemToArray(dnns, cJSON_CreateString(subnet->dnn[i]));
        cJSON_AddItemToObject(entry, "dnn", dnns);
        cJSON_AddItemToArray(arr, entry);
    }
}

static void json_append_upf_peers(cJSON *runtime)
{
    ogs_pfcp_node_t *node = NULL;
    cJSON *arr = cJSON_CreateArray();
    const char *addr;

    ogs_assert(arr);
    cJSON_AddItemToObject(runtime, "upf_pfcp_peers", arr);

    ogs_list_for_each(&ogs_pfcp_self()->pfcp_peer_list, node) {
        cJSON *entry = cJSON_CreateObject();

        addr = ogs_sockaddr_to_string_static(node->addr_list);
        if (!addr || !addr[0])
            continue;

        cJSON_AddStringToObject(entry, "addr", addr);
        cJSON_AddBoolToObject(entry, "associated",
                OGS_FSM_CHECK(&node->sm, smf_pfcp_state_associated));
        cJSON_AddItemToArray(arr, entry);
    }
}

static void json_append_radius(cJSON *runtime, smf_context_t *ctx)
{
    smf_radius_config_t *r = &ctx->radius;
    cJSON *obj = cJSON_CreateObject();
    cJSON *servers = cJSON_CreateArray();
    int i;

    ogs_assert(obj);
    cJSON_AddItemToObject(runtime, "radius", obj);

    cJSON_AddBoolToObject(obj, "enabled", r->enabled);
    cJSON_AddNumberToObject(obj, "num_servers", r->num_servers);
    cJSON_AddItemToObject(obj, "servers", servers);

    for (i = 0; i < r->num_servers; i++) {
        cJSON *srv = cJSON_CreateObject();
        cJSON_AddStringToObject(srv, "host",
                r->servers[i].host ? r->servers[i].host : "");
        cJSON_AddNumberToObject(srv, "auth_port", r->servers[i].auth_port);
        cJSON_AddNumberToObject(srv, "acct_port", r->servers[i].acct_port);
        cJSON_AddBoolToObject(srv, "is_primary", r->servers[i].is_primary);
        cJSON_AddItemToArray(servers, srv);
    }

    cJSON_AddBoolToObject(obj, "pod_enabled", r->pod_enabled);
    cJSON_AddStringToObject(obj, "pod_bind", r->pod_bind ? r->pod_bind : "");
    cJSON_AddNumberToObject(obj, "pod_port", r->pod_port);
}

static void json_append_dns_list(cJSON *parent, const char *name,
        const char **dns, int max)
{
    cJSON *arr = cJSON_CreateArray();
    int i;

    ogs_assert(arr);
    cJSON_AddItemToObject(parent, name, arr);
    for (i = 0; i < max; i++) {
        if (dns[i] && dns[i][0])
            cJSON_AddItemToArray(arr, cJSON_CreateString(dns[i]));
    }
}

char *smf_runtime_config_dump(void)
{
    smf_context_t *ctx = smf_self();
    cJSON *root = cJSON_CreateObject();
    cJSON *runtime = NULL;
    cJSON *cdr = NULL;
    char *out;

    ogs_assert(root);

    cJSON_AddStringToObject(root, "nf", "SMF");
    cJSON_AddStringToObject(root, "config_file",
            ogs_app()->file ? ogs_app()->file : "");

    ogs_reload_audit_snapshot_to_json(root);

    runtime = cJSON_CreateObject();
    ogs_assert(runtime);
    cJSON_AddItemToObject(root, "runtime", runtime);

    json_append_dns_list(runtime, "dns", ctx->dns, MAX_NUM_OF_DNS);
    json_append_dns_list(runtime, "dns6", ctx->dns6, MAX_NUM_OF_DNS);
    cJSON_AddNumberToObject(runtime, "mtu", ctx->mtu);
    cJSON_AddNumberToObject(runtime, "default_pdr_precedence",
            ctx->default_pdr_precedence);

    json_append_subnets(runtime);
    json_append_upf_peers(runtime);
    json_append_radius(runtime, ctx);

    cdr = cJSON_CreateObject();
    ogs_assert(cdr);
    cJSON_AddItemToObject(runtime, "cdr", cdr);
    cJSON_AddBoolToObject(cdr, "enabled", ctx->cdr.enabled);
    cJSON_AddStringToObject(cdr, "spool_dir",
            ctx->cdr.spool_dir ? ctx->cdr.spool_dir : "");

    cJSON_AddItemToObject(runtime, "trace_imsi", json_append_trace_imsi());

    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

size_t smf_dump_runtime_config(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    char *json;
    size_t n;

    (void)page;
    (void)page_size;
    (void)q;

    if (!buf || buflen == 0)
        return 0;

    json = smf_runtime_config_dump();
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
