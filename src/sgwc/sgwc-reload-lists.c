/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "context.h"
#include "sgwc-reload-lists.h"
#include "pfcp-path.h"
#include "ga-writer.h"

volatile int sgwc_reload_lists_changed = 0;

static bool sgwc_nwi_reload_cleared = false;

static bool sgwc_reload_sockaddr_lists_match(
        ogs_sockaddr_t *configured, ogs_sockaddr_t *peer_list,
        const ogs_sockaddr_t *peer_single)
{
    if (!configured)
        return false;

    if (ogs_sockaddr_check_any_match(configured, peer_list, peer_single, true))
        return true;
    if (ogs_sockaddr_check_any_match(configured, peer_list, peer_single, false))
        return true;

    return false;
}

static void sgwc_reload_cdr_cfg_clear(sgwc_cdr_config_t *cfg)
{
    ogs_assert(cfg);

    if (cfg->spool_dir) {
        ogs_free((void *)cfg->spool_dir);
        cfg->spool_dir = NULL;
    }
    if (cfg->node_id) {
        ogs_free((void *)cfg->node_id);
        cfg->node_id = NULL;
    }
    if (cfg->local_address) {
        ogs_free((void *)cfg->local_address);
        cfg->local_address = NULL;
    }
}

static void sgwc_reload_parse_cdr(ogs_yaml_iter_t *sgwc_iter,
        sgwc_cdr_config_t *cfg)
{
    ogs_yaml_iter_t c_iter;

    ogs_assert(sgwc_iter);
    ogs_assert(cfg);

    memset(cfg, 0, sizeof(*cfg));
    cfg->interim_interval_s = 300;
    cfg->rotate_max_records = 100;
    cfg->rotate_max_bytes = 65536;
    cfg->rotate_max_seconds = 30;
    cfg->triggers = SGWC_CDR_TRIG_START | SGWC_CDR_TRIG_INTERIM |
            SGWC_CDR_TRIG_STOP;

    ogs_yaml_iter_recurse(sgwc_iter, &c_iter);
    while (ogs_yaml_iter_next(&c_iter)) {
        const char *ck = ogs_yaml_iter_key(&c_iter);
        /* value may be a mapping/sequence: ogs_yaml_iter_value() would
         * abort the daemon on non-scalar nodes (SIGHUP crash) */
        const char *cv = ogs_yaml_iter_has_value(&c_iter) ?
                ogs_yaml_iter_value(&c_iter) : NULL;

        ogs_assert(ck);
        if (!strcmp(ck, "enabled")) {
            cfg->enabled = ogs_yaml_iter_bool(&c_iter);
        } else if (!strcmp(ck, "spool_dir") ||
                !strcmp(ck, "directory")) {
            cfg->spool_dir = cv ? ogs_strdup(cv) : NULL;
        } else if (!strcmp(ck, "node_id") ||
                !strcmp(ck, "nodeid")) {
            cfg->node_id = cv ? ogs_strdup(cv) : NULL;
        } else if (!strcmp(ck, "local_address") ||
                !strcmp(ck, "sgw_address")) {
            cfg->local_address = cv ? ogs_strdup(cv) : NULL;
        } else if (!strcmp(ck, "interim_interval_s") ||
                !strcmp(ck, "interim_interval")) {
            if (cv)
                cfg->interim_interval_s = (uint32_t)atoi(cv);
        } else if (!strcmp(ck, "max_records")) {
            if (cv)
                cfg->rotate_max_records = (uint32_t)atoi(cv);
        } else if (!strcmp(ck, "max_bytes")) {
            if (cv)
                cfg->rotate_max_bytes = (uint32_t)atoi(cv);
        } else if (!strcmp(ck, "max_seconds")) {
            if (cv)
                cfg->rotate_max_seconds = (uint32_t)atoi(cv);
        } else if (!strcmp(ck, "triggers")) {
            uint32_t t = 0;

            if (cv) {
                const char *p = cv;

                while (*p) {
                    while (*p == ' ' || *p == ',') p++;
                    if (!strncmp(p, "start", 5)) {
                        t |= SGWC_CDR_TRIG_START; p += 5;
                    } else if (!strncmp(p, "interim", 7)) {
                        t |= SGWC_CDR_TRIG_INTERIM; p += 7;
                    } else if (!strncmp(p, "stop", 4)) {
                        t |= SGWC_CDR_TRIG_STOP; p += 4;
                    } else {
                        while (*p && *p != ',') p++;
                    }
                }
            }
            if (t)
                cfg->triggers = t;
        }
    }
}

static void sgwc_reload_cdr_replace(ogs_yaml_iter_t *sgwc_iter)
{
    sgwc_cdr_config_t cfg;

    sgwc_reload_parse_cdr(sgwc_iter, &cfg);
    (void)sgwc_ga_writer_apply_runtime(&cfg);
    sgwc_reload_cdr_cfg_clear(&cfg);
    sgwc_reload_lists_changed++;
    ogs_reload_audit_note("sgwc.cdr configuration replaced");
}

static bool sgwc_reload_nwi_rule_key(const char *key)
{
    return !strcmp(key, "sgwu_nwi_rewrite") ||
           !strcmp(key, "nwi_rewrite") ||
           !strcmp(key, "pfcp_nwi_rewrite");
}

static int sgwc_reload_nwi_append(ogs_yaml_iter_t *parent_iter)
{
    ogs_yaml_iter_t rule_array, rule_iter;
    int added = 0;
    static int rule_entry_idx;

    if (!sgwc_nwi_reload_cleared) {
        sgwc_sgwu_nwi_rewrite_clear();
        sgwc_nwi_reload_cleared = true;
        rule_entry_idx = 0;
    }

    ogs_yaml_iter_recurse(parent_iter, &rule_array);
    do {
        const char *match = NULL;
        const char *replace = NULL;
        const char *order_v = NULL;
        sgwc_sgwu_nwi_rewrite_rule_t *rule = NULL;

        if (ogs_yaml_iter_type(&rule_array) == YAML_MAPPING_NODE) {
            memcpy(&rule_iter, &rule_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(&rule_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&rule_array))
                break;
            ogs_yaml_iter_recurse(&rule_array, &rule_iter);
        } else {
            break;
        }

        while (ogs_yaml_iter_next(&rule_iter)) {
            const char *key = ogs_yaml_iter_key(&rule_iter);
            ogs_assert(key);
            if (!strcmp(key, "match") || !strcmp(key, "from"))
                match = ogs_yaml_iter_value(&rule_iter);
            else if (!strcmp(key, "replace") || !strcmp(key, "to"))
                replace = ogs_yaml_iter_value(&rule_iter);
            else if (!strcmp(key, "order"))
                order_v = ogs_yaml_iter_value(&rule_iter);
        }

        if (!match || !replace || !match[0] || !replace[0])
            continue;

        rule = ogs_calloc(1, sizeof(*rule));
        ogs_assert(rule);
        rule->match = ogs_strdup(match);
        rule->replace = ogs_strdup(replace);
        ogs_assert(rule->match && rule->replace);
        rule->selection_order = ogs_pfcp_entry_selection_order(
                rule_entry_idx, order_v);
        rule_entry_idx++;
        /* Workers read this list under the same lock (nwi_rewrite_apply). */
        sgwc_ctx_lock();
        ogs_list_add(&sgwc_self()->sgwu_nwi_rewrite_list, rule);
        sgwc_ctx_unlock();
        added++;
        sgwc_reload_lists_changed++;
    } while (ogs_yaml_iter_type(&rule_array) == YAML_SEQUENCE_NODE);

    return added;
}

static void sgwc_reload_gtpu_key(
        const char *key, ogs_yaml_iter_t *iter,
        bool *force_cp_teid,
        uint32_t *teid_offset,
        uint8_t *teid_range_indication,
        uint8_t *teid_range)
{
    const char *value = NULL;

    ogs_assert(key);
    ogs_assert(iter);

    if (!strcmp(key, "force_cp_teid") || !strcmp(key, "cp_teid")) {
        *force_cp_teid = ogs_yaml_iter_bool(iter);
    } else if (!strcmp(key, "teid_offset")) {
        value = ogs_yaml_iter_value(iter);
        if (value)
            *teid_offset = (uint32_t)strtoul(value, NULL, 0);
    } else if (!strcmp(key, "teid_range_indication")) {
        value = ogs_yaml_iter_value(iter);
        if (value) {
            int teidri = atoi(value);

            if (teidri >= 1 && teidri <= 7)
                *teid_range_indication = (uint8_t)teidri;
        }
    } else if (!strcmp(key, "teid_range")) {
        value = ogs_yaml_iter_value(iter);
        if (value)
            *teid_range = (uint8_t)strtoul(value, NULL, 0);
    }
}

static ogs_pfcp_node_t *sgwc_reload_pfcp_peer_find(ogs_sockaddr_t *addr)
{
    ogs_pfcp_node_t *node = NULL;

    ogs_assert(addr);

    ogs_list_for_each(&ogs_pfcp_self()->pfcp_peer_list, node) {
        if (node->config_addr &&
                sgwc_reload_sockaddr_lists_match(
                    addr, node->config_addr, NULL))
            return node;
    }

    return NULL;
}

static int sgwc_reload_sgwu_peer_add_only(
        ogs_yaml_iter_t *sgwu_array, int *entry_idx)
{
    yaml_document_t *document = ogs_app()->document;
    int added = 0;

    ogs_assert(sgwu_array);
    ogs_assert(entry_idx);

    do {
        ogs_yaml_iter_t remote_iter;
        int family = AF_UNSPEC;
        int i, num = 0;
        uint16_t port = ogs_pfcp_self()->pfcp_port;
        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
        uint16_t tac[OGS_MAX_NUM_OF_TAI];
        uint8_t num_of_tac = 0;
        const char *dnn[OGS_MAX_NUM_OF_DNN];
        int num_of_dnn = 0;
        const char *order_v = NULL;
        ogs_sockaddr_t *addr = NULL;
        ogs_pfcp_node_t *node = NULL;
        int rv;

        if (ogs_yaml_iter_type(sgwu_array) == YAML_MAPPING_NODE) {
            memcpy(&remote_iter, sgwu_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(sgwu_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(sgwu_array))
                break;
            ogs_yaml_iter_recurse(sgwu_array, &remote_iter);
        } else {
            break;
        }

        memset(hostname, 0, sizeof(hostname));
        memset(tac, 0, sizeof(tac));
        memset(dnn, 0, sizeof(dnn));

        while (ogs_yaml_iter_next(&remote_iter)) {
            const char *remote_key = ogs_yaml_iter_key(&remote_iter);
            ogs_assert(remote_key);

            if (!strcmp(remote_key, "family")) {
                const char *v = ogs_yaml_iter_value(&remote_iter);
                if (v)
                    family = atoi(v);
            } else if (!strcmp(remote_key, "address")) {
                ogs_yaml_iter_t hostname_iter;

                ogs_yaml_iter_recurse(&remote_iter, &hostname_iter);
                do {
                    if (ogs_yaml_iter_type(&hostname_iter) ==
                            YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&hostname_iter))
                            break;
                    }
                    ogs_assert(num < OGS_MAX_NUM_OF_HOSTNAME);
                    hostname[num++] = ogs_yaml_iter_value(&hostname_iter);
                } while (ogs_yaml_iter_type(&hostname_iter) ==
                        YAML_SEQUENCE_NODE);
            } else if (!strcmp(remote_key, "port")) {
                const char *v = ogs_yaml_iter_value(&remote_iter);
                if (v)
                    port = atoi(v);
            } else if (!strcmp(remote_key, "tac")) {
                ogs_yaml_iter_t tac_iter;

                ogs_yaml_iter_recurse(&remote_iter, &tac_iter);
                do {
                    const char *v = NULL;

                    ogs_assert(num_of_tac < OGS_MAX_NUM_OF_TAI);
                    if (ogs_yaml_iter_type(&tac_iter) ==
                            YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&tac_iter))
                            break;
                    }
                    v = ogs_yaml_iter_value(&tac_iter);
                    if (v)
                        tac[num_of_tac++] = (uint16_t)atoi(v);
                } while (ogs_yaml_iter_type(&tac_iter) ==
                        YAML_SEQUENCE_NODE);
            } else if (!strcmp(remote_key, "apn") ||
                    !strcmp(remote_key, "dnn")) {
                yaml_node_t *dnn_node = yaml_document_get_node(
                        document, remote_iter.pair->value);

                if (dnn_node && dnn_node->type == YAML_SEQUENCE_NODE) {
                    ogs_yaml_iter_t dnn_iter;

                    ogs_yaml_iter_recurse(&remote_iter, &dnn_iter);
                    while (ogs_yaml_iter_next(&dnn_iter)) {
                        const char *v = ogs_yaml_iter_value(&dnn_iter);

                        if (num_of_dnn >= OGS_MAX_NUM_OF_DNN)
                            break;
                        if (v)
                            dnn[num_of_dnn++] = v;
                    }
                } else if (dnn_node && dnn_node->type == YAML_SCALAR_NODE) {
                    const char *v = (const char *)dnn_node->data.scalar.value;

                    if (v && num_of_dnn < OGS_MAX_NUM_OF_DNN)
                        dnn[num_of_dnn++] = v;
                }
            } else if (!strcmp(remote_key, "order")) {
                order_v = ogs_yaml_iter_value(&remote_iter);
            }
        }

        addr = NULL;
        for (i = 0; i < num; i++) {
            rv = ogs_addaddrinfo(&addr, family, hostname[i], port, 0);
            ogs_assert(rv == OGS_OK);
        }

        ogs_filter_ip_version(&addr,
                ogs_global_conf()->parameter.no_ipv4,
                ogs_global_conf()->parameter.no_ipv6,
                ogs_global_conf()->parameter.prefer_ipv4);

        if (!addr)
            continue;

        node = sgwc_reload_pfcp_peer_find(addr);
        if (node) {
            node->selection_order = ogs_pfcp_entry_selection_order(
                    *entry_idx, order_v);
            (*entry_idx)++;
            ogs_freeaddrinfo(addr);
            continue;
        }

        node = sgwc_pfcp_admin_add_sgwu_peer(addr, dnn, num_of_dnn);
        if (!node) {
            ogs_freeaddrinfo(addr);
            continue;
        }

        node->num_of_tac = num_of_tac;
        if (num_of_tac)
            memcpy(node->tac, tac, sizeof(node->tac));

        node->selection_order = ogs_pfcp_entry_selection_order(
                *entry_idx, order_v);
        (*entry_idx)++;

        ogs_reload_audit_note(" SGW-U peer added [%s]:%d",
                ogs_sockaddr_to_string_static(addr), OGS_PORT(addr));
        added++;
        sgwc_reload_lists_changed++;
    } while (ogs_yaml_iter_type(sgwu_array) == YAML_SEQUENCE_NODE);

    return added;
}

static int sgwc_reload_pfcp_sgwu_add_only(ogs_yaml_iter_t *pfcp_iter)
{
    ogs_yaml_iter_t pfcp_sub_iter;
    int entry_idx = 0;

    ogs_yaml_iter_recurse(pfcp_iter, &pfcp_sub_iter);
    while (ogs_yaml_iter_next(&pfcp_sub_iter)) {
        const char *pfcp_key = ogs_yaml_iter_key(&pfcp_sub_iter);
        ogs_assert(pfcp_key);

        if (!strcmp(pfcp_key, "client")) {
            ogs_yaml_iter_t client_iter;

            ogs_yaml_iter_recurse(&pfcp_sub_iter, &client_iter);
            while (ogs_yaml_iter_next(&client_iter)) {
                const char *client_key = ogs_yaml_iter_key(&client_iter);
                ogs_assert(client_key);

                if (!strcmp(client_key, "sgwu")) {
                    ogs_yaml_iter_t sgwu_array;

                    ogs_yaml_iter_recurse(&client_iter, &sgwu_array);
                    return sgwc_reload_sgwu_peer_add_only(
                            &sgwu_array, &entry_idx);
                }
            }
        } else if (!strcmp(pfcp_key, "server")) {
            ogs_reload_audit_warn("sgwc.pfcp.server ignored (bind address)");
        } else if (!strcmp(pfcp_key, "send_user_id") ||
                !strcmp(pfcp_key, "send_user_id_to_sgwu")) {
            sgwc_context_t *self = sgwc_self();

            self->pfcp_send_user_id = ogs_yaml_iter_bool(&pfcp_sub_iter);
            sgwc_reload_lists_changed++;
            ogs_reload_audit_note("sgwc.pfcp.send_user_id=%s",
                    self->pfcp_send_user_id ? "true" : "false");
        }
    }

    return 0;
}

static bool sgwc_reload_sgwu_peer_wanted(
        ogs_yaml_iter_t *pfcp_iter, const ogs_pfcp_node_t *node,
        bool *resolve_failed)
{
    ogs_yaml_iter_t pfcp_sub_iter;

    ogs_assert(pfcp_iter);
    ogs_assert(node);
    ogs_assert(node->config_addr);
    ogs_assert(resolve_failed);

    ogs_yaml_iter_recurse(pfcp_iter, &pfcp_sub_iter);
    while (ogs_yaml_iter_next(&pfcp_sub_iter)) {
        const char *pfcp_key = ogs_yaml_iter_key(&pfcp_sub_iter);

        if (!pfcp_key || strcmp(pfcp_key, "client"))
            continue;

        ogs_yaml_iter_t client_iter;
        ogs_yaml_iter_recurse(&pfcp_sub_iter, &client_iter);
        while (ogs_yaml_iter_next(&client_iter)) {
            const char *client_key = ogs_yaml_iter_key(&client_iter);
            ogs_yaml_iter_t sgwu_array;

            if (!client_key || strcmp(client_key, "sgwu"))
                continue;

            ogs_yaml_iter_recurse(&client_iter, &sgwu_array);
            do {
                ogs_yaml_iter_t remote_iter;
                int family = AF_UNSPEC;
                int i, num = 0;
                uint16_t port = ogs_pfcp_self()->pfcp_port;
                const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                ogs_sockaddr_t *addr = NULL;
                int rv;
                bool wanted = false;

                if (ogs_yaml_iter_type(&sgwu_array) == YAML_MAPPING_NODE) {
                    memcpy(&remote_iter, &sgwu_array, sizeof(ogs_yaml_iter_t));
                } else if (ogs_yaml_iter_type(&sgwu_array) ==
                        YAML_SEQUENCE_NODE) {
                    if (!ogs_yaml_iter_next(&sgwu_array))
                        break;
                    ogs_yaml_iter_recurse(&sgwu_array, &remote_iter);
                } else {
                    break;
                }

                memset(hostname, 0, sizeof(hostname));
                while (ogs_yaml_iter_next(&remote_iter)) {
                    const char *remote_key = ogs_yaml_iter_key(&remote_iter);

                    if (!remote_key)
                        continue;
                    if (!strcmp(remote_key, "family")) {
                        const char *v = ogs_yaml_iter_value(&remote_iter);
                        if (v)
                            family = atoi(v);
                    } else if (!strcmp(remote_key, "address")) {
                        ogs_yaml_iter_t hostname_iter;

                        ogs_yaml_iter_recurse(&remote_iter, &hostname_iter);
                        do {
                            if (ogs_yaml_iter_type(&hostname_iter) ==
                                    YAML_SEQUENCE_NODE) {
                                if (!ogs_yaml_iter_next(&hostname_iter))
                                    break;
                            }
                            if (num >= OGS_MAX_NUM_OF_HOSTNAME)
                                break;
                            hostname[num++] =
                                ogs_yaml_iter_value(&hostname_iter);
                        } while (ogs_yaml_iter_type(&hostname_iter) ==
                                YAML_SEQUENCE_NODE);
                    } else if (!strcmp(remote_key, "port")) {
                        const char *v = ogs_yaml_iter_value(&remote_iter);
                        if (v)
                            port = atoi(v);
                    }
                }

                for (i = 0; i < num; i++) {
                    rv = ogs_addaddrinfo(&addr, family, hostname[i], port, 0);
                    if (rv != OGS_OK) {
                        *resolve_failed = true;
                        continue;
                    }
                }

                ogs_filter_ip_version(&addr,
                        ogs_global_conf()->parameter.no_ipv4,
                        ogs_global_conf()->parameter.no_ipv6,
                        ogs_global_conf()->parameter.prefer_ipv4);

                if (addr &&
                        sgwc_reload_sockaddr_lists_match(
                            addr, node->config_addr, NULL))
                    wanted = true;

                if (addr)
                    ogs_freeaddrinfo(addr);
                if (wanted)
                    return true;
            } while (ogs_yaml_iter_type(&sgwu_array) == YAML_SEQUENCE_NODE);
        }
    }

    return false;
}

static void sgwc_reload_sgwu_remove_stale(ogs_yaml_iter_t *pfcp_iter)
{
    ogs_pfcp_node_t *node = NULL, *next = NULL;

    ogs_list_for_each_safe(&ogs_pfcp_self()->pfcp_peer_list, next, node) {
        bool resolve_failed = false;

        if (!node->config_addr)
            continue;
        if (sgwc_reload_sgwu_peer_wanted(pfcp_iter, node, &resolve_failed))
            continue;

        if (resolve_failed) {
            /* Cannot trust the wanted-set when DNS resolution failed;
             * keep the peer rather than dropping it on a transient error */
            ogs_reload_audit_warn(
                    "SGW-U peer removal skipped (DNS resolution failure) %s",
                    ogs_sockaddr_to_string_static(node->config_addr));
            continue;
        }

        if (!sgwc_pfcp_remove_sgwu_peer(node)) {
            ogs_reload_audit_warn(
                    "SGW-U peer removal skipped (sessions active) %s",
                    ogs_sockaddr_to_string_static(node->config_addr));
            continue;
        }

        sgwc_reload_lists_changed++;
        ogs_reload_audit_note(" SGW-U peer removed [%s]:%d",
                ogs_sockaddr_to_string_static(node->config_addr),
                OGS_PORT(node->config_addr));
    }
}

static int sgwc_reload_pfcp_sgwu_sync(ogs_yaml_iter_t *pfcp_iter)
{
    int added = sgwc_reload_pfcp_sgwu_add_only(pfcp_iter);

    sgwc_reload_sgwu_remove_stale(pfcp_iter);
    ogs_pfcp_peer_list_resort_by_order(&ogs_pfcp_self()->pfcp_peer_list);
    return added;
}

static int sgwc_reload_trace_imsi_replace(ogs_yaml_iter_t *sgwc_iter)
{
    ogs_yaml_iter_t trace_array, trace_iter;
    int count = 0;

    ogs_trace_filter_clear();

    ogs_yaml_iter_recurse(sgwc_iter, &trace_array);
    do {
        if (ogs_yaml_iter_type(&trace_array) == YAML_MAPPING_NODE)
            break;
        if (ogs_yaml_iter_type(&trace_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&trace_array))
                break;
            ogs_yaml_iter_recurse(&trace_array, &trace_iter);
        } else if (ogs_yaml_iter_type(&trace_array) == YAML_SCALAR_NODE) {
            ogs_yaml_iter_recurse(sgwc_iter, &trace_iter);
        } else {
            break;
        }

        while (ogs_yaml_iter_next(&trace_iter)) {
            const char *v = ogs_yaml_iter_value(&trace_iter);

            if (!v || !v[0])
                continue;
            if (ogs_trace_filter_add(v) != OGS_OK) {
                ogs_reload_audit_warn("trace_imsi could not add `%s'", v);
                continue;
            }
            count++;
        }
    } while (ogs_yaml_iter_type(&trace_array) == YAML_SEQUENCE_NODE &&
            ogs_yaml_iter_next(&trace_array));

    sgwc_reload_lists_changed++;
    ogs_reload_audit_note(" trace_imsi replaced (%d entries)", count);

    return count;
}

static void sgwc_reload_inbound_roam(ogs_yaml_iter_t *sgwc_iter)
{
    sgwc_context_t *self = sgwc_self();
    ogs_yaml_iter_t roam_iter;

    ogs_yaml_iter_recurse(sgwc_iter, &roam_iter);
    while (ogs_yaml_iter_next(&roam_iter)) {
        const char *rk = ogs_yaml_iter_key(&roam_iter);
        ogs_assert(rk);

        if (!strcmp(rk, "gtpc")) {
            ogs_yaml_iter_t gtpc_iter;

            ogs_yaml_iter_recurse(&roam_iter, &gtpc_iter);
            while (ogs_yaml_iter_next(&gtpc_iter)) {
                const char *gk = ogs_yaml_iter_key(&gtpc_iter);
                const char *gv = ogs_yaml_iter_has_value(&gtpc_iter) ?
                        ogs_yaml_iter_value(&gtpc_iter) : NULL;
                ogs_assert(gk);

                if (!strcmp(gk, "source_port") ||
                        !strcmp(gk, "send_port") ||
                        !strcmp(gk, "port")) {
                    ogs_reload_audit_warn("sgwc.inbound_roam.gtpc.source_port "
                            "ignored (bind address; restart required)");
                } else if (!strcmp(gk, "teid_offset")) {
                    if (gv) {
                        self->inbound_roam_teid_offset =
                            (uint32_t)strtoul(gv, NULL, 0);
                        sgwc_reload_lists_changed++;
                    }
                } else if (!strcmp(gk, "send_recovery_on_s5_csr") ||
                        !strcmp(gk, "recovery_on_s5_csr")) {
                    self->inbound_roam_gtpc_send_recovery_on_s5_csr =
                        ogs_yaml_iter_bool(&gtpc_iter);
                    sgwc_reload_lists_changed++;
                }
            }
        } else if (!strcmp(rk, "gtpu")) {
            ogs_yaml_iter_t gtpu_iter;

            ogs_yaml_iter_recurse(&roam_iter, &gtpu_iter);
            while (ogs_yaml_iter_next(&gtpu_iter)) {
                const char *gk = ogs_yaml_iter_key(&gtpu_iter);
                ogs_assert(gk);
                sgwc_reload_gtpu_key(gk, &gtpu_iter,
                        &self->inbound_roam_gtpu_force_cp_teid,
                        &self->inbound_roam_gtpu_teid_offset,
                        &self->inbound_roam_gtpu_teid_range_indication,
                        &self->inbound_roam_gtpu_teid_range);
                sgwc_reload_lists_changed++;
            }
        } else if (!strcmp(rk, "teid_offset")) {
            const char *rv = ogs_yaml_iter_value(&roam_iter);
            if (rv) {
                self->inbound_roam_teid_offset =
                    (uint32_t)strtoul(rv, NULL, 0);
                sgwc_reload_lists_changed++;
            }
        } else if (!strcmp(rk, "mtu")) {
            const char *rv = ogs_yaml_iter_value(&roam_iter);
            if (rv) {
                self->inbound_roam_mtu = (uint16_t)atoi(rv);
                sgwc_reload_lists_changed++;
                ogs_reload_audit_note("sgwc.inbound_roam.mtu=%u",
                        self->inbound_roam_mtu);
            }
        } else if (sgwc_reload_nwi_rule_key(rk)) {
            (void)sgwc_reload_nwi_append(&roam_iter);
        }
    }
}

static void sgwc_reload_gn(ogs_yaml_iter_t *sgwc_iter)
{
    ogs_yaml_iter_t gn_iter;
    ogs_list_t tmp_list;
    sgwc_gn_pgw_t *pgw = NULL, *next_pgw = NULL;
    int count = 0;

    ogs_assert(sgwc_iter);

    ogs_list_init(&tmp_list);

    /*
     * Rebuild the Gn PGW/SMF selection list from scratch into a temporary
     * list (replace semantics): SIGHUP may add, remove, or reorder entries,
     * and the default (no imsi_prefix) entry must be replaceable. The bind
     * address (gn.server) and gn enable state still require a restart.
     */
    ogs_yaml_iter_recurse(sgwc_iter, &gn_iter);
    while (ogs_yaml_iter_next(&gn_iter)) {
        const char *gn_key = ogs_yaml_iter_key(&gn_iter);
        ogs_assert(gn_key);

        if (!strcmp(gn_key, "pgw") || !strcmp(gn_key, "smf")) {
            sgwc_gn_pgw_yaml_add(&tmp_list, &gn_iter);
        } else if (!strcmp(gn_key, "server")) {
            ogs_reload_audit_warn(
                    "sgwc.gn.server ignored (bind address; restart required)");
        }
    }

    count = ogs_list_count(&tmp_list);
    if (count == 0) {
        ogs_reload_audit_warn(
                "sgwc.gn.pgw empty on reload; keeping current PGW list");
        sgwc_gn_pgw_clear_list(&tmp_list);
        return;
    }

    /*
     * Swap: drop the old list, move the freshly built entries in order.
     * Under the container lock — workers walk gn_pgw_list (PGW selection,
     * home-PLMN lookup) under the same lock, so they never observe the
     * half-swapped list or freed entries.
     */
    sgwc_ctx_lock();
    sgwc_gn_pgw_clear_list(&sgwc_self()->gn_pgw_list);
    ogs_list_for_each_safe(&tmp_list, next_pgw, pgw) {
        ogs_list_remove(&tmp_list, pgw);
        ogs_list_add(&sgwc_self()->gn_pgw_list, pgw);
    }
    sgwc_ctx_unlock();

    sgwc_reload_lists_changed++;
    ogs_reload_audit_note("sgwc.gn.pgw reloaded (%d entries)", count);
}

void sgwc_context_reload_runtime(void)
{
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;
    sgwc_context_t *self = sgwc_self();
    bool found = false;
    int lists_added = 0;
    bool yaml_ok = false;

    ogs_reload_audit_begin();
    sgwc_reload_lists_changed = 0;
    sgwc_nwi_reload_cleared = false;

    /*
     * Main thread only: the SGW-C context is process-global, so one
     * pass updates what every shard sees (list swaps happen under
     * sgwc_ctx_lock). Workers never run this.
     */
    ogs_assert(!ogs_worker_self());

    if (ogs_app_config_reload() != OGS_OK) {
        ogs_warn("Configuration reload failed; keeping previous config");
        ogs_reload_audit_warn("YAML parse failed; previous config kept");
        ogs_reload_audit_finish("SGWC", false);
        ogs_log_cycle();
        return;
    }

    yaml_ok = true;

    document = ogs_app()->document;
    if (!document) {
        ogs_warn("No configuration document for runtime reload");
        ogs_reload_audit_warn("no configuration document after reload");
        ogs_reload_audit_finish("SGWC", false);
        ogs_log_cycle();
        return;
    }

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);

        if (strcmp(root_key, "sgwc"))
            continue;

        ogs_yaml_iter_t sgwc_iter;
        ogs_yaml_iter_recurse(&root_iter, &sgwc_iter);
        while (ogs_yaml_iter_next(&sgwc_iter)) {
            const char *sgwc_key = ogs_yaml_iter_key(&sgwc_iter);
            ogs_assert(sgwc_key);

            if (!strcmp(sgwc_key, "gtpc")) {
                ogs_yaml_iter_t gtpc_iter;

                ogs_yaml_iter_recurse(&sgwc_iter, &gtpc_iter);
                while (ogs_yaml_iter_next(&gtpc_iter)) {
                    const char *gk = ogs_yaml_iter_key(&gtpc_iter);
                    /*
                     * gtpc: contains non-scalar children (server: is a
                     * sequence). Calling ogs_yaml_iter_value() on those
                     * aborts the daemon (YAML_SCALAR_NODE assert) —
                     * this crashed SGWC on SIGHUP. Guard every value.
                     */
                    const char *gv = ogs_yaml_iter_has_value(&gtpc_iter) ?
                            ogs_yaml_iter_value(&gtpc_iter) : NULL;

                    if (gk && !strcmp(gk, "echo_interval") && gv) {
                        self->gtpc_echo_interval = (uint32_t)atoi(gv);
                        sgwc_reload_lists_changed++;
                        ogs_reload_audit_note(
                                "sgwc.gtpc.echo_interval=%u",
                                self->gtpc_echo_interval);
                        found = true;
                    } else if (gk && !strcmp(gk, "server")) {
                        ogs_reload_audit_warn("sgwc.gtpc.server ignored "
                                "(bind address)");
                    }
                }
            } else if (!strcmp(sgwc_key, "gtpu")) {
                ogs_yaml_iter_t gtpu_iter;

                ogs_yaml_iter_recurse(&sgwc_iter, &gtpu_iter);
                while (ogs_yaml_iter_next(&gtpu_iter)) {
                    const char *gk = ogs_yaml_iter_key(&gtpu_iter);
                    ogs_assert(gk);
                    sgwc_reload_gtpu_key(gk, &gtpu_iter,
                            &self->gtpu_force_cp_teid,
                            &self->gtpu_teid_offset,
                            &self->gtpu_teid_range_indication,
                            &self->gtpu_teid_range);
                    sgwc_reload_lists_changed++;
                }
                ogs_reload_audit_note("sgwc.gtpu settings reloaded");
                found = true;
            } else if (sgwc_reload_nwi_rule_key(sgwc_key)) {
                lists_added += sgwc_reload_nwi_append(&sgwc_iter);
                found = true;
            } else if (!strcmp(sgwc_key, "pfcp") ||
                    !strcmp(sgwc_key, "sgwu")) {
                /* PFCP peer table is shared — only main mutates it. */
                if (!ogs_worker_self())
                    lists_added += sgwc_reload_pfcp_sgwu_sync(&sgwc_iter);
                found = true;
            } else if (!strcmp(sgwc_key, "inbound_roam")) {
                sgwc_reload_inbound_roam(&sgwc_iter);
                found = true;
            } else if (!strcmp(sgwc_key, "gn")) {
                sgwc_reload_gn(&sgwc_iter);
                found = true;
            } else if (!strcmp(sgwc_key, "admission")) {
                ogs_yaml_iter_t adm_iter;

                ogs_yaml_iter_recurse(&sgwc_iter, &adm_iter);
                while (ogs_yaml_iter_next(&adm_iter)) {
                    const char *ak = ogs_yaml_iter_key(&adm_iter);
                    const char *av = ogs_yaml_iter_has_value(&adm_iter) ?
                            ogs_yaml_iter_value(&adm_iter) : NULL;

                    if (!ak || !av)
                        continue;
                    if (!strcmp(ak, "max_outstanding")) {
                        __atomic_store_n(&self->admission_max_outstanding,
                                atoi(av), __ATOMIC_RELAXED);
                        sgwc_reload_lists_changed++;
                        ogs_reload_audit_note(
                                "sgwc.admission.max_outstanding=%d",
                                self->admission_max_outstanding);
                    } else if (!strcmp(ak, "rate_per_sec")) {
                        __atomic_store_n(&self->admission_rate_per_sec,
                                atoi(av), __ATOMIC_RELAXED);
                        sgwc_reload_lists_changed++;
                        ogs_reload_audit_note(
                                "sgwc.admission.rate_per_sec=%d",
                                self->admission_rate_per_sec);
                    }
                }
                found = true;
            } else if (!strcmp(sgwc_key, "cdr")) {
                sgwc_reload_cdr_replace(&sgwc_iter);
                found = true;
            } else if (!strcmp(sgwc_key, "trace_imsi")) {
                lists_added += sgwc_reload_trace_imsi_replace(&sgwc_iter);
                found = true;
            }
        }
    }

    if (sgwc_nwi_reload_cleared) {
        sgwc_sgwu_nwi_rewrite_resort();
        sgwc_reload_lists_changed++;
        ogs_reload_audit_note(" sgwu_nwi_rewrite replaced (%d entries)",
                ogs_list_count(&sgwc_self()->sgwu_nwi_rewrite_list));
    }

    (void)found;
    (void)lists_added;

    ogs_reload_audit_finish("SGWC", yaml_ok);
    ogs_log_cycle();
}
