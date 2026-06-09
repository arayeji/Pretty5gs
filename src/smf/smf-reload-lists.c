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
#include "smf-reload-lists.h"
#include "pfcp-path.h"
#include "ogs-trace.h"

int smf_reload_lists_changed = 0;

static bool smf_reload_dnn_set_equal(
        const ogs_pfcp_subnet_t *subnet,
        const char dnnv[][OGS_MAX_DNN_LEN+1], int num_of_dnn)
{
    int i, j;

    if (!subnet)
        return false;

    if (subnet->num_of_dnn != num_of_dnn)
        return false;

    for (i = 0; i < num_of_dnn; i++) {
        bool found = false;

        for (j = 0; j < subnet->num_of_dnn; j++) {
            if (ogs_strcasecmp(subnet->dnn[j], dnnv[i]) == 0) {
                found = true;
                break;
            }
        }
        if (!found)
            return false;
    }

    return true;
}

static bool smf_reload_subnet_exists(
        const char *ipstr, const char *mask_or_numbits,
        const char dnnv[][OGS_MAX_DNN_LEN+1], int num_of_dnn)
{
    ogs_ipsubnet_t probe;
    ogs_pfcp_subnet_t *subnet = NULL;

    if (!ipstr || !mask_or_numbits)
        return false;

    if (ogs_ipsubnet(&probe, ipstr, mask_or_numbits) != OGS_OK)
        return false;

    ogs_list_for_each(&ogs_pfcp_self()->subnet_list, subnet) {
        if (subnet->family != probe.family ||
                subnet->prefixlen != probe.prefixlen)
            continue;
        if (memcmp(subnet->sub.sub, probe.sub, sizeof(probe.sub)) != 0)
            continue;
        if (smf_reload_dnn_set_equal(subnet, dnnv, num_of_dnn))
            return true;
    }

    return false;
}

static bool smf_reload_pfcp_peer_exists(ogs_sockaddr_t *addr)
{
    ogs_pfcp_node_t *node = NULL;

    ogs_assert(addr);

    ogs_list_for_each(&ogs_pfcp_self()->pfcp_peer_list, node) {
        if (node->config_addr &&
                ogs_sockaddr_is_equal(node->config_addr, addr))
            return true;
    }

    return false;
}

static int smf_reload_session_entry_add_only(ogs_yaml_iter_t *subnet_iter)
{
    ogs_pfcp_subnet_t *subnet = NULL;
    const char *ipstr = NULL;
    const char *gateway = NULL;
    const char *mask_or_numbits = NULL;
    char (*dnn_seq)[OGS_MAX_DNN_LEN+1] = ogs_calloc(
            OGS_MAX_NUM_OF_DNN, OGS_MAX_DNN_LEN+1);
    int dnn_seq_n = 0;
    const char *dnn_scalar = NULL;
    const char *dev = ogs_pfcp_self()->tun_ifname;
    const char *low[OGS_MAX_NUM_OF_SUBNET_RANGE];
    const char *high[OGS_MAX_NUM_OF_SUBNET_RANGE];
    int i, num = 0;

    ogs_assert(subnet_iter);
    ogs_assert(dnn_seq);

    memset(low, 0, sizeof(low));
    memset(high, 0, sizeof(high));

    while (ogs_yaml_iter_next(subnet_iter)) {
        const char *subnet_key = ogs_yaml_iter_key(subnet_iter);
        ogs_assert(subnet_key);

        if (!strcmp(subnet_key, "subnet")) {
            char *v = (char *)ogs_yaml_iter_value(subnet_iter);
            if (v) {
                ipstr = (const char *)strsep(&v, "/");
                if (ipstr)
                    mask_or_numbits = (const char *)v;
            }
        } else if (!strcmp(subnet_key, "gateway")) {
            gateway = ogs_yaml_iter_value(subnet_iter);
        } else if (!strcmp(subnet_key, "apn") ||
                !strcmp(subnet_key, "dnn")) {
            yaml_document_t *document = ogs_app()->document;
            yaml_node_t *dnn_node = yaml_document_get_node(
                    document, subnet_iter->pair->value);

            if (dnn_node && dnn_node->type == YAML_SEQUENCE_NODE) {
                ogs_yaml_iter_t dnn_sq;

                ogs_yaml_iter_recurse(subnet_iter, &dnn_sq);
                while (ogs_yaml_iter_next(&dnn_sq) &&
                        dnn_seq_n < OGS_MAX_NUM_OF_DNN) {
                    const char *dv = ogs_yaml_iter_value(&dnn_sq);
                    int j, dup = 0;

                    if (!dv || !*dv)
                        continue;
                    for (j = 0; j < dnn_seq_n; j++) {
                        if (ogs_strcasecmp(dnn_seq[j], dv) == 0) {
                            dup = 1;
                            break;
                        }
                    }
                    if (dup)
                        continue;
                    ogs_cpystrn(dnn_seq[dnn_seq_n++], dv, OGS_MAX_DNN_LEN);
                }
            } else {
                dnn_scalar = ogs_yaml_iter_value(subnet_iter);
            }
        } else if (!strcmp(subnet_key, "dev")) {
            dev = ogs_yaml_iter_value(subnet_iter);
        } else if (!strcmp(subnet_key, "range")) {
            ogs_yaml_iter_t range_iter;

            ogs_yaml_iter_recurse(subnet_iter, &range_iter);
            ogs_assert(ogs_yaml_iter_type(&range_iter) !=
                    YAML_MAPPING_NODE);
            do {
                char *v = NULL;

                if (ogs_yaml_iter_type(&range_iter) ==
                        YAML_SEQUENCE_NODE) {
                    if (!ogs_yaml_iter_next(&range_iter))
                        break;
                }

                v = (char *)ogs_yaml_iter_value(&range_iter);
                if (v) {
                    ogs_assert(num < OGS_MAX_NUM_OF_SUBNET_RANGE);
                    low[num] = (const char *)strsep(&v, "-");
                    if (low[num] && strlen(low[num]) == 0)
                        low[num] = NULL;
                    high[num] = (const char *)v;
                    if (high[num] && strlen(high[num]) == 0)
                        high[num] = NULL;
                }

                if (low[num] || high[num])
                    num++;
            } while (ogs_yaml_iter_type(&range_iter) ==
                    YAML_SEQUENCE_NODE);
        }
    }

    if (!ipstr || !mask_or_numbits) {
        ogs_free(dnn_seq);
        return 0;
    }

    if (dnn_seq_n > 0) {
        if (smf_reload_subnet_exists(ipstr, mask_or_numbits,
                    (const char (*)[OGS_MAX_DNN_LEN+1])dnn_seq, dnn_seq_n)) {
            ogs_free(dnn_seq);
            return 0;
        }
    } else if (dnn_scalar && dnn_scalar[0]) {
        char one[1][OGS_MAX_DNN_LEN+1];
        ogs_cpystrn(one[0], dnn_scalar, OGS_MAX_DNN_LEN);
        if (smf_reload_subnet_exists(ipstr, mask_or_numbits, one, 1)) {
            ogs_free(dnn_seq);
            return 0;
        }
    } else if (smf_reload_subnet_exists(ipstr, mask_or_numbits, NULL, 0)) {
        ogs_free(dnn_seq);
        return 0;
    }

    if (dnn_seq_n > 0) {
        subnet = ogs_pfcp_subnet_add_multi(
                ipstr, mask_or_numbits, gateway,
                (const char (*)[OGS_MAX_DNN_LEN+1])dnn_seq, dnn_seq_n, dev);
    } else {
        subnet = ogs_pfcp_subnet_add(
                ipstr, mask_or_numbits, gateway, dnn_scalar, dev);
    }

    if (!subnet) {
        ogs_error("SIGHUP: Adding PFCP subnet failed");
        ogs_free(dnn_seq);
        return 0;
    }

    subnet->num_of_range = num;
    for (i = 0; i < subnet->num_of_range; i++) {
        subnet->range[i].low = low[i];
        subnet->range[i].high = high[i];
    }

    ogs_info("SIGHUP: subnet added %s/%s (dnn=%d)",
            ipstr, mask_or_numbits, dnn_seq_n > 0 ? dnn_seq_n :
            (dnn_scalar ? 1 : 0));
    ogs_free(dnn_seq);
    return 1;
}

static int smf_reload_session_add_only(ogs_yaml_iter_t *smf_iter)
{
    ogs_yaml_iter_t subnet_array, subnet_iter;
    int added = 0;

    ogs_yaml_iter_recurse(smf_iter, &subnet_array);
    do {
        if (ogs_yaml_iter_type(&subnet_array) == YAML_MAPPING_NODE) {
            memcpy(&subnet_iter, &subnet_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(&subnet_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&subnet_array))
                break;
            ogs_yaml_iter_recurse(&subnet_array, &subnet_iter);
        } else {
            break;
        }

        added += smf_reload_session_entry_add_only(&subnet_iter);
    } while (ogs_yaml_iter_type(&subnet_array) == YAML_SEQUENCE_NODE);

    return added;
}

static int smf_reload_upf_peer_entry_add_only(ogs_yaml_iter_t *upf_array)
{
    yaml_document_t *document = ogs_app()->document;
    int added = 0;

    ogs_assert(upf_array);

    do {
        ogs_yaml_iter_t remote_iter;
        int family = AF_UNSPEC;
        int i, num = 0;
        uint16_t port = ogs_pfcp_self()->pfcp_port;
        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
        uint16_t tac[OGS_MAX_NUM_OF_TAI];
        uint8_t num_of_tac = 0;
        const char *dnn[OGS_MAX_NUM_OF_DNN];
        uint8_t num_of_dnn = 0;
        ogs_sockaddr_t *addr = NULL;
        ogs_pfcp_node_t *node = NULL;
        int rv;

        if (ogs_yaml_iter_type(upf_array) == YAML_MAPPING_NODE) {
            memcpy(&remote_iter, upf_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(upf_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(upf_array))
                break;
            ogs_yaml_iter_recurse(upf_array, &remote_iter);
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

        if (smf_reload_pfcp_peer_exists(addr)) {
            ogs_freeaddrinfo(addr);
            continue;
        }

        node = smf_pfcp_admin_add_upf_peer(addr, dnn, num_of_dnn);
        if (!node) {
            ogs_freeaddrinfo(addr);
            continue;
        }

        node->num_of_tac = num_of_tac;
        if (num_of_tac)
            memcpy(node->tac, tac, sizeof(node->tac));

        ogs_info("SIGHUP: UPF peer added [%s]:%d",
                ogs_sockaddr_to_string_static(addr), OGS_PORT(addr));
        added++;
        smf_reload_lists_changed++;
    } while (ogs_yaml_iter_type(upf_array) == YAML_SEQUENCE_NODE);

    return added;
}

static int smf_reload_pfcp_upf_add_only(ogs_yaml_iter_t *pfcp_iter)
{
    ogs_yaml_iter_t pfcp_sub_iter;

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

                if (!strcmp(client_key, "upf")) {
                    ogs_yaml_iter_t upf_array;

                    ogs_yaml_iter_recurse(&client_iter, &upf_array);
                    return smf_reload_upf_peer_entry_add_only(&upf_array);
                }
            }
        } else if (!strcmp(pfcp_key, "server")) {
            ogs_warn("SIGHUP: smf.pfcp.server ignored (bind address)");
        }
    }

    return 0;
}

static int smf_reload_trace_imsi_add_only(ogs_yaml_iter_t *smf_iter)
{
    ogs_yaml_iter_t trace_array, trace_iter;
    int added = 0;

    ogs_yaml_iter_recurse(smf_iter, &trace_array);
    do {
        if (ogs_yaml_iter_type(&trace_array) == YAML_MAPPING_NODE)
            break;
        if (ogs_yaml_iter_type(&trace_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&trace_array))
                break;
            ogs_yaml_iter_recurse(&trace_array, &trace_iter);
        } else if (ogs_yaml_iter_type(&trace_array) == YAML_SCALAR_NODE) {
            ogs_yaml_iter_recurse(smf_iter, &trace_iter);
        } else {
            break;
        }

        while (ogs_yaml_iter_next(&trace_iter)) {
            const char *v = ogs_yaml_iter_value(&trace_iter);
            int count_before = ogs_trace_filter_count();

            if (!v || !v[0])
                continue;
            if (ogs_trace_filter_add(v) != OGS_OK) {
                ogs_warn("SIGHUP: trace_imsi could not add `%s'", v);
                continue;
            }
            if (ogs_trace_filter_count() > count_before) {
                added++;
                smf_reload_lists_changed++;
                ogs_info("SIGHUP: trace_imsi added `%s'", v);
            }
        }
    } while (ogs_yaml_iter_type(&trace_array) == YAML_SEQUENCE_NODE &&
            ogs_yaml_iter_next(&trace_array));

    return added;
}

void smf_context_reload_runtime(void)
{
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;
    smf_context_t *self = smf_self();
    bool found = false;
    int lists_added = 0;

    smf_reload_lists_changed = 0;

    if (ogs_app_config_reload() != OGS_OK) {
        ogs_warn("Configuration reload failed; keeping previous config");
        return;
    }

    document = ogs_app()->document;
    if (!document) {
        ogs_warn("No configuration document for runtime reload");
        return;
    }

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);

        if (strcmp(root_key, "smf"))
            continue;

        ogs_yaml_iter_t smf_iter;
        ogs_yaml_iter_recurse(&root_iter, &smf_iter);
        while (ogs_yaml_iter_next(&smf_iter)) {
            const char *smf_key = ogs_yaml_iter_key(&smf_iter);
            ogs_assert(smf_key);

            if (!strcmp(smf_key, "session")) {
                lists_added += smf_reload_session_add_only(&smf_iter);
                found = true;
            } else if (!strcmp(smf_key, "pfcp")) {
                lists_added += smf_reload_pfcp_upf_add_only(&smf_iter);
                found = true;
            } else if (!strcmp(smf_key, "trace_imsi")) {
                lists_added += smf_reload_trace_imsi_add_only(&smf_iter);
                found = true;
            } else if (!strcmp(smf_key, "dns")) {
                ogs_yaml_iter_t dns_iter;
                ogs_yaml_iter_recurse(&smf_iter, &dns_iter);

                do {
                    const char *v = NULL;
                    ogs_ipsubnet_t ipsub;

                    if (ogs_yaml_iter_type(&dns_iter) ==
                            YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&dns_iter))
                            break;
                    }

                    v = ogs_yaml_iter_value(&dns_iter);
                    if (!v || !strlen(v))
                        continue;
                    if (ogs_ipsubnet(&ipsub, v, NULL) != OGS_OK)
                        continue;

                    if (ipsub.family == AF_INET) {
                        if (!self->dns[0])
                            self->dns[0] = v;
                        else if (!self->dns[1] &&
                                strcmp(self->dns[0], v) != 0) {
                            self->dns[1] = v;
                            smf_reload_lists_changed++;
                        }
                    } else if (ipsub.family == AF_INET6) {
                        if (!self->dns6[0])
                            self->dns6[0] = v;
                        else if (!self->dns6[1] &&
                                strcmp(self->dns6[0], v) != 0) {
                            self->dns6[1] = v;
                            smf_reload_lists_changed++;
                        }
                    }
                } while (ogs_yaml_iter_type(&dns_iter) ==
                        YAML_SEQUENCE_NODE);
                found = true;
            } else if (!strcmp(smf_key, "mtu")) {
                const char *v = ogs_yaml_iter_value(&smf_iter);
                if (v)
                    self->mtu = atoi(v);
                smf_reload_lists_changed++;
                found = true;
            } else if (!strcmp(smf_key, "gtpc")) {
                ogs_yaml_iter_t gtpc_iter;

                ogs_yaml_iter_recurse(&smf_iter, &gtpc_iter);
                while (ogs_yaml_iter_next(&gtpc_iter)) {
                    const char *gk = ogs_yaml_iter_key(&gtpc_iter);

                    if (gk && !strcmp(gk, "server")) {
                        ogs_warn("SIGHUP: smf.gtpc.server ignored "
                                "(bind address)");
                    }
                }
            }
        }
    }

    if (found || lists_added > 0 || smf_reload_lists_changed > 0) {
        ogs_info("SMF runtime config reloaded (%d list change(s))",
                lists_added + smf_reload_lists_changed);
    } else {
        ogs_warn("No reloadable SMF keys found in configuration");
    }
}
