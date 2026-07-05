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
#include "radius-path.h"
#include "ga-writer.h"

volatile int smf_reload_lists_changed = 0;

static char *smf_reload_owned_dns[2];
static char *smf_reload_owned_dns6[2];

static void smf_reload_replace_dns(const char **slot, char **owned,
        const char *v)
{
    char *dup = (v && v[0]) ? ogs_strdup(v) : NULL;
    char *old = *owned;

    *slot = dup;
    *owned = dup;
    if (old)
        ogs_free(old);
}

static void smf_reload_cdr_cfg_clear(smf_cdr_config_t *cfg)
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

static void smf_reload_radius_cfg_clear(smf_radius_config_t *cfg)
{
    int i;

    ogs_assert(cfg);

    /*
     * Legacy flat server/secret are aliased into servers[0] when no
     * servers[] list is present (see smf_reload_parse_radius). Free
     * each heap pointer once.
     */
    for (i = 0; i < cfg->num_servers; i++) {
        if (cfg->servers[i].host &&
                cfg->servers[i].host != cfg->server) {
            ogs_free((void *)cfg->servers[i].host);
            cfg->servers[i].host = NULL;
        }
        if (cfg->servers[i].secret &&
                cfg->servers[i].secret != cfg->secret) {
            ogs_free((void *)cfg->servers[i].secret);
            cfg->servers[i].secret = NULL;
        }
    }
    if (cfg->server) {
        ogs_free((void *)cfg->server);
        cfg->server = NULL;
    }
    if (cfg->secret) {
        ogs_free((void *)cfg->secret);
        cfg->secret = NULL;
    }
    if (cfg->nas_id) {
        ogs_free((void *)cfg->nas_id);
        cfg->nas_id = NULL;
    }
    if (cfg->nas_ip) {
        ogs_free((void *)cfg->nas_ip);
        cfg->nas_ip = NULL;
    }
    if (cfg->pod_bind) {
        ogs_free((void *)cfg->pod_bind);
        cfg->pod_bind = NULL;
    }
    if (cfg->pod_secret) {
        ogs_free((void *)cfg->pod_secret);
        cfg->pod_secret = NULL;
    }
}

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

    int probe_prefix = 0;

    if (ogs_ipsubnet(&probe, ipstr, mask_or_numbits) != OGS_OK)
        return false;

    if (mask_or_numbits)
        probe_prefix = atoi(mask_or_numbits);

    ogs_list_for_each(&ogs_pfcp_self()->subnet_list, subnet) {
        if (subnet->family != probe.family ||
                subnet->prefixlen != (uint8_t)probe_prefix)
            continue;
        if (memcmp(subnet->sub.sub, probe.sub, sizeof(probe.sub)) != 0)
            continue;
        if (smf_reload_dnn_set_equal(subnet, dnnv, num_of_dnn))
            return true;
    }

    return false;
}

static bool smf_reload_subnet_in_session_yaml(
        ogs_yaml_iter_t *smf_iter, const ogs_pfcp_subnet_t *subnet)
{
    ogs_yaml_iter_t subnet_array, subnet_iter;
    char ipstr[OGS_ADDRSTRLEN];
    char maskbuf[16];

    ogs_assert(smf_iter);
    ogs_assert(subnet);

    if (subnet->family == AF_INET6)
        OGS_INET6_NTOP(&subnet->sub.sub[0], ipstr);
    else
        OGS_INET_NTOP(&subnet->sub.sub[0], ipstr);
    ogs_snprintf(maskbuf, sizeof(maskbuf), "%u", subnet->prefixlen);

    ogs_yaml_iter_recurse(smf_iter, &subnet_array);
    do {
        char dnn_seq[OGS_MAX_NUM_OF_DNN][OGS_MAX_DNN_LEN+1];
        char subnet_buf[OGS_ADDRSTRLEN+16];
        int dnn_seq_n = 0;
        const char *entry_ip = NULL;
        const char *entry_mask = NULL;
        const char *dnn_scalar = NULL;

        if (ogs_yaml_iter_type(&subnet_array) == YAML_MAPPING_NODE) {
            memcpy(&subnet_iter, &subnet_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(&subnet_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&subnet_array))
                break;
            ogs_yaml_iter_recurse(&subnet_array, &subnet_iter);
        } else {
            break;
        }

        memset(dnn_seq, 0, sizeof(dnn_seq));
        while (ogs_yaml_iter_next(&subnet_iter)) {
            const char *subnet_key = ogs_yaml_iter_key(&subnet_iter);
            ogs_assert(subnet_key);

            if (!strcmp(subnet_key, "subnet")) {
                /* Copy before splitting: strsep on the YAML scalar would
                 * corrupt the document for later passes in this reload */
                const char *raw = ogs_yaml_iter_value(&subnet_iter);
                if (raw) {
                    char *v = subnet_buf;
                    ogs_cpystrn(subnet_buf, raw, sizeof(subnet_buf));
                    entry_ip = (const char *)strsep(&v, "/");
                    if (entry_ip)
                        entry_mask = (const char *)v;
                }
            } else if (!strcmp(subnet_key, "apn") ||
                    !strcmp(subnet_key, "dnn")) {
                yaml_document_t *document = ogs_app()->document;
                yaml_node_t *dnn_node = yaml_document_get_node(
                        document, subnet_iter.pair->value);

                if (dnn_node && dnn_node->type == YAML_SEQUENCE_NODE) {
                    ogs_yaml_iter_t dnn_sq;

                    ogs_yaml_iter_recurse(&subnet_iter, &dnn_sq);
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
                        ogs_cpystrn(dnn_seq[dnn_seq_n++], dv,
                                OGS_MAX_DNN_LEN);
                    }
                } else {
                    dnn_scalar = ogs_yaml_iter_value(&subnet_iter);
                }
            }
        }

        if (!entry_ip || !entry_mask)
            continue;

        if (dnn_seq_n > 0) {
            if (smf_reload_dnn_set_equal(subnet,
                        (const char (*)[OGS_MAX_DNN_LEN+1])dnn_seq,
                        dnn_seq_n) &&
                    ogs_strcasecmp(entry_ip, ipstr) == 0 &&
                    atoi(entry_mask) == subnet->prefixlen)
                return true;
        } else if (dnn_scalar && dnn_scalar[0]) {
            char one[1][OGS_MAX_DNN_LEN+1];
            ogs_cpystrn(one[0], dnn_scalar, OGS_MAX_DNN_LEN);
            if (smf_reload_dnn_set_equal(subnet, one, 1) &&
                    ogs_strcasecmp(entry_ip, ipstr) == 0 &&
                    atoi(entry_mask) == subnet->prefixlen)
                return true;
        } else if (subnet->num_of_dnn == 0 &&
                ogs_strcasecmp(entry_ip, ipstr) == 0 &&
                atoi(entry_mask) == subnet->prefixlen) {
            return true;
        }
    } while (ogs_yaml_iter_type(&subnet_array) == YAML_SEQUENCE_NODE);

    return false;
}

static void smf_reload_session_sync(ogs_yaml_iter_t *smf_iter)
{
    ogs_pfcp_subnet_t *subnet = NULL, *next = NULL;
    char ip[OGS_ADDRSTRLEN];
    int removed = 0;

    (void)smf_reload_session_add_only(smf_iter);

    ogs_list_for_each_safe(&ogs_pfcp_self()->subnet_list, next, subnet) {
        if (smf_reload_subnet_in_session_yaml(smf_iter, subnet))
            continue;

        if (subnet->pool.avail != subnet->pool.size) {
            if (subnet->family == AF_INET6)
                OGS_INET6_NTOP(&subnet->sub.sub[0], ip);
            else
                OGS_INET_NTOP(&subnet->sub.sub[0], ip);
            ogs_reload_audit_warn(
                    "subnet removal skipped (IPs allocated) %s/%u",
                    ip, subnet->prefixlen);
            continue;
        }

        if (subnet->family == AF_INET6)
            OGS_INET6_NTOP(&subnet->sub.sub[0], ip);
        else
            OGS_INET_NTOP(&subnet->sub.sub[0], ip);
        ogs_pfcp_subnet_remove(subnet);
        removed++;
        smf_reload_lists_changed++;
        ogs_reload_audit_note(" subnet removed %s/%u", ip, subnet->prefixlen);
    }

    if (removed > 0)
        ogs_reload_audit_note(" session pools synced (%d removed)", removed);
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
    char subnet_buf[OGS_ADDRSTRLEN+16];
    int i, num = 0;

    ogs_assert(subnet_iter);
    ogs_assert(dnn_seq);

    memset(low, 0, sizeof(low));
    memset(high, 0, sizeof(high));

    while (ogs_yaml_iter_next(subnet_iter)) {
        const char *subnet_key = ogs_yaml_iter_key(subnet_iter);
        ogs_assert(subnet_key);

        if (!strcmp(subnet_key, "subnet")) {
            /* Copy before splitting: strsep on the YAML scalar would
             * corrupt the document for the stale-subnet check pass */
            const char *raw = ogs_yaml_iter_value(subnet_iter);
            if (raw) {
                char *v = subnet_buf;
                ogs_cpystrn(subnet_buf, raw, sizeof(subnet_buf));
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
        ogs_reload_audit_warn("Adding PFCP subnet failed");
        ogs_free(dnn_seq);
        return 0;
    }

    subnet->num_of_range = num;
    for (i = 0; i < subnet->num_of_range; i++) {
        subnet->range[i].low = low[i] ? ogs_strdup(low[i]) : NULL;
        subnet->range[i].high = high[i] ? ogs_strdup(high[i]) : NULL;
    }

    ogs_reload_audit_note(" subnet added %s/%s (dnn=%d)",
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
        int num_of_dnn = 0;
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

        ogs_reload_audit_note(" UPF peer added [%s]:%d",
                ogs_sockaddr_to_string_static(addr), OGS_PORT(addr));
        added++;
        smf_reload_lists_changed++;
    } while (ogs_yaml_iter_type(upf_array) == YAML_SEQUENCE_NODE);

    return added;
}

static bool smf_reload_upf_peer_wanted(
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
            ogs_yaml_iter_t upf_array;

            if (!client_key || strcmp(client_key, "upf"))
                continue;

            ogs_yaml_iter_recurse(&client_iter, &upf_array);
            do {
                ogs_yaml_iter_t remote_iter;
                int family = AF_UNSPEC;
                int i, num = 0;
                uint16_t port = ogs_pfcp_self()->pfcp_port;
                const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                ogs_sockaddr_t *addr = NULL;
                int rv;
                bool wanted = false;

                if (ogs_yaml_iter_type(&upf_array) == YAML_MAPPING_NODE) {
                    memcpy(&remote_iter, &upf_array, sizeof(ogs_yaml_iter_t));
                } else if (ogs_yaml_iter_type(&upf_array) ==
                        YAML_SEQUENCE_NODE) {
                    if (!ogs_yaml_iter_next(&upf_array))
                        break;
                    ogs_yaml_iter_recurse(&upf_array, &remote_iter);
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
                        ogs_sockaddr_is_equal(node->config_addr, addr))
                    wanted = true;

                if (addr)
                    ogs_freeaddrinfo(addr);
                if (wanted)
                    return true;
            } while (ogs_yaml_iter_type(&upf_array) == YAML_SEQUENCE_NODE);
        }
    }

    return false;
}

static void smf_reload_upf_remove_stale(ogs_yaml_iter_t *pfcp_iter)
{
    ogs_pfcp_node_t *node = NULL, *next = NULL;

    ogs_list_for_each_safe(&ogs_pfcp_self()->pfcp_peer_list, next, node) {
        bool resolve_failed = false;

        if (!node->config_addr)
            continue;
        if (smf_reload_upf_peer_wanted(pfcp_iter, node, &resolve_failed))
            continue;

        if (resolve_failed) {
            /* Cannot trust the wanted-set when DNS resolution failed;
             * keep the peer rather than dropping it on a transient error */
            ogs_reload_audit_warn(
                    "UPF peer removal skipped (DNS resolution failure) %s",
                    ogs_sockaddr_to_string_static(node->config_addr));
            continue;
        }

        if (!smf_pfcp_remove_upf_peer(node)) {
            ogs_reload_audit_warn(
                    "UPF peer removal skipped (sessions active) %s",
                    ogs_sockaddr_to_string_static(node->config_addr));
            continue;
        }

        smf_reload_lists_changed++;
        ogs_reload_audit_note(" UPF peer removed [%s]:%d",
                ogs_sockaddr_to_string_static(node->config_addr),
                OGS_PORT(node->config_addr));
    }
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
            ogs_reload_audit_warn("smf.pfcp.server ignored (bind address)");
        }
    }

    return 0;
}

static int smf_reload_pfcp_upf_sync(ogs_yaml_iter_t *pfcp_iter)
{
    int added = smf_reload_pfcp_upf_add_only(pfcp_iter);

    smf_reload_upf_remove_stale(pfcp_iter);
    return added;
}

static int smf_reload_trace_imsi_replace(ogs_yaml_iter_t *smf_iter)
{
    ogs_yaml_iter_t trace_array, trace_iter;
    int count = 0;

    ogs_trace_filter_clear();

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

    smf_reload_lists_changed++;
    ogs_reload_audit_note(" trace_imsi replaced (%d entries)", count);

    return count;
}

static void smf_reload_dns_replace(ogs_yaml_iter_t *smf_iter)
{
    smf_context_t *self = smf_self();
    ogs_yaml_iter_t dns_iter;
    const char *dns4[2] = {NULL, NULL};
    const char *dns6[2] = {NULL, NULL};
    int n4 = 0, n6 = 0;
    int i;

    ogs_yaml_iter_recurse(smf_iter, &dns_iter);
    do {
        const char *v = NULL;
        ogs_ipsubnet_t ipsub;

        if (ogs_yaml_iter_type(&dns_iter) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&dns_iter))
                break;
        }

        v = ogs_yaml_iter_value(&dns_iter);
        if (!v || !strlen(v))
            continue;
        if (ogs_ipsubnet(&ipsub, v, NULL) != OGS_OK)
            continue;

        if (ipsub.family == AF_INET && n4 < 2)
            dns4[n4++] = v;
        else if (ipsub.family == AF_INET6 && n6 < 2)
            dns6[n6++] = v;
    } while (ogs_yaml_iter_type(&dns_iter) == YAML_SEQUENCE_NODE);

    for (i = 0; i < 2; i++) {
        smf_reload_replace_dns(&self->dns[i], &smf_reload_owned_dns[i],
                i < n4 ? dns4[i] : NULL);
        smf_reload_replace_dns(&self->dns6[i], &smf_reload_owned_dns6[i],
                i < n6 ? dns6[i] : NULL);
    }

    smf_reload_lists_changed++;
    ogs_reload_audit_note("smf.dns replaced (v4=%d v6=%d)", n4, n6);
}

static void smf_reload_parse_cdr(ogs_yaml_iter_t *smf_iter, smf_cdr_config_t *cfg)
{
    ogs_yaml_iter_t c_iter;

    ogs_assert(smf_iter);
    ogs_assert(cfg);

    memset(cfg, 0, sizeof(*cfg));
    cfg->rotate_max_records = 100;
    cfg->rotate_max_bytes = 65536;
    cfg->rotate_max_seconds = 30;
    cfg->triggers = SMF_CDR_TRIG_START | SMF_CDR_TRIG_INTERIM | SMF_CDR_TRIG_STOP;

    ogs_yaml_iter_recurse(smf_iter, &c_iter);
    while (ogs_yaml_iter_next(&c_iter)) {
        const char *ck = ogs_yaml_iter_key(&c_iter);
        const char *cv = ogs_yaml_iter_value(&c_iter);

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
                !strcmp(ck, "pgw_address")) {
            cfg->local_address = cv ? ogs_strdup(cv) : NULL;
        } else if (!strcmp(ck, "max_records")) {
            if (cv) cfg->rotate_max_records = (uint32_t)atoi(cv);
        } else if (!strcmp(ck, "max_bytes")) {
            if (cv) cfg->rotate_max_bytes = (uint32_t)atoi(cv);
        } else if (!strcmp(ck, "max_seconds")) {
            if (cv) cfg->rotate_max_seconds = (uint32_t)atoi(cv);
        } else if (!strcmp(ck, "triggers")) {
            uint32_t t = 0;

            if (cv) {
                const char *p = cv;

                while (*p) {
                    while (*p == ' ' || *p == ',') p++;
                    if (!strncmp(p, "start", 5)) {
                        t |= SMF_CDR_TRIG_START; p += 5;
                    } else if (!strncmp(p, "interim", 7)) {
                        t |= SMF_CDR_TRIG_INTERIM; p += 7;
                    } else if (!strncmp(p, "stop", 4)) {
                        t |= SMF_CDR_TRIG_STOP; p += 4;
                    } else {
                        while (*p && *p != ',') p++;
                    }
                }
            }
            if (t) cfg->triggers = t;
        }
    }
}

static bool smf_reload_parse_radius(
        ogs_yaml_iter_t *smf_iter, smf_radius_config_t *cfg)
{
    ogs_yaml_iter_t r_iter;

    ogs_assert(smf_iter);
    ogs_assert(cfg);

    memset(cfg, 0, sizeof(*cfg));
    cfg->auth_port = 1812;
    cfg->acct_port = 1813;
    cfg->timeout_ms = 3000;
    cfg->retry = 3;
    cfg->pod_port = 3799;
    cfg->pod_teardown_timeout_ms = 5000;
    cfg->use_framed_ip_for_ue = true;
    cfg->select_mode = SMF_RADIUS_SELECT_PRIMARY_FAILOVER;

    ogs_yaml_iter_recurse(smf_iter, &r_iter);
    while (ogs_yaml_iter_next(&r_iter)) {
        const char *rk = ogs_yaml_iter_key(&r_iter);

        ogs_assert(rk);
        if (!strcmp(rk, "enabled")) {
            cfg->enabled = ogs_yaml_iter_bool(&r_iter);
        } else if (!strcmp(rk, "pod_enabled") || !strcmp(rk, "pod")) {
            cfg->pod_enabled = ogs_yaml_iter_bool(&r_iter);
        } else if (!strcmp(rk, "use_framed_ip_for_ue")) {
            cfg->use_framed_ip_for_ue = ogs_yaml_iter_bool(&r_iter);
        } else if (!strcmp(rk, "servers")) {
            ogs_yaml_iter_t s_arr;

            ogs_yaml_iter_recurse(&r_iter, &s_arr);
            while (ogs_yaml_iter_type(&s_arr) == YAML_SEQUENCE_NODE) {
                ogs_yaml_iter_t s_map;
                smf_radius_server_t *d;

                if (!ogs_yaml_iter_next(&s_arr))
                    break;
                if (cfg->num_servers >= SMF_MAX_RADIUS_SERVERS)
                    break;

                d = &cfg->servers[cfg->num_servers];
                d->auth_port = 1812;
                d->acct_port = 1813;
                d->is_primary = true;
                d->weight = 1;

                ogs_yaml_iter_recurse(&s_arr, &s_map);
                while (ogs_yaml_iter_next(&s_map)) {
                    const char *sk = ogs_yaml_iter_key(&s_map);
                    const char *sv = ogs_yaml_iter_value(&s_map);

                    if (!sk)
                        continue;
                    if (!strcmp(sk, "host") || !strcmp(sk, "address") ||
                            !strcmp(sk, "server")) {
                        d->host = sv ? ogs_strdup(sv) : NULL;
                    } else if (!strcmp(sk, "auth_port")) {
                        if (sv) d->auth_port = (uint16_t)atoi(sv);
                    } else if (!strcmp(sk, "acct_port")) {
                        if (sv) d->acct_port = (uint16_t)atoi(sv);
                    } else if (!strcmp(sk, "port")) {
                        if (sv) {
                            int p = atoi(sv);

                            d->auth_port = (uint16_t)p;
                            d->acct_port = (uint16_t)(p + 1);
                        }
                    } else if (!strcmp(sk, "secret") ||
                            !strcmp(sk, "community")) {
                        d->secret = sv ? ogs_strdup(sv) : NULL;
                    } else if (!strcmp(sk, "role")) {
                        d->is_primary = !sv || strcmp(sv, "secondary") != 0;
                    } else if (!strcmp(sk, "weight")) {
                        if (sv) d->weight = atoi(sv);
                    }
                }

                if (!d->host || !d->secret)
                    continue;
                cfg->num_servers++;
            }
        } else {
            const char *rv = ogs_yaml_iter_value(&r_iter);

            if (!strcmp(rk, "server")) {
                cfg->server = rv ? ogs_strdup(rv) : NULL;
            } else if (!strcmp(rk, "auth_port")) {
                if (rv) cfg->auth_port = (uint16_t)atoi(rv);
            } else if (!strcmp(rk, "acct_port")) {
                if (rv) cfg->acct_port = (uint16_t)atoi(rv);
            } else if (!strcmp(rk, "port")) {
                if (rv) {
                    int p = atoi(rv);

                    cfg->auth_port = (uint16_t)p;
                    cfg->acct_port = (uint16_t)(p + 1);
                }
            } else if (!strcmp(rk, "secret") || !strcmp(rk, "community")) {
                cfg->secret = rv ? ogs_strdup(rv) : NULL;
            } else if (!strcmp(rk, "nas_identifier")) {
                cfg->nas_id = rv ? ogs_strdup(rv) : NULL;
            } else if (!strcmp(rk, "nas_ip")) {
                cfg->nas_ip = rv ? ogs_strdup(rv) : NULL;
            } else if (!strcmp(rk, "timeout")) {
                if (rv) cfg->timeout_ms = (unsigned)atoi(rv);
            } else if (!strcmp(rk, "retry")) {
                if (rv) cfg->retry = atoi(rv);
            } else if (!strcmp(rk, "acct_interim_interval")) {
                if (rv) cfg->acct_interim_interval = (unsigned)atoi(rv);
            } else if (!strcmp(rk, "pod_bind") || !strcmp(rk, "pod_address")) {
                cfg->pod_bind = rv ? ogs_strdup(rv) : NULL;
            } else if (!strcmp(rk, "pod_port")) {
                if (rv) cfg->pod_port = (uint16_t)atoi(rv);
            } else if (!strcmp(rk, "pod_secret")) {
                cfg->pod_secret = rv ? ogs_strdup(rv) : NULL;
            } else if (!strcmp(rk, "pod_teardown_timeout_ms") ||
                    !strcmp(rk, "pod_teardown_timeout")) {
                if (rv) cfg->pod_teardown_timeout_ms = (uint32_t)atoi(rv);
            } else if (!strcmp(rk, "select") || !strcmp(rk, "select_mode")) {
                if (rv && !strcmp(rv, "hash_imsi"))
                    cfg->select_mode = SMF_RADIUS_SELECT_HASH_IMSI;
                else
                    cfg->select_mode = SMF_RADIUS_SELECT_PRIMARY_FAILOVER;
            }
        }
    }

    if (!cfg->enabled)
        return true;

    if (cfg->num_servers == 0) {
        if (!cfg->server || !cfg->secret || !cfg->secret[0])
            return false;
        cfg->servers[0].host = cfg->server;
        cfg->servers[0].auth_port = cfg->auth_port ? cfg->auth_port : 1812;
        cfg->servers[0].acct_port = cfg->acct_port ? cfg->acct_port : 1813;
        cfg->servers[0].secret = cfg->secret;
        cfg->servers[0].is_primary = true;
        cfg->servers[0].weight = 1;
        cfg->num_servers = 1;
    }

    return true;
}

void smf_context_reload_runtime(void)
{
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;
    smf_context_t *self = smf_self();
    bool found = false;
    int lists_added = 0;
    bool yaml_ok = false;

    ogs_reload_audit_begin();
    smf_reload_lists_changed = 0;

    if (ogs_app_config_reload() != OGS_OK) {
        ogs_warn("Configuration reload failed; keeping previous config");
        ogs_reload_audit_warn("YAML parse failed; previous config kept");
        ogs_reload_audit_finish("SMF", false);
        ogs_log_cycle();
        return;
    }

    yaml_ok = true;

    document = ogs_app()->document;
    if (!document) {
        ogs_warn("No configuration document for runtime reload");
        ogs_reload_audit_warn("no configuration document after reload");
        ogs_reload_audit_finish("SMF", false);
        ogs_log_cycle();
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
                smf_reload_session_sync(&smf_iter);

                /*
                 * Per-APN `radius:` blocks are plain scalars with no
                 * live references, so unlike subnets they support
                 * full-replace semantics on reload: rebuild the table
                 * from scratch so flips (auth on/off, skip, ...) and
                 * removed blocks all take effect immediately.
                 */
                smf_apn_radius_cfg_reset();
                smf_apn_radius_parse_session_list(&smf_iter);
                ogs_reload_audit_note(
                        " per-APN radius table rebuilt (%d entr%s)",
                        smf_self()->num_apn_radius,
                        smf_self()->num_apn_radius == 1 ? "y" : "ies");
                smf_reload_lists_changed++;
                found = true;
            } else if (!strcmp(smf_key, "pfcp")) {
                lists_added += smf_reload_pfcp_upf_sync(&smf_iter);
                found = true;
            } else if (!strcmp(smf_key, "trace_imsi")) {
                lists_added += smf_reload_trace_imsi_replace(&smf_iter);
                found = true;
            } else if (!strcmp(smf_key, "dns")) {
                smf_reload_dns_replace(&smf_iter);
                found = true;
            } else if (!strcmp(smf_key, "mtu")) {
                const char *v = ogs_yaml_iter_value(&smf_iter);
                if (v) {
                    self->mtu = atoi(v);
                    ogs_reload_audit_note("smf.mtu=%u", self->mtu);
                }
                smf_reload_lists_changed++;
                found = true;
            } else if (!strcmp(smf_key, "gtpc")) {
                ogs_yaml_iter_t gtpc_iter;

                ogs_yaml_iter_recurse(&smf_iter, &gtpc_iter);
                while (ogs_yaml_iter_next(&gtpc_iter)) {
                    const char *gk = ogs_yaml_iter_key(&gtpc_iter);

                    if (gk && !strcmp(gk, "server")) {
                        ogs_reload_audit_warn("smf.gtpc.server ignored "
                                "(bind address)");
                    }
                }
            } else if (!strcmp(smf_key, "radius")) {
                smf_radius_config_t cfg;

                if (smf_reload_parse_radius(&smf_iter, &cfg)) {
                    (void)smf_radius_apply_runtime(&cfg);
                    smf_reload_radius_cfg_clear(&cfg);
                    smf_reload_lists_changed++;
                    ogs_reload_audit_note("smf.radius configuration replaced");
                    found = true;
                } else {
                    smf_reload_radius_cfg_clear(&cfg);
                    ogs_reload_audit_warn("smf.radius invalid; keeping previous "
                            "RADIUS config");
                }
            } else if (!strcmp(smf_key, "cdr")) {
                smf_cdr_config_t cfg;

                smf_reload_parse_cdr(&smf_iter, &cfg);
                (void)smf_ga_writer_apply_runtime(&cfg);
                smf_reload_cdr_cfg_clear(&cfg);
                smf_reload_lists_changed++;
                ogs_reload_audit_note("smf.cdr configuration replaced");
                found = true;
            }
        }
    }

    (void)found;
    (void)lists_added;

    ogs_reload_audit_finish("SMF", yaml_ok);
    ogs_log_cycle();
}
