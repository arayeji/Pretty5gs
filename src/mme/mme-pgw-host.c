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

#include "mme-pgw-host.h"

#include "mme-context.h"

static ogs_hash_t *pgw_host_cache = NULL;

static void pgw_host_cache_free_entry(char *fqdn, ogs_ip_t *ip)
{
    if (fqdn)
        ogs_free(fqdn);
    if (ip)
        ogs_free(ip);
}

void mme_pgw_host_cache_init(void)
{
    ogs_assert(pgw_host_cache == NULL);
    pgw_host_cache = ogs_hash_make();
    ogs_assert(pgw_host_cache);
}

void mme_pgw_host_cache_final(void)
{
    ogs_hash_index_t *hi = NULL;

    if (!pgw_host_cache)
        return;

    for (hi = ogs_hash_first(pgw_host_cache); hi; hi = ogs_hash_next(hi)) {
        char *fqdn = (char *)ogs_hash_this_key(hi);
        ogs_ip_t *ip = (ogs_ip_t *)ogs_hash_this_val(hi);
        pgw_host_cache_free_entry(fqdn, ip);
    }

    ogs_hash_destroy(pgw_host_cache);
    pgw_host_cache = NULL;
}

static void pgw_host_build_fqdn(char *fqdn, int buflen,
        const char *host, int host_len,
        const char *realm, int realm_len)
{
    const char *dot = NULL;

    ogs_assert(fqdn);
    ogs_assert(buflen > 0);

    fqdn[0] = 0;

    if (!host || host_len <= 0)
        return;

    dot = memchr(host, '.', host_len);
    if (dot) {
        ogs_snprintf(fqdn, buflen, "%.*s", host_len, host);
        return;
    }

    if (realm && realm_len > 0)
        ogs_snprintf(fqdn, buflen, "%.*s.%.*s", host_len, host, realm_len, realm);
    else
        ogs_snprintf(fqdn, buflen, "%.*s", host_len, host);
}

static int pgw_host_dns_resolve(const char *fqdn, ogs_ip_t *smf_ip)
{
    int rv;
    ogs_sockaddr_t *sa_list = NULL;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;
    ogs_sockaddr_t *walk = NULL;

    ogs_assert(fqdn);
    ogs_assert(smf_ip);

    rv = ogs_getaddrinfo(&sa_list, AF_UNSPEC, fqdn, 0, 0);
    if (rv != OGS_OK || !sa_list) {
        ogs_error("DNS failed for PGW host [%s]", fqdn);
        return OGS_ERROR;
    }

    ogs_filter_ip_version(&sa_list,
            ogs_global_conf()->parameter.no_ipv4,
            ogs_global_conf()->parameter.no_ipv6,
            ogs_global_conf()->parameter.prefer_ipv4);

    if (!sa_list) {
        ogs_error("No usable address for PGW host [%s]", fqdn);
        ogs_freeaddrinfo(sa_list);
        return OGS_ERROR;
    }

    for (walk = sa_list; walk; walk = walk->next) {
        if (walk->ogs_sa_family == AF_INET) {
            addr = walk;
            break;
        }
    }
    for (walk = sa_list; walk; walk = walk->next) {
        if (walk->ogs_sa_family == AF_INET6) {
            addr6 = walk;
            break;
        }
    }

    if (!addr && !addr6) {
        ogs_error("No IPv4/IPv6 for PGW host [%s]", fqdn);
        ogs_freeaddrinfo(sa_list);
        return OGS_ERROR;
    }

    rv = ogs_sockaddr_to_ip(addr, addr6, smf_ip);
    ogs_freeaddrinfo(sa_list);

    if (rv != OGS_OK) {
        ogs_error("ogs_sockaddr_to_ip() failed for [%s]", fqdn);
        return OGS_ERROR;
    }

    if (smf_ip->ipv4) {
        char buf[OGS_ADDRSTRLEN];

        OGS_INET_NTOP(&smf_ip->addr, buf);
        ogs_info("Resolved PGW host [%s] -> IPv4:%s", fqdn, buf);
    } else if (smf_ip->ipv6) {
        ogs_info("Resolved PGW host [%s] -> IPv6", fqdn);
    }

    return OGS_OK;
}

int mme_pgw_host_lookup_cache(
        const char *destination_host, int destination_host_len,
        const char *destination_realm, int destination_realm_len,
        ogs_ip_t *smf_ip)
{
    char fqdn[OGS_MAX_FQDN_LEN+1];
    ogs_ip_t *cached = NULL;

    ogs_assert(smf_ip);
    memset(smf_ip, 0, sizeof(*smf_ip));

    if (!mme_self()->mip_home_agent_host_dns)
        return OGS_ERROR;

    pgw_host_build_fqdn(fqdn, sizeof(fqdn),
            destination_host, destination_host_len,
            destination_realm, destination_realm_len);

    if (!fqdn[0])
        return OGS_ERROR;

    ogs_assert(pgw_host_cache);
    cached = ogs_hash_get(pgw_host_cache, fqdn, strlen(fqdn));
    if (!cached)
        return OGS_ERROR;

    memcpy(smf_ip, cached, sizeof(*smf_ip));
    ogs_debug("PGW host cache hit [%s]", fqdn);
    return OGS_OK;
}

int mme_pgw_host_resolve(
        const char *destination_host, int destination_host_len,
        const char *destination_realm, int destination_realm_len,
        ogs_ip_t *smf_ip)
{
    char fqdn[OGS_MAX_FQDN_LEN+1];
    char *cache_key = NULL;
    ogs_ip_t *cached = NULL;
    ogs_ip_t resolved;

    ogs_assert(smf_ip);

    if (mme_pgw_host_lookup_cache(destination_host, destination_host_len,
                destination_realm, destination_realm_len, smf_ip) == OGS_OK)
        return OGS_OK;

    if (!mme_self()->mip_home_agent_host_dns) {
        ogs_debug("MIP-Home-Agent-Host DNS resolve is disabled");
        return OGS_ERROR;
    }

    pgw_host_build_fqdn(fqdn, sizeof(fqdn),
            destination_host, destination_host_len,
            destination_realm, destination_realm_len);

    if (!fqdn[0]) {
        ogs_error("Empty MIP-Home-Agent-Host");
        return OGS_ERROR;
    }

    memset(&resolved, 0, sizeof(resolved));
    if (pgw_host_dns_resolve(fqdn, &resolved) != OGS_OK)
        return OGS_ERROR;

    cache_key = ogs_strdup(fqdn);
    ogs_assert(cache_key);
    cached = ogs_calloc(1, sizeof(ogs_ip_t));
    ogs_assert(cached);
    memcpy(cached, &resolved, sizeof(*cached));
    ogs_hash_set(pgw_host_cache, cache_key, strlen(cache_key), cached);

    memcpy(smf_ip, cached, sizeof(*smf_ip));
    return OGS_OK;
}

void mme_pgw_host_resolve_pending_sessions(ogs_slice_data_t *slice_data)
{
    int i;

    if (!slice_data)
        return;

    for (i = 0; i < slice_data->num_of_session; i++) {
        ogs_session_t *sess = &slice_data->session[i];

        if (!sess->mip_home_agent_host[0])
            continue;
        if (sess->smf_ip.ipv4 || sess->smf_ip.ipv6)
            continue;

        if (mme_pgw_host_resolve(sess->mip_home_agent_host,
                    (int)strlen(sess->mip_home_agent_host),
                    sess->mip_home_agent_realm,
                    (int)strlen(sess->mip_home_agent_realm),
                    &sess->smf_ip) != OGS_OK) {
            ogs_error("MIP-Home-Agent-Host resolution failed [%s]",
                    sess->mip_home_agent_host);
        }

        sess->mip_home_agent_host[0] = '\0';
        sess->mip_home_agent_realm[0] = '\0';
    }
}
