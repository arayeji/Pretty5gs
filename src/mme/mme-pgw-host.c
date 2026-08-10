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
#include "ogs-core.h"

static ogs_hash_t *pgw_host_cache = NULL;
static ogs_thread_mutex_t pgw_host_cache_mutex;

/*
 * Negative-cache TTL. ogs_getaddrinfo() is a *blocking* call on the MME main
 * event loop; a slow/unreachable resolver stalls all UE processing for the
 * full resolver timeout. We cannot make the lookup truly asynchronous without
 * reworking the ULA->Create-Session path, but we can ensure a failing FQDN
 * blocks at most once per TTL instead of on every attach for that APN.
 *
 * TODO: move resolution to a worker thread / async resolver to remove the
 * first-lookup stall entirely.
 */
#define PGW_HOST_NEG_CACHE_TTL ogs_time_from_sec(30)

typedef struct pgw_host_cache_entry_s {
    ogs_ip_t    ip;
    bool        resolved;   /* false => negative (resolution failed) */
    ogs_time_t  expire;     /* monotonic expiry for negative entries */
} pgw_host_cache_entry_t;

static void pgw_host_cache_free_entry(char *fqdn, pgw_host_cache_entry_t *entry)
{
    if (fqdn)
        ogs_free(fqdn);
    if (entry)
        ogs_free(entry);
}

static void pgw_host_cache_clear_unlocked(void)
{
    ogs_hash_index_t *hi = NULL;

    if (!pgw_host_cache)
        return;

    for (hi = ogs_hash_first(pgw_host_cache); hi; hi = ogs_hash_next(hi)) {
        char *fqdn = (char *)ogs_hash_this_key(hi);
        pgw_host_cache_entry_t *entry =
            (pgw_host_cache_entry_t *)ogs_hash_this_val(hi);
        pgw_host_cache_free_entry(fqdn, entry);
    }

    ogs_hash_clear(pgw_host_cache);
}

void mme_pgw_host_cache_init(void)
{
    ogs_assert(pgw_host_cache == NULL);
    ogs_thread_mutex_init(&pgw_host_cache_mutex);
    pgw_host_cache = ogs_hash_make();
    ogs_assert(pgw_host_cache);
}

void mme_pgw_host_cache_final(void)
{
    if (!pgw_host_cache)
        return;

    ogs_thread_mutex_lock(&pgw_host_cache_mutex);
    pgw_host_cache_clear_unlocked();
    ogs_hash_destroy(pgw_host_cache);
    pgw_host_cache = NULL;
    ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
    ogs_thread_mutex_destroy(&pgw_host_cache_mutex);
}

int mme_pgw_host_cache_clear_all(void)
{
    int removed = 0;
    ogs_hash_index_t *hi = NULL;

    ogs_thread_mutex_lock(&pgw_host_cache_mutex);
    if (!pgw_host_cache) {
        ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
        return 0;
    }

    for (hi = ogs_hash_first(pgw_host_cache); hi; hi = ogs_hash_next(hi))
        removed++;

    pgw_host_cache_clear_unlocked();
    ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
    return removed;
}

int mme_pgw_host_cache_remove_fqdn(const char *fqdn)
{
    ogs_hash_index_t *hi = NULL;
    size_t fqdn_len = 0;

    if (!fqdn || !*fqdn)
        return OGS_ERROR;

    fqdn_len = strlen(fqdn);

    ogs_thread_mutex_lock(&pgw_host_cache_mutex);
    if (!pgw_host_cache) {
        ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
        return OGS_ERROR;
    }

    for (hi = ogs_hash_first(pgw_host_cache); hi; hi = ogs_hash_next(hi)) {
        char *key = (char *)ogs_hash_this_key(hi);
        int klen = ogs_hash_this_key_len(hi);
        pgw_host_cache_entry_t *entry =
            (pgw_host_cache_entry_t *)ogs_hash_this_val(hi);

        if ((size_t)klen == fqdn_len && memcmp(key, fqdn, fqdn_len) == 0) {
            ogs_hash_set(pgw_host_cache, key, klen, NULL);
            pgw_host_cache_free_entry(key, entry);
            ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
            return OGS_OK;
        }
    }

    ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
    return OGS_ERROR;
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
    pgw_host_cache_entry_t *cached = NULL;

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
    ogs_thread_mutex_lock(&pgw_host_cache_mutex);
    cached = ogs_hash_get(pgw_host_cache, fqdn, strlen(fqdn));
    if (!cached || !cached->resolved) {
        ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
        return OGS_ERROR;
    }

    memcpy(smf_ip, &cached->ip, sizeof(*smf_ip));
    ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
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
    pgw_host_cache_entry_t *cached = NULL;
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

    ogs_assert(pgw_host_cache);

    /*
     * Negative cache: if this FQDN failed to resolve recently, do not block
     * the main event loop again on getaddrinfo() until the TTL expires.
     * (lookup_cache() above only returns positive hits, so a non-NULL entry
     * here is a negative one; we reuse it in place to avoid key churn.)
     */
    ogs_thread_mutex_lock(&pgw_host_cache_mutex);
    cached = ogs_hash_get(pgw_host_cache, fqdn, strlen(fqdn));
    if (cached && !cached->resolved && ogs_time_now() < cached->expire) {
        ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
        ogs_debug("PGW host negative-cache hit [%s], skipping DNS", fqdn);
        return OGS_ERROR;
    }
    ogs_thread_mutex_unlock(&pgw_host_cache_mutex);

    memset(&resolved, 0, sizeof(resolved));
    if (pgw_host_dns_resolve(fqdn, &resolved) != OGS_OK) {
        /* Cache/refresh the failure so subsequent attaches don't each block. */
        ogs_thread_mutex_lock(&pgw_host_cache_mutex);
        cached = ogs_hash_get(pgw_host_cache, fqdn, strlen(fqdn));
        if (cached) {
            cached->resolved = false;
            cached->expire = ogs_time_now() + PGW_HOST_NEG_CACHE_TTL;
        } else {
            cache_key = ogs_strdup(fqdn);
            ogs_assert(cache_key);
            cached = ogs_calloc(1, sizeof(*cached));
            ogs_assert(cached);
            cached->resolved = false;
            cached->expire = ogs_time_now() + PGW_HOST_NEG_CACHE_TTL;
            ogs_hash_set(pgw_host_cache, cache_key, strlen(cache_key), cached);
        }
        ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
        return OGS_ERROR;
    }

    ogs_thread_mutex_lock(&pgw_host_cache_mutex);
    cached = ogs_hash_get(pgw_host_cache, fqdn, strlen(fqdn));
    if (cached) {
        /* Promote the (expired-negative) entry to a positive one. */
        cached->resolved = true;
        cached->expire = 0;
        memcpy(&cached->ip, &resolved, sizeof(cached->ip));
    } else {
        cache_key = ogs_strdup(fqdn);
        ogs_assert(cache_key);
        cached = ogs_calloc(1, sizeof(*cached));
        ogs_assert(cached);
        cached->resolved = true;
        cached->expire = 0;
        memcpy(&cached->ip, &resolved, sizeof(cached->ip));
        ogs_hash_set(pgw_host_cache, cache_key, strlen(cache_key), cached);
    }

    memcpy(smf_ip, &cached->ip, sizeof(*smf_ip));
    ogs_thread_mutex_unlock(&pgw_host_cache_mutex);
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

        /*
         * TS 29.272 / 23.401: DYNAMIC means the MIP6 identity was selected
         * by another node, not operator-provisioned. For initial request the
         * MME may re-select (APN DNS / YAML); Host DNS is not required and
         * must not block attach when the FQDN is unreachable. Selection
         * already ignores DYNAMIC via mme_pgw_hss_static_usable().
         */
        if (sess->pdn_gw_allocation_type ==
                OGS_PDN_GW_ALLOCATION_DYNAMIC) {
            ogs_debug("Skip MIP-Home-Agent-Host DNS [%s] "
                    "(PDN-GW-Allocation-Type=DYNAMIC)",
                    sess->mip_home_agent_host);
            sess->mip_home_agent_host[0] = '\0';
            sess->mip_home_agent_realm[0] = '\0';
            continue;
        }

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
