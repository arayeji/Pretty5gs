/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
 *
 * APN-FQDN PGW discovery (TS 23.003 / TS 29.303).
 */

#include "mme-pgw-dns.h"

#include "mme-context.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define MME_PGW_DNS_MAX_NS          4
#define MME_PGW_DNS_TIMEOUT_MS      2000
#define MME_PGW_DNS_MAX_CANDIDATES  16
#define MME_PGW_DNS_CACHE_TTL_SEC   300
#define MME_PGW_DNS_NEG_TTL_SEC     30
#define MME_PGW_DNS_PKT_MAX         1500

#define DNS_TYPE_A      1
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_SRV    33
#define DNS_TYPE_NAPTR  35
#define DNS_CLASS_IN    1

typedef struct pgw_dns_cache_entry_s {
    ogs_ip_t    ip;
    bool        resolved;
    ogs_time_t  expire;
} pgw_dns_cache_entry_t;

typedef struct naptr_rr_s {
    uint16_t order;
    uint16_t preference;
    char flags[8];
    char service[128];
    char replacement[OGS_MAX_FQDN_LEN + 1];
} naptr_rr_t;

typedef struct srv_rr_s {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    char target[OGS_MAX_FQDN_LEN + 1];
} srv_rr_t;

static ogs_hash_t *pgw_dns_cache = NULL;
static ogs_thread_mutex_t pgw_dns_cache_mutex;

static void pgw_dns_tolower(char *s)
{
    char *p;

    if (!s)
        return;
    for (p = s; *p; p++) {
        if (*p >= 'A' && *p <= 'Z')
            *p = (char)tolower((unsigned char)*p);
    }
}

static void pgw_dns_cache_free_entry(char *key, pgw_dns_cache_entry_t *entry)
{
    if (key)
        ogs_free(key);
    if (entry)
        ogs_free(entry);
}

static void pgw_dns_cache_clear_unlocked(void)
{
    ogs_hash_index_t *hi;

    if (!pgw_dns_cache)
        return;

    for (hi = ogs_hash_first(pgw_dns_cache); hi; hi = ogs_hash_next(hi)) {
        char *key = (char *)ogs_hash_this_key(hi);
        pgw_dns_cache_entry_t *entry =
            (pgw_dns_cache_entry_t *)ogs_hash_this_val(hi);
        pgw_dns_cache_free_entry(key, entry);
    }
    ogs_hash_clear(pgw_dns_cache);
}

void mme_pgw_dns_cache_init(void)
{
    ogs_assert(pgw_dns_cache == NULL);
    ogs_thread_mutex_init(&pgw_dns_cache_mutex);
    pgw_dns_cache = ogs_hash_make();
    ogs_assert(pgw_dns_cache);
}

void mme_pgw_dns_cache_final(void)
{
    if (!pgw_dns_cache)
        return;

    ogs_thread_mutex_lock(&pgw_dns_cache_mutex);
    pgw_dns_cache_clear_unlocked();
    ogs_hash_destroy(pgw_dns_cache);
    pgw_dns_cache = NULL;
    ogs_thread_mutex_unlock(&pgw_dns_cache_mutex);
    ogs_thread_mutex_destroy(&pgw_dns_cache_mutex);
}

int mme_pgw_dns_cache_clear_all(void)
{
    int removed = 0;
    ogs_hash_index_t *hi;

    ogs_thread_mutex_lock(&pgw_dns_cache_mutex);
    if (!pgw_dns_cache) {
        ogs_thread_mutex_unlock(&pgw_dns_cache_mutex);
        return 0;
    }
    for (hi = ogs_hash_first(pgw_dns_cache); hi; hi = ogs_hash_next(hi))
        removed++;
    pgw_dns_cache_clear_unlocked();
    ogs_thread_mutex_unlock(&pgw_dns_cache_mutex);
    return removed;
}

int mme_pgw_dns_build_apn_fqdn(
        char *buf, int buflen, const char *apn_ni,
        const ogs_plmn_id_t *oi_plmn_id)
{
    char ni[OGS_MAX_APN_LEN + 1];
    char *oi_pos;
    int mcc, mnc;
    int len;

    ogs_assert(buf);
    ogs_assert(buflen > 0);
    ogs_assert(apn_ni);
    ogs_assert(oi_plmn_id);

    buf[0] = '\0';
    if (!apn_ni[0])
        return 0;

    ogs_cpystrn(ni, apn_ni, sizeof(ni));
    pgw_dns_tolower(ni);

    /* Strip trailing dot */
    len = (int)strlen(ni);
    if (len > 0 && ni[len - 1] == '.')
        ni[len - 1] = '\0';

    oi_pos = ogs_dnn_oi_from_fqdn(ni);
    if (oi_pos) {
        /* Already NI.mncXXX.mccYYY.gprs — convert to EPC APN-FQDN */
        char ni_only[OGS_MAX_APN_LEN + 1];
        size_t ni_len = (size_t)(oi_pos - ni);

        if (ni_len == 0 || ni_len >= sizeof(ni_only))
            return 0;
        memcpy(ni_only, ni, ni_len);
        ni_only[ni_len] = '\0';
        if (ni_len > 0 && ni_only[ni_len - 1] == '.')
            ni_only[ni_len - 1] = '\0';

        mcc = ogs_plmn_id_mcc_from_fqdn(ni);
        mnc = ogs_plmn_id_mnc_from_fqdn(ni);
        if (!mcc)
            return 0;

        len = ogs_snprintf(buf, buflen,
                "%s.apn.epc.mnc%03d.mcc%03d.3gppnetwork.org",
                ni_only, mnc, mcc);
    } else {
        len = ogs_snprintf(buf, buflen,
                "%s.apn.epc.mnc%03d.mcc%03d.3gppnetwork.org",
                ni, ogs_plmn_id_mnc(oi_plmn_id), ogs_plmn_id_mcc(oi_plmn_id));
    }

    if (len <= 0 || len >= buflen)
        return 0;
    return len;
}

static int pgw_dns_read_resolv_conf(ogs_sockaddr_t **ns_list)
{
#ifndef _WIN32
    FILE *fp;
    char line[256];
    int count = 0;

    ogs_assert(ns_list);
    *ns_list = NULL;

    fp = fopen("/etc/resolv.conf", "r");
    if (!fp)
        return OGS_ERROR;

    while (fgets(line, sizeof(line), fp) && count < MME_PGW_DNS_MAX_NS) {
        char *p = line;
        char *addr;
        ogs_sockaddr_t *sa = NULL;

        while (*p == ' ' || *p == '\t')
            p++;
        if (strncmp(p, "nameserver", 10) != 0)
            continue;
        p += 10;
        while (*p == ' ' || *p == '\t')
            p++;
        addr = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
            p++;
        *p = '\0';
        if (!addr[0])
            continue;

        if (ogs_getaddrinfo(&sa, AF_UNSPEC, addr, 53, 0) != OGS_OK || !sa)
            continue;
        ogs_merge_addrinfo(ns_list, sa);
        ogs_freeaddrinfo(sa);
        count++;
    }
    fclose(fp);
    return count > 0 ? OGS_OK : OGS_ERROR;
#else
    (void)ns_list;
    return OGS_ERROR;
#endif
}

static int pgw_dns_encode_name(uint8_t *pkt, int pktlen, int off, const char *name)
{
    const char *p = name;
    const char *dot;

    while (*p) {
        int labellen;

        dot = strchr(p, '.');
        labellen = dot ? (int)(dot - p) : (int)strlen(p);
        if (labellen <= 0 || labellen > 63)
            return -1;
        if (off + 1 + labellen >= pktlen)
            return -1;
        pkt[off++] = (uint8_t)labellen;
        memcpy(pkt + off, p, labellen);
        off += labellen;
        if (!dot)
            break;
        p = dot + 1;
    }
    if (off >= pktlen)
        return -1;
    pkt[off++] = 0;
    return off;
}

static int pgw_dns_skip_name(const uint8_t *pkt, int pktlen, int off)
{
    int jumps = 0;

    while (off < pktlen) {
        uint8_t len = pkt[off];

        if (len == 0)
            return off + 1;
        if ((len & 0xc0) == 0xc0) {
            if (off + 1 >= pktlen)
                return -1;
            return off + 2;
        }
        if (len > 63)
            return -1;
        off += 1 + len;
        if (++jumps > 64)
            return -1;
    }
    return -1;
}

static int pgw_dns_decode_name(
        const uint8_t *pkt, int pktlen, int off, char *out, int outlen)
{
    int jumps = 0;
    int pos = 0;
    int next = -1;
    bool first = true;

    while (off < pktlen) {
        uint8_t len = pkt[off];

        if (len == 0) {
            if (next < 0)
                next = off + 1;
            break;
        }
        if ((len & 0xc0) == 0xc0) {
            int ptr;

            if (off + 1 >= pktlen)
                return -1;
            ptr = ((len & 0x3f) << 8) | pkt[off + 1];
            if (next < 0)
                next = off + 2;
            off = ptr;
            if (++jumps > 64)
                return -1;
            continue;
        }
        if (len > 63 || off + 1 + len > pktlen)
            return -1;
        if (!first) {
            if (pos + 1 >= outlen)
                return -1;
            out[pos++] = '.';
        }
        if (pos + len >= outlen)
            return -1;
        memcpy(out + pos, pkt + off + 1, len);
        pos += len;
        off += 1 + len;
        first = false;
        if (++jumps > 128)
            return -1;
    }
    if (pos >= outlen)
        return -1;
    out[pos] = '\0';
    return next >= 0 ? next : off;
}

static int pgw_dns_query_udp(
        ogs_sockaddr_t *ns_list, const char *qname, uint16_t qtype,
        uint8_t *resp, int resplen)
{
#ifndef _WIN32
    uint8_t req[512];
    int off = 0;
    uint16_t id;
    ogs_sockaddr_t *ns;
    int sock = -1;
    int rv = OGS_ERROR;
    struct timeval tv;

    ogs_assert(ns_list);
    ogs_assert(qname);
    ogs_assert(resp);

    id = (uint16_t)(ogs_time_now() & 0xffff);
    memset(req, 0, sizeof(req));
    req[0] = (uint8_t)(id >> 8);
    req[1] = (uint8_t)(id & 0xff);
    req[2] = 0x01; /* RD */
    req[5] = 1;    /* QDCOUNT = 1 */
    off = 12;
    off = pgw_dns_encode_name(req, (int)sizeof(req), off, qname);
    if (off < 0)
        return OGS_ERROR;
    if (off + 4 > (int)sizeof(req))
        return OGS_ERROR;
    req[off++] = (uint8_t)(qtype >> 8);
    req[off++] = (uint8_t)(qtype & 0xff);
    req[off++] = 0;
    req[off++] = DNS_CLASS_IN;

    for (ns = ns_list; ns; ns = ns->next) {
        ssize_t n;
        fd_set rfds;
        socklen_t fromlen;
        ogs_sockaddr_t from;

        sock = socket(ns->ogs_sa_family, SOCK_DGRAM, 0);
        if (sock < 0)
            continue;

        tv.tv_sec = MME_PGW_DNS_TIMEOUT_MS / 1000;
        tv.tv_usec = (MME_PGW_DNS_TIMEOUT_MS % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (sendto(sock, req, off, 0, &ns->sa,
                    ogs_sockaddr_len((const void *)ns)) < 0) {
            close(sock);
            sock = -1;
            continue;
        }

        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        if (select(sock + 1, &rfds, NULL, NULL, &tv) <= 0) {
            close(sock);
            sock = -1;
            continue;
        }

        memset(&from, 0, sizeof(from));
        fromlen = sizeof(from.ss);
        n = recvfrom(sock, resp, resplen, 0, &from.sa, &fromlen);
        close(sock);
        sock = -1;
        if (n < 12)
            continue;
        if (resp[0] != req[0] || resp[1] != req[1])
            continue;
        if ((resp[3] & 0x0f) != 0) /* RCODE */
            continue;
        rv = (int)n;
        break;
    }

    return rv;
#else
    (void)ns_list;
    (void)qname;
    (void)qtype;
    (void)resp;
    (void)resplen;
    return OGS_ERROR;
#endif
}

static bool pgw_dns_service_match(const char *service, bool use_s8)
{
    const char *need = use_s8 ? "x-s8-gtp" : "x-s5-gtp";

    if (!service)
        return false;
    if (!strstr(service, "x-3gpp-pgw"))
        return false;
    return strstr(service, need) != NULL;
}

static int pgw_dns_parse_naptr(
        const uint8_t *pkt, int pktlen, naptr_rr_t *out, int max_out)
{
    int off;
    uint16_t ancount, i;
    int n = 0;

    if (pktlen < 12)
        return 0;

    ancount = (uint16_t)((pkt[6] << 8) | pkt[7]);
    off = 12;
    off = pgw_dns_skip_name(pkt, pktlen, off);
    if (off < 0 || off + 4 > pktlen)
        return 0;
    off += 4; /* QTYPE QCLASS */

    for (i = 0; i < ancount && n < max_out && off + 10 <= pktlen; i++) {
        uint16_t type, rdlen;
        int rdata;

        off = pgw_dns_skip_name(pkt, pktlen, off);
        if (off < 0 || off + 10 > pktlen)
            break;
        type = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
        rdlen = (uint16_t)((pkt[off + 8] << 8) | pkt[off + 9]);
        rdata = off + 10;
        off = rdata + rdlen;
        if (off > pktlen)
            break;
        if (type != DNS_TYPE_NAPTR || rdlen < 7)
            continue;

        {
            int p = rdata;
            uint8_t flen, slen, rlen;
            naptr_rr_t *rr = &out[n];

            memset(rr, 0, sizeof(*rr));
            rr->order = (uint16_t)((pkt[p] << 8) | pkt[p + 1]);
            rr->preference = (uint16_t)((pkt[p + 2] << 8) | pkt[p + 3]);
            p += 4;
            if (p >= rdata + rdlen)
                continue;
            flen = pkt[p++];
            if (p + flen > rdata + rdlen)
                continue;
            memcpy(rr->flags, pkt + p, ogs_min(flen, sizeof(rr->flags) - 1));
            p += flen;
            if (p >= rdata + rdlen)
                continue;
            slen = pkt[p++];
            if (p + slen > rdata + rdlen)
                continue;
            memcpy(rr->service, pkt + p,
                    ogs_min(slen, sizeof(rr->service) - 1));
            p += slen;
            if (p >= rdata + rdlen)
                continue;
            rlen = pkt[p++]; /* regexp — ignore content */
            if (p + rlen > rdata + rdlen)
                continue;
            p += rlen;
            if (pgw_dns_decode_name(pkt, pktlen, p,
                        rr->replacement, sizeof(rr->replacement)) < 0)
                continue;
            pgw_dns_tolower(rr->flags);
            pgw_dns_tolower(rr->service);
            pgw_dns_tolower(rr->replacement);
            n++;
        }
    }
    return n;
}

static int pgw_dns_parse_srv(
        const uint8_t *pkt, int pktlen, srv_rr_t *out, int max_out)
{
    int off;
    uint16_t ancount, i;
    int n = 0;

    if (pktlen < 12)
        return 0;

    ancount = (uint16_t)((pkt[6] << 8) | pkt[7]);
    off = 12;
    off = pgw_dns_skip_name(pkt, pktlen, off);
    if (off < 0 || off + 4 > pktlen)
        return 0;
    off += 4;

    for (i = 0; i < ancount && n < max_out && off + 10 <= pktlen; i++) {
        uint16_t type, rdlen;
        int rdata;

        off = pgw_dns_skip_name(pkt, pktlen, off);
        if (off < 0 || off + 10 > pktlen)
            break;
        type = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
        rdlen = (uint16_t)((pkt[off + 8] << 8) | pkt[off + 9]);
        rdata = off + 10;
        off = rdata + rdlen;
        if (off > pktlen)
            break;
        if (type != DNS_TYPE_SRV || rdlen < 6)
            continue;

        {
            srv_rr_t *rr = &out[n];

            memset(rr, 0, sizeof(*rr));
            rr->priority = (uint16_t)((pkt[rdata] << 8) | pkt[rdata + 1]);
            rr->weight = (uint16_t)((pkt[rdata + 2] << 8) | pkt[rdata + 3]);
            rr->port = (uint16_t)((pkt[rdata + 4] << 8) | pkt[rdata + 5]);
            if (pgw_dns_decode_name(pkt, pktlen, rdata + 6,
                        rr->target, sizeof(rr->target)) < 0)
                continue;
            pgw_dns_tolower(rr->target);
            n++;
        }
    }
    return n;
}

static int pgw_dns_hostname_to_ip(const char *hostname, ogs_ip_t *out_ip)
{
    int rv;
    ogs_sockaddr_t *sa_list = NULL;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL, *walk;

    ogs_assert(hostname);
    ogs_assert(out_ip);
    memset(out_ip, 0, sizeof(*out_ip));

    rv = ogs_getaddrinfo(&sa_list, AF_UNSPEC, hostname, 0, 0);
    if (rv != OGS_OK || !sa_list)
        return OGS_ERROR;

    ogs_filter_ip_version(&sa_list,
            ogs_global_conf()->parameter.no_ipv4,
            ogs_global_conf()->parameter.no_ipv6,
            ogs_global_conf()->parameter.prefer_ipv4);
    if (!sa_list)
        return OGS_ERROR;

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
        ogs_freeaddrinfo(sa_list);
        return OGS_ERROR;
    }

    rv = ogs_sockaddr_to_ip(addr, addr6, out_ip);
    ogs_freeaddrinfo(sa_list);
    return rv;
}

static int naptr_cmp(const void *a, const void *b)
{
    const naptr_rr_t *x = a;
    const naptr_rr_t *y = b;

    if (x->order != y->order)
        return (int)x->order - (int)y->order;
    return (int)x->preference - (int)y->preference;
}

static int srv_cmp(const void *a, const void *b)
{
    const srv_rr_t *x = a;
    const srv_rr_t *y = b;

    if (x->priority != y->priority)
        return (int)x->priority - (int)y->priority;
    return (int)y->weight - (int)x->weight;
}

static int pgw_dns_resolve_via_naptr(
        ogs_sockaddr_t *ns_list, const char *apn_fqdn, bool use_s8,
        ogs_ip_t *out_ip)
{
    uint8_t resp[MME_PGW_DNS_PKT_MAX];
    int rlen;
    naptr_rr_t naptrs[MME_PGW_DNS_MAX_CANDIDATES];
    int n_naptr, i;

    rlen = pgw_dns_query_udp(ns_list, apn_fqdn, DNS_TYPE_NAPTR,
            resp, (int)sizeof(resp));
    if (rlen < 0)
        return OGS_ERROR;

    n_naptr = pgw_dns_parse_naptr(resp, rlen, naptrs, MME_PGW_DNS_MAX_CANDIDATES);
    if (n_naptr <= 0)
        return OGS_ERROR;

    qsort(naptrs, n_naptr, sizeof(naptr_rr_t), naptr_cmp);

    for (i = 0; i < n_naptr; i++) {
        if (!pgw_dns_service_match(naptrs[i].service, use_s8))
            continue;
        if (!naptrs[i].replacement[0])
            continue;

        if (strchr(naptrs[i].flags, 's')) {
            uint8_t sresp[MME_PGW_DNS_PKT_MAX];
            int slen;
            srv_rr_t srvs[MME_PGW_DNS_MAX_CANDIDATES];
            int n_srv, j;

            slen = pgw_dns_query_udp(ns_list, naptrs[i].replacement,
                    DNS_TYPE_SRV, sresp, (int)sizeof(sresp));
            if (slen < 0)
                continue;
            n_srv = pgw_dns_parse_srv(sresp, slen, srvs,
                    MME_PGW_DNS_MAX_CANDIDATES);
            if (n_srv <= 0)
                continue;
            qsort(srvs, n_srv, sizeof(srv_rr_t), srv_cmp);
            for (j = 0; j < n_srv; j++) {
                if (!srvs[j].target[0] || strcmp(srvs[j].target, ".") == 0)
                    continue;
                if (pgw_dns_hostname_to_ip(srvs[j].target, out_ip) == OGS_OK) {
                    ogs_info("PGW APN DNS NAPTR/SRV: %s -> %s",
                            apn_fqdn, srvs[j].target);
                    return OGS_OK;
                }
            }
        } else {
            /* flag "a" or empty: replacement is a host */
            if (pgw_dns_hostname_to_ip(naptrs[i].replacement, out_ip) ==
                    OGS_OK) {
                ogs_info("PGW APN DNS NAPTR: %s -> %s (svc=%s)",
                        apn_fqdn, naptrs[i].replacement, naptrs[i].service);
                return OGS_OK;
            }
        }
    }
    return OGS_ERROR;
}

static void pgw_dns_cache_store(
        const char *key, const ogs_ip_t *ip, bool resolved)
{
    char *cache_key;
    pgw_dns_cache_entry_t *entry;

    ogs_assert(key);
    ogs_thread_mutex_lock(&pgw_dns_cache_mutex);
    entry = ogs_hash_get(pgw_dns_cache, key, strlen(key));
    if (!entry) {
        cache_key = ogs_strdup(key);
        ogs_assert(cache_key);
        entry = ogs_calloc(1, sizeof(*entry));
        ogs_assert(entry);
        ogs_hash_set(pgw_dns_cache, cache_key, strlen(cache_key), entry);
    }
    entry->resolved = resolved;
    if (resolved && ip)
        memcpy(&entry->ip, ip, sizeof(entry->ip));
    else
        memset(&entry->ip, 0, sizeof(entry->ip));
    entry->expire = ogs_time_now() + ogs_time_from_sec(
            resolved ? MME_PGW_DNS_CACHE_TTL_SEC : MME_PGW_DNS_NEG_TTL_SEC);
    ogs_thread_mutex_unlock(&pgw_dns_cache_mutex);
}

static int pgw_dns_cache_lookup(const char *key, ogs_ip_t *out_ip)
{
    pgw_dns_cache_entry_t *entry;
    ogs_time_t now = ogs_time_now();

    ogs_thread_mutex_lock(&pgw_dns_cache_mutex);
    entry = ogs_hash_get(pgw_dns_cache, key, strlen(key));
    if (!entry || now >= entry->expire) {
        ogs_thread_mutex_unlock(&pgw_dns_cache_mutex);
        return OGS_ERROR;
    }
    if (!entry->resolved) {
        ogs_thread_mutex_unlock(&pgw_dns_cache_mutex);
        return OGS_RETRY; /* negative hit */
    }
    memcpy(out_ip, &entry->ip, sizeof(*out_ip));
    ogs_thread_mutex_unlock(&pgw_dns_cache_mutex);
    return OGS_OK;
}

int mme_pgw_dns_resolve_apn(
        const char *apn_ni, const ogs_plmn_id_t *oi_plmn_id,
        bool use_s8, ogs_ip_t *out_ip)
{
    char apn_fqdn[OGS_MAX_FQDN_LEN + 1];
    char legacy[OGS_MAX_FQDN_LEN + 1];
    char cache_key[OGS_MAX_FQDN_LEN + 16];
    ogs_sockaddr_t *ns_list = NULL;
    int rv;
    ogs_ip_t resolved;

    ogs_assert(apn_ni);
    ogs_assert(oi_plmn_id);
    ogs_assert(out_ip);
    memset(out_ip, 0, sizeof(*out_ip));

    if (mme_pgw_dns_build_apn_fqdn(
                apn_fqdn, sizeof(apn_fqdn), apn_ni, oi_plmn_id) <= 0) {
        ogs_error("Failed to build APN-FQDN for NI[%s]", apn_ni);
        return OGS_ERROR;
    }

    ogs_snprintf(cache_key, sizeof(cache_key), "%s|%s",
            apn_fqdn, use_s8 ? "s8" : "s5");

    rv = pgw_dns_cache_lookup(cache_key, out_ip);
    if (rv == OGS_OK) {
        ogs_debug("PGW APN DNS cache hit [%s]", cache_key);
        return OGS_OK;
    }
    if (rv == OGS_RETRY) {
        ogs_debug("PGW APN DNS negative-cache hit [%s]", cache_key);
        return OGS_ERROR;
    }

    ogs_info("PGW APN DNS lookup: fqdn=%s service=x-3gpp-pgw:%s",
            apn_fqdn, use_s8 ? "x-s8-gtp" : "x-s5-gtp");

    memset(&resolved, 0, sizeof(resolved));

    if (pgw_dns_read_resolv_conf(&ns_list) == OGS_OK && ns_list) {
        if (pgw_dns_resolve_via_naptr(
                    ns_list, apn_fqdn, use_s8, &resolved) == OGS_OK) {
            ogs_freeaddrinfo(ns_list);
            memcpy(out_ip, &resolved, sizeof(*out_ip));
            pgw_dns_cache_store(cache_key, out_ip, true);
            return OGS_OK;
        }
        ogs_freeaddrinfo(ns_list);
        ns_list = NULL;
    }

    /* Fallback: A/AAAA on APN-FQDN */
    if (pgw_dns_hostname_to_ip(apn_fqdn, &resolved) == OGS_OK) {
        ogs_info("PGW APN DNS A/AAAA fallback: %s", apn_fqdn);
        memcpy(out_ip, &resolved, sizeof(*out_ip));
        pgw_dns_cache_store(cache_key, out_ip, true);
        return OGS_OK;
    }

    /* Fallback: legacy .gprs APN */
    {
        char ni_copy[OGS_MAX_APN_LEN + 1];

        ogs_cpystrn(ni_copy, apn_ni, sizeof(ni_copy));
        pgw_dns_tolower(ni_copy);
        if (ogs_dnn_oi_from_fqdn(ni_copy))
            ogs_cpystrn(legacy, ni_copy, sizeof(legacy));
        else
            ogs_snprintf(legacy, sizeof(legacy),
                    "%s.mnc%03d.mcc%03d.gprs",
                    ni_copy,
                    ogs_plmn_id_mnc(oi_plmn_id),
                    ogs_plmn_id_mcc(oi_plmn_id));

        if (pgw_dns_hostname_to_ip(legacy, &resolved) == OGS_OK) {
            ogs_info("PGW APN DNS legacy .gprs fallback: %s", legacy);
            memcpy(out_ip, &resolved, sizeof(*out_ip));
            pgw_dns_cache_store(cache_key, out_ip, true);
            return OGS_OK;
        }
    }

    ogs_error("PGW APN DNS failed: fqdn=%s", apn_fqdn);
    pgw_dns_cache_store(cache_key, NULL, false);
    return OGS_ERROR;
}
