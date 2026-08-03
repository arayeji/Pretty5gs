/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
 *
 * TS 29.303 APN-FQDN PGW discovery (S-NAPTR / SRV / A/AAAA) with fallbacks.
 * Blocking getaddrinfo / NAPTR UDP runs only on the DNS worker pool.
 */

#if !defined(MME_PGW_DNS_H_INCLUDED)
#define MME_PGW_DNS_H_INCLUDED

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

void mme_pgw_dns_cache_init(void);
void mme_pgw_dns_cache_final(void);
int mme_pgw_dns_cache_clear_all(void);

/* DNS worker pool (default 2). No-op if already started. */
void mme_pgw_dns_workers_start(void);
void mme_pgw_dns_workers_stop(void);

/*
 * Build TS 23.003 APN-FQDN:
 *   <ni>.apn.epc.mncXXX.mccYYY.3gppnetwork.org
 * NI already containing a valid OI is preserved (rewritten to EPC form).
 */
int mme_pgw_dns_build_apn_fqdn(
        char *buf, int buflen, const char *apn_ni,
        const ogs_plmn_id_t *oi_plmn_id);

/*
 * Resolve PGW-C via APN-FQDN S-NAPTR (x-s5-gtp / x-s8-gtp), then SRV/A/AAAA.
 * Falls back to A/AAAA on APN-FQDN and legacy <ni>.mnc.mcc.gprs.
 *
 * Cache hit/negative is fast on the caller. On miss, work is queued to the
 * DNS worker pool and the caller waits on the job (getaddrinfo never runs
 * on UE shard / mme-main). Prefer mme_pgw_dns_resolve_apn_async().
 */
int mme_pgw_dns_resolve_apn(
        const char *apn_ni, const ogs_plmn_id_t *oi_plmn_id,
        bool use_s8, ogs_ip_t *out_ip);

/*
 * Async APN DNS for Create Session.
 *
 * Returns:
 *   OGS_OK    — positive cache hit (*out_ip_on_cache_hit filled)
 *   OGS_ERROR — negative cache hit (or hard failure before queue)
 *   OGS_RETRY — miss queued; MME_EVENT_PGW_DNS_DONE will be posted to
 *               the UE owner with sess_id / create_action / result
 */
int mme_pgw_dns_resolve_apn_async(
        const char *apn_ni, const ogs_plmn_id_t *oi_plmn_id,
        bool use_s8,
        ogs_pool_id_t sess_id, ogs_pool_id_t mme_ue_id,
        ogs_pool_id_t enb_ue_id, int create_action,
        ogs_ip_t *out_ip_on_cache_hit);

#ifdef __cplusplus
}
#endif

#endif /* MME_PGW_DNS_H_INCLUDED */
