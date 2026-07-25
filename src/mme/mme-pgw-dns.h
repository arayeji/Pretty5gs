/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
 *
 * TS 29.303 APN-FQDN PGW discovery (S-NAPTR / SRV / A/AAAA) with fallbacks.
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
 */
int mme_pgw_dns_resolve_apn(
        const char *apn_ni, const ogs_plmn_id_t *oi_plmn_id,
        bool use_s8, ogs_ip_t *out_ip);

#ifdef __cplusplus
}
#endif

#endif /* MME_PGW_DNS_H_INCLUDED */
