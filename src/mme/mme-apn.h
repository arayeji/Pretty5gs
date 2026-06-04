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

#if !defined(MME_APN_H_INCLUDED)
#define MME_APN_H_INCLUDED

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mme_ue_s mme_ue_t;
typedef struct ogs_session_s ogs_session_t;

void mme_apn_oi_plmn_id(
        mme_ue_t *mme_ue, ogs_session_t *session,
        ogs_plmn_id_t *oi_plmn_id);
int mme_apn_build_fqdn(
        char *buf, int buflen, const char *apn_ni,
        const ogs_plmn_id_t *oi_plmn_id, bool lowercase);
/*
 * GTP APN string for S11/Gn (before ogs_fqdn_build).
 * S11/Gn GTP APN string (before ogs_fqdn_build).
 * Home PLMN: APN-NI only (stock). Roaming PLMN: mme.inbound_roam gtp_apn_*.
 */
int mme_apn_for_gtp(
        mme_ue_t *mme_ue, ogs_session_t *session,
        char *buf, int buflen);

/*
 * PCO for GTP Create Session Request. When home PGW (session->smf_ip) and
 * strip_pap is true, removes PAP/CHAP containers (Huawei PGW interop).
 * Returns OGS_OK; *out_len is 0 to omit PCO IE.
 */
int mme_gtp_pco_for_csr(ogs_session_t *session,
        const uint8_t *ue_pco, int ue_pco_len,
        unsigned char *buf, int buflen, int *out_len);

/* Omit Indication IE on CSR when mme.inbound_roam.omit_indication_on_gtp_csr. */
bool mme_gtp_csr_omit_indication(mme_ue_t *mme_ue, ogs_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* MME_APN_H_INCLUDED */
