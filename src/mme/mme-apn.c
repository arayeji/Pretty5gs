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

#include "mme-apn.h"

#include "mme-context.h"

#include <ctype.h>

/*
 * GTP/DNS APN labels are case-insensitive (TS 23.003) but several EPC
 * peers (e.g. Huawei SGW/PGW) log and match lowercase NI (mcinet, hiweb).
 */
static void mme_apn_fqdn_tolower(char *fqdn)
{
    char *p = NULL;

    ogs_assert(fqdn);

    for (p = fqdn; *p; p++) {
        if (*p >= 'A' && *p <= 'Z')
            *p = (char)tolower((unsigned char)*p);
    }
}

void mme_apn_oi_plmn_id(
        mme_ue_t *mme_ue, ogs_session_t *session, ogs_plmn_id_t *oi_plmn_id)
{
    ogs_plmn_id_t home_plmn_id;

    ogs_assert(mme_ue);
    ogs_assert(session);
    ogs_assert(oi_plmn_id);

    ogs_plmn_id_from_imsi_bcd(mme_ue->imsi_bcd, &home_plmn_id);

    /*
     * TS 23.003 9.1 / TS 23.401 5.10.2:
     * - HSS Service-Selection carries APN-NI only (TS 29.272).
     * - MME appends APN-OI for DNS and GTP.
     * - Home PGW from subscription (MIP6-Agent-Info) -> HPLMN OI (HR).
     * - Visited PGW (local list) while roaming -> VPLMN OI (LBO).
     * - Non-roaming -> serving PLMN OI.
     */
    if (session->smf_ip.ipv4 || session->smf_ip.ipv6) {
        memcpy(oi_plmn_id, &home_plmn_id, OGS_PLMN_ID_LEN);
        return;
    }

    memcpy(oi_plmn_id, &mme_ue->tai.plmn_id, OGS_PLMN_ID_LEN);
}

static bool mme_ue_uses_home_pgw(ogs_session_t *session)
{
    ogs_assert(session);
    return session->smf_ip.ipv4 || session->smf_ip.ipv6;
}

static bool mme_ue_is_inbound_roam(mme_ue_t *mme_ue)
{
    ogs_plmn_id_t home_plmn_id;

    ogs_assert(mme_ue);

    ogs_plmn_id_from_imsi_bcd(mme_ue->imsi_bcd, &home_plmn_id);
    return memcmp(&home_plmn_id, &mme_ue->tai.plmn_id, OGS_PLMN_ID_LEN) != 0;
}

int mme_apn_for_gtp(
        mme_ue_t *mme_ue, ogs_session_t *session,
        char *buf, int buflen)
{
    ogs_plmn_id_t oi_plmn_id;
    bool inbound_roam = false;
    bool lowercase = true;
    int len;

    ogs_assert(mme_ue);
    ogs_assert(session);
    ogs_assert(buf);
    ogs_assert(buflen > OGS_MAX_APN_LEN);

    inbound_roam = mme_ue_uses_home_pgw(session) ||
        mme_ue_is_inbound_roam(mme_ue);

    if (inbound_roam) {
        lowercase = mme_self()->inbound_roam_gtp_apn_lowercase;

        if (mme_self()->inbound_roam_gtp_apn_format ==
                MME_INBOUND_ROAM_GTP_APN_RECEIVED) {
            ogs_assert(session->name);
            ogs_cpystrn(buf, session->name, buflen);
            len = (int)strlen(buf);
            if (len <= 0)
                return 0;
            if (lowercase)
                mme_apn_fqdn_tolower(buf);
            return len;
        }
    }

    mme_apn_oi_plmn_id(mme_ue, session, &oi_plmn_id);
    return mme_apn_build_fqdn(
            buf, buflen, session->name, &oi_plmn_id, lowercase);
}

int mme_apn_build_fqdn(
        char *buf, int buflen, const char *apn_ni,
        const ogs_plmn_id_t *oi_plmn_id, bool lowercase)
{
    char *oi = NULL;
    char *oi_alloc = NULL;
    int len;

    ogs_assert(buf);
    ogs_assert(buflen > OGS_MAX_APN_LEN);
    ogs_assert(apn_ni);
    ogs_assert(oi_plmn_id);

    if (!apn_ni[0])
        return 0;

    if (ogs_dnn_oi_from_fqdn((char *)apn_ni)) {
        ogs_cpystrn(buf, apn_ni, buflen);
        if (lowercase)
            mme_apn_fqdn_tolower(buf);
        return strlen(buf);
    }

    oi_alloc = ogs_dnn_oi_from_plmn_id(oi_plmn_id);
    ogs_assert(oi_alloc);
    oi = oi_alloc;

    len = ogs_snprintf(buf, buflen, "%s.%s", apn_ni, oi);
    ogs_free(oi_alloc);

    if (len <= 0 || len >= buflen)
        return 0;

    if (lowercase)
        mme_apn_fqdn_tolower(buf);
    return len;
}

bool mme_gtp_csr_omit_indication(mme_ue_t *mme_ue, ogs_session_t *session)
{
    ogs_assert(mme_ue);
    ogs_assert(session);

    if (!mme_self()->inbound_roam_omit_indication_on_gtp_csr)
        return false;

    return mme_ue_uses_home_pgw(session) || mme_ue_is_inbound_roam(mme_ue);
}

int mme_gtp_pco_for_csr(ogs_session_t *session,
        const uint8_t *ue_pco, int ue_pco_len,
        unsigned char *buf, int buflen, int *out_len)
{
    /* Containers many LTE PGWs (e.g. Huawei) reject on S5 CSR */
    static const uint16_t home_pgw_exclude_ids[] = {
        OGS_PCO_ID_INTERNET_PROTOCOL_CONTROL_PROTOCOL,
        OGS_PCO_ID_PASSWORD_AUTHENTICATION_PROTOCOL,
        OGS_PCO_ID_CHALLENGE_HANDSHAKE_AUTHENTICATION_PROTOCOL,
        OGS_PCO_ID_MS_SUPPORT_LOCAL_ADDR_TFT_INDICATOR,
        OGS_PCO_ID_3GPP_PS_DATA_OFF_UE_STATUS,
        OGS_PCO_ID_PDU_SESSION_ID,
        OGS_PCO_ID_QOS_RULES_TWO_OCTET_LENGTH_SUPPORT,
        OGS_PCO_ID_QOS_FLOW_DESCRIPTIONS_TWO_OCTET_LENGTH_SUPPORT,
    };
    int filtered_len;

    ogs_assert(session);
    ogs_assert(buf);
    ogs_assert(out_len);

    *out_len = 0;

    if (!ue_pco || ue_pco_len <= 0)
        return OGS_OK;

    if ((session->smf_ip.ipv4 || session->smf_ip.ipv6) &&
            mme_self()->inbound_roam_strip_pap_from_gtp_pco) {
        filtered_len = ogs_pco_filter_copy(buf, buflen,
                ue_pco, ue_pco_len,
                home_pgw_exclude_ids, OGS_ARRAY_SIZE(home_pgw_exclude_ids));
        if (filtered_len < 0) {
            ogs_error("ogs_pco_filter_copy() failed");
            return OGS_ERROR;
        }
        if (filtered_len > 1) {
            *out_len = filtered_len;
            ogs_debug("GTP CSR PCO: home-PGW sanitize (%d -> %d bytes)",
                    ue_pco_len, filtered_len);
        } else {
            ogs_debug("GTP CSR PCO: empty after home-PGW sanitize, omitting IE");
        }
        return OGS_OK;
    }

    if (ue_pco_len > buflen) {
        ogs_error("PCO too large [%d > %d]", ue_pco_len, buflen);
        return OGS_ERROR;
    }
    memcpy(buf, ue_pco, ue_pco_len);
    *out_len = ue_pco_len;
    return OGS_OK;
}
