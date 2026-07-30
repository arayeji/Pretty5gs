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

#include "mme-ambr.h"

#include "mme-context.h"

bool mme_ambr_bps_meaningful(uint32_t bps)
{
    /*
     * Only 0 means "no AMBR provisioned".
     *
     * Previously 2^30 (MME_AMBR_HSS_LARGE_BPS) and UINT32_MAX
     * (MME_AMBR_UNLIMITED_BPS) were treated as sentinels and forced to 0 by
     * mme_ambr_sanitize_bitrate(). But 2^30 is exactly the value the Open5GS
     * WebUI stores for a "1 Gbps" subscription (value << unit*10, 1 << 30),
     * so every subscriber provisioned with a whole-Gbps AMBR had their
     * UE-AMBR zeroed -> the eNB policed them to ~0 -> no uplink/downlink.
     *
     * Treat all nonzero rates as real values. When an operator genuinely
     * wants to clamp huge/unlimited AMBRs, ambr_limit (enabled/force) is the
     * intended mechanism and still applies on top of this.
     */
    return bps != 0;
}

void mme_ambr_complete_directions(ogs_bitrate_t *ambr)
{
    ogs_assert(ambr);

    mme_ambr_sanitize_bitrate(ambr);

    if (mme_ambr_bps_meaningful(ambr->uplink) &&
            !mme_ambr_bps_meaningful(ambr->downlink))
        ambr->downlink = ambr->uplink;
    else if (mme_ambr_bps_meaningful(ambr->downlink) &&
            !mme_ambr_bps_meaningful(ambr->uplink))
        ambr->uplink = ambr->downlink;

    mme_ambr_sanitize_bitrate(ambr);
}

void mme_ambr_sanitize_bitrate(ogs_bitrate_t *ambr)
{
    ogs_assert(ambr);

    if (!mme_ambr_bps_meaningful(ambr->downlink))
        ambr->downlink = 0;
    if (!mme_ambr_bps_meaningful(ambr->uplink))
        ambr->uplink = 0;
}

uint8_t mme_gtp2_pdn_type_for_sess(
        ogs_session_t *session, uint8_t ue_request_type)
{
    uint8_t derived;

    ogs_assert(session);

    derived = (session->session_type & ue_request_type);
    if (derived == 0) {
        /*
         * Paths that build a CSR without the ESM reconciliation (TAU,
         * handover, Gn) can land here. The subscribed type is the only
         * defensible answer, and it beats aborting the MME.
         */
        ogs_error("No PDN type overlap [UE:%d,HSS:%d] for APN[%s]; "
                "using subscribed type",
                ue_request_type, session->session_type,
                session->name ? session->name : "-");
        derived = session->session_type;
    }

    /*
     * Inbound roam to a home PGW (MIP6/SMF in ULA): use IPv4 on S5 CSR when
     * both UE and subscription allow it. IPv4v6 + empty dual PAA often fails
     * on vendor PGWs (e.g. Huawei) while attach is still IPv4-capable.
     */
    if (mme_self()->inbound_roam_force_ipv4_pdn_on_home_pgw &&
            (session->smf_ip.ipv4 || session->smf_ip.ipv6) &&
            derived == OGS_PDU_SESSION_TYPE_IPV4V6 &&
            (session->session_type & OGS_PDU_SESSION_TYPE_IPV4) &&
            (ue_request_type & OGS_PDU_SESSION_TYPE_IPV4))
        return OGS_PDU_SESSION_TYPE_IPV4;

    return derived;
}

void mme_ambr_apply_config(ogs_bitrate_t *ambr)
{
    mme_context_t *self = mme_self();
    uint32_t dl_cap, ul_cap;

    ogs_assert(ambr);

    mme_ambr_sanitize_bitrate(ambr);

    if (!self->ambr_limit.enabled)
        return;

    dl_cap = self->ambr_limit.downlink_bps;
    ul_cap = self->ambr_limit.uplink_bps;

    if (self->ambr_limit.force) {
        ambr->downlink = dl_cap;
        ambr->uplink = ul_cap;
        return;
    }

    if (ambr->downlink > dl_cap)
        ambr->downlink = dl_cap;
    if (ambr->uplink > ul_cap)
        ambr->uplink = ul_cap;
}

ogs_bitrate_t mme_sess_ambr_for_pdn(mme_ue_t *mme_ue, ogs_session_t *session)
{
    ogs_bitrate_t ambr;

    ogs_assert(session);

    memset(&ambr, 0, sizeof(ambr));

    ambr = session->ambr;
    mme_ambr_sanitize_bitrate(&ambr);
    if (ambr.downlink || ambr.uplink)
        return ambr;

    if (mme_ue) {
        ambr = mme_ue->ambr;
        mme_ambr_sanitize_bitrate(&ambr);
        if (ambr.downlink || ambr.uplink)
            return ambr;
    }

    memset(&ambr, 0, sizeof(ambr));
    return ambr;
}

ogs_bitrate_t mme_ue_ambr_for_s1ap(mme_ue_t *mme_ue)
{
    ogs_bitrate_t ambr, pdn_ambr, sum;
    mme_sess_t *sess;

    ogs_assert(mme_ue);

    memset(&ambr, 0, sizeof(ambr));
    memset(&sum, 0, sizeof(sum));

    ambr = mme_ue->ambr;
    mme_ambr_sanitize_bitrate(&ambr);
    if (ambr.downlink || ambr.uplink) {
        mme_ambr_apply_config(&ambr);
        mme_ambr_complete_directions(&ambr);
        if (ambr.uplink || ambr.downlink)
            return ambr;
    }

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        if (!sess->session)
            continue;
        pdn_ambr = mme_sess_ambr_for_pdn(mme_ue, sess->session);
        mme_ambr_sanitize_bitrate(&pdn_ambr);
        sum.downlink += pdn_ambr.downlink;
        sum.uplink += pdn_ambr.uplink;
    }

    if (sum.downlink || sum.uplink) {
        ambr = sum;
        mme_ambr_apply_config(&ambr);
        mme_ambr_complete_directions(&ambr);
        if (ambr.uplink || ambr.downlink)
            return ambr;
    }

    memset(&ambr, 0, sizeof(ambr));
    mme_ambr_apply_config(&ambr);
    mme_ambr_complete_directions(&ambr);
    if (!ambr.uplink && !ambr.downlink &&
            mme_self()->ambr_limit.enabled) {
        ambr.uplink = mme_self()->ambr_limit.uplink_bps;
        ambr.downlink = mme_self()->ambr_limit.downlink_bps;
    }

    return ambr;
}

bool mme_epc_qci_is_gbr(uint8_t qci)
{
    switch (qci) {
    case 1:
    case 2:
    case 3:
    case 4:
    case 65:
    case 66:
    case 67:
    case 75:
        return true;
    default:
        return false;
    }
}

void mme_qos_fill_bearer_bitrates(
        mme_ue_t *mme_ue, ogs_session_t *session, ogs_qos_t *qos)
{
    ogs_bitrate_t pdn_ambr;

    ogs_assert(session);
    ogs_assert(qos);

    if (qos->mbr.downlink || qos->mbr.uplink)
        return;

    /*
     * Optional inbound-roam interop: non-GBR MBR/GBR stay zero on CSR (AMBR IE
     * carries rates). When disabled, non-GBR bearers get MBR from PDN AMBR.
     */
    if (mme_self()->inbound_roam_zero_bearer_mbr_for_non_gbr &&
            !mme_epc_qci_is_gbr(qos->index))
        return;

    pdn_ambr = mme_sess_ambr_for_pdn(mme_ue, session);
    mme_ambr_apply_config(&pdn_ambr);
    if (!pdn_ambr.downlink && !pdn_ambr.uplink)
        return;

    qos->mbr = pdn_ambr;

    /*
     * GBR bearers also need GBR; non-GBR (e.g. QCI 9) keep GBR at zero
     * but still signal MBR from subscribed / PDN AMBR on CSR/NAS.
     */
    if (mme_epc_qci_is_gbr(qos->index) &&
            !qos->gbr.downlink && !qos->gbr.uplink)
        qos->gbr = pdn_ambr;
}

void mme_gtp2_bearer_qos_from_session(
        ogs_gtp2_bearer_qos_t *bearer_qos,
        mme_ue_t *mme_ue, ogs_session_t *session)
{
    ogs_qos_t qos;

    ogs_assert(bearer_qos);
    ogs_assert(session);

    memcpy(&qos, &session->qos, sizeof(qos));
    mme_qos_fill_bearer_bitrates(mme_ue, session, &qos);

    memset(bearer_qos, 0, sizeof(*bearer_qos));
    bearer_qos->qci = qos.index;
    bearer_qos->priority_level = qos.arp.priority_level;
    bearer_qos->pre_emption_capability = qos.arp.pre_emption_capability;
    bearer_qos->pre_emption_vulnerability = qos.arp.pre_emption_vulnerability;
    bearer_qos->ul_mbr = qos.mbr.uplink;
    bearer_qos->dl_mbr = qos.mbr.downlink;
    bearer_qos->ul_gbr = qos.gbr.uplink;
    bearer_qos->dl_gbr = qos.gbr.downlink;
}

void mme_bearer_qos_for_s1ap(ogs_qos_t *qos)
{
    ogs_assert(qos);

    if (!mme_epc_qci_is_gbr(qos->index)) {
        qos->mbr.downlink = 0;
        qos->mbr.uplink = 0;
        qos->gbr.downlink = 0;
        qos->gbr.uplink = 0;
        return;
    }

    if (!(qos->mbr.downlink && qos->mbr.uplink &&
            qos->gbr.downlink && qos->gbr.uplink)) {
        ogs_warn("GBR QCI[%u] has incomplete MBR/GBR; omit S1AP gbrQosInformation",
                qos->index);
        qos->mbr.downlink = 0;
        qos->mbr.uplink = 0;
        qos->gbr.downlink = 0;
        qos->gbr.uplink = 0;
    }
}

uint8_t mme_gtp2_selection_mode_for_sess(
        mme_ue_t *mme_ue, mme_sess_t *sess, ogs_session_t *session)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_pdn_connectivity_request_t *pdn_req = NULL;
    ogs_nas_esm_message_container_t *esm_container = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    char req_apn[OGS_MAX_APN_LEN+1];
    int req_len;

    ogs_assert(mme_ue);
    ogs_assert(sess);
    ogs_assert(session);
    ogs_assert(session->name);

    esm_container = &mme_ue->pdn_connectivity_request;
    if (!esm_container->length || !esm_container->buffer)
        return OGS_GTP2_SELECTION_MODE_MS_OR_NETWORK_PROVIDED_APN;

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_NAS_HEADROOM + esm_container->length);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_NAS_HEADROOM);
    ogs_pkbuf_put_data(pkbuf, esm_container->buffer, esm_container->length);

    memset(&message, 0, sizeof(message));
    if (ogs_nas_esm_decode(&message, pkbuf) != OGS_OK) {
        ogs_pkbuf_free(pkbuf);
        return OGS_GTP2_SELECTION_MODE_MS_OR_NETWORK_PROVIDED_APN;
    }
    ogs_pkbuf_free(pkbuf);

    if (message.esm.h.message_type != OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST)
        return OGS_GTP2_SELECTION_MODE_MS_OR_NETWORK_PROVIDED_APN;

    pdn_req = &message.esm.pdn_connectivity_request;
    if (!(pdn_req->presencemask &
            OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST_ACCESS_POINT_NAME_PRESENT))
        return OGS_GTP2_SELECTION_MODE_MS_OR_NETWORK_PROVIDED_APN;

    if (!pdn_req->access_point_name.length)
        return OGS_GTP2_SELECTION_MODE_MS_OR_NETWORK_PROVIDED_APN;

    req_len = ogs_min(pdn_req->access_point_name.length, OGS_MAX_APN_LEN);
    memcpy(req_apn, pdn_req->access_point_name.apn, req_len);
    req_apn[req_len] = 0;

    if (ogs_strcasecmp(req_apn, session->name) == 0)
        return OGS_GTP2_SELECTION_MODE_MS_OR_NETWORK_PROVIDED_APN;

    return OGS_GTP2_SELECTION_MODE_MS_PROVIDED_APN;
}
