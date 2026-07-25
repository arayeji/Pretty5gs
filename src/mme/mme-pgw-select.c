/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
 */

#include "mme-pgw-select.h"

#include "mme-apn.h"
#include "mme-context.h"
#include "mme-pgw-dns.h"
#include "mme-trace.h"

const char *mme_pgw_selection_source_string(mme_pgw_selection_source_t source)
{
    switch (source) {
    case MME_PGW_SOURCE_FORCE_YAML:
        return "force-yaml";
    case MME_PGW_SOURCE_HSS_STATIC:
        return "hss-static";
    case MME_PGW_SOURCE_APN_DNS:
        return "apn-dns";
    case MME_PGW_SOURCE_YAML_FALLBACK:
        return "yaml-fallback";
    default:
        return "unknown";
    }
}

static bool mme_pgw_hss_static_usable(const ogs_session_t *session)
{
    ogs_assert(session);

    if (!session->smf_ip.ipv4 && !session->smf_ip.ipv6)
        return false;

    /* DYNAMIC means HSS identity is not a permanent static binding. */
    if (session->pdn_gw_allocation_type == OGS_PDN_GW_ALLOCATION_DYNAMIC)
        return false;

    return true;
}

static int mme_pgw_select_yaml(
        mme_ue_t *mme_ue, mme_sess_t *sess, ogs_session_t *session,
        ogs_ip_t *out_ip, mme_pgw_t **out_pgw)
{
    mme_pgw_t *pgw;
    ogs_sockaddr_t *pgw_addr = NULL;
    ogs_sockaddr_t *pgw_addr6 = NULL;

    ogs_assert(sess);
    ogs_assert(session);
    ogs_assert(out_ip);

    pgw = mme_pgw_find_for_sess(&mme_self()->pgw_list, sess);
    if (!pgw) {
        ogs_error("[%s] No SMF/PGW match for DNN[%s]",
                mme_ue ? mme_ue->imsi_bcd : "-",
                session->name ? session->name : "-");
        return OGS_ERROR;
    }

    mme_pgw_log_pick(mme_ue, pgw, session->name);
    if (mme_ue)
        mme_ue_progress(mme_ue, "pgw_selected");

    pgw_addr = mme_pgw_sockaddr_by_family(pgw, AF_INET);
    pgw_addr6 = mme_pgw_sockaddr_by_family(pgw, AF_INET6);
    if (!pgw_addr && !pgw_addr6) {
        ogs_error("[%s] No SMF/PGW address for DNN[%s]",
                mme_ue ? mme_ue->imsi_bcd : "-",
                session->name ? session->name : "-");
        return OGS_ERROR;
    }

    if (ogs_sockaddr_to_ip(pgw_addr, pgw_addr6, out_ip) != OGS_OK) {
        ogs_error("ogs_sockaddr_to_ip() failed for YAML PGW");
        return OGS_ERROR;
    }

    if (out_pgw)
        *out_pgw = pgw;
    return OGS_OK;
}

static int mme_pgw_select_apn_dns(
        mme_ue_t *mme_ue, ogs_session_t *session, ogs_ip_t *out_ip)
{
    ogs_plmn_id_t oi_plmn_id;
    bool use_s8;

    ogs_assert(mme_ue);
    ogs_assert(session);
    ogs_assert(session->name);
    ogs_assert(out_ip);

    mme_apn_oi_plmn_id(mme_ue, session, &oi_plmn_id);
    use_s8 = mme_ue_is_inbound_roam(mme_ue);

    ogs_info("PGW selection APN DNS: apn=%s roam=%s oi_plmn=%03d-%03d",
            session->name,
            use_s8 ? "true" : "false",
            ogs_plmn_id_mcc(&oi_plmn_id),
            ogs_plmn_id_mnc(&oi_plmn_id));

    return mme_pgw_dns_resolve_apn(session->name, &oi_plmn_id, use_s8, out_ip);
}

int mme_pgw_select_for_sess(
        mme_ue_t *mme_ue, mme_sess_t *sess, ogs_session_t *session,
        ogs_ip_t *out_ip, mme_pgw_t **out_pgw,
        mme_pgw_selection_source_t *out_source)
{
    mme_pgw_selection_source_t source = MME_PGW_SOURCE_YAML_FALLBACK;

    ogs_assert(sess);
    ogs_assert(session);
    ogs_assert(out_ip);

    memset(out_ip, 0, sizeof(*out_ip));
    if (out_pgw)
        *out_pgw = NULL;

    /*
     * 1) Per-rule force: gtpc.client.smf entry with force:true whose
     *    match (apn/plmn/imsi_prefix/tac/e_cell_id) covers this session
     *    always wins over HSS MIP6 and APN DNS.
     */
    {
        mme_pgw_t *forced = mme_pgw_find_forced_for_sess(
                &mme_self()->pgw_list, sess);

        if (forced) {
            ogs_sockaddr_t *pgw_addr =
                mme_pgw_sockaddr_by_family(forced, AF_INET);
            ogs_sockaddr_t *pgw_addr6 =
                mme_pgw_sockaddr_by_family(forced, AF_INET6);

            if ((pgw_addr || pgw_addr6) &&
                    ogs_sockaddr_to_ip(pgw_addr, pgw_addr6, out_ip) ==
                    OGS_OK) {
                mme_pgw_log_pick(mme_ue, forced, session->name);
                if (mme_ue)
                    mme_ue_progress(mme_ue, "pgw_selected");
                if (out_pgw)
                    *out_pgw = forced;
                source = MME_PGW_SOURCE_FORCE_YAML;
                goto done;
            }
            ogs_error("force PGW rule matched but has no usable address; "
                    "continuing with standard selection");
        }
    }

    /* 1b) Global force mode: always use configured gtpc.client.smf */
    if (mme_self()->pgw_selection.force_yaml) {
        source = MME_PGW_SOURCE_FORCE_YAML;
        if (mme_pgw_select_yaml(mme_ue, sess, session, out_ip, out_pgw) !=
                OGS_OK)
            return OGS_ERROR;
        goto done;
    }

    /* 2) HSS static MIP6 assignment */
    if (mme_pgw_hss_static_usable(session)) {
        memcpy(out_ip, &session->smf_ip, sizeof(*out_ip));
        source = MME_PGW_SOURCE_HSS_STATIC;
        goto done;
    }

    /* 3) Standards APN DNS discovery */
    if (mme_self()->pgw_selection.dns_enabled && mme_ue) {
        if (mme_pgw_select_apn_dns(mme_ue, session, out_ip) == OGS_OK) {
            source = MME_PGW_SOURCE_APN_DNS;
            /* Persist into subscription slot for later CSR / mobility. */
            memcpy(&session->smf_ip, out_ip, sizeof(session->smf_ip));
            goto done;
        }
        ogs_warn("[%s] APN DNS PGW selection failed for APN[%s]; "
                "trying next fallback",
                mme_ue->imsi_bcd, session->name ? session->name : "-");
    }

    /*
     * 4) Soft use of HSS MIP6 even when DYNAMIC (last allocated PGW), when
     *    APN DNS is off or failed. Preserves prior Pretty5GS behaviour.
     */
    if (session->smf_ip.ipv4 || session->smf_ip.ipv6) {
        memcpy(out_ip, &session->smf_ip, sizeof(*out_ip));
        source = MME_PGW_SOURCE_HSS_STATIC;
        ogs_info("[%s] Using HSS MIP6 PGW (incl. dynamic) for APN[%s]",
                mme_ue ? mme_ue->imsi_bcd : "-",
                session->name ? session->name : "-");
        goto done;
    }

    /* 5) YAML fallback (legacy Open5GS behaviour) */
    source = MME_PGW_SOURCE_YAML_FALLBACK;
    if (mme_pgw_select_yaml(mme_ue, sess, session, out_ip, out_pgw) != OGS_OK)
        return OGS_ERROR;

done:
    if (out_source)
        *out_source = source;

    {
        char addr[OGS_ADDRSTRLEN] = "-";

        if (out_ip->ipv4)
            OGS_INET_NTOP(&out_ip->addr, addr);
        else if (out_ip->ipv6)
            ogs_snprintf(addr, sizeof(addr), "ipv6");

        ogs_info("[%s] PGW selected source=%s apn=%s address=%s",
                mme_ue && MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-",
                mme_pgw_selection_source_string(source),
                session->name ? session->name : "-",
                addr);
    }
    return OGS_OK;
}
