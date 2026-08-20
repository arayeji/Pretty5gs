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

    /*
     * TS 29.272: MIP6 without PDN-GW-Allocation-Type ⇒ statically
     * allocated. DYNAMIC ⇒ last/previously allocated; MME must perform
     * local PGW selection instead of treating MIP6 as a permanent bind.
     */
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

static int mme_pgw_select_apn_dns_async(
        mme_ue_t *mme_ue, mme_sess_t *sess, ogs_session_t *session,
        enb_ue_t *enb_ue, int create_action, ogs_ip_t *out_ip)
{
    ogs_plmn_id_t oi_plmn_id;
    bool use_s8;

    ogs_assert(mme_ue);
    ogs_assert(sess);
    ogs_assert(session);
    ogs_assert(session->name);
    ogs_assert(out_ip);

    mme_apn_oi_plmn_id(mme_ue, session, &oi_plmn_id);
    use_s8 = mme_ue_is_inbound_roam(mme_ue);

    ogs_info("PGW selection APN DNS (async): apn=%s roam=%s oi_plmn=%03d-%03d",
            session->name,
            use_s8 ? "true" : "false",
            ogs_plmn_id_mcc(&oi_plmn_id),
            ogs_plmn_id_mnc(&oi_plmn_id));

    return mme_pgw_dns_resolve_apn_async(
            session->name, &oi_plmn_id, use_s8,
            sess->id, mme_ue->id,
            enb_ue ? enb_ue->id : OGS_INVALID_POOL_ID,
            create_action, out_ip);
}

static void mme_pgw_bind_log(
        mme_ue_t *mme_ue, ogs_session_t *session,
        mme_pgw_selection_source_t source, const ogs_ip_t *ip)
{
    char addr[OGS_ADDRSTRLEN] = "-";

    /* Format only when INFO would emit (ogs_info is lazy; this is not). */
    if (!ogs_log_domain_prints(OGS_LOG_DOMAIN, OGS_LOG_INFO))
        return;

    if (ip->ipv4)
        OGS_INET_NTOP(&ip->addr, addr);
    else if (ip->ipv6)
        ogs_snprintf(addr, sizeof(addr), "ipv6");

    ogs_info("[%s] PGW bound for CSR source=%s apn=%s address=%s",
            mme_ue && MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-",
            mme_pgw_selection_source_string(source),
            session && session->name ? session->name : "-",
            addr);
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

    /*
     * 1c) Per-APN policy rule (pgw_selection.rules): mode=dns resolves
     *     the PGW via APN DNS only, ignoring HSS MIP6 and the static
     *     YAML list. Runs even when the global dns.enabled flag is off.
     */
    {
        mme_pgw_sel_rule_t *rule = mme_pgw_sel_rule_find_for_sess(sess);

        if (rule && rule->mode == MME_PGW_SEL_RULE_MODE_DNS && mme_ue) {
            if (mme_pgw_select_apn_dns(mme_ue, session, out_ip) == OGS_OK) {
                source = MME_PGW_SOURCE_APN_DNS;
                goto done;
            }
            switch (rule->fallback) {
            case MME_PGW_SEL_RULE_FALLBACK_HSS:
                if (session->smf_ip.ipv4 || session->smf_ip.ipv6) {
                    memcpy(out_ip, &session->smf_ip, sizeof(*out_ip));
                    source = MME_PGW_SOURCE_HSS_STATIC;
                    ogs_warn("[%s] APN DNS failed for APN[%s]; "
                            "rule fallback=hss",
                            mme_ue->imsi_bcd,
                            session->name ? session->name : "-");
                    goto done;
                }
                ogs_warn("[%s] APN DNS failed for APN[%s]; "
                        "rule fallback=hss but no HSS PGW address",
                        mme_ue->imsi_bcd,
                        session->name ? session->name : "-");
                return OGS_ERROR;
            case MME_PGW_SEL_RULE_FALLBACK_YAML:
                source = MME_PGW_SOURCE_YAML_FALLBACK;
                ogs_warn("[%s] APN DNS failed for APN[%s]; "
                        "rule fallback=yaml",
                        mme_ue->imsi_bcd,
                        session->name ? session->name : "-");
                if (mme_pgw_select_yaml(mme_ue, sess, session,
                            out_ip, out_pgw) != OGS_OK)
                    return OGS_ERROR;
                goto done;
            case MME_PGW_SEL_RULE_FALLBACK_NONE:
            default:
                ogs_warn("[%s] APN DNS failed for APN[%s]; "
                        "dns-only rule, no fallback — rejecting session",
                        mme_ue->imsi_bcd,
                        session->name ? session->name : "-");
                return OGS_ERROR;
            }
        }
    }

    /*
     * 2) HSS MIP6 only when statically allocated (TS 29.272):
     *    - MIP6 present + PDN-GW-Allocation-Type absent → static
     *    - MIP6 present + STATIC → use it
     *    - MIP6 present + DYNAMIC → do NOT bind permanently; fall
     *      through to APN DNS / YAML (local PGW selection)
     */
    if (mme_pgw_hss_static_usable(session)) {
        memcpy(out_ip, &session->smf_ip, sizeof(*out_ip));
        source = MME_PGW_SOURCE_HSS_STATIC;
        goto done;
    }
    if ((session->smf_ip.ipv4 || session->smf_ip.ipv6) &&
            session->pdn_gw_allocation_type ==
                OGS_PDN_GW_ALLOCATION_DYNAMIC) {
        ogs_info("[%s] HSS MIP6 for APN[%s] is DYNAMIC — "
                "re-selecting PGW (APN DNS / YAML)",
                mme_ue ? mme_ue->imsi_bcd : "-",
                session->name ? session->name : "-");
    }

    /* 3) Standards APN DNS discovery (no usable static HSS PGW) */
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

    /* 4) YAML fallback (legacy Open5GS behaviour) */
    source = MME_PGW_SOURCE_YAML_FALLBACK;
    if (mme_pgw_select_yaml(mme_ue, sess, session, out_ip, out_pgw) != OGS_OK)
        return OGS_ERROR;

done:
    if (out_source)
        *out_source = source;

    if (ogs_log_domain_prints(OGS_LOG_DOMAIN, OGS_LOG_INFO)) {
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

int mme_pgw_bind_for_csr(mme_ue_t *mme_ue, mme_sess_t *sess,
        enb_ue_t *enb_ue, int create_action)
{
    ogs_session_t *session = NULL;
    ogs_ip_t ip;
    mme_pgw_t *pgw = NULL;
    mme_pgw_selection_source_t source = MME_PGW_SOURCE_YAML_FALLBACK;
    int rv;

    ogs_assert(sess);
    session = sess->session;
    if (!session) {
        ogs_error("bind_for_csr: session missing");
        return OGS_ERROR;
    }

    if (sess->pgw_s5c_ip.ipv4 || sess->pgw_s5c_ip.ipv6)
        return OGS_OK;

    if (sess->pgw_dns_pending)
        return OGS_RETRY;

    memset(&ip, 0, sizeof(ip));

    /* 1) Per-rule force YAML */
    {
        mme_pgw_t *forced = mme_pgw_find_forced_for_sess(
                &mme_self()->pgw_list, sess);

        if (forced) {
            ogs_sockaddr_t *pgw_addr =
                mme_pgw_sockaddr_by_family(forced, AF_INET);
            ogs_sockaddr_t *pgw_addr6 =
                mme_pgw_sockaddr_by_family(forced, AF_INET6);

            if ((pgw_addr || pgw_addr6) &&
                    ogs_sockaddr_to_ip(pgw_addr, pgw_addr6, &ip) ==
                    OGS_OK) {
                mme_pgw_log_pick(mme_ue, forced, session->name);
                if (mme_ue)
                    mme_ue_progress(mme_ue, "pgw_selected");
                memcpy(&sess->pgw_s5c_ip, &ip, sizeof(sess->pgw_s5c_ip));
                mme_pgw_bind_log(mme_ue, session,
                        MME_PGW_SOURCE_FORCE_YAML, &ip);
                return OGS_OK;
            }
            ogs_error("force PGW rule matched but has no usable address; "
                    "continuing with standard selection");
        }
    }

    /* 1b) Global force mode */
    if (mme_self()->pgw_selection.force_yaml) {
        if (mme_pgw_select_yaml(mme_ue, sess, session, &ip, &pgw) != OGS_OK)
            return OGS_ERROR;
        memcpy(&sess->pgw_s5c_ip, &ip, sizeof(sess->pgw_s5c_ip));
        mme_pgw_bind_log(mme_ue, session, MME_PGW_SOURCE_FORCE_YAML, &ip);
        return OGS_OK;
    }

    /* 1c) Per-APN policy rule mode=dns */
    {
        mme_pgw_sel_rule_t *rule = mme_pgw_sel_rule_find_for_sess(sess);

        if (rule && rule->mode == MME_PGW_SEL_RULE_MODE_DNS && mme_ue) {
            rv = mme_pgw_select_apn_dns_async(
                    mme_ue, sess, session, enb_ue, create_action, &ip);
            if (rv == OGS_OK) {
                memcpy(&sess->pgw_s5c_ip, &ip, sizeof(sess->pgw_s5c_ip));
                mme_pgw_bind_log(mme_ue, session,
                        MME_PGW_SOURCE_APN_DNS, &ip);
                return OGS_OK;
            }
            if (rv == OGS_RETRY) {
                sess->pgw_dns_pending = true;
                return OGS_RETRY;
            }
            switch (rule->fallback) {
            case MME_PGW_SEL_RULE_FALLBACK_HSS:
                if (session->smf_ip.ipv4 || session->smf_ip.ipv6) {
                    memcpy(&sess->pgw_s5c_ip, &session->smf_ip,
                            sizeof(sess->pgw_s5c_ip));
                    mme_pgw_bind_log(mme_ue, session,
                            MME_PGW_SOURCE_HSS_STATIC, &session->smf_ip);
                    return OGS_OK;
                }
                ogs_warn("[%s] APN DNS failed for APN[%s]; "
                        "rule fallback=hss but no HSS PGW address",
                        mme_ue->imsi_bcd,
                        session->name ? session->name : "-");
                return OGS_ERROR;
            case MME_PGW_SEL_RULE_FALLBACK_YAML:
                ogs_warn("[%s] APN DNS failed for APN[%s]; "
                        "rule fallback=yaml",
                        mme_ue->imsi_bcd,
                        session->name ? session->name : "-");
                if (mme_pgw_select_yaml(mme_ue, sess, session,
                            &ip, &pgw) != OGS_OK)
                    return OGS_ERROR;
                memcpy(&sess->pgw_s5c_ip, &ip, sizeof(sess->pgw_s5c_ip));
                mme_pgw_bind_log(mme_ue, session,
                        MME_PGW_SOURCE_YAML_FALLBACK, &ip);
                return OGS_OK;
            case MME_PGW_SEL_RULE_FALLBACK_NONE:
            default:
                ogs_warn("[%s] APN DNS failed for APN[%s]; "
                        "dns-only rule, no fallback — rejecting session",
                        mme_ue->imsi_bcd,
                        session->name ? session->name : "-");
                return OGS_ERROR;
            }
        }
    }

    /* 2) HSS MIP6 only when statically allocated (see select_for_sess) */
    if (mme_pgw_hss_static_usable(session)) {
        memcpy(&sess->pgw_s5c_ip, &session->smf_ip, sizeof(sess->pgw_s5c_ip));
        mme_pgw_bind_log(mme_ue, session, MME_PGW_SOURCE_HSS_STATIC,
                &session->smf_ip);
        return OGS_OK;
    }
    if ((session->smf_ip.ipv4 || session->smf_ip.ipv6) &&
            session->pdn_gw_allocation_type ==
                OGS_PDN_GW_ALLOCATION_DYNAMIC) {
        ogs_info("[%s] HSS MIP6 for APN[%s] is DYNAMIC — "
                "re-selecting PGW (APN DNS / YAML)",
                mme_ue ? mme_ue->imsi_bcd : "-",
                session->name ? session->name : "-");
    }

    /* 3) Standards APN DNS (async) */
    if (mme_self()->pgw_selection.dns_enabled && mme_ue) {
        rv = mme_pgw_select_apn_dns_async(
                mme_ue, sess, session, enb_ue, create_action, &ip);
        if (rv == OGS_OK) {
            memcpy(&sess->pgw_s5c_ip, &ip, sizeof(sess->pgw_s5c_ip));
            memcpy(&session->smf_ip, &ip, sizeof(session->smf_ip));
            mme_pgw_bind_log(mme_ue, session, MME_PGW_SOURCE_APN_DNS, &ip);
            return OGS_OK;
        }
        if (rv == OGS_RETRY) {
            sess->pgw_dns_pending = true;
            return OGS_RETRY;
        }
        ogs_warn("[%s] APN DNS PGW selection failed for APN[%s]; "
                "trying next fallback",
                mme_ue->imsi_bcd, session->name ? session->name : "-");
    }

    /* 4) YAML fallback */
    source = MME_PGW_SOURCE_YAML_FALLBACK;
    if (mme_pgw_select_yaml(mme_ue, sess, session, &ip, &pgw) != OGS_OK)
        return OGS_ERROR;
    memcpy(&sess->pgw_s5c_ip, &ip, sizeof(sess->pgw_s5c_ip));
    mme_pgw_bind_log(mme_ue, session, source, &ip);
    return OGS_OK;
}
