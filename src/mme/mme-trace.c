/*
 * Copyright (C) 2025 Open5GS contributors
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

#include "mme-trace.h"

#include <stdarg.h>

void ogs_mme_trace_set(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        const char *apn, const char *proc)
{
    ogs_trace_ctx_t ctx;
    mme_enb_t *enb = NULL;
    sgw_ue_t *sgw_ue = NULL;
    mme_sess_t *sess = NULL;

    memset(&ctx, 0, sizeof(ctx));

    if (proc && proc[0])
        ogs_cpystrn(ctx.proc, proc, sizeof(ctx.proc));
    if (apn && apn[0])
        ogs_cpystrn(ctx.apn, apn, sizeof(ctx.apn));

    if (enb_ue) {
        ctx.enb_ue_s1ap_id = enb_ue->enb_ue_s1ap_id;
        ctx.mme_ue_s1ap_id = enb_ue->mme_ue_s1ap_id;
        enb = mme_enb_find_by_id(enb_ue->enb_id);
        if (enb && enb->enb_id_presence)
            ctx.enb_id = enb->enb_id;
    }

    if (mme_ue) {
        mme_bearer_t *bearer = NULL;

        if (MME_UE_HAVE_IMSI(mme_ue))
            ogs_cpystrn(ctx.imsi, mme_ue->imsi_bcd, sizeof(ctx.imsi));
        ctx.mme_s11_teid = mme_ue->mme_s11_teid;

        sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
        if (sgw_ue)
            ctx.sgw_s11_teid = sgw_ue->sgw_s11_teid;

        sess = mme_sess_first(mme_ue);
        if (sess) {
            if (!ctx.apn[0] && sess->session && sess->session->name)
                ogs_cpystrn(ctx.apn, sess->session->name, sizeof(ctx.apn));

            if (sess->session) {
                char ipbuf[OGS_ADDRSTRLEN];

                if (sess->session->ue_ip.ipv4) {
                    ogs_cpystrn(ctx.ue_ip, OGS_INET_NTOP(
                                &sess->session->ue_ip.addr, ipbuf),
                            sizeof(ctx.ue_ip));
                } else if (sess->session->ue_ip.ipv6) {
                    ogs_cpystrn(ctx.ue_ip, OGS_INET6_NTOP(
                                sess->session->ue_ip.addr6, ipbuf),
                            sizeof(ctx.ue_ip));
                }
            }

            ogs_list_for_each(&sess->bearer_list, bearer) {
                ctx.ebi = bearer->ebi;
                break;
            }
        }
    }

    /* Full snapshot: unset fields show "-" instead of previous UE/session data. */
    ogs_trace_set(&ctx);
}

void ogs_mme_trace_from_ids(
        ogs_pool_id_t enb_ue_id, ogs_pool_id_t mme_ue_id,
        const char *apn, const char *proc)
{
    ogs_mme_trace_set(
            enb_ue_find_by_id(enb_ue_id),
            mme_ue_find_by_id(mme_ue_id),
            apn, proc);
}

static const char *mme_ue_log_id(mme_ue_t *mme_ue)
{
    if (!mme_ue)
        return "-";
    if (MME_UE_HAVE_IMSI(mme_ue))
        return mme_ue->imsi_bcd;
    return "-";
}

static bool mme_ue_progress_is_failure(const char *step)
{
    size_t len;

    ogs_assert(step);

    if (!strcmp(step, "attach_reject") ||
            !strcmp(step, "attach_accept_no_s1") ||
            !strcmp(step, "attach_accept_fail") ||
            !strcmp(step, "sgsap_lu_reject") ||
            !strcmp(step, "sgsap_lu_timeout") ||
            !strcmp(step, "create_session_rsp_late"))
        return true;

    len = strlen(step);
    if (len > 5 && !strcmp(step + len - 5, "_fail"))
        return true;

    return false;
}

void mme_ue_progress(mme_ue_t *mme_ue, const char *step)
{
    ogs_assert(step);

    if (mme_ue_progress_is_failure(step))
        /* Reject/fail is an expected per-subscriber outcome (roaming reject,
         * ACL, S6a deny), not an MME error - log at debug so it stays
         * filterable per-IMSI via mme.trace_imsi instead of flooding error. */
        mme_ue_debug(mme_ue, NULL, "attach", NULL, "ATTACH step: %s", step);
    else
        mme_ue_info(mme_ue, NULL, "attach", NULL, "ATTACH step: %s", step);
}

static enb_ue_t *mme_ue_resolve_enb(mme_ue_t *mme_ue, enb_ue_t *enb_ue)
{
    if (enb_ue)
        return enb_ue;
    if (mme_ue && mme_ue->enb_ue_id != OGS_INVALID_POOL_ID)
        return enb_ue_find_by_id(mme_ue->enb_ue_id);
    return NULL;
}

void mme_ue_log(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue,
        const char *proc, const char *apn, int level, const char *fmt, ...)
{
    va_list ap;
    char prefix[OGS_TRACE_PREFIX_BUFSIZE];
    char msg[OGS_HUGE_LEN];
    const char *imsi = mme_ue_log_id(mme_ue);

    ogs_assert(fmt);

    if (level == OGS_LOG_DEBUG &&
            !ogs_trace_filter_match(imsi) &&
            !ogs_log_domain_prints(OGS_LOG_DOMAIN, OGS_LOG_DEBUG))
        return;

    enb_ue = mme_ue_resolve_enb(mme_ue, enb_ue);
    ogs_mme_trace_set(enb_ue, mme_ue, apn, proc);
    ogs_trace_format_prefix(prefix, sizeof(prefix));

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    ogs_log_printf(level, OGS_LOG_DOMAIN,
            0, __FILE__, __LINE__, OGS_FUNC, 0, "%s %s", prefix, msg);
}

void mme_sess_removed_log(mme_ue_t *mme_ue, const char *apn)
{
    mme_ue_info(mme_ue, NULL, "esm", apn,
            "Session removed APN[%s]", apn ? apn : "Unknown");
}

void mme_bearer_added_log(mme_ue_t *mme_ue, mme_bearer_t *bearer)
{
    mme_sess_t *sess = NULL;
    const char *apn = NULL;

    ogs_assert(mme_ue);
    ogs_assert(bearer);

    sess = mme_sess_find_by_id(bearer->sess_id);
    if (sess && sess->session && sess->session->name)
        apn = sess->session->name;

    mme_ue_info(mme_ue, NULL, "bearer", apn,
            "Bearer added EBI=%d", bearer->ebi);
}

void mme_bearer_removed_log(mme_ue_t *mme_ue, mme_bearer_t *bearer)
{
    mme_sess_t *sess = NULL;
    const char *apn = NULL;

    ogs_assert(mme_ue);
    ogs_assert(bearer);

    sess = mme_sess_find_by_id(bearer->sess_id);
    if (sess && sess->session && sess->session->name)
        apn = sess->session->name;

    mme_ue_info(mme_ue, NULL, "bearer", apn,
            "Bearer removed EBI=%d", bearer->ebi);
}

void mme_ue_service_info(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue, const char *fmt, ...)
{
    va_list ap;
    char msg[OGS_HUGE_LEN];

    ogs_assert(fmt);

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    mme_ue_info(mme_ue, enb_ue, "service-req", NULL, "%s", msg);
}

void mme_ue_service_error(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue, const char *fmt, ...)
{
    va_list ap;
    char msg[OGS_HUGE_LEN];

    ogs_assert(fmt);

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    mme_ue_error(mme_ue, enb_ue, "service-req", NULL, "%s", msg);
}

void mme_ue_service_progress(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue, const char *step)
{
    ogs_assert(step);

    if (mme_ue_progress_is_failure(step))
        mme_ue_service_error(mme_ue, enb_ue, "SERVICE step: %s", step);
    else
        mme_ue_service_info(mme_ue, enb_ue, "SERVICE step: %s", step);
}

void mme_ran_error(
        mme_enb_t *enb, enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        const char *proc, const char *apn, const char *fmt, ...)
{
    va_list ap;
    char prefix[OGS_TRACE_PREFIX_BUFSIZE];
    char msg[OGS_HUGE_LEN];

    ogs_assert(fmt);

    if (mme_ue || enb_ue) {
        va_start(ap, fmt);
        ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
        mme_ue_error(mme_ue, enb_ue, proc, apn, "%s", msg);
        return;
    }

    {
        ogs_trace_ctx_t ctx;

        memset(&ctx, 0, sizeof(ctx));
        if (proc && proc[0])
            ogs_cpystrn(ctx.proc, proc, sizeof(ctx.proc));
        if (apn && apn[0])
            ogs_cpystrn(ctx.apn, apn, sizeof(ctx.apn));
        if (enb && enb->enb_id_presence)
            ctx.enb_id = enb->enb_id;
        ogs_trace_set(&ctx);
        ogs_trace_format_prefix(prefix, sizeof(prefix));
    }

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    ogs_log_printf(OGS_LOG_ERROR, OGS_LOG_DOMAIN,
            0, __FILE__, __LINE__, OGS_FUNC, 0, "%s %s", prefix, msg);
}

const char *mme_log_imsi(mme_ue_t *mme_ue)
{
    return mme_ue_log_id(mme_ue);
}

void mme_log_gtp_peer(char *buf, size_t buflen, ogs_gtp_node_t *gnode)
{
    char ipbuf[OGS_ADDRSTRLEN];

    ogs_assert(buf);
    ogs_assert(buflen > 0);

    buf[0] = '\0';
    if (!gnode)
        return;

    ogs_snprintf(buf, buflen, "[%s]:%d",
            OGS_ADDR(&gnode->addr, ipbuf), OGS_PORT(&gnode->addr));
}

void mme_log_pgw_peer(char *buf, size_t buflen, mme_sess_t *sess)
{
    char ipbuf[OGS_ADDRSTRLEN];

    ogs_assert(buf);
    ogs_assert(buflen > 0);
    buf[0] = '\0';

    if (!sess)
        return;

    if (sess->pgw_s5c_ip.ipv4)
        ogs_snprintf(buf, buflen, "%s:2123",
                OGS_INET_NTOP(&sess->pgw_s5c_ip.addr, ipbuf));
    else if (sess->pgw_s5c_ip.ipv6)
        ogs_snprintf(buf, buflen, "%s:2123",
                OGS_INET6_NTOP(sess->pgw_s5c_ip.addr6, ipbuf));
    else if (sess->pgw_s5c_teid)
        ogs_snprintf(buf, buflen, "TEID[0x%x]", sess->pgw_s5c_teid);
}

void mme_log_radio(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue,
        uint16_t *tac, uint32_t *cell_id, uint32_t *enb_id)
{
    mme_enb_t *enb = NULL;

    if (tac)
        *tac = 0;
    if (cell_id)
        *cell_id = 0;
    if (enb_id)
        *enb_id = 0;

    if (mme_ue && mme_ue->tai.tac) {
        if (tac)
            *tac = mme_ue->tai.tac;
        if (cell_id)
            *cell_id = mme_ue->e_cgi.cell_id;
    } else if (enb_ue) {
        if (tac)
            *tac = enb_ue->saved.tai.tac;
        if (cell_id)
            *cell_id = enb_ue->saved.e_cgi.cell_id;
    }

    if (enb_ue) {
        enb = mme_enb_find_by_id(enb_ue->enb_id);
        if (enb && enb_id)
            *enb_id = enb->enb_id;
    }
}
