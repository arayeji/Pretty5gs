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
            !strcmp(step, "sgsap_lu_timeout"))
        return true;

    len = strlen(step);
    if (len > 5 && !strcmp(step + len - 5, "_fail"))
        return true;

    return false;
}

void mme_ue_progress(mme_ue_t *mme_ue, const char *step)
{
    const char *imsi = mme_ue_log_id(mme_ue);

    ogs_assert(step);

    if (mme_ue_progress_is_failure(step))
        ogs_error("[%s] ATTACH step: %s", imsi, step);
    else
        ogs_info("[%s] ATTACH step: %s", imsi, step);
}

void mme_ue_debug(mme_ue_t *mme_ue, const char *fmt, ...)
{
    va_list ap;
    char msg[OGS_HUGE_LEN];
    const char *imsi = mme_ue_log_id(mme_ue);

    ogs_assert(fmt);

    if (!ogs_trace_filter_match(imsi) &&
            !ogs_log_domain_prints(OGS_LOG_DOMAIN, OGS_LOG_DEBUG))
        return;

    ogs_mme_trace_set(
            mme_ue ? enb_ue_find_by_id(mme_ue->enb_ue_id) : NULL,
            mme_ue, NULL, NULL);

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    ogs_log_printf(OGS_LOG_DEBUG, OGS_LOG_DOMAIN,
            0, __FILE__, __LINE__, OGS_FUNC, 0, "[%s] %s", imsi, msg);
}
