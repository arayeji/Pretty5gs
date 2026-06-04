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
