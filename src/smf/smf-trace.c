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

#include "smf-trace.h"

void ogs_smf_trace_set(
        smf_ue_t *smf_ue, smf_sess_t *sess,
        const char *proc)
{
    ogs_trace_ctx_t ctx;
    smf_bearer_t *bearer = NULL;
    char buf1[OGS_ADDRSTRLEN];
    char buf2[OGS_ADDRSTRLEN];

    memset(&ctx, 0, sizeof(ctx));

    if (proc && proc[0])
        ogs_cpystrn(ctx.proc, proc, sizeof(ctx.proc));

    if (smf_ue) {
        if (smf_ue->imsi_bcd[0])
            ogs_cpystrn(ctx.imsi, smf_ue->imsi_bcd, sizeof(ctx.imsi));
        else if (smf_ue->supi)
            ogs_cpystrn(ctx.imsi, smf_ue->supi, sizeof(ctx.imsi));
    }

    if (sess) {
        if (sess->session.name)
            ogs_cpystrn(ctx.apn, sess->session.name, sizeof(ctx.apn));
        if (sess->sgw_s5c_teid)
            ctx.sgw_s5c_teid = sess->sgw_s5c_teid;
        if (sess->smf_n4_teid)
            ctx.pgw_s5c_teid = sess->smf_n4_teid;

        ogs_list_for_each(&sess->bearer_list, bearer) {
            ctx.ebi = bearer->ebi;
            break;
        }

        if (sess->ipv4 && sess->ipv6) {
            ogs_snprintf(ctx.ue_ip, sizeof(ctx.ue_ip), "%s/%s",
                    OGS_INET_NTOP(&sess->ipv4->addr, buf1),
                    OGS_INET6_NTOP(&sess->ipv6->addr, buf2));
        } else if (sess->ipv4) {
            ogs_cpystrn(ctx.ue_ip,
                    OGS_INET_NTOP(&sess->ipv4->addr, buf1), sizeof(ctx.ue_ip));
        } else if (sess->ipv6) {
            ogs_cpystrn(ctx.ue_ip,
                    OGS_INET6_NTOP(&sess->ipv6->addr, buf2), sizeof(ctx.ue_ip));
        }
    }

    ogs_trace_merge(&ctx);
}
