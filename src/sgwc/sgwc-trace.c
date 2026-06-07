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

#include "sgwc-trace.h"

void ogs_sgwc_trace_set(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess,
        const char *apn, const char *proc)
{
    ogs_trace_ctx_t ctx;
    sgwc_bearer_t *bearer = NULL;

    memset(&ctx, 0, sizeof(ctx));

    if (proc && proc[0])
        ogs_cpystrn(ctx.proc, proc, sizeof(ctx.proc));

    if (sgwc_ue) {
        if (sgwc_ue->imsi_bcd[0])
            ogs_cpystrn(ctx.imsi, sgwc_ue->imsi_bcd, sizeof(ctx.imsi));
        ctx.mme_s11_teid = sgwc_ue->mme_s11_teid;
        ctx.sgw_s11_teid = sgwc_ue->sgw_s11_teid;
    }

    if (sess) {
        char ipbuf[OGS_ADDRSTRLEN];
        ogs_ip_t ip;

        if (sess->session.name)
            ogs_cpystrn(ctx.apn, sess->session.name, sizeof(ctx.apn));
        ctx.sgw_s5c_teid = sess->sgw_s5c_teid;
        ctx.pgw_s5c_teid = sess->pgw_s5c_teid;

        if (sess->gnode)
            ogs_cpystrn(ctx.pgw_ip, OGS_ADDR(&sess->gnode->addr, ipbuf),
                    sizeof(ctx.pgw_ip));

        if (sess->paa.session_type &&
                ogs_paa_to_ip(&sess->paa, &ip) == OGS_OK) {
            if (ip.ipv4)
                ogs_cpystrn(ctx.ue_ip, OGS_INET_NTOP(&ip.addr, ipbuf),
                        sizeof(ctx.ue_ip));
            else if (ip.ipv6)
                ogs_cpystrn(ctx.ue_ip, OGS_INET6_NTOP(ip.addr6, ipbuf),
                        sizeof(ctx.ue_ip));
        }

        ogs_list_for_each(&sess->bearer_list, bearer) {
            ctx.ebi = bearer->ebi;
            break;
        }
    } else if (apn && apn[0]) {
        ogs_cpystrn(ctx.apn, apn, sizeof(ctx.apn));
    }

    ogs_trace_set(&ctx);
}

const char *sgwc_log_imsi(sgwc_ue_t *sgwc_ue)
{
    if (sgwc_ue && sgwc_ue->imsi_bcd[0])
        return sgwc_ue->imsi_bcd;
    return "-";
}

void sgwc_log_mme_peer(char *buf, size_t buflen, sgwc_ue_t *sgwc_ue)
{
    char ipbuf[OGS_ADDRSTRLEN];

    ogs_assert(buf);
    ogs_assert(buflen > 0);
    buf[0] = '\0';

    if (!sgwc_ue || !sgwc_ue->gnode)
        return;

    ogs_snprintf(buf, buflen, "[%s]:%d",
            OGS_ADDR(&sgwc_ue->gnode->addr, ipbuf),
            OGS_PORT(&sgwc_ue->gnode->addr));
}

void sgwc_log_pgw_peer(char *buf, size_t buflen, sgwc_sess_t *sess)
{
    char ipbuf[OGS_ADDRSTRLEN];

    ogs_assert(buf);
    ogs_assert(buflen > 0);
    buf[0] = '\0';

    if (!sess || !sess->gnode)
        return;

    ogs_snprintf(buf, buflen, "[%s]:%d TEID[0x%x]",
            OGS_ADDR(&sess->gnode->addr, ipbuf),
            OGS_PORT(&sess->gnode->addr), sess->pgw_s5c_teid);
}

void sgwc_log_sgwu_peer(char *buf, size_t buflen, sgwc_sess_t *sess)
{
    char *peer = NULL;

    ogs_assert(buf);
    ogs_assert(buflen > 0);
    buf[0] = '\0';

    if (!sess || !sess->pfcp_node)
        return;

    peer = ogs_sockaddr_to_string_static(sess->pfcp_node->addr_list);
    if (peer)
        ogs_cpystrn(buf, peer, buflen);
}
