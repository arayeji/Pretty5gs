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

#include <stdarg.h>

void ogs_smf_trace_set_from_gtp2_create_session_request(
        ogs_gtp2_create_session_request_t *req, const char *proc)
{
    ogs_trace_ctx_t ctx;
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
    char apn[OGS_MAX_APN_LEN+1];

    memset(&ctx, 0, sizeof(ctx));

    if (proc && proc[0])
        ogs_cpystrn(ctx.proc, proc, sizeof(ctx.proc));

    if (!req) {
        ogs_trace_set(&ctx);
        return;
    }

    if (req->imsi.presence && req->imsi.data && req->imsi.len) {
        ogs_buffer_to_bcd(req->imsi.data, req->imsi.len, imsi_bcd);
        ogs_cpystrn(ctx.imsi, imsi_bcd, sizeof(ctx.imsi));
    }

    if (req->access_point_name.presence && req->access_point_name.data &&
            req->access_point_name.len > 0) {
        if (ogs_fqdn_parse(apn, req->access_point_name.data,
                ogs_min(req->access_point_name.len, OGS_MAX_APN_LEN)) > 0) {
            char *apn_oi = ogs_dnn_oi_from_fqdn(apn);

            if (apn_oi && apn_oi > apn && apn_oi[-1] == '.')
                apn_oi[-1] = '\0';
            ogs_cpystrn(ctx.apn, apn, sizeof(ctx.apn));
        }
    }

    if (req->sender_f_teid_for_control_plane.presence &&
            req->sender_f_teid_for_control_plane.data &&
            req->sender_f_teid_for_control_plane.data->teid)
        ctx.sgw_s5c_teid = be32toh(
                req->sender_f_teid_for_control_plane.data->teid);

    ogs_trace_set(&ctx);
}

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
        ctx.sgw_s5c_teid = sess->sgw_s5c_teid;
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

    ogs_trace_set(&ctx);
}

void smf_ue_debug(smf_ue_t *smf_ue, const char *fmt, ...)
{
    va_list ap;
    char msg[OGS_HUGE_LEN];
    const char *id = "-";

    ogs_assert(fmt);

    if (smf_ue) {
        if (smf_ue->imsi_len > 0 && smf_ue->imsi_bcd[0])
            id = smf_ue->imsi_bcd;
        else if (smf_ue->supi)
            id = smf_ue->supi;
    }

    if (!ogs_trace_filter_match(id) &&
            !ogs_log_domain_prints(OGS_LOG_DOMAIN, OGS_LOG_DEBUG))
        return;

    ogs_smf_trace_set(smf_ue, NULL, NULL);

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    ogs_log_printf(OGS_LOG_DEBUG, OGS_LOG_DOMAIN,
            0, __FILE__, __LINE__, OGS_FUNC, 0, "[%s] %s", id, msg);
}

const char *smf_log_id(smf_ue_t *smf_ue)
{
    if (!smf_ue)
        return "-";
    if (smf_ue->imsi_len > 0 && smf_ue->imsi_bcd[0])
        return smf_ue->imsi_bcd;
    if (smf_ue->supi)
        return smf_ue->supi;
    return "-";
}

void smf_log_sgw_peer(char *buf, size_t buflen, smf_sess_t *sess)
{
    char ipbuf[OGS_ADDRSTRLEN];

    ogs_assert(buf);
    ogs_assert(buflen > 0);
    buf[0] = '\0';

    if (!sess)
        return;

    if (sess->sgw_s5c_ip.ipv4)
        ogs_snprintf(buf, buflen, "%s:2123 TEID[0x%x]",
                OGS_INET_NTOP(&sess->sgw_s5c_ip.addr, ipbuf),
                sess->sgw_s5c_teid);
    else if (sess->sgw_s5c_ip.ipv6)
        ogs_snprintf(buf, buflen, "%s:2123 TEID[0x%x]",
                OGS_INET6_NTOP(sess->sgw_s5c_ip.addr6, ipbuf),
                sess->sgw_s5c_teid);
    else if (sess->sgw_s5c_teid)
        ogs_snprintf(buf, buflen, "TEID[0x%x]", sess->sgw_s5c_teid);
}

void smf_log_upf_peer(char *buf, size_t buflen, smf_sess_t *sess)
{
    char *peer = NULL;

    ogs_assert(buf);
    ogs_assert(buflen > 0);
    buf[0] = '\0';

    if (!sess || !sess->pfcp_node)
        return;

    peer = ogs_sockaddr_to_string_static(sess->pfcp_node->addr_list);
    if (peer)
        ogs_snprintf(buf, buflen, "%s seid[0x%llx]",
                peer, (unsigned long long)sess->upf_n4_seid);
}
