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

#include <stdarg.h>

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
    if (ctx.imsi[0])
        ogs_trace_packet_on_imsi(ctx.imsi);
}

void sgwc_trace_bind_gtp(ogs_gtp_xact_t *xact, sgwc_ue_t *sgwc_ue)
{
    if (!xact || !sgwc_ue || !sgwc_ue->imsi_bcd[0])
        return;
    ogs_gtp_xact_set_imsi(xact, sgwc_ue->imsi_bcd);
}

void sgwc_trace_bind_pfcp(ogs_pfcp_xact_t *xact, sgwc_sess_t *sess)
{
    sgwc_ue_t *sgwc_ue;

    if (!xact || !sess)
        return;
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    if (!sgwc_ue || !sgwc_ue->imsi_bcd[0])
        return;
    ogs_pfcp_xact_set_imsi(xact, sgwc_ue->imsi_bcd);
}

void sgwc_trace_pfcp_rx(ogs_pfcp_xact_t *xact, sgwc_sess_t *sess,
        const void *data, size_t len)
{
    sgwc_ue_t *sgwc_ue;

    if (!sess)
        return;
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    if (!sgwc_ue || !sgwc_ue->imsi_bcd[0])
        return;
    if (xact)
        ogs_pfcp_xact_set_imsi(xact, sgwc_ue->imsi_bcd);
    /* Full PDU was bound before header pull; do not dump IE-only body. */
    (void)data;
    (void)len;
    ogs_trace_packet_on_imsi(sgwc_ue->imsi_bcd);
}

void sgwc_ue_log(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess,
        const char *proc, const char *apn, int level, const char *fmt, ...)
{
    va_list ap;
    char prefix[OGS_TRACE_PREFIX_BUFSIZE];
    char msg[OGS_HUGE_LEN];
    const char *imsi = sgwc_log_imsi(sgwc_ue);

    ogs_assert(fmt);

    if (!sgwc_ue && sess)
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);

    /* Per-IMSI trace lines are opt-in (see mme-trace.c): emit only for
     * filter-matched subscribers or a debug-enabled domain. */
    if (!ogs_trace_filter_match(imsi) &&
            !ogs_log_domain_prints(OGS_LOG_DOMAIN, OGS_LOG_DEBUG))
        return;

    /* storm guard: skip formatting entirely when over budget;
     * filter-matched DEBUG capture is never suppressed */
    if (level != OGS_LOG_DEBUG && !ogs_log_guard())
        return;

    ogs_sgwc_trace_set(sgwc_ue, sess, apn, proc);
    ogs_trace_format_prefix(prefix, sizeof(prefix));

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    ogs_log_printf(level, OGS_LOG_DOMAIN,
            0, __FILE__, __LINE__, OGS_FUNC, 0, "%s %s", prefix, msg);
}

void sgwc_ue_warn_no_ctx(
        const char *proc, uint32_t sgw_s11_teid,
        const char *fmt, ...)
{
    va_list ap;
    char prefix[OGS_TRACE_PREFIX_BUFSIZE];
    char msg[OGS_HUGE_LEN];
    ogs_trace_ctx_t ctx;

    ogs_assert(proc);
    ogs_assert(fmt);

    /* No-context warnings carry no IMSI to match: emit them only when
     * some subscriber tracing is active at all (or domain at debug). */
    if (!ogs_trace_filter_count() &&
            !ogs_log_domain_prints(OGS_LOG_DOMAIN, OGS_LOG_DEBUG))
        return;

    if (!ogs_log_guard())
        return;

    memset(&ctx, 0, sizeof(ctx));
    ogs_cpystrn(ctx.proc, proc, sizeof(ctx.proc));
    ctx.sgw_s11_teid = sgw_s11_teid;
    ogs_trace_set(&ctx);
    ogs_trace_format_prefix(prefix, sizeof(prefix));

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    ogs_log_printf(OGS_LOG_WARN, OGS_LOG_DOMAIN,
            0, __FILE__, __LINE__, OGS_FUNC, 0, "%s %s", prefix, msg);
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
