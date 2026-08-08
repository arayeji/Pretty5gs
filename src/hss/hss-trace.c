/*
 * Copyright (C) 2026 Open5GS contributors
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

#include "hss-trace.h"
#include "ogs-metrics.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void hss_trace_set(const char *imsi_bcd, const char *proc)
{
    ogs_trace_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));

    if (imsi_bcd && imsi_bcd[0])
        ogs_cpystrn(ctx.imsi, imsi_bcd, sizeof(ctx.imsi));
    if (proc && proc[0])
        ogs_cpystrn(ctx.proc, proc, sizeof(ctx.proc));

    ogs_trace_set(&ctx);
    if (ctx.imsi[0])
        ogs_trace_packet_on_imsi(ctx.imsi);
}

void hss_trace_done(void)
{
    ogs_trace_clear();
}

void hss_imsi_log(
        const char *imsi_bcd, const char *proc, int level,
        const char *fmt, ...)
{
    va_list ap;
    char prefix[OGS_TRACE_PREFIX_BUFSIZE];
    char msg[OGS_HUGE_LEN];
    const char *id = (imsi_bcd && imsi_bcd[0]) ? imsi_bcd : "-";
    bool filter_hit;
    ogs_log_level_e domain_level;

    ogs_assert(fmt);

    /*
     * Opt-in like mme_ue_log / sgwc_ue_log. Use the configured domain level
     * for the "domain at debug" path — do NOT call ogs_log_domain_prints()
     * here, because that helper itself elevates when TLS IMSI matches the
     * filter and would let non-matched IMSIs through while a traced IMSI
     * is still sticky on the freeDiameter worker.
     */
    filter_hit = ogs_trace_filter_match(id);
    domain_level = ogs_log_get_domain_level(OGS_LOG_DOMAIN);

    if (!filter_hit && domain_level < OGS_LOG_DEBUG)
        return;

    /*
     * Filter-matched lines must not share the thread-local ogs_log_guard
     * with unrelated FD-thread INFO/WARN chatter.
     */
    if (!filter_hit && level != OGS_LOG_DEBUG && !ogs_log_guard())
        return;

    /*
     * When elevating past the domain level, cap with the process-wide
     * trace budget (peek; ogs_log_vprintf consumes).
     */
    if (domain_level < (ogs_log_level_e)level &&
            !ogs_log_trace_budget(false))
        return;

    hss_trace_set(id, proc);
    ogs_trace_format_prefix(prefix, sizeof(prefix));

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    ogs_log_printf(level, OGS_LOG_DOMAIN,
            0, __FILE__, __LINE__, OGS_FUNC, 0, "%s %s", prefix, msg);

    /*
     * Do not leave IMSI sticky on freeDiameter workers. Sticky filter match
     * makes ogs_log_domain_prints() elevate every ogs_debug/ogs_info on the
     * thread (unlike MME/SGWC, which overwrite context on the next UE event).
     * HSS_TRACE_SCOPE() is a safety net if a path returns early.
     */
    ogs_trace_clear();
}

void hss_trace_event(
        const char *imsi_bcd, const char *proc,
        const char *fmt, ...)
{
    va_list ap;
    char msg[OGS_HUGE_LEN];
    const char *id = (imsi_bcd && imsi_bcd[0]) ? imsi_bcd : "-";

    ogs_assert(fmt);

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    hss_imsi_info(id, proc, "%s", msg);
}

void hss_trace_diameter(
        const char *imsi_bcd, const char *dir, struct msg *msg)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    int ret;

    if (!imsi_bcd || !imsi_bcd[0] || !msg)
        return;
    /* Same empty-filter fast path as ogs_trace_packet(). */
    if (ogs_trace_filter_count() == 0)
        return;
    if (!ogs_trace_filter_match(imsi_bcd))
        return;

    /* Lengths must be current or bufferize returns an empty/failed buffer. */
    ret = fd_msg_update_length(msg);
    if (ret != 0) {
        ogs_warn("[%s] PACKET diameter %s: fd_msg_update_length failed (%d)",
                imsi_bcd, dir && dir[0] ? dir : "-", ret);
        return;
    }

    ret = fd_msg_bufferize(msg, &buf, &len);
    if (ret != 0 || !buf || !len) {
        ogs_warn("[%s] PACKET diameter %s: fd_msg_bufferize failed "
                "(ret=%d len=%zu) — no PACKET line",
                imsi_bcd, dir && dir[0] ? dir : "-", ret, len);
        if (buf)
            free(buf);
        return;
    }

    /* Keep IMSI sticky across ogs_trace_packet (we clear after events). */
    hss_trace_set(imsi_bcd, "diameter");
    ogs_trace_packet(imsi_bcd, "diameter", dir && dir[0] ? dir : "-",
            buf, len);
    hss_trace_done();
    free(buf);
}

static int hss_admin_trace_imsi(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    ogs_metrics_query_t resolved = { 0 };
    char imsi_buf[OGS_TRACE_IMSI_LEN];
    const ogs_metrics_query_t *use_q = q;

    if (q && q->msisdn && q->msisdn[0] &&
            !q->force && !(q->imsi && strcmp(q->imsi, "list") == 0)) {
        ogs_msisdn_data_t msisdn_data;

        memset(&msisdn_data, 0, sizeof(msisdn_data));
        if (hss_db_msisdn_data((char *)q->msisdn, &msisdn_data) != OGS_OK ||
                !msisdn_data.imsi.bcd[0]) {
            *body_len = (size_t)snprintf(body, body_cap,
                    "{\"ok\":false,\"detail\":\"msisdn %s not found in HSS DB\","
                    "\"trace_imsi\":[]}\n", q->msisdn);
            return 400;
        }

        ogs_cpystrn(imsi_buf, msisdn_data.imsi.bcd, sizeof(imsi_buf));
        if (!q->remove)
            (void)ogs_trace_alias_set(OGS_TRACE_ALIAS_MSISDN, q->msisdn, imsi_buf);

        resolved = *q;
        resolved.imsi = imsi_buf;
        resolved.msisdn = NULL;
        if (!resolved.match)
            resolved.match = "exact";
        use_q = &resolved;
    }

    return ogs_metrics_admin_trace_imsi(use_q, body, body_cap, body_len);
}

void hss_admin_api_register(void)
{
    ogs_metrics_register_admin_ep(hss_admin_trace_imsi,
            "/admin/trace/imsi",
            OGS_METRICS_ADMIN_METHOD_GET);
}
