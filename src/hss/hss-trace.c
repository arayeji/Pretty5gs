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

#include <stdarg.h>

void hss_trace_set(const char *imsi_bcd, const char *proc)
{
    ogs_trace_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));

    if (imsi_bcd && imsi_bcd[0])
        ogs_cpystrn(ctx.imsi, imsi_bcd, sizeof(ctx.imsi));
    if (proc && proc[0])
        ogs_cpystrn(ctx.proc, proc, sizeof(ctx.proc));

    ogs_trace_set(&ctx);
}

void hss_imsi_log(
        const char *imsi_bcd, const char *proc, int level,
        const char *fmt, ...)
{
    va_list ap;
    char prefix[OGS_TRACE_PREFIX_BUFSIZE];
    char msg[OGS_HUGE_LEN];
    const char *id = (imsi_bcd && imsi_bcd[0]) ? imsi_bcd : "-";

    ogs_assert(fmt);

    /* Per-IMSI trace lines are opt-in: emit only for filter-matched
     * subscribers or a debug-enabled domain. */
    if (!ogs_trace_filter_match(id) &&
            !ogs_log_domain_prints(OGS_LOG_DOMAIN, OGS_LOG_DEBUG))
        return;

    if (level != OGS_LOG_DEBUG && !ogs_log_guard())
        return;

    hss_trace_set(id, proc);
    ogs_trace_format_prefix(prefix, sizeof(prefix));

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    ogs_log_printf(level, OGS_LOG_DOMAIN,
            0, __FILE__, __LINE__, OGS_FUNC, 0, "%s %s", prefix, msg);
}

void hss_admin_api_register(void)
{
    ogs_metrics_register_admin_ep(ogs_metrics_admin_trace_imsi,
            "/admin/trace/imsi",
            OGS_METRICS_ADMIN_METHOD_GET);
}
