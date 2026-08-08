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

#ifndef HSS_TRACE_H
#define HSS_TRACE_H

#include "hss-context.h"

#ifdef __cplusplus
extern "C" {
#endif

void hss_trace_set(const char *imsi_bcd, const char *proc);

/* Clear thread-local trace context (call when leaving a Diameter callback). */
void hss_trace_done(void);

/*
 * Per-IMSI log: emit only when hss.trace_imsi / GET /admin/trace/imsi matches
 * this subscriber, or when the domain is at debug. Same opt-in model as
 * mme_ue_log / sgwc_ue_log — does not flood the process at INFO.
 * proc examples: "S6a-AIR", "Cx-UAR", "SWx-MAR", "Sh-UDR"
 */
void hss_imsi_log(
        const char *imsi_bcd, const char *proc, int level,
        const char *fmt, ...) OGS_GNUC_PRINTF(4, 5);

#define hss_imsi_info(imsi, proc, ...) \
    hss_imsi_log(imsi, proc, OGS_LOG_INFO, __VA_ARGS__)
#define hss_imsi_warn(imsi, proc, ...) \
    hss_imsi_log(imsi, proc, OGS_LOG_WARN, __VA_ARGS__)
#define hss_imsi_error(imsi, proc, ...) \
    hss_imsi_log(imsi, proc, OGS_LOG_ERROR, __VA_ARGS__)
#define hss_imsi_debug(imsi, proc, ...) \
    hss_imsi_log(imsi, proc, OGS_LOG_DEBUG, __VA_ARGS__)

/*
 * Procedure boundary for a traced IMSI: one opt-in INFO line (same gate as
 * mme_ue_log). Does NOT use ogs_error and does NOT leave TLS IMSI sticky.
 */
void hss_trace_event(
        const char *imsi_bcd, const char *proc,
        const char *fmt, ...) OGS_GNUC_PRINTF(3, 4);

/*
 * Install at the top of freeDiameter callbacks so sticky IMSI cannot
 * elevate unrelated DEBUG on the worker after the callback returns.
 */
#if defined(__GNUC__)
static inline void hss_trace_scope_cleanup(int *unused)
{
    hss_trace_done();
}
#define HSS_TRACE_SCOPE() \
    int _hss_trace_scope __attribute__((cleanup(hss_trace_scope_cleanup))) = 0
#else
#define HSS_TRACE_SCOPE() do { } while (0)
#endif

void hss_admin_api_register(void);

#ifdef __cplusplus
}
#endif

#endif /* HSS_TRACE_H */
