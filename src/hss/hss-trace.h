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

/*
 * Per-IMSI log: DEBUG is emitted when logger level is debug or
 * hss.trace_imsi / GET /admin/trace/imsi matches.
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

void hss_admin_api_register(void);

#ifdef __cplusplus
}
#endif

#endif /* HSS_TRACE_H */
