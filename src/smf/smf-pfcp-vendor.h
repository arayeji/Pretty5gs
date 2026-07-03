/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef SMF_PFCP_VENDOR_H
#define SMF_PFCP_VENDOR_H

#include "ogs-pfcp.h"

#ifdef __cplusplus
extern "C" {
#endif

void smf_pfcp_log_travelping_errors(ogs_pkbuf_t *pkbuf);
bool smf_pfcp_parse_travelping_conflict_seid(
        ogs_pkbuf_t *pkbuf, uint64_t *up_seid_out, uint64_t *cp_seid_out);

#ifdef __cplusplus
}
#endif

#endif /* SMF_PFCP_VENDOR_H */
