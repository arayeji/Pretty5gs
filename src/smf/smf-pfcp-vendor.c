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

#include "smf-pfcp-vendor.h"

#include <string.h>

void smf_pfcp_log_travelping_errors(ogs_pkbuf_t *pkbuf)
{
    ogs_pfcp_log_travelping_error(pkbuf);
}

bool smf_pfcp_parse_travelping_conflict_seid(
        ogs_pkbuf_t *pkbuf, uint64_t *up_seid_out, uint64_t *cp_seid_out)
{
    char msg[512];
    char *p = NULL;
    unsigned long long up_seid = 0, cp_seid = 0;

    ogs_assert(up_seid_out);
    ogs_assert(cp_seid_out);
    *up_seid_out = 0;
    *cp_seid_out = 0;

    if (!ogs_pfcp_travelping_error_message(pkbuf, msg, sizeof(msg)))
        return false;

    p = strstr(msg, "up_seid ");
    if (p && sscanf(p, "%*s 0x%llx", &up_seid) != 1)
        up_seid = 0;

    p = strstr(msg, "cp_seid ");
    if (p && sscanf(p, "%*s 0x%llx", &cp_seid) != 1)
        cp_seid = 0;

    /* Fall back to the other SEID when only one is present:
     * upg-vpp allocates the UP SEID equal to the CP SEID anyway. */
    if (!up_seid)
        up_seid = cp_seid;
    if (!cp_seid)
        cp_seid = up_seid;

    *up_seid_out = (uint64_t)up_seid;
    *cp_seid_out = (uint64_t)cp_seid;
    return *up_seid_out != 0;
}
