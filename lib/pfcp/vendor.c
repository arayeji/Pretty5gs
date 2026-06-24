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

#include "ogs-pfcp.h"

#include <string.h>

#define TRAVELPING_ENTERPRISE_ID 18681
#define TRAVELPING_IE_ERROR_REPORT 32774
#define TRAVELPING_IE_ERROR_MESSAGE 32775

static bool pfcp_travelping_scan_tlvs(
        const uint8_t *p, uint16_t len, char *msg, size_t msglen)
{
    const uint8_t *end = p + len;

    while (p + 4 <= end) {
        uint16_t type = (p[0] << 8) | p[1];
        uint16_t vlen = (p[2] << 8) | p[3];
        const uint8_t *v = p + 4;

        if (v + vlen > end)
            break;

        if (type >= 32768) {
            uint16_t enterprise;

            if (vlen < 2)
                goto next;
            enterprise = (v[0] << 8) | v[1];
            if (enterprise == TRAVELPING_ENTERPRISE_ID) {
                if (type == TRAVELPING_IE_ERROR_MESSAGE && vlen > 2) {
                    uint16_t mlen = vlen - 2;

                    if (mlen >= msglen)
                        mlen = msglen - 1;
                    memcpy(msg, v + 2, mlen);
                    msg[mlen] = '\0';
                    return true;
                }
                if (pfcp_travelping_scan_tlvs(v + 2, vlen - 2, msg, msglen))
                    return true;
            }
        }

next:
        p += 4 + vlen;
    }

    return false;
}

bool ogs_pfcp_travelping_error_message(
        ogs_pkbuf_t *pkbuf, char *msg, size_t msglen)
{
    ogs_assert(pkbuf);
    ogs_assert(msg);
    ogs_assert(msglen > 0);

    msg[0] = '\0';

    /*
     * By the time this is called, ogs_pfcp_parse_msg() has already
     * ogs_pkbuf_pull()'d past the PFCP fixed header so pkbuf->data points
     * directly at the first IE.  Scan from there.
     */
    if (pkbuf->len == 0)
        return false;

    return pfcp_travelping_scan_tlvs(pkbuf->data, pkbuf->len, msg, msglen);
}

void ogs_pfcp_log_travelping_error(ogs_pkbuf_t *pkbuf)
{
    char msg[512];

    if (ogs_pfcp_travelping_error_message(pkbuf, msg, sizeof(msg)))
        ogs_error("UPF/VPP PFCP Error: %s", msg);
}
