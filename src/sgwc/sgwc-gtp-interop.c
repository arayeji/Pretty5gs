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

#include "sgwc-gtp-interop.h"

#include <ctype.h>

/* 3GPP TS 24.008 Table 10.5.154 */
#define OGS_PCO_ID_IM_CN_SUBSYSTEM_SIGNALLING_FLAG 0x0002

/* Huawei SGW S5 CSR IPCP (Configure-Request) */
static const uint8_t sgwc_roam_ipcp_default[] = {
    0x01, 0x01, 0x00, 0x10,
    0x81, 0x06, 0x00, 0x00, 0x00, 0x00,
    0x83, 0x06, 0x00, 0x00, 0x00, 0x00,
};

static const uint16_t sgwc_roam_pco_order[] = {
    OGS_PCO_ID_P_CSCF_IPV6_ADDRESS_REQUEST,
    OGS_PCO_ID_IM_CN_SUBSYSTEM_SIGNALLING_FLAG,
    OGS_PCO_ID_DNS_SERVER_IPV6_ADDRESS_REQUEST,
    OGS_PCO_ID_MS_SUPPORTS_BCM,
    OGS_PCO_ID_IP_ADDRESS_ALLOCATION_VIA_NAS_SIGNALLING,
    OGS_PCO_ID_P_CSCF_IPV4_ADDRESS_REQUEST,
    OGS_PCO_ID_DNS_SERVER_IPV4_ADDRESS_REQUEST,
    OGS_PCO_ID_IPV4_LINK_MTU_REQUEST,
};

int sgwc_gtp_apn_copy(
        uint8_t *dst, int dst_max, void *src, int src_len)
{
    ogs_assert(dst);
    ogs_assert(src);

    if (src_len <= 0 || dst_max <= 0)
        return 0;

    if (src_len > dst_max)
        src_len = dst_max;

    memcpy(dst, src, src_len);
    return src_len;
}

int sgwc_gtp_apn_tolower_copy(
        uint8_t *dst, int dst_max, void *src, int src_len)
{
    uint8_t *p = (uint8_t *)src;
    int i = 0, j = 0;
    int label_len;

    ogs_assert(dst);
    ogs_assert(src);

    if (src_len <= 0 || dst_max <= 0)
        return 0;

    while (i < src_len && j < dst_max) {
        label_len = p[i];
        if (i + label_len >= src_len)
            break;

        dst[j++] = (uint8_t)label_len;
        i++;

        while (label_len-- > 0 && i < src_len && j < dst_max) {
            char c = (char)p[i++];
            if (c >= 'A' && c <= 'Z')
                c = (char)tolower((unsigned char)c);
            dst[j++] = (uint8_t)c;
        }
    }

    return j;
}

int sgwc_gtp_roam_pco_build(
        uint8_t *dst, int dst_max, void *src, int src_len)
{
    ogs_pco_t parsed, out;
    uint8_t ipcp_buf[64];
    int ipcp_len = 0;
    int i, n, size;

    ogs_assert(dst);

    memset(&out, 0, sizeof(out));
    out.ext = 1;
    out.configuration_protocol =
        OGS_PCO_PPP_FOR_USE_WITH_IP_PDP_TYPE_OR_IP_PDN_TYPE;

    if (src && src_len > 0) {
        if (ogs_pco_parse(&parsed, src, src_len) > 0) {
            out.ext = parsed.ext;
            out.configuration_protocol = parsed.configuration_protocol;

            for (i = 0; i < parsed.num_of_id; i++) {
                if (parsed.ids[i].id ==
                        OGS_PCO_ID_INTERNET_PROTOCOL_CONTROL_PROTOCOL &&
                        parsed.ids[i].len > 0 &&
                        parsed.ids[i].len <= (int)sizeof(ipcp_buf)) {
                    ipcp_len = parsed.ids[i].len;
                    memcpy(ipcp_buf, parsed.ids[i].data, ipcp_len);
                    break;
                }
            }
        }
    }

    if (ipcp_len == 0) {
        ipcp_len = sizeof(sgwc_roam_ipcp_default);
        memcpy(ipcp_buf, sgwc_roam_ipcp_default, ipcp_len);
    }

    n = 0;
    ogs_assert(n < OGS_MAX_NUM_OF_PROTOCOL_OR_CONTAINER_ID);
    out.ids[n].id = OGS_PCO_ID_INTERNET_PROTOCOL_CONTROL_PROTOCOL;
    out.ids[n].len = ipcp_len;
    out.ids[n].data = ipcp_buf;
    n++;

    for (i = 0; i < (int)(sizeof(sgwc_roam_pco_order) /
            sizeof(sgwc_roam_pco_order[0])); i++) {
        ogs_assert(n < OGS_MAX_NUM_OF_PROTOCOL_OR_CONTAINER_ID);
        out.ids[n].id = sgwc_roam_pco_order[i];
        out.ids[n].len = 0;
        out.ids[n].data = NULL;
        n++;
    }

    out.num_of_id = n;

    size = ogs_pco_build(dst, dst_max, &out);
    if (size <= 0)
        return 0;

    return size;
}
