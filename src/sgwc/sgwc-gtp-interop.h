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

#ifndef SGWC_GTP_INTEROP_H
#define SGWC_GTP_INTEROP_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

int sgwc_gtp_apn_copy(
        uint8_t *dst, int dst_max, void *src, int src_len);
int sgwc_gtp_apn_tolower_copy(
        uint8_t *dst, int dst_max, void *src, int src_len);
int sgwc_gtp_roam_pco_build(
        uint8_t *dst, int dst_max, void *src, int src_len);

/*
 * Rewrite IPv4 link MTU (PCO/ePCO id 0x0010) for inbound-roam CSA.
 * - missing MTU → inject local_mtu
 * - home MTU > local_mtu → clamp
 * - home MTU <= local_mtu → copy src unchanged
 * Returns built length, or 0 on failure / no change buffer needed.
 */
int sgwc_gtp_roam_pco_mtu_rewrite(
        uint8_t *dst, int dst_max, void *src, int src_len,
        uint16_t local_mtu);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_GTP_INTEROP_H */
