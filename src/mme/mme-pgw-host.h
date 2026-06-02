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

#if !defined(MME_PGW_HOST_H_INCLUDED)
#define MME_PGW_HOST_H_INCLUDED

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

void mme_pgw_host_cache_init(void);
void mme_pgw_host_cache_final(void);

int mme_pgw_host_resolve(
        const char *destination_host, int destination_host_len,
        const char *destination_realm, int destination_realm_len,
        ogs_ip_t *smf_ip);

#ifdef __cplusplus
}
#endif

#endif /* MME_PGW_HOST_H_INCLUDED */
