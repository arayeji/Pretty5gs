/*
 * Copyright (C) 2026 by Ahmad Raeiji <ahmad.rayeji@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
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

#ifndef SMF_SHARD_H
#define SMF_SHARD_H

#include "ogs-gtp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pure shard arithmetic and raw-packet peeks behind the SMF RX routers.
 * No SMF context: the live worker count is passed in, so the unit tests
 * link this file on its own.
 */

/* Owner shard encoded in the top OGS_WORKER_ID_BITS of a local TEID. */
int smf_shard_decode_teid(uint32_t teid);
/* Local SEIDs are composed in the low 32 bits (same as the S5C TEID). */
int smf_shard_decode_seid(uint64_t seid);
/* GTPv2 / PFCP sequence number: shard bits directly below bit 23. */
int smf_shard_decode_xid(uint32_t xid);

/* Map a peer-supplied shard onto 0..nworkers, else 1 + key % nworkers. */
int smf_shard_clamp_n(int shard, uint32_t fallback_key, int nworkers);
/* Sticky worker shard (1..nworkers) for a new IMSI; 0 without workers. */
int smf_shard_imsi_hash_n(const char *imsi_bcd, int nworkers);

/* IMSI of a raw GTPv2 message (first IMSI IE, instance 0). */
int smf_gtpv2_peek_imsi_bcd(ogs_pkbuf_t *pkbuf, char *bcd, size_t bcd_size);
/* IMSI of a raw GTPv1 message: the leading TV IE of Create PDP Context. */
int smf_gtpv1_peek_imsi_bcd(ogs_pkbuf_t *pkbuf, char *bcd, size_t bcd_size);

#ifdef __cplusplus
}
#endif

#endif /* SMF_SHARD_H */
