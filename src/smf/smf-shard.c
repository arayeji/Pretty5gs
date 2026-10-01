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

#include "smf-shard.h"

#define SMF_SHARD_MASK ((1u << OGS_WORKER_ID_BITS) - 1)

int smf_shard_decode_teid(uint32_t teid)
{
    return (int)((teid >> (32 - OGS_WORKER_ID_BITS)) & SMF_SHARD_MASK);
}

int smf_shard_decode_seid(uint64_t seid)
{
    return smf_shard_decode_teid((uint32_t)seid);
}

int smf_shard_decode_xid(uint32_t xid)
{
    return (int)((xid >> (23 - OGS_WORKER_ID_BITS)) & SMF_SHARD_MASK);
}

int smf_shard_clamp_n(int shard, uint32_t fallback_key, int nworkers)
{
    if (shard >= 0 && shard <= nworkers)
        return shard;
    if (nworkers <= 0)
        return 0;
    return 1 + (int)(fallback_key % (unsigned)nworkers);
}

int smf_shard_imsi_hash_n(const char *imsi_bcd, int nworkers)
{
    unsigned h = 5381;
    const char *p;

    ogs_assert(imsi_bcd);

    if (nworkers <= 0)
        return 0;

    for (p = imsi_bcd; *p; p++)
        h = ((h << 5) + h) + (unsigned char)*p;

    return 1 + (int)(h % (unsigned)nworkers);
}

int smf_gtpv2_peek_imsi_bcd(ogs_pkbuf_t *pkbuf, char *bcd, size_t bcd_size)
{
    ogs_gtp2_header_t *h;
    uint8_t *p, *end;
    int hdr_len;

    ogs_assert(pkbuf);
    ogs_assert(bcd);
    ogs_assert(bcd_size > OGS_MAX_IMSI_BCD_LEN);

    bcd[0] = '\0';

    if (pkbuf->len < 8)
        return OGS_ERROR;

    h = (ogs_gtp2_header_t *)pkbuf->data;
    hdr_len = h->teid_presence ? OGS_GTPV2C_HEADER_LEN : 8;
    if (pkbuf->len < (unsigned int)hdr_len)
        return OGS_ERROR;

    p = (uint8_t *)pkbuf->data + hdr_len;
    end = (uint8_t *)pkbuf->data + pkbuf->len;

    while (p + 4 <= end) {
        uint8_t type = p[0];
        uint16_t len = ((uint16_t)p[1] << 8) | p[2];
        uint8_t instance = p[3] & 0x0f;
        uint8_t *val = p + 4;

        if (val + len > end)
            break;

        if (type == OGS_GTP2_IMSI_TYPE && instance == 0 && len > 0) {
            if (len > OGS_MAX_IMSI_LEN)
                len = OGS_MAX_IMSI_LEN;
            ogs_buffer_to_bcd(val, len, bcd);
            return OGS_OK;
        }

        p = val + len;
    }

    return OGS_ERROR;
}

/*
 * GTPv1-C (TS 29.060): TV IEs precede TLVs and the IMSI (type 2, 8
 * octets) is always the first IE of a Create PDP Context Request, so
 * only the fixed layout right after the header is checked.
 */
int smf_gtpv1_peek_imsi_bcd(ogs_pkbuf_t *pkbuf, char *bcd, size_t bcd_size)
{
    ogs_gtp1_header_t *h;
    uint8_t *p;
    int hdr_len;

    ogs_assert(pkbuf);
    ogs_assert(bcd);
    ogs_assert(bcd_size > OGS_MAX_IMSI_BCD_LEN);

    bcd[0] = '\0';

    if (pkbuf->len < 8)
        return OGS_ERROR;

    h = (ogs_gtp1_header_t *)pkbuf->data;
    hdr_len = (h->e || h->s || h->pn) ? OGS_GTPV1C_HEADER_LEN : 8;
    if (h->e)
        return OGS_ERROR;   /* extension headers: let the parser decide */
    if (pkbuf->len < (unsigned int)(hdr_len + 1 + 8))
        return OGS_ERROR;

    p = (uint8_t *)pkbuf->data + hdr_len;
    if (p[0] != OGS_GTP1_IMSI_TYPE)
        return OGS_ERROR;

    ogs_buffer_to_bcd(p + 1, 8, bcd);
    return OGS_OK;
}
