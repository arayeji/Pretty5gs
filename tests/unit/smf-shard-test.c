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

/*
 * SMF SMP routing: the shard arithmetic and raw-packet peeks the GTP-C /
 * PFCP RX routers use to pick the owning shard before any parse.
 * Synthetic MCC 999 / MNC 70 IMSIs only.
 */

#include "ogs-gtp.h"
#include "core/abts.h"

#include "../../src/smf/smf-shard.h"

#define IMSI_A  "999700000000001"
#define IMSI_B  "999700000000002"

#define SHARD_MAX ((1 << OGS_WORKER_ID_BITS) - 1)

static void teid_seid_xid_decode_test(abts_case *tc, void *data)
{
    int shard;

    for (shard = 0; shard <= SHARD_MAX; shard++) {
        uint32_t teid = ((uint32_t)shard << (32 - OGS_WORKER_ID_BITS)) |
            0x0abcdef;
        uint64_t seid = ((uint64_t)0xdeadbeef << 32) | teid;
        /* GTPv2 / PFCP window = 0x800000 >> OGS_WORKER_ID_BITS */
        uint32_t xid = (uint32_t)shard *
            (0x800000u >> OGS_WORKER_ID_BITS) + 7;

        ABTS_INT_EQUAL(tc, shard, smf_shard_decode_teid(teid));
        /* only the low 32 bits of a local SEID carry the owner */
        ABTS_INT_EQUAL(tc, shard, smf_shard_decode_seid(seid));
        ABTS_INT_EQUAL(tc, shard, smf_shard_decode_xid(xid));
    }

    /* xid window edges */
    ABTS_INT_EQUAL(tc, 0, smf_shard_decode_xid(1));
    ABTS_INT_EQUAL(tc, SHARD_MAX, smf_shard_decode_xid(0x7fffff));
}

static void clamp_test(abts_case *tc, void *data)
{
    /* live shards pass through, main included */
    ABTS_INT_EQUAL(tc, 0, smf_shard_clamp_n(0, 99, 4));
    ABTS_INT_EQUAL(tc, 4, smf_shard_clamp_n(4, 99, 4));

    /* a peer-mangled shard past the worker count lands on a worker */
    ABTS_INT_EQUAL(tc, 1 + (99 % 4), smf_shard_clamp_n(9, 99, 4));
    ABTS_INT_EQUAL(tc, 1 + (99 % 4), smf_shard_clamp_n(-1, 99, 4));

    /* no workers: everything is main */
    ABTS_INT_EQUAL(tc, 0, smf_shard_clamp_n(3, 99, 0));
    ABTS_INT_EQUAL(tc, 0, smf_shard_clamp_n(-1, 99, 0));
}

static void imsi_hash_test(abts_case *tc, void *data)
{
    int hits[5] = { 0, 0, 0, 0, 0 };
    char imsi[OGS_MAX_IMSI_BCD_LEN + 1];
    int i, s;

    ABTS_INT_EQUAL(tc, 0, smf_shard_imsi_hash_n(IMSI_A, 0));

    /* sticky */
    ABTS_INT_EQUAL(tc, smf_shard_imsi_hash_n(IMSI_A, 4),
            smf_shard_imsi_hash_n(IMSI_A, 4));

    /* never main, always a live worker, and every worker gets UEs */
    for (i = 0; i < 1000; i++) {
        ogs_snprintf(imsi, sizeof(imsi), "99970%010d", i);
        s = smf_shard_imsi_hash_n(imsi, 4);
        ABTS_TRUE(tc, s >= 1 && s <= 4);
        if (s >= 1 && s <= 4)
            hits[s]++;
    }
    ABTS_INT_EQUAL(tc, 0, hits[0]);
    for (s = 1; s <= 4; s++)
        ABTS_TRUE(tc, hits[s] > 100);
}

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static int put_imsi_ie(uint8_t *p, uint8_t instance, const char *imsi_bcd)
{
    uint8_t buf[OGS_MAX_IMSI_LEN];
    int len = 0;

    ogs_bcd_to_buffer(imsi_bcd, buf, &len);
    p[0] = OGS_GTP2_IMSI_TYPE;
    put_be16(p + 1, (uint16_t)len);
    p[3] = instance & 0x0f;
    memcpy(p + 4, buf, len);
    return 4 + len;
}

static ogs_pkbuf_t *pkbuf_from(const uint8_t *data, int len)
{
    ogs_pkbuf_t *pkbuf = ogs_pkbuf_alloc(NULL, 256);
    ogs_assert(pkbuf);
    ogs_pkbuf_put_data(pkbuf, data, len);
    return pkbuf;
}

/* GTPv2 Create Session Request with an IE ahead of the IMSI. */
static int build_gtpv2_csr(uint8_t *out, bool with_teid,
        uint8_t imsi_instance, const char *imsi_bcd)
{
    int hdr = with_teid ? OGS_GTPV2C_HEADER_LEN : 8;
    int n = hdr;

    memset(out, 0, 128);
    out[0] = with_teid ? 0x48 : 0x40;
    out[1] = OGS_GTP2_CREATE_SESSION_REQUEST_TYPE;

    /* Recovery IE (type 3, len 1) first: the peek must skip it */
    out[n++] = OGS_GTP2_RECOVERY_TYPE;
    put_be16(out + n, 1); n += 2;
    out[n++] = 0;
    out[n++] = 5;

    n += put_imsi_ie(out + n, imsi_instance, imsi_bcd);

    put_be16(out + 2, (uint16_t)(n - 4));
    return n;
}

static void gtpv2_peek_test(abts_case *tc, void *data)
{
    uint8_t raw[128];
    char bcd[OGS_MAX_IMSI_BCD_LEN + 1];
    ogs_pkbuf_t *pkbuf;
    int n;

    /* with TEID */
    n = build_gtpv2_csr(raw, true, 0, IMSI_A);
    pkbuf = pkbuf_from(raw, n);
    ABTS_INT_EQUAL(tc, OGS_OK,
            smf_gtpv2_peek_imsi_bcd(pkbuf, bcd, sizeof(bcd)));
    ABTS_STR_EQUAL(tc, IMSI_A, bcd);
    ogs_pkbuf_free(pkbuf);

    /* without TEID (8-octet header) */
    n = build_gtpv2_csr(raw, false, 0, IMSI_B);
    pkbuf = pkbuf_from(raw, n);
    ABTS_INT_EQUAL(tc, OGS_OK,
            smf_gtpv2_peek_imsi_bcd(pkbuf, bcd, sizeof(bcd)));
    ABTS_STR_EQUAL(tc, IMSI_B, bcd);
    ogs_pkbuf_free(pkbuf);

    /* IMSI on another instance is not the subscriber IMSI */
    n = build_gtpv2_csr(raw, true, 1, IMSI_A);
    pkbuf = pkbuf_from(raw, n);
    ABTS_INT_EQUAL(tc, OGS_ERROR,
            smf_gtpv2_peek_imsi_bcd(pkbuf, bcd, sizeof(bcd)));
    ABTS_STR_EQUAL(tc, "", bcd);
    ogs_pkbuf_free(pkbuf);

    /* IMSI IE truncated by the datagram: never read past the end */
    n = build_gtpv2_csr(raw, true, 0, IMSI_A);
    pkbuf = pkbuf_from(raw, n - 3);
    ABTS_INT_EQUAL(tc, OGS_ERROR,
            smf_gtpv2_peek_imsi_bcd(pkbuf, bcd, sizeof(bcd)));
    ogs_pkbuf_free(pkbuf);

    /* runt */
    pkbuf = pkbuf_from(raw, 6);
    ABTS_INT_EQUAL(tc, OGS_ERROR,
            smf_gtpv2_peek_imsi_bcd(pkbuf, bcd, sizeof(bcd)));
    ogs_pkbuf_free(pkbuf);
}

/* GTPv1 Create PDP Context Request: IMSI is the leading TV IE. */
static int build_gtpv1_cpc(uint8_t *out, uint8_t flags, uint8_t first_ie,
        const char *imsi_bcd)
{
    uint8_t buf[OGS_MAX_IMSI_LEN];
    int len = 0, hdr, n;

    memset(out, 0, 128);
    out[0] = flags;
    out[1] = OGS_GTP1_CREATE_PDP_CONTEXT_REQUEST_TYPE;
    hdr = (flags & 0x07) ? OGS_GTPV1C_HEADER_LEN : 8;
    n = hdr;

    ogs_bcd_to_buffer(imsi_bcd, buf, &len);
    out[n++] = first_ie;
    memset(out + n, 0xff, 8);
    memcpy(out + n, buf, len);
    n += 8;

    put_be16(out + 2, (uint16_t)(n - 8));
    return n;
}

static void gtpv1_peek_test(abts_case *tc, void *data)
{
    uint8_t raw[128];
    char bcd[OGS_MAX_IMSI_BCD_LEN + 1];
    ogs_pkbuf_t *pkbuf;
    int n;

    /* v1, PT=1, S=1 => 12-octet header */
    n = build_gtpv1_cpc(raw, 0x32, OGS_GTP1_IMSI_TYPE, IMSI_A);
    pkbuf = pkbuf_from(raw, n);
    ABTS_INT_EQUAL(tc, OGS_OK,
            smf_gtpv1_peek_imsi_bcd(pkbuf, bcd, sizeof(bcd)));
    ABTS_STR_EQUAL(tc, IMSI_A, bcd);
    ogs_pkbuf_free(pkbuf);

    /* no optional fields => 8-octet header */
    n = build_gtpv1_cpc(raw, 0x30, OGS_GTP1_IMSI_TYPE, IMSI_B);
    pkbuf = pkbuf_from(raw, n);
    ABTS_INT_EQUAL(tc, OGS_OK,
            smf_gtpv1_peek_imsi_bcd(pkbuf, bcd, sizeof(bcd)));
    ABTS_STR_EQUAL(tc, IMSI_B, bcd);
    ogs_pkbuf_free(pkbuf);

    /* first IE is not the IMSI (e.g. secondary PDP context) */
    n = build_gtpv1_cpc(raw, 0x32, 3 /* RAI */, IMSI_A);
    pkbuf = pkbuf_from(raw, n);
    ABTS_INT_EQUAL(tc, OGS_ERROR,
            smf_gtpv1_peek_imsi_bcd(pkbuf, bcd, sizeof(bcd)));
    ogs_pkbuf_free(pkbuf);

    /* extension headers present: left to the full parser */
    n = build_gtpv1_cpc(raw, 0x34, OGS_GTP1_IMSI_TYPE, IMSI_A);
    pkbuf = pkbuf_from(raw, n);
    ABTS_INT_EQUAL(tc, OGS_ERROR,
            smf_gtpv1_peek_imsi_bcd(pkbuf, bcd, sizeof(bcd)));
    ogs_pkbuf_free(pkbuf);

    /* IMSI cut short */
    n = build_gtpv1_cpc(raw, 0x32, OGS_GTP1_IMSI_TYPE, IMSI_A);
    pkbuf = pkbuf_from(raw, n - 1);
    ABTS_INT_EQUAL(tc, OGS_ERROR,
            smf_gtpv1_peek_imsi_bcd(pkbuf, bcd, sizeof(bcd)));
    ogs_pkbuf_free(pkbuf);
}

static int build_gtpv2_hdr(uint8_t *out, uint8_t type, uint32_t xid)
{
    memset(out, 0, OGS_GTPV2C_HEADER_LEN);
    out[0] = 0x48;
    out[1] = type;
    put_be16(out + 2, OGS_GTPV2C_HEADER_LEN - 4);
    out[8] = (uint8_t)(xid >> 16);
    out[9] = (uint8_t)(xid >> 8);
    out[10] = (uint8_t)xid;
    return OGS_GTPV2C_HEADER_LEN;
}

static int build_gtpv1_hdr(uint8_t *out, uint8_t flags, uint8_t type,
        uint16_t xid)
{
    memset(out, 0, OGS_GTPV1C_HEADER_LEN);
    out[0] = flags;
    out[1] = type;
    put_be16(out + 2, OGS_GTPV1C_HEADER_LEN - 8);
    put_be16(out + 8, xid);
    return OGS_GTPV1C_HEADER_LEN;
}

/*
 * Responses to our own requests go back to the shard whose xid window
 * the sequence number falls in; peer-initiated requests do not.
 * Runs last: ogs_worker_shards_enable() cannot be undone.
 */
static void reply_shard_test(abts_case *tc, void *data)
{
    uint8_t raw[32];
    int n, shard;

    n = build_gtpv1_hdr(raw, 0x32,
            OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE, 3 << 12);
    if (!ogs_worker_shards_active())
        ABTS_INT_EQUAL(tc, -1, ogs_gtp1_rx_reply_shard(raw, n));

    ogs_worker_shards_enable();

    for (shard = 0; shard <= SHARD_MAX; shard++) {
        uint32_t xid2 = (uint32_t)shard *
            (0x800000u >> OGS_WORKER_ID_BITS) + 11;
        uint16_t xid1 = (uint16_t)((shard << (16 - OGS_WORKER_ID_BITS)) + 11);

        n = build_gtpv2_hdr(raw,
                OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE, xid2);
        ABTS_INT_EQUAL(tc, shard, ogs_gtp2_rx_reply_shard(raw, n));

        n = build_gtpv1_hdr(raw, 0x32,
                OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE, xid1);
        ABTS_INT_EQUAL(tc, shard, ogs_gtp1_rx_reply_shard(raw, n));
    }

    /* requests are routed by TEID / IMSI, never by xid */
    n = build_gtpv2_hdr(raw, OGS_GTP2_CREATE_SESSION_REQUEST_TYPE, 5);
    ABTS_INT_EQUAL(tc, -1, ogs_gtp2_rx_reply_shard(raw, n));
    n = build_gtpv1_hdr(raw, 0x32,
            OGS_GTP1_CREATE_PDP_CONTEXT_REQUEST_TYPE, 5);
    ABTS_INT_EQUAL(tc, -1, ogs_gtp1_rx_reply_shard(raw, n));

    /* GTPv1 without a sequence number cannot be matched */
    n = build_gtpv1_hdr(raw, 0x30,
            OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE, 3 << 12);
    ABTS_INT_EQUAL(tc, -1, ogs_gtp1_rx_reply_shard(raw, n));

    /* wrong version / runt */
    n = build_gtpv1_hdr(raw, 0x32,
            OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE, 3 << 12);
    ABTS_INT_EQUAL(tc, -1, ogs_gtp2_rx_reply_shard(raw, n));
    ABTS_INT_EQUAL(tc, -1, ogs_gtp1_rx_reply_shard(raw, 8));
}

abts_suite *test_smf_shard(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, teid_seid_xid_decode_test, NULL);
    abts_run_test(suite, clamp_test, NULL);
    abts_run_test(suite, imsi_hash_test, NULL);
    abts_run_test(suite, gtpv2_peek_test, NULL);
    abts_run_test(suite, gtpv1_peek_test, NULL);
    abts_run_test(suite, reply_shard_test, NULL);

    return suite;
}
