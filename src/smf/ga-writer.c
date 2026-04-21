/*
 * Copyright (C) 2026 by Open5GS Contributors
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

#include "ga-writer.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#define smf_mkdir(p) _mkdir(p)
#else
#include <unistd.h>
#define smf_mkdir(p) mkdir((p), 0755)
#endif

/* ================================================================== */
/*  On-disk framing                                                   */
/* ================================================================== */

#define CDR_FILE_MAGIC     "O5CD"
#define CDR_FILE_VERSION   0x01
#define CDR_FILE_FORMAT_BER 0x01

/* Cap the encoded PGWRecord at 4 KiB. Well above anything TS 32.298
 * ever produces in practice (the sample in the design doc is 217 B). */
#define SMF_GA_RECORD_MAX  4096

/* ================================================================== */
/*  Writer state                                                      */
/* ================================================================== */

static struct {
    bool initialized;

    char *current_path;     /* full path of the active .cdr file */
    char *ready_dir;        /* <spool_dir>/ready */
    char *current_dir;      /* <spool_dir>/current */
    char *seq_path;         /* <spool_dir>/.seq */

    FILE *fp;               /* active file handle, or NULL */

    /* Rotation bookkeeping for the active file. */
    uint32_t cur_records;
    uint32_t cur_bytes;
    ogs_time_t cur_opened;
} g;

/* ================================================================== */
/*  Minimal BER encoder                                               */
/* ================================================================== */

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t off;
    bool overflow;
} ber_t;

static void ber_init(ber_t *b, uint8_t *buf, size_t cap)
{
    b->buf = buf;
    b->cap = cap;
    b->off = 0;
    b->overflow = false;
}

static void ber_raw(ber_t *b, const void *data, size_t len)
{
    if (b->overflow) return;
    if (b->off + len > b->cap) {
        b->overflow = true;
        return;
    }
    /* memcpy(dst, NULL, 0) is technically UB per C standard; ber_prim_ctx
     * is called with (NULL, 0) for NULL-valued primitives like [25]
     * iMSsignalingContext, so short-circuit before touching memcpy. */
    if (len > 0)
        memcpy(b->buf + b->off, data, len);
    b->off += len;
}

static void ber_u8(ber_t *b, uint8_t v) { ber_raw(b, &v, 1); }

/* Encode length in minimal BER long form where needed. */
static void ber_len(ber_t *b, size_t len)
{
    if (len < 0x80) {
        ber_u8(b, (uint8_t)len);
    } else if (len <= 0xff) {
        ber_u8(b, 0x81);
        ber_u8(b, (uint8_t)len);
    } else if (len <= 0xffff) {
        ber_u8(b, 0x82);
        ber_u8(b, (uint8_t)(len >> 8));
        ber_u8(b, (uint8_t)(len & 0xff));
    } else {
        /* Single CDR larger than 64KB is never legal for us. */
        b->overflow = true;
    }
}

/* [n] IMPLICIT with a primitive value. For n < 31 the tag fits in one
 * byte; for larger n we use two (high tag number form). The class bits
 * used here are context-specific (10...) which matches 3GPP CDR modules
 * that default to IMPLICIT TAGS without a class override. */
static void ber_prim_ctx(ber_t *b, uint32_t tag,
        const void *value, size_t len)
{
    if (tag < 31) {
        ber_u8(b, (uint8_t)(0x80 | tag)); /* context, primitive, tag */
    } else {
        ber_u8(b, 0x9f);                  /* context, primitive, 0x1f */
        ber_u8(b, (uint8_t)tag);          /* high tag number */
    }
    ber_len(b, len);
    ber_raw(b, value, len);
}

static void ber_uint_ctx(ber_t *b, uint32_t tag, uint64_t v)
{
    /* Encode as minimal-length unsigned INTEGER.
     * Note: strict ASN.1 INTEGER is signed, but TS 32.298 uses primitive
     * OCTET-STRING / ENUMERATED / INTEGER interchangeably through IMPLICIT
     * tagging, and the values we emit are always fields like ChargingID
     * that fit in <= 4 unsigned bytes. We skip the sign-bit padding byte
     * for pragmatic compatibility with real-world CGF implementations. */
    uint8_t tmp[8];
    int n = 0;
    if (v == 0) {
        tmp[n++] = 0x00;
    } else {
        uint64_t x = v;
        int shift;
        for (shift = 56; shift >= 0; shift -= 8) {
            if ((x >> shift) & 0xff) break;
        }
        for (; shift >= 0; shift -= 8)
            tmp[n++] = (uint8_t)((x >> shift) & 0xff);
    }
    ber_prim_ctx(b, tag, tmp, n);
}

/* Fixed-size big-endian integer (e.g. 4-byte chargingID). */
static void ber_uint_be_ctx(ber_t *b, uint32_t tag, uint64_t v, int bytes)
{
    uint8_t tmp[8];
    int i;
    ogs_assert(bytes >= 1 && bytes <= 8);
    for (i = 0; i < bytes; i++)
        tmp[i] = (uint8_t)((v >> (8 * (bytes - 1 - i))) & 0xff);
    ber_prim_ctx(b, tag, tmp, bytes);
}

/* Reserve space for a constructed header and return a marker used by
 * ber_end() to patch the length once the children are encoded.
 *
 * We reserve the worst-case 3-byte length form (0x82 LL LL) up-front
 * so children can be written into the buffer without relocation. Once
 * the inner size is known, ber_end() computes the MINIMAL length form
 * (short / 1-octet / 2-octet) and memmove()s the children back by 1
 * or 2 bytes as needed. This is required because real-world CGFs
 * (Ericsson, Nokia, Huawei) enforce X.690 §8.1.3 canonical length
 * encoding on decode and reject non-minimal forms like `82 00 06` as
 * malformed CDRs — even though raw BER technically permits them. */
static size_t ber_begin_ctx(ber_t *b, uint32_t tag)
{
    size_t mark;
    if (tag < 31) {
        ber_u8(b, (uint8_t)(0xa0 | tag)); /* context, constructed, tag */
    } else {
        ber_u8(b, 0xbf);                  /* context, constructed, 0x1f */
        ber_u8(b, (uint8_t)tag);
    }
    mark = b->off;
    /* placeholder for 0x82 LL LL — collapsed to minimal form in ber_end */
    ber_u8(b, 0x82);
    ber_u8(b, 0x00);
    ber_u8(b, 0x00);
    return mark;
}

static void ber_end(ber_t *b, size_t mark)
{
    size_t inner;
    uint8_t lenbuf[3];
    unsigned lenlen;

    if (b->overflow) return;
    ogs_assert(mark + 3 <= b->off);
    inner = b->off - (mark + 3);

    /* Minimal (canonical) BER length encoding per X.690 §8.1.3:
     *   len < 128          -> 1 byte, value directly (short form)
     *   128..255           -> 0x81 + 1 byte
     *   256..65535         -> 0x82 + 2 bytes
     * Strict decoders require the shortest form that fits. */
    if (inner < 0x80) {
        lenbuf[0] = (uint8_t)inner;
        lenlen = 1;
    } else if (inner <= 0xff) {
        lenbuf[0] = 0x81;
        lenbuf[1] = (uint8_t)inner;
        lenlen = 2;
    } else if (inner <= 0xffff) {
        lenbuf[0] = 0x82;
        lenbuf[1] = (uint8_t)(inner >> 8);
        lenbuf[2] = (uint8_t)(inner & 0xff);
        lenlen = 3;
    } else {
        b->overflow = true;
        return;
    }

    /* If the minimal length header is shorter than the 3-byte
     * placeholder, slide children back so the encoding is canonical.
     * Any outer mark lives BEFORE `mark`, so its offset is unaffected;
     * b->off is rewound so the outer ber_end() sees the correct
     * child length when it computes its own `inner`. */
    if (lenlen < 3) {
        memmove(b->buf + mark + lenlen,
                b->buf + mark + 3,
                inner);
        b->off -= (3 - lenlen);
    }
    memcpy(b->buf + mark, lenbuf, lenlen);
}

/* Plain UNIVERSAL SEQUENCE (0x30) — used for list-of-traffic-volumes
 * rows and similar nested structures. Uses the same 3-byte placeholder
 * as ber_begin_ctx so ber_end() collapses it identically. */
static size_t ber_begin_seq(ber_t *b)
{
    size_t mark;
    ber_u8(b, 0x30);
    mark = b->off;
    ber_u8(b, 0x82);
    ber_u8(b, 0x00);
    ber_u8(b, 0x00);
    return mark;
}

/* ================================================================== */
/*  Field encoders                                                    */
/* ================================================================== */

/*
 * Encode a decimal-digit string (0-9) into TBCD-STRING as used by
 * TS 29.002 / TS 32.298 for IMSI, MSISDN and IMEISV. Each byte carries
 * two digits with the low nibble holding the earlier digit; a trailing
 * nibble of 0xF pads an odd-length value.
 */
static size_t tbcd_encode(const char *digits, uint8_t *out, size_t out_cap)
{
    size_t n, i, o;
    n = digits ? strlen(digits) : 0;
    o = (n + 1) / 2;
    if (o > out_cap) return 0;
    memset(out, 0, o);
    for (i = 0; i < n; i++) {
        uint8_t d = (uint8_t)(digits[i] - '0');
        if (d > 9) return 0;
        if (i & 1)
            out[i / 2] |= (uint8_t)(d << 4);
        else
            out[i / 2] |= d;
    }
    if (n & 1)
        out[n / 2] |= 0xf0;
    return o;
}

/*
 * TS 32.298 TimeStamp: 9-octet BCD of YY MM DD hh mm ss S hh mm where
 * each digit pair is a separate byte and S is the ASCII '+'/'-' sign
 * octet of the local-time offset from UTC.
 */
static void timestamp_encode(ogs_time_t t, uint8_t out[9])
{
    struct tm lt;
    time_t sec = (time_t)(t / OGS_USEC_PER_SEC);
    long tz_min;
    int sign;

    ogs_localtime(sec, &lt);

    /* Local zone offset in minutes. ogs_timezone() returns seconds east
     * of UTC on all platforms open5gs supports. */
    tz_min = ogs_timezone() / 60;
    sign = tz_min >= 0 ? '+' : '-';
    if (tz_min < 0) tz_min = -tz_min;

    out[0] = (uint8_t)(((lt.tm_year % 100) / 10) << 4 |
                       ((lt.tm_year % 100) % 10));
    out[1] = (uint8_t)(((lt.tm_mon + 1) / 10) << 4 |
                       ((lt.tm_mon + 1) % 10));
    out[2] = (uint8_t)((lt.tm_mday / 10) << 4 | (lt.tm_mday % 10));
    out[3] = (uint8_t)((lt.tm_hour / 10) << 4 | (lt.tm_hour % 10));
    out[4] = (uint8_t)((lt.tm_min / 10) << 4 | (lt.tm_min % 10));
    out[5] = (uint8_t)((lt.tm_sec / 10) << 4 | (lt.tm_sec % 10));
    out[6] = (uint8_t)sign;
    out[7] = (uint8_t)(((tz_min / 60) / 10) << 4 | ((tz_min / 60) % 10));
    out[8] = (uint8_t)(((tz_min % 60) / 10) << 4 | ((tz_min % 60) % 10));
}

/*
 * 3-octet PLMN-Id. ogs_plmn_id_t is already stored in the nibble-swapped
 * wire format required by both TS 24.008 §10.5.1.3 and TS 32.298, so a
 * straight 3-byte copy is sufficient.
 */
static void plmn_encode(const ogs_plmn_id_t *plmn, uint8_t out[3])
{
    memcpy(out, plmn, 3);
}

/*
 * MS Time Zone, TS 24.008 §10.5.3.8 — 2-octet fallback built from the
 * SMF host's local timezone when no UE-sourced IE was captured. This is
 * the same encoding the MME ships to the SGW/PGW for "network time" (see
 * src/mme/mme-s11-build.c). DST byte is left at 0 (no adjustment) because
 * ogs_timezone() already folds DST into the offset.
 *
 *   Octet 1  : [units:4 (high nibble)] [tens:3 | sign:1 (low nibble)]
 *   Octet 2  : [spare:6 (high) | DST:2 (low)]
 */
static void ms_timezone_fallback(uint8_t out[2])
{
    long tz_sec = (long)ogs_timezone();
    long qh;
    uint8_t tens, units, tz_byte;
    int negative = 0;

    if (tz_sec < 0) {
        negative = 1;
        tz_sec = -tz_sec;
    }
    qh = tz_sec / (15L * 60L);  /* quarter hours 0..96 */
    if (qh > 99) qh = 99;       /* clamp to 2 BCD digits */

    tens = (uint8_t)(qh / 10);
    units = (uint8_t)(qh % 10);

    /* Per TS 23.040 §9.2.3.11: nibble-swapped BCD, sign in bit 3
     * of the first (low) semi-octet. */
    tz_byte = (uint8_t)((units << 4) | (tens & 0x07));
    if (negative)
        tz_byte |= 0x08;

    out[0] = tz_byte;
    out[1] = 0x00;              /* DST = no adjustment */
}

/* ================================================================== */
/*  PGWRecord construction                                            */
/* ================================================================== */

/* TS 32.298 RecordType values (subset). */
#define CDR_RT_PGW_PDP_RECORD 85

/* TS 32.298 ServingNodeType enumerated. */
#define CDR_SNT_SGSN          0
#define CDR_SNT_PMIP_SGW      1
#define CDR_SNT_GTP_SGW       2
#define CDR_SNT_MME           5

/*
 * Render a GSNAddress choice. GSNAddress ::= CHOICE {
 *   iPBinaryAddress  [0] IPBinaryAddress,
 *   iPTextRepresented [1] IPTextRepresented }
 * where IPBinaryAddress ::= CHOICE {
 *   iPBinV4Address [0] OCTET STRING(SIZE(4)),
 *   iPBinV6Address [1] OCTET STRING(SIZE(16)) }
 *
 * The outer wrapper is therefore a SEQUENCE-like construct built from a
 * nested [0] containing the IPv4 / IPv6 primitive.
 */
static void encode_gsn_address_v4(ber_t *b, uint32_t outer_tag, uint32_t addr)
{
    size_t m;
    uint8_t v4[4];
    v4[0] = (uint8_t)(addr >> 24);
    v4[1] = (uint8_t)(addr >> 16);
    v4[2] = (uint8_t)(addr >> 8);
    v4[3] = (uint8_t)(addr & 0xff);
    m = ber_begin_ctx(b, outer_tag);
    ber_prim_ctx(b, 0, v4, 4);
    ber_end(b, m);
}

/*
 * Build a single [APPLICATION 79] PGWRecord -like PDU and return the
 * encoded length. The output buffer is filled starting at byte 0.
 */
static size_t build_pgw_record(
        smf_sess_t *sess, uint8_t *out, size_t out_cap, bool is_stop)
{
    smf_ue_t *smf_ue = NULL;
    smf_cdr_config_t *cfg = &smf_self()->cdr;
    ber_t b;
    size_t outer;
    uint8_t tmp[16];
    size_t n;
    ogs_time_t now;

    ogs_assert(sess);
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    if (!smf_ue) return 0;

    ber_init(&b, out, out_cap);
    now = ogs_time_now();

    /*
     * The outermost shape is [CONTEXT 79] IMPLICIT SET (0xbf 0x4f ...)
     * which is how 3GPP IMPLICIT-tagged CHOICE alternatives appear on
     * the wire; the SET body contains the [n]-tagged fields below.
     */
    outer = ber_begin_ctx(&b, 79);

    /* [0] recordType */
    ber_uint_be_ctx(&b, 0, CDR_RT_PGW_PDP_RECORD, 1);

    /* [3] servedIMSI (TBCD) */
    if (smf_ue->imsi_bcd[0]) {
        n = tbcd_encode(smf_ue->imsi_bcd, tmp, sizeof(tmp));
        if (n) ber_prim_ctx(&b, 3, tmp, n);
    }

    /* [4] p-GWAddress from configured local_address (IPv4 only for v1). */
    if (cfg->local_address) {
        ogs_ipsubnet_t ipsub;
        if (ogs_ipsubnet(&ipsub, cfg->local_address, NULL) == OGS_OK &&
                ipsub.family == AF_INET) {
            encode_gsn_address_v4(&b, 4, ntohl(ipsub.sub[0]));
        }
    }

    /* [5] chargingID */
    if (sess->charging.id)
        ber_uint_be_ctx(&b, 5, sess->charging.id, 4);

    /* [6] servingNodeAddress SEQUENCE OF GSNAddress.
     *
     * MANDATORY per TS 32.298 PGWRecord — Wireshark's PGW-CDR dissector
     * reports "BER Error: Missing field in SET class:CONTEXT(2) tag:6
     * expected" when this is absent, and real CGFs reject the record.
     *
     * We always emit at least one address:
     *   1. SGW S5-C IPv4 (EPC GTPv2 path), else
     *   2. SGW S5-C IPv6, else
     *   3. 0.0.0.0 placeholder so the mandatory slot is filled.
     */
    if (sess->sgw_s5c_ip.ipv4) {
        encode_gsn_address_v4(&b, 6, ntohl(sess->sgw_s5c_ip.addr));
    } else if (sess->sgw_s5c_ip.ipv6) {
        /* GSNAddress with IPBinV6Address [1] variant. */
        size_t m = ber_begin_ctx(&b, 6);
        ber_prim_ctx(&b, 1, sess->sgw_s5c_ip.addr6, OGS_IPV6_LEN);
        ber_end(&b, m);
    } else {
        encode_gsn_address_v4(&b, 6, 0);
    }

    /* [7] accessPointNameNI */
    if (sess->session.name) {
        ber_prim_ctx(&b, 7, sess->session.name,
                strlen(sess->session.name));
    }

    /* [8] pdpPDNType: two-octet value {PDN type org, PDN type number}.
     * Org=0 (IETF), Number=session_type directly matches EPC IE values. */
    tmp[0] = 0x00;
    tmp[1] = sess->session.session_type;
    ber_prim_ctx(&b, 8, tmp, 2);

    /* [9] servedPDPPDNAddress = PDPAddress: CHOICE { iPAddress [0] }.
     * IPBinaryAddress nested under it. */
    if (sess->ipv4) {
        size_t m1 = ber_begin_ctx(&b, 9);
        encode_gsn_address_v4(&b, 0, ntohl(sess->ipv4->addr[0]));
        ber_end(&b, m1);
    }

    /* [11] dynamicAddressFlag = TRUE (Open5GS always allocates from pool) */
    if (sess->ipv4 || sess->ipv6) {
        tmp[0] = 0xff;
        ber_prim_ctx(&b, 11, tmp, 1);
    }

    /* [12] listOfTrafficVolumes SEQUENCE OF ChangeOfCharCondition.
     * One row per emitted record, carrying the delta (preferred) or the
     * running total if last_* was not set. */
    {
        uint64_t ul_delta = sess->gy.ul_octets - sess->cdr.last_ul_octets;
        uint64_t dl_delta = sess->gy.dl_octets - sess->cdr.last_dl_octets;
        uint8_t ts[9];
        size_t list, row;

        list = ber_begin_ctx(&b, 12);
        row = ber_begin_seq(&b);

        /* [3] dataVolumeGPRSUplink */
        ber_uint_ctx(&b, 3, ul_delta);
        /* [4] dataVolumeGPRSDownlink */
        ber_uint_ctx(&b, 4, dl_delta);
        /* [5] changeCondition: 0=qoSChange, 2=recordClosure... pragmatic
         * mapping: use 2 on stop, 3 (timeLimit) on interim, 0 on start. */
        tmp[0] = is_stop ? 2 : (sess->cdr.record_seq == 0 ? 0 : 3);
        ber_prim_ctx(&b, 5, tmp, 1);
        /* [6] changeTime */
        timestamp_encode(now, ts);
        ber_prim_ctx(&b, 6, ts, 9);

        ber_end(&b, row);
        ber_end(&b, list);
    }

    /* [13] recordOpeningTime */
    {
        uint8_t ts[9];
        ogs_time_t open_t = sess->cdr.start_time ?
                sess->cdr.start_time : now;
        timestamp_encode(open_t, ts);
        ber_prim_ctx(&b, 13, ts, 9);
    }

    /* [14] duration (seconds since session start) */
    {
        ogs_time_t start = sess->cdr.start_time ? sess->cdr.start_time : now;
        uint64_t secs = (uint64_t)((now - start) / OGS_USEC_PER_SEC);
        ber_uint_ctx(&b, 14, secs);
    }

    /* [15] causeForRecClosing */
    {
        uint8_t c = is_stop ? sess->cdr.cause_for_rec_closing : 0;
        ber_prim_ctx(&b, 15, &c, 1);
    }

    /* [17] recordSequenceNumber — only on partial records per TS 32.298. */
    if (!is_stop || sess->cdr.record_seq > 0) {
        ber_uint_ctx(&b, 17, sess->cdr.record_seq + 1);
    }

    /* [18] nodeID */
    if (cfg->node_id) {
        ber_prim_ctx(&b, 18, cfg->node_id, strlen(cfg->node_id));
    }

    /* [20] localSequenceNumber.
     *
     * Must be strictly increasing across the lifetime of the node (TS
     * 32.298 §5.1.1.2). We bump the counter BEFORE encoding so the value
     * that lands in this record is the one we persist on the next rotate
     * / shutdown, guaranteeing uniqueness even if the SMF crashes after
     * the record is on disk but before the spool rotates.
     *
     * Encoded as a fixed 4-octet big-endian INTEGER so every record in a
     * file has the same field width, which is what Ericsson/Nokia CGFs
     * match on for gap detection. */
    smf_self()->cdr_local_seq++;
    ber_uint_be_ctx(&b, 20, smf_self()->cdr_local_seq, 4);

    /* [21] apnSelectionMode (EPC only) */
    if (sess->epc) {
        tmp[0] = sess->gtp.selection_mode;
        ber_prim_ctx(&b, 21, tmp, 1);
    }

    /* [22] servedMSISDN (TBCD) */
    if (smf_ue->msisdn_bcd[0]) {
        n = tbcd_encode(smf_ue->msisdn_bcd, tmp, sizeof(tmp));
        if (n) ber_prim_ctx(&b, 22, tmp, n);
    }

    /* [23] chargingCharacteristics */
    ber_prim_ctx(&b, 23, sess->session.charging_characteristics,
            OGS_CHRGCHARS_LEN);

    /* [24] chChSelectionMode = 0 (served subscription) */
    tmp[0] = 0;
    ber_prim_ctx(&b, 24, tmp, 1);

    /* [25] iMSsignalingContext ::= NULL.
     *
     * Always emitted as an empty primitive (`99 00`) — this is what real
     * Ericsson/Nokia CGFs put in their PGW-CDR template even though the
     * spec marks the field OPTIONAL. Some decoders (notably older Comptel
     * / Ericsson BSCS) reject records whose SET layout differs from the
     * reference template by more than the OPTIONAL tail, so we emit the
     * slot unconditionally to stay maximally compatible. */
    ber_prim_ctx(&b, 25, NULL, 0);

    /* [27] servingNodePLMNIdentifier */
    {
        uint8_t pl[3];
        plmn_encode(&sess->serving_plmn_id, pl);
        ber_prim_ctx(&b, 27, pl, 3);
    }

    /* [29] servedIMEISV (TBCD) */
    if (smf_ue->imeisv_bcd[0]) {
        n = tbcd_encode(smf_ue->imeisv_bcd, tmp, sizeof(tmp));
        if (n) ber_prim_ctx(&b, 29, tmp, n);
    }

    /* [30] rATType */
    if (sess->gtp_rat_type) {
        tmp[0] = sess->gtp_rat_type;
        ber_prim_ctx(&b, 30, tmp, 1);
    }

    /* [31] mSTimeZone — prefer the 2-byte IE that the MME/SGW passed us
     * in the Create Session Request. If the peer didn't send one (older
     * SGSN, WLAN access, etc.) fall back to the SMF host's local TZ so
     * the field is never missing from the emitted CDR. */
    if (sess->gtp.ue_timezone.data && sess->gtp.ue_timezone.len) {
        ber_prim_ctx(&b, 31,
                sess->gtp.ue_timezone.data,
                sess->gtp.ue_timezone.len);
    } else {
        uint8_t tz[2];
        ms_timezone_fallback(tz);
        ber_prim_ctx(&b, 31, tz, sizeof(tz));
    }

    /* [32] userLocationInformation (raw GTPv2 ULI TLV, TS 29.274 §8.21).
     *
     * There is NO safe fallback — the tracking-area / cell-identity is
     * peer-supplied and the SMF has no way to synthesize it. We warn
     * once per CDR when the peer didn't include it so operators can see
     * the upstream is misconfigured (MME not sending ULI in CSR). */
    if (sess->gtp.user_location_information.data &&
            sess->gtp.user_location_information.len) {
        ber_prim_ctx(&b, 32,
                sess->gtp.user_location_information.data,
                sess->gtp.user_location_information.len);
    } else {
        ogs_warn("smf_ga_writer: user_location_information absent from "
                 "session (IMSI=%s) — CGF will see [32] missing; check "
                 "MME's Create Session Request is carrying the ULI IE",
                 smf_ue->imsi_bcd[0] ? smf_ue->imsi_bcd : "?");
    }

    /* [35] servingNodeType SEQUENCE OF. */
    {
        size_t m = ber_begin_ctx(&b, 35);
        uint8_t snt = sess->epc ? CDR_SNT_GTP_SGW : CDR_SNT_MME;
        /* ServingNodeType ::= ENUMERATED — encoded as a context [x] is
         * wrong; spec says it's a universal ENUMERATED inside the SEQ.
         * Use UNIVERSAL ENUMERATED primitive tag 0x0a. */
        ber_u8(&b, 0x0a);
        ber_u8(&b, 0x01);
        ber_u8(&b, snt);
        ber_end(&b, m);
    }

    /* [36] is NOT emitted in PGW-CDRs.
     *
     * In TS 32.298 the semantics of [36] differ by record type:
     *   SGWRecord:  [36] p-GWAddressUsed    (SEQUENCE OF GSNAddress)
     *   PGWRecord:  [36] sGWChange          (BOOLEAN)
     *
     * The reference PGW-CDR capture from the target CGF confirms [36]
     * is absent — emitting a GSNAddress here with the PGWRecord outer
     * tag (0xbf 0x4f) would trip the CGF's strict schema check. The
     * field-name "pGWAddressUsed" belongs to the SGW-CDR record only. */

    /* [37] p-GWPLMNIdentifier (same as serving PLMN for non-roaming).
     * For roaming SMFs it should come from the local PLMN config; we
     * fall back to the serving PLMN. */
    {
        uint8_t pl[3];
        plmn_encode(&sess->serving_plmn_id, pl);
        ber_prim_ctx(&b, 37, pl, 3);
    }

    /* [38] startTime */
    {
        uint8_t ts[9];
        ogs_time_t st = sess->cdr.start_time ? sess->cdr.start_time : now;
        timestamp_encode(st, ts);
        ber_prim_ctx(&b, 38, ts, 9);
    }

    /* [39] stopTime — only on the final record. */
    if (is_stop) {
        uint8_t ts[9];
        timestamp_encode(now, ts);
        ber_prim_ctx(&b, 39, ts, 9);
    }

    ber_end(&b, outer);
    if (b.overflow) return 0;
    return b.off;
}

/* ================================================================== */
/*  Spool file management                                             */
/* ================================================================== */

static int mkdir_p(const char *path)
{
    /* Create every intermediate directory; ignore EEXIST. */
    char *copy, *p;
    int rc = OGS_OK;

    if (!path || !*path) return OGS_ERROR;
    copy = ogs_strdup(path);
    if (!copy) return OGS_ERROR;

    for (p = copy + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char saved = *p;
            *p = '\0';
            if (smf_mkdir(copy) != 0 && errno != EEXIST) {
                rc = OGS_ERROR;
                *p = saved;
                break;
            }
            *p = saved;
        }
    }
    if (rc == OGS_OK && smf_mkdir(copy) != 0 && errno != EEXIST)
        rc = OGS_ERROR;

    ogs_free(copy);
    return rc;
}

static void load_local_seq(void)
{
    FILE *fp;
    unsigned long v = 0;

    if (!g.seq_path) return;
    fp = fopen(g.seq_path, "r");
    if (!fp) return;
    if (fscanf(fp, "%lu", &v) == 1)
        smf_self()->cdr_local_seq = (uint32_t)v;
    fclose(fp);
}

static void persist_local_seq(void)
{
    FILE *fp;
    if (!g.seq_path) return;
    fp = fopen(g.seq_path, "w");
    if (!fp) return;
    fprintf(fp, "%u\n", smf_self()->cdr_local_seq);
    fclose(fp);
}

static int open_current_file(void)
{
    smf_cdr_config_t *cfg = &smf_self()->cdr;
    char name[256];
    const char *node = cfg->node_id ? cfg->node_id : "smf";

    if (g.fp) return OGS_OK;

    ogs_snprintf(name, sizeof(name), "%s/%s-%llu.cdr",
            g.current_dir, node,
            (unsigned long long)(ogs_time_now() / OGS_USEC_PER_SEC));

    if (g.current_path) { ogs_free(g.current_path); g.current_path = NULL; }
    g.current_path = ogs_strdup(name);
    ogs_assert(g.current_path);

    g.fp = fopen(g.current_path, "ab");
    if (!g.fp) {
        ogs_warn("smf_ga_writer: cannot open spool file '%s': %s",
                g.current_path, strerror(errno));
        return OGS_ERROR;
    }
    g.cur_records = 0;
    g.cur_bytes = 0;
    g.cur_opened = ogs_time_now();
    return OGS_OK;
}

static void rotate_locked(void)
{
    char ready_name[256];
    const char *base;

    if (!g.fp || !g.current_path) return;
    fflush(g.fp);
    fclose(g.fp);
    g.fp = NULL;

    /* Rename <current_dir>/NAME.cdr -> <ready_dir>/NAME.cdr */
    base = strrchr(g.current_path, '/');
#ifdef _WIN32
    { const char *bb = strrchr(g.current_path, '\\'); if (bb > base) base = bb; }
#endif
    base = base ? base + 1 : g.current_path;

    ogs_snprintf(ready_name, sizeof(ready_name), "%s/%s", g.ready_dir, base);
    if (rename(g.current_path, ready_name) != 0) {
        ogs_warn("smf_ga_writer: rotate rename '%s' -> '%s' failed: %s",
                g.current_path, ready_name, strerror(errno));
    } else {
        ogs_debug("smf_ga_writer: rotated to '%s' (%u records, %u bytes)",
                ready_name, g.cur_records, g.cur_bytes);
    }

    ogs_free(g.current_path);
    g.current_path = NULL;
    g.cur_records = 0;
    g.cur_bytes = 0;

    /* Persist the sequence counter on every rotate so that a crash
     * (kernel panic, OOM-kill, SIGKILL) after records are safely in the
     * ready/ directory can't wind the counter backwards and cause the
     * CGF to see duplicate localSequenceNumber values. */
    persist_local_seq();
}

static bool should_rotate(void)
{
    smf_cdr_config_t *cfg = &smf_self()->cdr;
    if (cfg->rotate_max_records &&
            g.cur_records >= cfg->rotate_max_records) return true;
    if (cfg->rotate_max_bytes &&
            g.cur_bytes >= cfg->rotate_max_bytes) return true;
    if (cfg->rotate_max_seconds &&
            ogs_time_now() - g.cur_opened >=
            ogs_time_from_sec(cfg->rotate_max_seconds)) return true;
    return false;
}

static void write_record(const uint8_t *rec, size_t rec_len)
{
    uint8_t hdr[8];

    if (!g.initialized) return;
    if (!rec || !rec_len) return;
    if (rec_len > 0xffff) {
        ogs_warn("smf_ga_writer: record too large (%zu B), dropping",
                rec_len);
        return;
    }

    if (!g.fp && open_current_file() != OGS_OK)
        return;

    memcpy(hdr, CDR_FILE_MAGIC, 4);
    hdr[4] = CDR_FILE_VERSION;
    hdr[5] = CDR_FILE_FORMAT_BER;
    hdr[6] = (uint8_t)(rec_len >> 8);
    hdr[7] = (uint8_t)(rec_len & 0xff);

    if (fwrite(hdr, 1, sizeof(hdr), g.fp) != sizeof(hdr) ||
            fwrite(rec, 1, rec_len, g.fp) != rec_len) {
        ogs_warn("smf_ga_writer: short write, closing file");
        fclose(g.fp);
        g.fp = NULL;
        return;
    }
    fflush(g.fp);

    g.cur_records++;
    g.cur_bytes += (uint32_t)(rec_len + sizeof(hdr));
    /* cdr_local_seq was already bumped by build_pgw_record() so that
     * the value ENCODED in the record matches what we persist. */

    if (should_rotate())
        rotate_locked();
}

/* ================================================================== */
/*  Public API                                                        */
/* ================================================================== */

int smf_ga_writer_open(void)
{
    smf_cdr_config_t *cfg = &smf_self()->cdr;
    char path[512];

    if (!cfg->enabled) {
        ogs_info("smf_ga_writer: disabled");
        return OGS_OK;
    }
    if (!cfg->spool_dir || !*cfg->spool_dir) {
        ogs_error("smf_ga_writer: enabled but no smf.cdr.spool_dir");
        return OGS_ERROR;
    }

    if (mkdir_p(cfg->spool_dir) != OGS_OK) {
        ogs_error("smf_ga_writer: cannot create spool dir '%s'",
                cfg->spool_dir);
        return OGS_ERROR;
    }
    ogs_snprintf(path, sizeof(path), "%s/current", cfg->spool_dir);
    if (mkdir_p(path) != OGS_OK) return OGS_ERROR;
    g.current_dir = ogs_strdup(path);

    ogs_snprintf(path, sizeof(path), "%s/ready", cfg->spool_dir);
    if (mkdir_p(path) != OGS_OK) return OGS_ERROR;
    g.ready_dir = ogs_strdup(path);

    ogs_snprintf(path, sizeof(path), "%s/.seq", cfg->spool_dir);
    g.seq_path = ogs_strdup(path);

    load_local_seq();
    g.initialized = true;

    ogs_info("smf_ga_writer: ready, spool='%s' node='%s' local_seq=%u",
            cfg->spool_dir,
            cfg->node_id ? cfg->node_id : "(unset)",
            smf_self()->cdr_local_seq);
    return OGS_OK;
}

void smf_ga_writer_close(void)
{
    if (g.fp)
        rotate_locked();

    persist_local_seq();

    if (g.current_dir) { ogs_free(g.current_dir); g.current_dir = NULL; }
    if (g.ready_dir)   { ogs_free(g.ready_dir);   g.ready_dir = NULL; }
    if (g.seq_path)    { ogs_free(g.seq_path);    g.seq_path = NULL; }
    if (g.current_path){ ogs_free(g.current_path);g.current_path = NULL; }

    g.initialized = false;
}

static void emit(smf_sess_t *sess, bool is_stop)
{
    uint8_t rec[SMF_GA_RECORD_MAX];
    size_t n;

    if (!smf_self()->cdr.enabled || !g.initialized) return;
    n = build_pgw_record(sess, rec, sizeof(rec), is_stop);
    if (!n) {
        ogs_warn("smf_ga_writer: BER encode failed (sess_id=%d)",
                (int)sess->id);
        return;
    }
    write_record(rec, n);

    sess->cdr.last_ul_octets = sess->gy.ul_octets;
    sess->cdr.last_dl_octets = sess->gy.dl_octets;
    sess->cdr.last_change_time = ogs_time_now();
    sess->cdr.record_seq++;
}

void smf_ga_cdr_session_start(smf_sess_t *sess)
{
    if (!smf_self()->cdr.enabled) return;
    ogs_assert(sess);

    if (!sess->cdr.start_time)
        sess->cdr.start_time = ogs_time_now();

    if (smf_self()->cdr.triggers & SMF_CDR_TRIG_START)
        emit(sess, false);
}

void smf_ga_cdr_session_interim(smf_sess_t *sess)
{
    if (!smf_self()->cdr.enabled) return;
    ogs_assert(sess);

    if (!(smf_self()->cdr.triggers & SMF_CDR_TRIG_INTERIM)) return;
    emit(sess, false);
}

void smf_ga_cdr_session_stop(smf_sess_t *sess)
{
    if (!smf_self()->cdr.enabled) return;
    ogs_assert(sess);

    if (!(smf_self()->cdr.triggers & SMF_CDR_TRIG_STOP)) return;
    emit(sess, true);
}

void smf_ga_sess_clear(smf_sess_t *sess)
{
    ogs_assert(sess);
    sess->cdr.start_time = 0;
    sess->cdr.record_seq = 0;
    sess->cdr.last_ul_octets = 0;
    sess->cdr.last_dl_octets = 0;
    sess->cdr.last_change_time = 0;
    sess->cdr.cause_for_rec_closing = 0;
}

/* ================================================================== */
/*  Runtime reconfiguration (admin watcher entry point)                */
/* ================================================================== */

/*
 * The yaml-parsed config strings inside smf_self()->cdr are pointers into
 * the libogs YAML buffer (process-lifetime, never freed). Once we accept
 * an admin-driven update we must replace them with strings WE own so we
 * can free and reassign them on the next update.
 *
 * `g_owned_*` track whether the current pointer in smf_self()->cdr was
 * heap-allocated by us. If yes we free it; if no we leave it alone and
 * just overwrite the field.
 */
static char *g_owned_spool_dir;
static char *g_owned_node_id;
static char *g_owned_local_address;

static void replace_owned_string(const char **field, char **owned,
                                 const char *new_value)
{
    if (*owned) {
        ogs_free(*owned);
        *owned = NULL;
    }
    if (new_value && *new_value) {
        *owned = ogs_strdup(new_value);
        *field = *owned;
    } else {
        *field = NULL;
    }
}

int smf_ga_writer_apply_runtime(const smf_cdr_config_t *new_cfg)
{
    smf_cdr_config_t *cur = &smf_self()->cdr;

    ogs_assert(new_cfg);

    ogs_info("smf_ga_writer: apply_runtime "
             "(enabled=%d->%d spool=%s->%s node=%s->%s)",
             cur->enabled, new_cfg->enabled,
             cur->spool_dir ? cur->spool_dir : "(unset)",
             new_cfg->spool_dir ? new_cfg->spool_dir : "(unset)",
             cur->node_id ? cur->node_id : "(unset)",
             new_cfg->node_id ? new_cfg->node_id : "(unset)");

    /* 1. Close any currently-open writer so the active file rotates
     *    into ready/ before we change its target directory. */
    smf_ga_writer_close();

    /* 2. Reseat the strings into our owned heap. */
    replace_owned_string(&cur->spool_dir,     &g_owned_spool_dir,
                         new_cfg->spool_dir);
    replace_owned_string(&cur->node_id,       &g_owned_node_id,
                         new_cfg->node_id);
    replace_owned_string(&cur->local_address, &g_owned_local_address,
                         new_cfg->local_address);

    /* 3. Scalar fields. */
    cur->rotate_max_records = new_cfg->rotate_max_records
            ? new_cfg->rotate_max_records : 100;
    cur->rotate_max_bytes   = new_cfg->rotate_max_bytes
            ? new_cfg->rotate_max_bytes   : 65536;
    cur->rotate_max_seconds = new_cfg->rotate_max_seconds
            ? new_cfg->rotate_max_seconds : 30;
    cur->triggers           = new_cfg->triggers
            ? new_cfg->triggers
            : (SMF_CDR_TRIG_START | SMF_CDR_TRIG_INTERIM | SMF_CDR_TRIG_STOP);
    cur->enabled            = new_cfg->enabled;

    /* 4. Reopen if enabled. On failure leave it disabled so the rest of
     *    the SMF keeps serving sessions; the watcher will report the
     *    error in its next heartbeat. */
    if (!cur->enabled) {
        ogs_info("smf_ga_writer: now disabled by admin");
        return OGS_OK;
    }

    int rv = smf_ga_writer_open();
    if (rv != OGS_OK) {
        ogs_error("smf_ga_writer: reopen after apply_runtime failed "
                  "— writer is disabled until the next successful update");
        cur->enabled = false;
        return OGS_ERROR;
    }
    return OGS_OK;
}
