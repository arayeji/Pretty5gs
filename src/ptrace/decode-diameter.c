/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Lightweight Diameter AVP extract for S6a / Gx / Gy.
 */

#include "decode.h"

/* RFC 6733 + 3GPP TS 29.272 */
#define DIAM_AVP_USER_NAME              1
#define DIAM_AVP_SESSION_ID             263
#define DIAM_AVP_VENDOR_SPECIFIC_APP_ID 260
#define DIAM_AVP_RESULT_CODE            268
#define DIAM_AVP_SUBSCRIPTION_ID        443
#define DIAM_AVP_SUBSCRIPTION_ID_DATA   444
#define DIAM_AVP_MSISDN                 701
#define DIAM_AVP_SUBSCRIPTION_DATA      1400
#define DIAM_AVP_TERMINAL_INFORMATION   1401
#define DIAM_AVP_IMEI                   1402

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void copy_digits(const uint8_t *v, int vlen, char *out, size_t outlen)
{
    int i, o = 0;
    if (!v || vlen <= 0 || !out || !outlen)
        return;
    for (i = 0; i < vlen && o + 1 < (int)outlen; i++) {
        char c = (char)v[i];
        if (c >= '0' && c <= '9')
            out[o++] = c;
    }
    out[o] = '\0';
}

static void tbcd_to_str(const uint8_t *b, int len, char *out, size_t outlen)
{
    int i, o = 0;
    for (i = 0; i < len && o + 2 < (int)outlen; i++) {
        int lo = b[i] & 0x0f;
        int hi = (b[i] >> 4) & 0x0f;
        if (lo <= 9)
            out[o++] = (char)('0' + lo);
        if (hi == 0x0f)
            break;
        if (hi <= 9)
            out[o++] = (char)('0' + hi);
    }
    out[o] = '\0';
}

static void walk_avps(const uint8_t *p, int len, ptrace_event_t *evt);

static void maybe_recurse(uint32_t code, uint8_t flags,
        const uint8_t *v, int vlen, ptrace_event_t *evt)
{
    switch (code) {
    case DIAM_AVP_VENDOR_SPECIFIC_APP_ID:
    case DIAM_AVP_SUBSCRIPTION_ID:
    case DIAM_AVP_SUBSCRIPTION_DATA:
    case DIAM_AVP_TERMINAL_INFORMATION:
        walk_avps(v, vlen, evt);
        return;
    default:
        /* Grouped AVPs are often marked M; vendor bit alone is not enough. */
        if ((flags & 0x40) && vlen >= 8)
            walk_avps(v, vlen, evt);
        return;
    }
}

static void walk_avps(const uint8_t *p, int len, ptrace_event_t *evt)
{
    while (len >= 8) {
        uint32_t code = rd32(p);
        uint8_t flags = p[4];
        uint32_t avplen = ((uint32_t)(p[5] & 0xff) << 16) |
                ((uint32_t)p[6] << 8) | p[7];
        int hdr = 8;
        const uint8_t *v;
        int vlen;
        int padded;

        if (avplen < 8 || (int)avplen > len)
            break; /* truncated TCP segment */

        if (flags & 0x80) {
            if (avplen < 12)
                break;
            hdr = 12;
        }
        v = p + hdr;
        vlen = (int)avplen - hdr;
        if (vlen < 0)
            break;
        padded = (int)((avplen + 3) & ~3u);
        if (padded > len)
            break;

        switch (code) {
        case DIAM_AVP_USER_NAME:
            if (vlen > 0 && !evt->ids.imsi[0]) {
                copy_digits(v, vlen, evt->ids.imsi, sizeof(evt->ids.imsi));
                if (!evt->ids.imsi[0]) {
                    int n = vlen < (int)sizeof(evt->ids.imsi) - 1 ?
                        vlen : (int)sizeof(evt->ids.imsi) - 1;
                    memcpy(evt->ids.imsi, v, (size_t)n);
                    evt->ids.imsi[n] = '\0';
                }
            }
            break;
        case DIAM_AVP_RESULT_CODE:
            if (vlen >= 4) {
                evt->cause_code = rd32(v);
                snprintf(evt->cause, sizeof(evt->cause), "%u",
                        evt->cause_code);
            }
            break;
        case DIAM_AVP_SESSION_ID:
            if (vlen > 0) {
                int n = vlen < (int)sizeof(evt->ids.session_id) - 1 ?
                    vlen : (int)sizeof(evt->ids.session_id) - 1;
                memcpy(evt->ids.session_id, v, (size_t)n);
                evt->ids.session_id[n] = '\0';
            }
            break;
        case DIAM_AVP_MSISDN:
            if (vlen > 0 && !evt->ids.msisdn[0])
                tbcd_to_str(v, vlen, evt->ids.msisdn, sizeof(evt->ids.msisdn));
            break;
        case DIAM_AVP_IMEI:
            if (vlen > 0 && !evt->ids.imei[0]) {
                copy_digits(v, vlen, evt->ids.imei, sizeof(evt->ids.imei));
                if (!evt->ids.imei[0])
                    tbcd_to_str(v, vlen, evt->ids.imei, sizeof(evt->ids.imei));
            }
            break;
        case DIAM_AVP_SUBSCRIPTION_ID_DATA:
            if (vlen > 0 && !evt->ids.imsi[0])
                copy_digits(v, vlen, evt->ids.imsi, sizeof(evt->ids.imsi));
            break;
        default:
            maybe_recurse(code, flags, v, vlen, evt);
            break;
        }

        /* Always recurse known identity containers */
        if (code == DIAM_AVP_SUBSCRIPTION_ID ||
                code == DIAM_AVP_SUBSCRIPTION_DATA ||
                code == DIAM_AVP_TERMINAL_INFORMATION ||
                code == DIAM_AVP_VENDOR_SPECIFIC_APP_ID)
            walk_avps(v, vlen, evt);

        p += padded;
        len -= padded;
    }
}

int ptrace_decode_diameter(const uint8_t *data, int len, ptrace_event_t *evt)
{
    uint32_t cmd;
    uint32_t msg_len;
    uint8_t flags;
    int walk_len;

    if (!data || len < 20 || !evt)
        return OGS_ERROR;
    if (data[0] != 1)
        return OGS_ERROR;

    msg_len = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    if (msg_len < 20)
        return OGS_ERROR;
    walk_len = len;
    if ((int)msg_len < walk_len)
        walk_len = (int)msg_len;

    flags = data[4];
    cmd = ((uint32_t)(data[5] & 0xff) << 16) |
          ((uint32_t)data[6] << 8) | data[7];

    /* Hop-by-Hop Identifier (correlates request/answer when Session-Id
     * is missing from a truncated TCP segment). */
    evt->ids.diam_hbh = rd32(data + 12);
    evt->ids.has_diam_hbh = true;

    evt->protocol = PTRACE_PROTO_DIAMETER;
    evt->msg_type = (uint8_t)(cmd & 0xff);
    if (cmd == 316)
        ogs_cpystrn(evt->message,
                (flags & 0x80) ? "ULR" : "ULA", sizeof(evt->message));
    else if (cmd == 318)
        ogs_cpystrn(evt->message,
                (flags & 0x80) ? "AIR" : "AIA", sizeof(evt->message));
    else if (cmd == 272)
        ogs_cpystrn(evt->message,
                (flags & 0x80) ? "CCR" : "CCA", sizeof(evt->message));
    else if (cmd == 319)
        ogs_cpystrn(evt->message,
                (flags & 0x80) ? "CLR" : "CLA", sizeof(evt->message));
    else if (cmd == 321)
        ogs_cpystrn(evt->message,
                (flags & 0x80) ? "IDR" : "IDA", sizeof(evt->message));
    else
        snprintf(evt->message, sizeof(evt->message), "Diameter-%u", cmd);

    walk_avps(data + 20, walk_len - 20, evt);
    snprintf(evt->fields, sizeof(evt->fields),
            "cmd=%u imsi=%s msisdn=%s imei=%s session=%s result=%s",
            cmd, evt->ids.imsi, evt->ids.msisdn, evt->ids.imei,
            evt->ids.session_id, evt->cause);
    return OGS_OK;
}
