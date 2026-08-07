/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Lightweight Diameter AVP extract for S6a / Gx / Gy.
 */

#include "decode.h"

#define DIAM_AVP_USER_NAME          1
#define DIAM_AVP_RESULT_CODE        268
#define DIAM_AVP_SESSION_ID         263
#define DIAM_AVP_SUBSCRIPTION_ID    443
#define DIAM_AVP_SUBSCRIPTION_ID_DATA 444
#define DIAM_AVP_SUBSCRIPTION_ID_TYPE 450
#define DIAM_VENDOR_3GPP            10415
#define DIAM_AVP_MSISDN             701
#define DIAM_AVP_IMEI               1402

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
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
            break;
        if (flags & 0x80) { /* V vendor */
            if (avplen < 12)
                break;
            hdr = 12;
        }
        v = p + hdr;
        vlen = (int)avplen - hdr;
        padded = (int)((avplen + 3) & ~3u);

        switch (code) {
        case DIAM_AVP_USER_NAME: /* IMSI as string */
            if (vlen > 0 && vlen < (int)sizeof(evt->ids.imsi)) {
                memcpy(evt->ids.imsi, v, (size_t)vlen);
                evt->ids.imsi[vlen] = '\0';
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
            if (vlen > 0 && vlen < (int)sizeof(evt->ids.session_id)) {
                int n = vlen < (int)sizeof(evt->ids.session_id) - 1 ?
                    vlen : (int)sizeof(evt->ids.session_id) - 1;
                memcpy(evt->ids.session_id, v, (size_t)n);
                evt->ids.session_id[n] = '\0';
            }
            break;
        case DIAM_AVP_MSISDN:
            if (vlen > 0) {
                /* BCD */
                int i, o = 0;
                for (i = 0; i < vlen && o + 2 < (int)sizeof(evt->ids.msisdn); i++) {
                    int lo = v[i] & 0x0f, hi = (v[i] >> 4) & 0x0f;
                    if (lo <= 9) evt->ids.msisdn[o++] = (char)('0' + lo);
                    if (hi <= 9) evt->ids.msisdn[o++] = (char)('0' + hi);
                }
                evt->ids.msisdn[o] = '\0';
            }
            break;
        case DIAM_AVP_SUBSCRIPTION_ID:
            walk_avps(v, vlen, evt);
            break;
        case DIAM_AVP_SUBSCRIPTION_ID_DATA:
            if (vlen > 0 && vlen < (int)sizeof(evt->ids.imsi) &&
                    !evt->ids.imsi[0]) {
                memcpy(evt->ids.imsi, v, (size_t)vlen);
                evt->ids.imsi[vlen] = '\0';
            }
            break;
        default:
            if (flags & 0x40) /* M grouped possible */
                walk_avps(v, vlen, evt);
            break;
        }

        p += padded;
        len -= padded;
    }
}

int ptrace_decode_diameter(const uint8_t *data, int len, ptrace_event_t *evt)
{
    uint32_t cmd;
    uint8_t flags;

    if (!data || len < 20 || !evt)
        return OGS_ERROR;
    if (data[0] != 1) /* version */
        return OGS_ERROR;

    flags = data[4];
    cmd = ((uint32_t)(data[5] & 0xff) << 16) |
          ((uint32_t)data[6] << 8) | data[7];

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
    else
        snprintf(evt->message, sizeof(evt->message), "Diameter-%u", cmd);

    walk_avps(data + 20, len - 20, evt);
    snprintf(evt->fields, sizeof(evt->fields),
            "cmd=%u session=%s result=%s",
            cmd, evt->ids.session_id, evt->cause);
    return OGS_OK;
}
