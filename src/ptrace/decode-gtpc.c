/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Lightweight GTPv2-C field extract (Create/Modify/Delete/Release).
 */

#include "decode.h"

#include <arpa/inet.h>

static const char *gtpc_msg_name(uint8_t t)
{
    switch (t) {
    case 32: return "Create Session Request";
    case 33: return "Create Session Response";
    case 34: return "Modify Bearer Request";
    case 35: return "Modify Bearer Response";
    case 36: return "Delete Session Request";
    case 37: return "Delete Session Response";
    case 170: return "Release Access Bearers Request";
    case 171: return "Release Access Bearers Response";
    default: return NULL;
    }
}

static void bcd_imsi(const uint8_t *b, int len, char *out, size_t outlen)
{
    int i, o = 0;
    for (i = 0; i < len && o + 2 < (int)outlen; i++) {
        int lo = b[i] & 0x0f;
        int hi = (b[i] >> 4) & 0x0f;
        if (lo <= 9)
            out[o++] = (char)('0' + lo);
        if (hi <= 9)
            out[o++] = (char)('0' + hi);
        else if (hi == 0x0f)
            break;
    }
    out[o] = '\0';
}

static void walk_ie(const uint8_t *p, int len, ptrace_event_t *evt)
{
    while (len >= 4) {
        uint8_t type = p[0];
        uint16_t ielen = (uint16_t)((p[1] << 8) | p[2]);
        /* uint8_t instance = p[3] & 0x0f; */
        const uint8_t *v;
        int vlen;

        if (ielen + 4 > len)
            break;
        v = p + 4;
        vlen = ielen;

        switch (type) {
        case 1: /* IMSI */
            if (vlen > 0)
                bcd_imsi(v, vlen, evt->ids.imsi, sizeof(evt->ids.imsi));
            break;
        case 2: /* Cause */
            if (vlen >= 1) {
                evt->cause_code = v[0];
                snprintf(evt->cause, sizeof(evt->cause), "%u", v[0]);
            }
            break;
        case 71: /* APN */
            if (vlen > 0 && vlen < (int)sizeof(evt->ids.apn)) {
                /* dotted labels */
                int o = 0, i = 0;
                while (i < vlen && o + 1 < (int)sizeof(evt->ids.apn)) {
                    int lab = v[i++];
                    if (lab <= 0 || i + lab > vlen)
                        break;
                    if (o)
                        evt->ids.apn[o++] = '.';
                    while (lab-- > 0 && o + 1 < (int)sizeof(evt->ids.apn))
                        evt->ids.apn[o++] = (char)v[i++];
                }
                evt->ids.apn[o] = '\0';
            }
            break;
        case 73: /* EBI */
            if (vlen >= 1) {
                evt->ids.bearer_id = v[0] & 0x0f;
                evt->ids.has_bearer_id = true;
            }
            break;
        case 79: /* PAA */
            if (vlen >= 5 && v[0] == 1) { /* IPv4 */
                snprintf(evt->ids.ue_ip, sizeof(evt->ids.ue_ip),
                        "%u.%u.%u.%u", v[1], v[2], v[3], v[4]);
            }
            break;
        case 87: /* F-TEID */
            if (vlen >= 5) {
                evt->ids.teid = (uint32_t)((v[1] << 24) | (v[2] << 16) |
                        (v[3] << 8) | v[4]);
                evt->ids.has_teid = true;
            }
            break;
        case 93: /* Bearer Context — recurse nested IEs (same TLV) */
            walk_ie(v, vlen, evt);
            break;
        default:
            break;
        }

        p += 4 + ielen;
        len -= 4 + ielen;
    }
}

int ptrace_decode_gtpc(const uint8_t *data, int len, ptrace_event_t *evt)
{
    uint8_t flags, type;
    int hdr;
    const char *name;

    if (!data || len < 8 || !evt)
        return OGS_ERROR;

    flags = data[0];
    if (((flags >> 5) & 0x07) != 2)
        return OGS_ERROR;

    type = data[1];
    name = gtpc_msg_name(type);
    if (!name)
        return OGS_ERROR; /* ignore echoes / uninteresting */

    hdr = (flags & 0x08) ? 12 : 8;
    if (len < hdr)
        return OGS_ERROR;

    evt->protocol = PTRACE_PROTO_GTPC;
    evt->msg_type = type;
    ogs_cpystrn(evt->message, name, sizeof(evt->message));

    if (flags & 0x08) {
        evt->ids.teid = (uint32_t)((data[4] << 24) | (data[5] << 16) |
                (data[6] << 8) | data[7]);
        evt->ids.has_teid = true;
    }

    walk_ie(data + hdr, len - hdr, evt);
    snprintf(evt->fields, sizeof(evt->fields),
            "teid=%u apn=%s ue_ip=%s cause=%s",
            evt->ids.has_teid ? evt->ids.teid : 0,
            evt->ids.apn, evt->ids.ue_ip, evt->cause);
    return OGS_OK;
}
