/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Cleartext EPS NAS extract (lightweight — no full IE tree).
 */

#include "decode.h"

/* 3GPP TS 24.301 EMM message types */
#define NAS_ATTACH_REQUEST              0x41
#define NAS_ATTACH_ACCEPT               0x42
#define NAS_ATTACH_COMPLETE             0x43
#define NAS_ATTACH_REJECT               0x44
#define NAS_DETACH_REQUEST              0x45
#define NAS_DETACH_ACCEPT               0x46
#define NAS_AUTH_REQUEST                0x52
#define NAS_AUTH_RESPONSE               0x53
#define NAS_AUTH_REJECT                 0x54
#define NAS_SECURITY_MODE_COMMAND       0x5d
#define NAS_SECURITY_MODE_COMPLETE      0x5e
#define NAS_TAU_REQUEST                 0x48
#define NAS_TAU_ACCEPT                  0x49
#define NAS_SERVICE_REQUEST             0x4c

static const char *nas_name(uint8_t t)
{
    switch (t) {
    case NAS_ATTACH_REQUEST: return "NAS Attach Request";
    case NAS_ATTACH_ACCEPT: return "NAS Attach Accept";
    case NAS_ATTACH_COMPLETE: return "NAS Attach Complete";
    case NAS_ATTACH_REJECT: return "NAS Attach Reject";
    case NAS_DETACH_REQUEST: return "NAS Detach Request";
    case NAS_DETACH_ACCEPT: return "NAS Detach Accept";
    case NAS_AUTH_REQUEST: return "Authentication Request";
    case NAS_AUTH_RESPONSE: return "Authentication Response";
    case NAS_AUTH_REJECT: return "Authentication Reject";
    case NAS_SECURITY_MODE_COMMAND: return "Security Mode Command";
    case NAS_SECURITY_MODE_COMPLETE: return "Security Mode Complete";
    case NAS_TAU_REQUEST: return "NAS TAU Request";
    case NAS_TAU_ACCEPT: return "NAS TAU Accept";
    case NAS_SERVICE_REQUEST: return "NAS Service Request";
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
        if (hi == 0x0f)
            break;
        if (hi <= 9)
            out[o++] = (char)('0' + hi);
    }
    out[o] = '\0';
}

int ptrace_decode_nas(const uint8_t *data, int len, ptrace_event_t *evt)
{
    uint8_t pd, sec, msg_type;
    const char *name;
    int off = 0;

    if (!data || len < 2 || !evt)
        return OGS_ERROR;

    pd = data[0] & 0x0f;
    sec = (data[0] >> 4) & 0x0f;

    /* Security protected: skip MAC + seq, then plain NAS */
    if (sec == 1 || sec == 2 || sec == 3 || sec == 4) {
        if (len < 7)
            return OGS_ERROR;
        if (sec == 2 || sec == 4) {
            /* ciphered — cannot decode payload */
            evt->protocol = PTRACE_PROTO_NAS;
            ogs_cpystrn(evt->message, "NAS (ciphered)", sizeof(evt->message));
            snprintf(evt->fields, sizeof(evt->fields), "sec_hdr=%u", sec);
            return OGS_OK;
        }
        off = 6; /* header + MAC(4) + seq(1) approx for integrity-only */
        if (off >= len)
            return OGS_ERROR;
        data += off;
        len -= off;
        pd = data[0] & 0x0f;
    }

    if (pd != 0x07 && pd != 0x02) /* EMM / ESM */
        return OGS_ERROR;

    if (pd == 0x07) {
        if (len < 2)
            return OGS_ERROR;
        msg_type = data[1];
    } else {
        /* ESM: skip EPS bearer id / PTI */
        if (len < 3)
            return OGS_ERROR;
        msg_type = data[2];
        evt->protocol = PTRACE_PROTO_NAS;
        snprintf(evt->message, sizeof(evt->message), "NAS ESM-%u", msg_type);
        return OGS_OK;
    }

    name = nas_name(msg_type);
    if (!name) {
        evt->protocol = PTRACE_PROTO_NAS;
        snprintf(evt->message, sizeof(evt->message), "NAS EMM-%u", msg_type);
        evt->msg_type = msg_type;
        return OGS_OK;
    }

    evt->protocol = PTRACE_PROTO_NAS;
    evt->msg_type = msg_type;
    ogs_cpystrn(evt->message, name, sizeof(evt->message));

    /* Attach Request: EPS mobile identity after attach type / KSI */
    if (msg_type == NAS_ATTACH_REQUEST && len >= 6) {
        int mi_len = data[4]; /* after 2 hdr + 1 attach/ksi + 1 spare? */
        /* Layout: PD|sec, msg_type, EPS attach type/NAS KSI, MI length */
        mi_len = data[3];
        if (mi_len > 0 && 4 + mi_len <= len) {
            const uint8_t *mi = data + 4;
            uint8_t type_id = mi[0] & 0x07;
            if (type_id == 1 && mi_len >= 2) { /* IMSI */
                bcd_imsi(mi, mi_len, evt->ids.imsi, sizeof(evt->ids.imsi));
                /* first digit is in high nibble of byte0 with type */
                /* Standard: byte0 = dig1 | (type<<4) in different packing —
                 * use full MI buffer as TBCD starting at byte0 */
            } else if (type_id == 6 && mi_len >= 11) { /* GUTI */
                uint32_t mtmsi = (uint32_t)((mi[7] << 24) | (mi[8] << 16) |
                        (mi[9] << 8) | mi[10]);
                snprintf(evt->ids.m_tmsi, sizeof(evt->ids.m_tmsi),
                        "%08x", mtmsi);
                snprintf(evt->ids.guti, sizeof(evt->ids.guti),
                        "guti-%08x", mtmsi);
            }
        }
    } else if (msg_type == NAS_ATTACH_REJECT && len >= 3) {
        evt->cause_code = data[2];
        snprintf(evt->cause, sizeof(evt->cause), "%u", evt->cause_code);
    } else if (msg_type == NAS_ATTACH_ACCEPT && len >= 15) {
        /* GUTI often present as IEI 0x50 */
        int i;
        for (i = 2; i + 13 < len; i++) {
            if (data[i] == 0x50 && data[i + 1] == 11) {
                const uint8_t *mi = data + i + 2;
                uint32_t mtmsi = (uint32_t)((mi[7] << 24) | (mi[8] << 16) |
                        (mi[9] << 8) | mi[10]);
                snprintf(evt->ids.m_tmsi, sizeof(evt->ids.m_tmsi),
                        "%08x", mtmsi);
                snprintf(evt->ids.guti, sizeof(evt->ids.guti),
                        "guti-%08x", mtmsi);
                break;
            }
        }
    }

    snprintf(evt->fields, sizeof(evt->fields),
            "imsi=%s guti=%s cause=%s",
            evt->ids.imsi, evt->ids.guti, evt->cause);
    return OGS_OK;
}
