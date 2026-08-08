/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Cleartext EPS NAS extract (lightweight — no full IE tree).
 */

#include "decode.h"
#include "context.h"
#include "correlate.h"

/* 3GPP TS 24.301 EMM message types */
#define NAS_ATTACH_REQUEST              0x41
#define NAS_ATTACH_ACCEPT               0x42
#define NAS_ATTACH_COMPLETE             0x43
#define NAS_ATTACH_REJECT               0x44
#define NAS_DETACH_REQUEST              0x45
#define NAS_DETACH_ACCEPT               0x46
#define NAS_TAU_REQUEST                 0x48
#define NAS_TAU_ACCEPT                  0x49
#define NAS_SERVICE_REQUEST             0x4c
#define NAS_AUTH_REQUEST                0x52
#define NAS_AUTH_RESPONSE               0x53
#define NAS_AUTH_REJECT                 0x54
#define NAS_IDENTITY_REQUEST            0x55
#define NAS_IDENTITY_RESPONSE           0x56
#define NAS_SECURITY_MODE_COMMAND       0x5d
#define NAS_SECURITY_MODE_COMPLETE      0x5e

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
    case NAS_IDENTITY_REQUEST: return "Identity Request";
    case NAS_IDENTITY_RESPONSE: return "Identity Response";
    case NAS_SECURITY_MODE_COMMAND: return "Security Mode Command";
    case NAS_SECURITY_MODE_COMPLETE: return "Security Mode Complete";
    case NAS_TAU_REQUEST: return "NAS TAU Request";
    case NAS_TAU_ACCEPT: return "NAS TAU Accept";
    case NAS_SERVICE_REQUEST: return "NAS Service Request";
    default: return NULL;
    }
}

/* TS 24.008 / 24.301 Mobile Identity — IMSI/IMEI digits */
static void parse_mobile_identity(const uint8_t *mi, int mi_len,
        ptrace_event_t *evt)
{
    uint8_t type_id;
    uint8_t odd;
    char digits[32];
    int o = 0;
    int i;

    if (!mi || mi_len < 1 || !evt)
        return;

    type_id = mi[0] & 0x07;
    odd = (mi[0] >> 3) & 0x01;

    /* first digit in high nibble of octet 0 */
    {
        int d1 = (mi[0] >> 4) & 0x0f;
        if (d1 <= 9)
            digits[o++] = (char)('0' + d1);
    }
    for (i = 1; i < mi_len && o + 2 < (int)sizeof(digits); i++) {
        int lo = mi[i] & 0x0f;
        int hi = (mi[i] >> 4) & 0x0f;
        if (lo <= 9)
            digits[o++] = (char)('0' + lo);
        if (i == mi_len - 1 && !odd)
            break;
        if (hi == 0x0f)
            break;
        if (hi <= 9)
            digits[o++] = (char)('0' + hi);
    }
    digits[o] = '\0';

    if (type_id == 1) { /* IMSI */
        if (!evt->ids.imsi[0] && o >= 6)
            ogs_cpystrn(evt->ids.imsi, digits, sizeof(evt->ids.imsi));
    } else if (type_id == 2 || type_id == 3) { /* IMEI / IMEISV */
        if (!evt->ids.imei[0] && o >= 14)
            ogs_cpystrn(evt->ids.imei, digits, sizeof(evt->ids.imei));
    } else if (type_id == 6 && mi_len >= 11) { /* GUTI */
        uint32_t mtmsi = (uint32_t)((mi[7] << 24) | (mi[8] << 16) |
                (mi[9] << 8) | mi[10]);
        snprintf(evt->ids.m_tmsi, sizeof(evt->ids.m_tmsi), "%08x", mtmsi);
        snprintf(evt->ids.guti, sizeof(evt->ids.guti), "guti-%08x", mtmsi);
    }
}

/* Decode cleartext (or integrity-only) EMM and pull identities. */
static int decode_plain_emm(const uint8_t *data, int len, ptrace_event_t *evt)
{
    uint8_t pd, msg_type;
    const char *name;

    if (!data || len < 2 || !evt)
        return OGS_ERROR;

    pd = data[0] & 0x0f;
    if (pd != 0x07 && pd != 0x02)
        return OGS_ERROR;

    if (pd == 0x02) {
        if (len < 3)
            return OGS_ERROR;
        msg_type = data[2];
        evt->protocol = PTRACE_PROTO_NAS;
        snprintf(evt->message, sizeof(evt->message), "NAS ESM-%u", msg_type);
        return OGS_OK;
    }

    msg_type = data[1];
    name = nas_name(msg_type);
    evt->protocol = PTRACE_PROTO_NAS;
    evt->msg_type = msg_type;
    if (name)
        ogs_cpystrn(evt->message, name, sizeof(evt->message));
    else
        snprintf(evt->message, sizeof(evt->message), "NAS EMM-%u", msg_type);

    if (msg_type == NAS_ATTACH_REQUEST && len >= 4) {
        /* PD, type, attach_type|ksi, MI-len, MI */
        int mi_len = data[3];
        if (mi_len > 0 && 4 + mi_len <= len)
            parse_mobile_identity(data + 4, mi_len, evt);
    } else if (msg_type == NAS_TAU_REQUEST && len >= 4) {
        int mi_len = data[3];
        if (mi_len > 0 && 4 + mi_len <= len)
            parse_mobile_identity(data + 4, mi_len, evt);
    } else if (msg_type == NAS_IDENTITY_RESPONSE && len >= 3) {
        int mi_len = data[2];
        if (mi_len > 0 && 3 + mi_len <= len)
            parse_mobile_identity(data + 3, mi_len, evt);
    } else if (msg_type == NAS_ATTACH_REJECT && len >= 3) {
        evt->cause_code = data[2];
        snprintf(evt->cause, sizeof(evt->cause), "%u", evt->cause_code);
    } else if (msg_type == NAS_ATTACH_ACCEPT && len >= 15) {
        int i;
        for (i = 2; i + 13 < len; i++) {
            if (data[i] == 0x50 && data[i + 1] == 11) {
                parse_mobile_identity(data + i + 2, 11, evt);
                break;
            }
        }
    } else if (msg_type == NAS_SECURITY_MODE_COMPLETE && len >= 5) {
        int i;
        for (i = 2; i + 2 < len; i++) {
            if (data[i] == 0x23 && i + 1 < len) {
                int mi_len = data[i + 1];
                if (mi_len > 0 && i + 2 + mi_len <= len)
                    parse_mobile_identity(data + i + 2, mi_len, evt);
                break;
            }
        }
    }

    snprintf(evt->fields, sizeof(evt->fields),
            "imsi=%s imei=%s guti=%s cause=%s",
            evt->ids.imsi, evt->ids.imei, evt->ids.guti, evt->cause);
    return OGS_OK;
}

int ptrace_decode_nas(const uint8_t *data, int len, ptrace_event_t *evt)
{
    uint8_t sec;
    int off = 0;

    if (!data || len < 2 || !evt)
        return OGS_ERROR;

    sec = (data[0] >> 4) & 0x0f;

    if (sec == 1 || sec == 2 || sec == 3 || sec == 4) {
        if (len < 7)
            return OGS_ERROR;
        if (sec == 2 || sec == 4) {
            evt->protocol = PTRACE_PROTO_NAS;
            ogs_cpystrn(evt->message, "NAS (ciphered)", sizeof(evt->message));
            snprintf(evt->fields, sizeof(evt->fields), "sec_hdr=%u", sec);
            return OGS_OK;
        }
        /* integrity-protected, not ciphered: PD/sec + MAC(4) + seq(1) */
        off = 6;
        if (off >= len)
            return OGS_ERROR;
        return decode_plain_emm(data + off, len - off, evt);
    }

    return decode_plain_emm(data, len, evt);
}

/*
 * Last-resort: find cleartext Attach Request / Identity Response inside a
 * blob (S1AP PER or truncated SCTP) and extract IMSI/GUTI.
 */
int ptrace_decode_nas_scan(const uint8_t *data, int len, ptrace_event_t *evt)
{
    int i;

    if (!data || len < 6 || !evt)
        return OGS_ERROR;

    for (i = 0; i + 5 < len; i++) {
        const uint8_t *p = data + i;
        int remain = len - i;
        uint8_t b0 = p[0];
        uint8_t sec = (b0 >> 4) & 0x0f;
        uint8_t pd = b0 & 0x0f;

        /* Plain EMM Attach / Identity / TAU / Auth / SMC (pre-cipher) */
        if (pd == 0x07 && (p[1] == NAS_ATTACH_REQUEST ||
                p[1] == NAS_IDENTITY_RESPONSE ||
                p[1] == NAS_TAU_REQUEST ||
                p[1] == NAS_AUTH_REQUEST ||
                p[1] == NAS_AUTH_RESPONSE ||
                p[1] == NAS_SECURITY_MODE_COMMAND ||
                p[1] == NAS_SECURITY_MODE_COMPLETE ||
                p[1] == NAS_ATTACH_ACCEPT ||
                p[1] == NAS_ATTACH_COMPLETE ||
                p[1] == NAS_ATTACH_REJECT ||
                p[1] == NAS_DETACH_REQUEST)) {
            if (decode_plain_emm(p, remain, evt) == OGS_OK &&
                    (evt->ids.imsi[0] || evt->ids.guti[0] || evt->ids.imei[0] ||
                     evt->ids.m_tmsi[0]))
                return OGS_OK;
        }

        /* Integrity-protected (not ciphered): 0x17/0x37 … then plain EMM */
        if ((sec == 1 || sec == 3) && pd == 0x07 && remain >= 8) {
            const uint8_t *plain = p + 6;
            int plen = remain - 6;
            if (plen >= 2 && (plain[0] & 0x0f) == 0x07 &&
                    (plain[1] == NAS_ATTACH_REQUEST ||
                     plain[1] == NAS_IDENTITY_RESPONSE ||
                     plain[1] == NAS_TAU_REQUEST ||
                     plain[1] == NAS_AUTH_REQUEST ||
                     plain[1] == NAS_AUTH_RESPONSE ||
                     plain[1] == NAS_SECURITY_MODE_COMMAND ||
                     plain[1] == NAS_SECURITY_MODE_COMPLETE ||
                     plain[1] == NAS_ATTACH_ACCEPT ||
                     plain[1] == NAS_ATTACH_COMPLETE ||
                     plain[1] == NAS_ATTACH_REJECT ||
                     plain[1] == NAS_DETACH_REQUEST)) {
                if (decode_plain_emm(plain, plen, evt) == OGS_OK &&
                        (evt->ids.imsi[0] || evt->ids.guti[0] ||
                         evt->ids.imei[0] || evt->ids.m_tmsi[0]))
                    return OGS_OK;
            }
        }
    }
    return OGS_ERROR;
}

bool ptrace_bytes_look_like_identity(const uint8_t *data, uint16_t len)
{
    int i;
    if (!data || len < 6)
        return false;
    for (i = 0; i + 1 < (int)len; i++) {
        if (data[i] == 0x07 && (data[i + 1] == NAS_ATTACH_REQUEST ||
                data[i + 1] == NAS_IDENTITY_RESPONSE))
            return true;
        if ((data[i] == 0x17 || data[i] == 0x37) && i + 7 < (int)len &&
                data[i + 6] == 0x07 &&
                (data[i + 7] == NAS_ATTACH_REQUEST ||
                 data[i + 7] == NAS_IDENTITY_RESPONSE))
            return true;
    }
    return false;
}

void ptrace_index_identity_inline(const uint8_t *data, uint16_t len,
        ogs_time_t ts, ptrace_role_e role)
{
    ptrace_event_t evt;
    ptrace_context_t *ctx = ptrace_self();

    if (!data || len < 6)
        return;

    memset(&evt, 0, sizeof(evt));
    evt.ts = ts ? ts : ogs_time_now();
    evt.role = role;
    evt.protocol = PTRACE_PROTO_NAS;
    if (ptrace_decode_nas_scan(data, (int)len, &evt) != OGS_OK)
        return;
    if (!evt.ids.imsi[0] && !evt.ids.guti[0])
        return;
    if (!evt.message[0])
        ogs_cpystrn(evt.message, "NAS (inline)", sizeof(evt.message));
    ptrace_correlate_event(&evt);
    if (ctx)
        ctx->identity_inline++;
}
