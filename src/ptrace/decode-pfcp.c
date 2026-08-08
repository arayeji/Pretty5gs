/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Lightweight PFCP Session Establishment/Modification/Deletion extract.
 */

#include "decode.h"

static const char *pfcp_msg_name(uint8_t t)
{
    switch (t) {
    case 50: return "PFCP Session Establishment Request";
    case 51: return "PFCP Session Establishment Response";
    case 52: return "PFCP Session Modification Request";
    case 53: return "PFCP Session Modification Response";
    case 54: return "PFCP Session Deletion Request";
    case 55: return "PFCP Session Deletion Response";
    default: return NULL;
    }
}

static void walk_pfcp_ie(const uint8_t *p, int len, ptrace_event_t *evt,
        int *pdr, int *far, int *qer)
{
    while (len >= 4) {
        uint16_t type = (uint16_t)((p[0] << 8) | p[1]);
        uint16_t ielen = (uint16_t)((p[2] << 8) | p[3]);
        const uint8_t *v;
        if (ielen + 4 > len)
            break;
        v = p + 4;

        switch (type) {
        case 1: /* Cause */
            if (ielen >= 1) {
                evt->cause_code = v[0];
                snprintf(evt->cause, sizeof(evt->cause), "%u", v[0]);
            }
            break;
        case 19: /* F-SEID */
            if (ielen >= 9) {
                uint64_t seid = 0;
                int i;
                for (i = 0; i < 8; i++)
                    seid = (seid << 8) | v[1 + i];
                evt->ids.seid = seid;
                evt->ids.has_seid = true;
            }
            break;
        case 21: /* UE IP Address */
            if (ielen >= 5 && (v[0] & 0x02)) {
                snprintf(evt->ids.ue_ip, sizeof(evt->ids.ue_ip),
                        "%u.%u.%u.%u", v[1], v[2], v[3], v[4]);
            }
            break;
        case 141: /* User ID — IMSI / IMEI / MSISDN (TS 29.244) */
            if (ielen >= 2) {
                uint8_t flags = v[0];
                int off = 1;
                if ((flags & 0x01) && off < ielen) { /* IMSI */
                    int ilen = v[off++];
                    int o = 0, j;
                    if (off + ilen <= ielen) {
                        for (j = 0; j < ilen && o + 2 < (int)sizeof(evt->ids.imsi); j++) {
                            int lo = v[off + j] & 0x0f;
                            int hi = (v[off + j] >> 4) & 0x0f;
                            if (lo <= 9)
                                evt->ids.imsi[o++] = (char)('0' + lo);
                            if (hi == 0x0f)
                                break;
                            if (hi <= 9)
                                evt->ids.imsi[o++] = (char)('0' + hi);
                        }
                        evt->ids.imsi[o] = '\0';
                        off += ilen;
                    }
                }
                if ((flags & 0x02) && off < ielen) { /* IMEI */
                    int ilen = v[off++];
                    int o = 0, j;
                    if (off + ilen <= ielen) {
                        for (j = 0; j < ilen && o + 2 < (int)sizeof(evt->ids.imei); j++) {
                            int lo = v[off + j] & 0x0f;
                            int hi = (v[off + j] >> 4) & 0x0f;
                            if (lo <= 9)
                                evt->ids.imei[o++] = (char)('0' + lo);
                            if (hi == 0x0f)
                                break;
                            if (hi <= 9)
                                evt->ids.imei[o++] = (char)('0' + hi);
                        }
                        evt->ids.imei[o] = '\0';
                        off += ilen;
                    }
                }
                if ((flags & 0x04) && off < ielen) { /* MSISDN */
                    int ilen = v[off++];
                    int o = 0, j;
                    if (off + ilen <= ielen) {
                        for (j = 0; j < ilen && o + 2 < (int)sizeof(evt->ids.msisdn); j++) {
                            int lo = v[off + j] & 0x0f;
                            int hi = (v[off + j] >> 4) & 0x0f;
                            if (lo <= 9)
                                evt->ids.msisdn[o++] = (char)('0' + lo);
                            if (hi == 0x0f)
                                break;
                            if (hi <= 9)
                                evt->ids.msisdn[o++] = (char)('0' + hi);
                        }
                        evt->ids.msisdn[o] = '\0';
                    }
                }
            }
            break;
        case 56: /* Create PDR */
            (*pdr)++;
            walk_pfcp_ie(v, ielen, evt, pdr, far, qer);
            break;
        case 57: /* Create FAR */
            (*far)++;
            walk_pfcp_ie(v, ielen, evt, pdr, far, qer);
            break;
        case 58: /* Create QER */
            (*qer)++;
            break;
        default:
            if (ielen > 4)
                walk_pfcp_ie(v, ielen, evt, pdr, far, qer);
            break;
        }

        p += 4 + ielen;
        len -= 4 + ielen;
    }
}

int ptrace_decode_pfcp(const uint8_t *data, int len, ptrace_event_t *evt)
{
    uint8_t flags, type;
    int hdr;
    const char *name;
    int pdr = 0, far = 0, qer = 0;

    if (!data || len < 4 || !evt)
        return OGS_ERROR;

    flags = data[0];
    type = data[1];
    name = pfcp_msg_name(type);
    if (!name)
        return OGS_ERROR;

    hdr = (flags & 0x01) ? 16 : 4;
    if (len < hdr)
        return OGS_ERROR;

    evt->protocol = PTRACE_PROTO_PFCP;
    evt->msg_type = type;
    ogs_cpystrn(evt->message, name, sizeof(evt->message));

    if (flags & 0x01) {
        uint64_t seid = 0;
        int i;
        for (i = 0; i < 8; i++)
            seid = (seid << 8) | data[4 + i];
        evt->ids.seid = seid;
        evt->ids.has_seid = true;
    }

    walk_pfcp_ie(data + hdr, len - hdr, evt, &pdr, &far, &qer);
    snprintf(evt->fields, sizeof(evt->fields),
            "seid=%llu pdr=%d far=%d qer=%d ue_ip=%s",
            (unsigned long long)evt->ids.seid, pdr, far, qer, evt->ids.ue_ip);
    return OGS_OK;
}
