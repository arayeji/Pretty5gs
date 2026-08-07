/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Lightweight S1AP PER/BER field scan for UE IDs + NAS-PDU.
 * Uses procedureCode from initiating message; extracts known IE ids.
 */

#include "decode.h"
#include "context.h"

/* S1AP Procedure codes (subset) */
#define S1AP_PROC_INITIAL_UE            12
#define S1AP_PROC_DL_NAS_TRANSPORT      11
#define S1AP_PROC_UL_NAS_TRANSPORT      13
#define S1AP_PROC_INITIAL_CONTEXT_SETUP 9
#define S1AP_PROC_UE_CONTEXT_RELEASE    23

/* IE ids */
#define S1AP_IE_MME_UE_S1AP_ID          0
#define S1AP_IE_ENB_UE_S1AP_ID          8
#define S1AP_IE_NAS_PDU                 26
#define S1AP_IE_TAI                     67
#define S1AP_IE_EUTRAN_CGI              100

static const char *s1ap_proc_name(uint32_t code)
{
    switch (code) {
    case S1AP_PROC_INITIAL_UE: return "Initial UE Message";
    case S1AP_PROC_DL_NAS_TRANSPORT: return "Downlink NAS Transport";
    case S1AP_PROC_UL_NAS_TRANSPORT: return "Uplink NAS Transport";
    case S1AP_PROC_INITIAL_CONTEXT_SETUP: return "Initial Context Setup";
    case S1AP_PROC_UE_CONTEXT_RELEASE: return "UE Context Release";
    default: return NULL;
    }
}

/* Very small ASN.1 BER helper: find SEQUENCE contents after tag */
static int ber_len(const uint8_t *p, int len, int *hdr, int *vlen)
{
    if (len < 2)
        return OGS_ERROR;
    if (!(p[1] & 0x80)) {
        *hdr = 2;
        *vlen = p[1];
        return (*hdr + *vlen <= len) ? OGS_OK : OGS_ERROR;
    }
    {
        int n = p[1] & 0x7f;
        int i;
        uint32_t L = 0;
        if (n == 0 || n > 3 || len < 2 + n)
            return OGS_ERROR;
        for (i = 0; i < n; i++)
            L = (L << 8) | p[2 + i];
        *hdr = 2 + n;
        *vlen = (int)L;
        return (*hdr + *vlen <= len) ? OGS_OK : OGS_ERROR;
    }
}

static void scan_ies(const uint8_t *p, int len, ptrace_event_t *evt,
        const uint8_t **nas, int *nas_len)
{
    /* Heuristic scan for known IE id patterns in PER-aligned S1AP is hard.
     * Instead scan for plaintext markers: many stacks emit IE id as 2-byte
     * big-endian near value. We look for criticality+id patterns commonly
     * seen after Open5GS encode. Fallback: extract from decoded-like layout.
     *
     * Practical approach used here: byte-scan for IE ID followed by length
     * for the few IEs we care about (aligned with APER open type dumps).
     */
    int i;
    for (i = 0; i + 6 < len; i++) {
        uint16_t ieid = (uint16_t)((p[i] << 8) | p[i + 1]);
        /* Prefer single-byte id encoding used in APER (id < 256) */
        uint8_t id8 = p[i];
        if (id8 == S1AP_IE_ENB_UE_S1AP_ID && p[i + 1] <= 2) {
            /* speculative */
        }
        (void)ieid;
    }

    /* Alternative: after S1AP header, Open5GS PER starts with procedureCode.
     * We already set procedure from first bytes. For IDs, use permissive
     * scan of 24-bit / 32-bit values near NAS-PDU OCTET STRING. */
    for (i = 0; i + 8 < len; i++) {
        /* Look for plausible NAS PDU: EMM PD 0x07 at start of OCTET STRING */
        if ((p[i] & 0x0f) == 0x07 && (p[i] >> 4) <= 4) {
            uint8_t mt = (i + 1 < len) ? p[i + 1] : 0;
            if (mt == 0x41 || mt == 0x42 || mt == 0x52 || mt == 0x53 ||
                    mt == 0x5d || mt == 0x48 || mt == 0x4c || mt == 0x45) {
                *nas = &p[i];
                *nas_len = len - i;
                /* Prefer shorter plausible NAS (cap 256) */
                if (*nas_len > 256)
                    *nas_len = 256;
                break;
            }
        }
    }

    /* eNB/MME UE S1AP ID: scan for 4-byte values after procedure — best effort
     * using first two uint32 after header for InitialUEMessage-like layouts. */
    if (len > 20) {
        /* Leave unset unless we find stronger signal; NAS correlation fills IDs */
        (void)evt;
    }
}

int ptrace_decode_s1ap(const uint8_t *data, int len,
        ptrace_event_t *base, ptrace_event_t **extra, int *nextra)
{
    uint32_t proc = 0;
    const char *name;
    const uint8_t *nas = NULL;
    int nas_len = 0;
    int hdr = 0, vlen = 0;

    if (!data || len < 2 || !base || !extra || !nextra)
        return OGS_ERROR;
    *nextra = 0;

    /* S1AP initiatingMessage CHOICE often starts with 0x00 / 0x20 / 0x40 */
    if (ber_len(data, len, &hdr, &vlen) == OGS_OK &&
            (data[0] == 0x00 || data[0] == 0x20 || data[0] == 0x40)) {
        const uint8_t *q = data + hdr;
        int qlen = vlen;
        /* procedureCode INTEGER typically next */
        if (qlen >= 3 && q[0] == 0x02) {
            int h2, l2;
            if (ber_len(q, qlen, &h2, &l2) == OGS_OK && l2 >= 1 && l2 <= 3) {
                int i;
                for (i = 0; i < l2; i++)
                    proc = (proc << 8) | q[h2 + i];
            }
        }
    } else {
        /* APER: first byte often contains procedure choice bits.
         * Use low 8 bits as procedure code heuristic. */
        proc = data[0] & 0x1f;
        if (len > 1 && proc == 0)
            proc = data[1];
    }

    name = s1ap_proc_name(proc);
    base->protocol = PTRACE_PROTO_S1AP;
    base->msg_type = (uint8_t)proc;
    if (name)
        ogs_cpystrn(base->message, name, sizeof(base->message));
    else
        snprintf(base->message, sizeof(base->message), "S1AP-proc-%u", proc);

    scan_ies(data, len, base, &nas, &nas_len);

    /* Extract eNB/MME IDs with a second pass: look for IE id bytes 0x00/0x08
     * followed by INTEGER length 1..4 in BER open types. */
    {
        int i;
        for (i = 0; i + 6 < len; i++) {
            if (data[i] == 0x02 && data[i + 1] >= 1 && data[i + 1] <= 4) {
                int L = data[i + 1];
                uint32_t v = 0;
                int j;
                if (i + 2 + L > len)
                    continue;
                for (j = 0; j < L; j++)
                    v = (v << 8) | data[i + 2 + j];
                /* Classify by magnitude / preceding IE id byte */
                if (i >= 1 && data[i - 1] == S1AP_IE_ENB_UE_S1AP_ID) {
                    base->ids.enb_ue_s1ap_id = v;
                    base->ids.has_enb_ue_s1ap_id = true;
                } else if (i >= 1 && data[i - 1] == S1AP_IE_MME_UE_S1AP_ID) {
                    base->ids.mme_ue_s1ap_id = v;
                    base->ids.has_mme_ue_s1ap_id = true;
                }
            }
            if (data[i] == S1AP_IE_TAI && i + 6 < len) {
                base->ids.tac = (uint16_t)((data[i + 4] << 8) | data[i + 5]);
                base->ids.has_tac = true;
            }
        }
    }

    snprintf(base->fields, sizeof(base->fields),
            "enb_ue=%u mme_ue=%u tac=%u",
            base->ids.has_enb_ue_s1ap_id ? base->ids.enb_ue_s1ap_id : 0,
            base->ids.has_mme_ue_s1ap_id ? base->ids.mme_ue_s1ap_id : 0,
            base->ids.has_tac ? base->ids.tac : 0);

    if (nas && nas_len > 0 && *nextra < PTRACE_MAX_EVENTS_PER_PKT) {
        ptrace_event_t *ne = ptrace_event_alloc();
        if (ne) {
            ne->ts = base->ts;
            ne->role = base->role;
            ogs_cpystrn(ne->src_ip, base->src_ip, sizeof(ne->src_ip));
            ogs_cpystrn(ne->dst_ip, base->dst_ip, sizeof(ne->dst_ip));
            ne->src_port = base->src_port;
            ne->dst_port = base->dst_port;
            ogs_cpystrn(ne->packet_ref, base->packet_ref,
                    sizeof(ne->packet_ref));
            ne->ids = base->ids;
            if (ptrace_decode_nas(nas, nas_len, ne) == OGS_OK)
                extra[(*nextra)++] = ne;
            else
                ptrace_event_free(ne);
        }
    }

    return OGS_OK;
}
