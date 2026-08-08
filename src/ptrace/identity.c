/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Capture hot-path identity extract for active targets.
 * S1AP: NAS scan + ASN (when IMSI hit or learned eNB/MME S1AP IDs present).
 */

#include "identity.h"
#include "decode.h"
#include "target.h"
#include "context.h"

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#define PTRACE_PORT_GTPC        2123
#define PTRACE_PORT_PFCP        8805
#define PTRACE_PORT_DIAMETER    3868
#define PTRACE_PORT_SCTP_S1AP   36412

static void ipv4_str(uint32_t be, char *buf, size_t buflen)
{
    struct in_addr a;
    a.s_addr = be;
    inet_ntop(AF_INET, &a, buf, (socklen_t)buflen);
}

static void ipv6_str(const uint8_t *addr, char *buf, size_t buflen)
{
    inet_ntop(AF_INET6, addr, buf, (socklen_t)buflen);
}

static void fill_base(ptrace_event_t *evt, ogs_time_t ts, ptrace_role_e role,
        const char *src, const char *dst, uint16_t sport, uint16_t dport,
        uint16_t raw_len, const char *packet_ref)
{
    memset(evt, 0, sizeof(*evt));
    evt->ts = ts ? ts : ogs_time_now();
    evt->role = role;
    if (src)
        ogs_cpystrn(evt->src_ip, src, sizeof(evt->src_ip));
    if (dst)
        ogs_cpystrn(evt->dst_ip, dst, sizeof(evt->dst_ip));
    evt->src_port = sport;
    evt->dst_port = dport;
    evt->raw_len = raw_len;
    if (packet_ref && packet_ref[0])
        ogs_cpystrn(evt->packet_ref, packet_ref, sizeof(evt->packet_ref));
}

static void copy_to_id(const ptrace_event_t *evt, ptrace_id_event_t *out)
{
    memset(out, 0, sizeof(*out));
    out->ts = evt->ts;
    out->protocol = evt->protocol;
    out->role = evt->role;
    ogs_cpystrn(out->message, evt->message, sizeof(out->message));
    ogs_cpystrn(out->src_ip, evt->src_ip, sizeof(out->src_ip));
    ogs_cpystrn(out->dst_ip, evt->dst_ip, sizeof(out->dst_ip));
    out->src_port = evt->src_port;
    out->dst_port = evt->dst_port;
    out->ids = evt->ids;
    ogs_cpystrn(out->packet_ref, evt->packet_ref, sizeof(out->packet_ref));
    out->raw_len = evt->raw_len;
}

static void merge_ids(ptrace_ids_t *dst, const ptrace_ids_t *src)
{
    int i;
    if (!dst || !src)
        return;
    if (src->imsi[0] && !dst->imsi[0])
        ogs_cpystrn(dst->imsi, src->imsi, sizeof(dst->imsi));
    if (src->msisdn[0] && !dst->msisdn[0])
        ogs_cpystrn(dst->msisdn, src->msisdn, sizeof(dst->msisdn));
    if (src->imei[0] && !dst->imei[0])
        ogs_cpystrn(dst->imei, src->imei, sizeof(dst->imei));
    if (src->guti[0])
        ogs_cpystrn(dst->guti, src->guti, sizeof(dst->guti));
    if (src->m_tmsi[0])
        ogs_cpystrn(dst->m_tmsi, src->m_tmsi, sizeof(dst->m_tmsi));
    if (src->ue_ip[0] && !dst->ue_ip[0])
        ogs_cpystrn(dst->ue_ip, src->ue_ip, sizeof(dst->ue_ip));
    if (src->has_enb_ue_s1ap_id) {
        dst->enb_ue_s1ap_id = src->enb_ue_s1ap_id;
        dst->has_enb_ue_s1ap_id = true;
    }
    if (src->has_mme_ue_s1ap_id) {
        dst->mme_ue_s1ap_id = src->mme_ue_s1ap_id;
        dst->has_mme_ue_s1ap_id = true;
    }
    if (src->has_teid)
        ptrace_ids_add_teid(dst, src->teid);
    for (i = 0; i < src->num_teids; i++)
        ptrace_ids_add_teid(dst, src->teids[i]);
    if (src->has_seid) {
        dst->seid = src->seid;
        dst->has_seid = true;
    }
}

static bool memmem_u24(const uint8_t *hay, int haylen, uint32_t id)
{
    uint8_t needle[3];
    int i;
    if (!id || haylen < 3)
        return false;
    needle[0] = (uint8_t)((id >> 16) & 0xff);
    needle[1] = (uint8_t)((id >> 8) & 0xff);
    needle[2] = (uint8_t)(id & 0xff);
    for (i = 0; i + 2 < haylen; i++) {
        if (hay[i] == needle[0] && hay[i + 1] == needle[1] &&
                hay[i + 2] == needle[2])
            return true;
    }
    return false;
}

static bool memmem_u32(const uint8_t *hay, int haylen, uint32_t id)
{
    uint8_t needle[4];
    int i;
    if (!id || haylen < 4)
        return false;
    needle[0] = (uint8_t)((id >> 24) & 0xff);
    needle[1] = (uint8_t)((id >> 16) & 0xff);
    needle[2] = (uint8_t)((id >> 8) & 0xff);
    needle[3] = (uint8_t)(id & 0xff);
    for (i = 0; i + 3 < haylen; i++) {
        if (hay[i] == needle[0] && hay[i + 1] == needle[1] &&
                hay[i + 2] == needle[2] && hay[i + 3] == needle[3])
            return true;
    }
    return false;
}

static bool s1ap_keys_in_payload(const uint8_t *l4, int l4len)
{
    uint32_t enb[64], mme[64];
    int n, i, nenb = 0, nmme = 0;

    n = ptrace_target_s1ap_keys(enb, 64, mme, 64);
    if (n <= 0)
        return false;
    for (i = 0; i < 64; i++) {
        if (enb[i])
            nenb++;
        else
            break;
    }
    for (i = 0; i < 64; i++) {
        if (mme[i])
            nmme++;
        else
            break;
    }
    for (i = 0; i < nenb; i++) {
        if (memmem_u24(l4, l4len, enb[i]))
            return true;
        if (memmem_u32(l4, l4len, enb[i]))
            return true;
    }
    for (i = 0; i < nmme; i++) {
        if (memmem_u32(l4, l4len, mme[i]))
            return true;
    }
    return false;
}

static int sctp_next_s1ap(const uint8_t *data, int len, int *state,
        const uint8_t **payload, int *plen)
{
    const uint8_t *p;
    int remain, off, step;

    if (!data || len < 16 || !state || !payload || !plen)
        return OGS_ERROR;
    off = *state > 12 ? *state : 12;
    p = data + off;
    remain = len - off;

    while (remain >= 4) {
        uint8_t type = p[0];
        uint8_t flags = p[1];
        uint16_t chunk_len = (uint16_t)((p[2] << 8) | p[3]);
        uint32_t ppid, ppid_le;

        if (chunk_len < 4 || chunk_len > remain)
            break;
        if (type == 0 && chunk_len >= 16) {
            ppid = ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                    ((uint32_t)p[14] << 8) | p[15];
            ppid_le = (uint32_t)p[12] | ((uint32_t)p[13] << 8) |
                    ((uint32_t)p[14] << 16) | ((uint32_t)p[15] << 24);
            if ((ppid == 18 || ppid_le == 18) && (flags & 0x03) == 0x03) {
                *payload = p + 16;
                *plen = chunk_len - 16;
                step = chunk_len + ((4 - (chunk_len & 3)) & 3);
                *state = (step <= 0 || step > remain) ? len :
                        (int)(p - data) + step;
                if (*plen > 0)
                    return OGS_OK;
            }
        }
        step = chunk_len + ((4 - (chunk_len & 3)) & 3);
        if (step <= 0 || step > remain)
            break;
        p += step;
        remain -= step;
    }
    *state = len;
    return OGS_ERROR;
}

/* ASN-decode complete S1AP PDUs; merge NAS extras' identities into evt. */
static bool s1ap_asn_extract(const uint8_t *l4, int l4len, ptrace_event_t *evt)
{
    int state = 12;
    const uint8_t *payload = NULL;
    int plen = 0;
    bool any = false;

    while (sctp_next_s1ap(l4, l4len, &state, &payload, &plen) == OGS_OK) {
        ptrace_event_t *extra[PTRACE_MAX_EVENTS_PER_PKT];
        int nextra = 0;
        ptrace_event_t base;

        memset(extra, 0, sizeof(extra));
        base = *evt;
        if (ptrace_decode_s1ap(payload, plen, &base, extra, &nextra) ==
                OGS_OK) {
            merge_ids(&evt->ids, &base.ids);
            if (base.message[0])
                ogs_cpystrn(evt->message, base.message, sizeof(evt->message));
            evt->protocol = PTRACE_PROTO_S1AP;
            any = true;
            while (nextra > 0) {
                nextra--;
                if (extra[nextra]) {
                    merge_ids(&evt->ids, &extra[nextra]->ids);
                    /* Prefer concrete NAS message name when cleartext. */
                    if (extra[nextra]->message[0] &&
                            strncmp(extra[nextra]->message, "NAS (ciphered)",
                                    14) != 0)
                        ogs_cpystrn(evt->message, extra[nextra]->message,
                                sizeof(evt->message));
                    ptrace_event_free(extra[nextra]);
                }
            }
        } else {
            while (nextra > 0) {
                nextra--;
                if (extra[nextra])
                    ptrace_event_free(extra[nextra]);
            }
        }
    }
    return any;
}

static bool extract_s1ap(const uint8_t *l4, int l4len, ogs_time_t ts,
        ptrace_role_e role, const char *src, const char *dst,
        uint16_t sport, uint16_t dport, uint16_t raw_len,
        const char *packet_ref, ptrace_id_event_t *out)
{
    ptrace_event_t evt;
    bool nas_hit = false;
    bool need_asn = false;

    fill_base(&evt, ts, role, src, dst, sport, dport, raw_len, packet_ref);

    /* Cleartext Attach/Identity/TAU — always try NAS scan first. */
    if (ptrace_decode_nas_scan(l4, l4len, &evt) == OGS_OK &&
            (evt.ids.imsi[0] || evt.ids.guti[0] || evt.ids.imei[0] ||
             evt.ids.m_tmsi[0])) {
        nas_hit = true;
        need_asn = true; /* learn eNB/MME S1AP IDs from same frame */
        if (!evt.message[0])
            ogs_cpystrn(evt.message, "NAS Identity", sizeof(evt.message));
    } else if (s1ap_keys_in_payload(l4, l4len)) {
        /* Follow-up for a traced UE — ASN for message + NAS/IMEI/MSISDN. */
        need_asn = true;
    } else {
        return false;
    }

    if (need_asn)
        s1ap_asn_extract(l4, l4len, &evt);

    if (!ptrace_ids_worth_indexing(&evt.ids) && !nas_hit)
        return false;

    if (!evt.message[0])
        ogs_cpystrn(evt.message, "S1AP", sizeof(evt.message));
    copy_to_id(&evt, out);
    return true;
}

bool ptrace_identity_extract(const uint8_t *data, uint16_t len,
        ogs_time_t ts, ptrace_role_e role, const char *packet_ref,
        ptrace_id_event_t *out)
{
    const uint8_t *p;
    int remain;
    uint16_t ethertype;
    uint8_t ipproto = 0;
    uint16_t sport = 0, dport = 0;
    char src_ip[PTRACE_MAX_ID_LEN] = "";
    char dst_ip[PTRACE_MAX_ID_LEN] = "";
    const uint8_t *l4 = NULL;
    int l4len = 0;
    const uint8_t *payload = NULL;
    int plen = 0;
    ptrace_event_t evt;

    if (!data || !out || len < 14)
        return false;

    p = data;
    remain = (int)len;
    ethertype = (uint16_t)((p[12] << 8) | p[13]);
    p += 14;
    remain -= 14;

    while ((ethertype == 0x8100 || ethertype == 0x88a8) && remain >= 4) {
        ethertype = (uint16_t)((p[2] << 8) | p[3]);
        p += 4;
        remain -= 4;
    }

    if (ethertype == ETHERTYPE_IP && remain >= (int)sizeof(struct iphdr)) {
        const struct iphdr *ip = (const struct iphdr *)p;
        int ihl = ip->ihl * 4;
        if (ihl < 20 || remain < ihl)
            return false;
        if (ip->frag_off & htons(0x1FFF))
            return false;
        ipv4_str(ip->saddr, src_ip, sizeof(src_ip));
        ipv4_str(ip->daddr, dst_ip, sizeof(dst_ip));
        ipproto = ip->protocol;
        l4 = p + ihl;
        l4len = remain - ihl;
    } else if (ethertype == ETHERTYPE_IPV6 &&
            remain >= (int)sizeof(struct ip6_hdr)) {
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)p;
        ipv6_str(ip6->ip6_src.s6_addr, src_ip, sizeof(src_ip));
        ipv6_str(ip6->ip6_dst.s6_addr, dst_ip, sizeof(dst_ip));
        ipproto = ip6->ip6_nxt;
        l4 = p + sizeof(struct ip6_hdr);
        l4len = remain - (int)sizeof(struct ip6_hdr);
    } else {
        return false;
    }

    if (!l4 || l4len < 4)
        return false;

    if (ipproto == IPPROTO_UDP && l4len >= 8) {
        sport = (uint16_t)((l4[0] << 8) | l4[1]);
        dport = (uint16_t)((l4[2] << 8) | l4[3]);
        payload = l4 + 8;
        plen = l4len - 8;
    } else if (ipproto == IPPROTO_TCP && l4len >= 20) {
        int doff = (l4[12] >> 4) * 4;
        if (doff < 20 || l4len < doff)
            return false;
        sport = (uint16_t)((l4[0] << 8) | l4[1]);
        dport = (uint16_t)((l4[2] << 8) | l4[3]);
        payload = l4 + doff;
        plen = l4len - doff;
    } else if (ipproto == IPPROTO_SCTP && l4len >= 12) {
        sport = (uint16_t)((l4[0] << 8) | l4[1]);
        dport = (uint16_t)((l4[2] << 8) | l4[3]);
        if (sport == PTRACE_PORT_SCTP_S1AP || dport == PTRACE_PORT_SCTP_S1AP ||
                role == PTRACE_ROLE_S1MME) {
            return extract_s1ap(l4, l4len, ts, role, src_ip, dst_ip,
                    sport, dport, len, packet_ref, out);
        }
        return false;
    } else {
        return false;
    }

    if (!payload || plen <= 0)
        return false;

    fill_base(&evt, ts, role, src_ip, dst_ip, sport, dport, len, packet_ref);

    if (sport == PTRACE_PORT_GTPC || dport == PTRACE_PORT_GTPC ||
            role == PTRACE_ROLE_S11 || role == PTRACE_ROLE_S5 ||
            role == PTRACE_ROLE_S8) {
        if (ptrace_decode_gtpc(payload, plen, &evt) == OGS_OK &&
                ptrace_ids_worth_indexing(&evt.ids)) {
            copy_to_id(&evt, out);
            return true;
        }
        return false;
    }

    if (sport == PTRACE_PORT_DIAMETER || dport == PTRACE_PORT_DIAMETER ||
            role == PTRACE_ROLE_DIAMETER) {
        if (ptrace_decode_diameter(payload, plen, &evt) == OGS_OK &&
                ptrace_ids_worth_indexing(&evt.ids)) {
            copy_to_id(&evt, out);
            return true;
        }
        return false;
    }

    if (sport == PTRACE_PORT_PFCP || dport == PTRACE_PORT_PFCP ||
            role == PTRACE_ROLE_N4) {
        if (ptrace_decode_pfcp(payload, plen, &evt) == OGS_OK &&
                ptrace_ids_worth_indexing(&evt.ids)) {
            copy_to_id(&evt, out);
            return true;
        }
        return false;
    }

    return false;
}

void ptrace_identity_to_event(const ptrace_id_event_t *id, ptrace_event_t *evt)
{
    if (!id || !evt)
        return;
    memset(evt, 0, sizeof(*evt));
    evt->ts = id->ts;
    evt->protocol = id->protocol;
    evt->role = id->role;
    ogs_cpystrn(evt->message, id->message, sizeof(evt->message));
    ogs_cpystrn(evt->src_ip, id->src_ip, sizeof(evt->src_ip));
    ogs_cpystrn(evt->dst_ip, id->dst_ip, sizeof(evt->dst_ip));
    evt->src_port = id->src_port;
    evt->dst_port = id->dst_port;
    evt->ids = id->ids;
    ogs_cpystrn(evt->packet_ref, id->packet_ref, sizeof(evt->packet_ref));
    evt->raw_len = id->raw_len;
}
