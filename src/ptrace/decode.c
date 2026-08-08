/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * L2/L3/L4 demux + protocol dispatch (no tshark).
 */

#include "decode.h"
#include "context.h"

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#define PTRACE_PORT_GTPC        2123
#define PTRACE_PORT_GTPU        2152
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

static int sctp_next_s1ap(const uint8_t *data, int len, int *state,
        const uint8_t **payload, int *plen)
{
    /* *state is byte offset into SCTP after common header (start 12).
     * Yields successive PPID=18 DATA payloads (prefer B+E, else B). */
    const uint8_t *p;
    int remain;
    int off;

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
        int step;

        if (chunk_len < 4)
            return OGS_ERROR;
        if (chunk_len > remain)
            chunk_len = (uint16_t)remain;

        if (type == 0 && chunk_len >= 16) {
            ppid = ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                    ((uint32_t)p[14] << 8) | p[15];
            ppid_le = (uint32_t)p[12] |
                    ((uint32_t)p[13] << 8) |
                    ((uint32_t)p[14] << 16) |
                    ((uint32_t)p[15] << 24);
            if (ppid == 18 || ppid_le == 18) {
                if ((flags & 0x03) == 0x03 || (flags & 0x02)) {
                    *payload = p + 16;
                    *plen = chunk_len - 16;
                    step = chunk_len + ((4 - (chunk_len & 3)) & 3);
                    if (step <= 0 || step > remain)
                        *state = len;
                    else
                        *state = (int)(p - data) + step;
                    if (*plen > 0)
                        return OGS_OK;
                }
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

int ptrace_decode_packet(ptrace_packet_t *pkt,
        ptrace_event_t **out, int *nout)
{
    const uint8_t *p;
    int len;
    uint16_t ethertype;
    uint8_t ipproto = 0;
    uint16_t sport = 0, dport = 0;
    char src_ip[PTRACE_MAX_ID_LEN] = "";
    char dst_ip[PTRACE_MAX_ID_LEN] = "";
    const uint8_t *l4 = NULL;
    int l4len = 0;
    const uint8_t *payload = NULL;
    int plen = 0;
    ptrace_event_t *evt;
    int n = 0;

    ogs_assert(pkt && out && nout);
    *nout = 0;

    p = pkt->data;
    len = pkt->len;
    if (len < 14)
        return OGS_OK;

    ethertype = (uint16_t)((p[12] << 8) | p[13]);
    p += 14;
    len -= 14;

    /* VLAN / QinQ */
    while ((ethertype == 0x8100 || ethertype == 0x88a8) && len >= 4) {
        ethertype = (uint16_t)((p[2] << 8) | p[3]);
        p += 4;
        len -= 4;
    }

    if (ethertype == ETHERTYPE_IP && len >= (int)sizeof(struct iphdr)) {
        const struct iphdr *ip = (const struct iphdr *)p;
        int ihl = ip->ihl * 4;
        if (ihl < 20 || len < ihl)
            return OGS_OK;
        ipv4_str(ip->saddr, src_ip, sizeof(src_ip));
        ipv4_str(ip->daddr, dst_ip, sizeof(dst_ip));
        ipproto = ip->protocol;
        l4 = p + ihl;
        l4len = len - ihl;
        if (ip->frag_off & htons(0x1FFF))
            return OGS_OK; /* skip fragments */
    } else if (ethertype == ETHERTYPE_IPV6 &&
            len >= (int)sizeof(struct ip6_hdr)) {
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)p;
        ipv6_str(ip6->ip6_src.s6_addr, src_ip, sizeof(src_ip));
        ipv6_str(ip6->ip6_dst.s6_addr, dst_ip, sizeof(dst_ip));
        ipproto = ip6->ip6_nxt;
        l4 = p + sizeof(struct ip6_hdr);
        l4len = len - (int)sizeof(struct ip6_hdr);
    } else {
        return OGS_OK;
    }

    if (!l4 || l4len < 4)
        return OGS_OK;

    if (ipproto == IPPROTO_UDP && l4len >= 8) {
        sport = (uint16_t)((l4[0] << 8) | l4[1]);
        dport = (uint16_t)((l4[2] << 8) | l4[3]);
        payload = l4 + 8;
        plen = l4len - 8;
    } else if (ipproto == IPPROTO_TCP && l4len >= 20) {
        int doff = (l4[12] >> 4) * 4;
        if (doff < 20 || l4len < doff)
            return OGS_OK;
        sport = (uint16_t)((l4[0] << 8) | l4[1]);
        dport = (uint16_t)((l4[2] << 8) | l4[3]);
        payload = l4 + doff;
        plen = l4len - doff;
    } else if (ipproto == IPPROTO_SCTP) {
        sport = (uint16_t)((l4[0] << 8) | l4[1]);
        dport = (uint16_t)((l4[2] << 8) | l4[3]);
        /* Tried below with multi-chunk iteration */
        payload = NULL;
        plen = 0;
    } else {
        return OGS_OK;
    }

    if (ipproto != IPPROTO_SCTP) {
        if (!payload || plen <= 0)
            return OGS_OK;
    }

    if (ipproto == IPPROTO_SCTP &&
            (sport == PTRACE_PORT_SCTP_S1AP ||
             dport == PTRACE_PORT_SCTP_S1AP ||
             pkt->role == PTRACE_ROLE_S1MME)) {
        int sctp_state = 12;
        while (sctp_next_s1ap(l4, l4len, &sctp_state, &payload, &plen) ==
                OGS_OK) {
            ptrace_event_t *extra[PTRACE_MAX_EVENTS_PER_PKT];
            int nextra = 0;
            evt = ptrace_event_alloc();
            if (!evt)
                break;
            evt->ts = pkt->ts;
            evt->role = pkt->role;
            ogs_cpystrn(evt->src_ip, src_ip, sizeof(evt->src_ip));
            ogs_cpystrn(evt->dst_ip, dst_ip, sizeof(evt->dst_ip));
            evt->src_port = sport;
            evt->dst_port = dport;
            evt->raw_len = pkt->len;
            ogs_cpystrn(evt->packet_ref, pkt->packet_ref,
                    sizeof(evt->packet_ref));
            if (ptrace_decode_s1ap(payload, plen, evt, extra, &nextra) ==
                    OGS_OK) {
                out[n++] = evt;
                while (nextra > 0 && n < PTRACE_MAX_EVENTS_PER_PKT)
                    out[n++] = extra[--nextra];
                while (nextra > 0)
                    ptrace_event_free(extra[--nextra]);
                /* Keep scanning chunks — one SCTP packet can carry
                 * several S1AP PDUs (rare but seen on SPAN). */
                if (n >= PTRACE_MAX_EVENTS_PER_PKT)
                    break;
            } else {
                ptrace_event_free(evt);
            }
        }
        *nout = n;
        return OGS_OK;
    }

    if (!payload || plen <= 0)
        return OGS_OK;

    evt = ptrace_event_alloc();
    if (!evt)
        return OGS_ERROR;

    evt->ts = pkt->ts;
    evt->role = pkt->role;
    ogs_cpystrn(evt->src_ip, src_ip, sizeof(evt->src_ip));
    ogs_cpystrn(evt->dst_ip, dst_ip, sizeof(evt->dst_ip));
    evt->src_port = sport;
    evt->dst_port = dport;
    evt->raw_len = pkt->len;
    ogs_cpystrn(evt->packet_ref, pkt->packet_ref, sizeof(evt->packet_ref));

    if (sport == PTRACE_PORT_GTPC || dport == PTRACE_PORT_GTPC ||
            pkt->role == PTRACE_ROLE_S11 ||
            pkt->role == PTRACE_ROLE_S5 ||
            pkt->role == PTRACE_ROLE_S8) {
        if (ptrace_decode_gtpc(payload, plen, evt) == OGS_OK)
            out[n++] = evt;
        else
            ptrace_event_free(evt);
    } else if (sport == PTRACE_PORT_GTPU || dport == PTRACE_PORT_GTPU ||
            pkt->role == PTRACE_ROLE_S1U ||
            pkt->role == PTRACE_ROLE_N3) {
        if (ptrace_decode_gtpu(payload, plen, evt) == OGS_OK)
            out[n++] = evt;
        else
            ptrace_event_free(evt);
    } else if (sport == PTRACE_PORT_PFCP || dport == PTRACE_PORT_PFCP ||
            pkt->role == PTRACE_ROLE_N4) {
        if (ptrace_decode_pfcp(payload, plen, evt) == OGS_OK)
            out[n++] = evt;
        else
            ptrace_event_free(evt);
    } else if (sport == PTRACE_PORT_DIAMETER || dport == PTRACE_PORT_DIAMETER ||
            pkt->role == PTRACE_ROLE_DIAMETER) {
        if (ptrace_decode_diameter(payload, plen, evt) == OGS_OK)
            out[n++] = evt;
        else
            ptrace_event_free(evt);
    } else {
        ptrace_event_free(evt);
    }

    *nout = n;
    return OGS_OK;
}
