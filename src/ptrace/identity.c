/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Capture hot-path identity extract (no full-frame worker queue, no ASN.1).
 */

#include "identity.h"
#include "decode.h"

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
        /* NAS byte-scan over whole SCTP datagram (covers fragmented chunks). */
        if (sport == PTRACE_PORT_SCTP_S1AP || dport == PTRACE_PORT_SCTP_S1AP ||
                role == PTRACE_ROLE_S1MME) {
            fill_base(&evt, ts, role, src_ip, dst_ip, sport, dport, len,
                    packet_ref);
            evt.protocol = PTRACE_PROTO_NAS;
            if (ptrace_decode_nas_scan(l4, l4len, &evt) == OGS_OK &&
                    ptrace_ids_worth_indexing(&evt.ids)) {
                if (!evt.message[0])
                    ogs_cpystrn(evt.message, "NAS Identity",
                            sizeof(evt.message));
                copy_to_id(&evt, out);
                return true;
            }
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
