#!/usr/bin/env python3
from scapy.all import rdpcap, IP, UDP
import struct
import sys
from collections import Counter

if len(sys.argv) < 2:
    print("usage: analyze-pcap-gtp.py <file.pcap>", file=sys.stderr)
    sys.exit(1)
pcap = sys.argv[1]
pkts = rdpcap(pcap)
print(f"Total packets: {len(pkts)}")

GTP_TYPES = {
    32: "Create Session Request",
    33: "Create Session Response",
    34: "Modify Bearer Request",
    35: "Modify Bearer Response",
    95: "Echo Request",
    96: "Echo Response",
}
PFCP_TYPES = {
    50: "Session Establishment Request",
    51: "Session Establishment Response",
    52: "Session Modification Request",
    53: "Session Modification Response",
}


def parse_gtpc(payload):
    if len(payload) < 8:
        return None
    flags = payload[0]
    msg_type = payload[1]
    teid = struct.unpack("!I", payload[4:8])[0]
    off = 8
    if flags & 0x08:
        off += 4
    return msg_type, teid, off


def parse_pfcp(payload):
    if len(payload) < 4:
        return None
    flags = payload[0]
    msg_type = payload[1]
    seid = 0
    if flags & 0x01 and len(payload) >= 12:
        seid = struct.unpack("!Q", payload[4:12])[0]
    return msg_type, seid


def walk_ies(payload, start):
    off = start
    while off + 4 <= len(payload):
        ie_type = payload[off]
        ie_len = struct.unpack("!H", payload[off + 1:off + 3])[0]
        if off + 4 + ie_len > len(payload):
            break
        yield ie_type, payload[off + 4:off + 4 + ie_len]
        off += 4 + ie_len


def fqdn_parse(data):
    if not data:
        return ""
    labels = []
    i = 0
    while i < len(data):
        l = data[i]
        i += 1
        if l == 0 or i + l > len(data):
            break
        labels.append(data[i:i + l].decode("ascii", errors="replace"))
        i += l
    return ".".join(labels)


def fteid_ip(data):
    if not data or len(data) < 5:
        return ""
    iface = data[0] & 0x3f
    v4 = bool(data[1] & 0x80)
    v6 = bool(data[1] & 0x40)
    teid = struct.unpack("!I", data[2:6])[0]
    parts = [f"if={iface}", f"teid=0x{teid:08x}"]
    o = 6
    if v4 and o + 4 <= len(data):
        parts.append("ip=" + ".".join(str(b) for b in data[o:o + 4]))
        o += 4
    if v6 and o + 16 <= len(data):
        h = data[o:o + 16].hex()
        parts.append("ip6=" + h[:8] + "...")
    return " ".join(parts)


events = []
ips = set()

for i, p in enumerate(pkts):
    if not p.haslayer(IP) or not p.haslayer(UDP):
        continue
    ip = p[IP]
    udp = p[UDP]
    ips.add(ip.src)
    ips.add(ip.dst)
    payload = bytes(udp.payload)

    if udp.dport == 2123 or udp.sport == 2123:
        g = parse_gtpc(payload)
        if not g:
            continue
        mt, teid, ie_off = g
        name = GTP_TYPES.get(mt, f"GTPv2-{mt}")
        extra = f"TEID=0x{teid:08x}"
        if mt == 32:
            for ie_t, ie_v in walk_ies(payload, ie_off):
                if ie_t == 71:
                    extra += f" APN={fqdn_parse(ie_v)!r}"
                elif ie_t == 87:
                    extra += f" PGW={fteid_ip(ie_v)}"
                elif ie_t == 1:
                    extra += f" IMSI={ie_v.hex()}"
        events.append((i + 1, float(p.time), ip.src, ip.dst, "GTP-C", name, extra))
    elif udp.dport == 8805 or udp.sport == 8805:
        pf = parse_pfcp(payload)
        if not pf:
            continue
        mt, seid = pf
        name = PFCP_TYPES.get(mt, f"PFCP-{mt}")
        events.append((i + 1, float(p.time), ip.src, ip.dst, "PFCP", name, f"SEID=0x{seid:016x}"))

events.sort(key=lambda x: x[1])

print("\n=== Unique IPs ===")
for a in sorted(ips):
    print(f"  {a}")

print("\n=== Chronological signaling ===")
for e in events:
    print(f"#{e[0]:5d} t={e[1]:.6f} {e[2]:>16} -> {e[3]:<16} {e[4]:5s} {e[5]:32s} {e[6]}")

print(f"\n=== Total signaling events: {len(events)} ===")
c = Counter((f"{e[2]}->{e[3]}", e[5]) for e in events)
print("\n=== Per-flow message counts ===")
for (flow, typ), n in sorted(c.items(), key=lambda x: (-x[1], x[0])):
    print(f"  {n:3d}x {flow:40s} {typ}")
