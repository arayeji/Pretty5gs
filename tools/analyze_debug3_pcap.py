#!/usr/bin/env python3
"""Deep analysis of debug3.pcap - GTP, PFCP, Diameter search."""
import os
import struct
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import IP, Raw, UDP, rdpcap

PCAP = r"c:\Capture\debug3.pcap"

GTP_PORT = 2123
PFCP_PORT = 8805
GTP_TYPES = {
    32: "CreateSessionReq",
    33: "CreateSessionRsp",
    34: "ModifyBearerReq",
    35: "ModifyBearerRsp",
    95: "CreateBearerReq",
    96: "CreateBearerRsp",
    97: "UpdateBearerReq",
    98: "UpdateBearerRsp",
    99: "DeleteBearerReq",
    100: "DeleteBearerRsp",
    170: "ReleaseAccessBearersReq",
    171: "ReleaseAccessBearersRsp",
}
PFCP_TYPES = {50: "SessionEstReq", 51: "SessionEstRsp", 52: "SessionModReq", 53: "SessionModRsp"}


def fmt_ts(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.") + f"{int((ts % 1) * 1000):03d}"


def parse_gtpc(payload):
    if len(payload) < 4:
        return None
    flags, msg_type = payload[0], payload[1]
    off = 4
    teid = None
    if flags & 0x08:
        if len(payload) < 8:
            return None
        teid = struct.unpack("!I", payload[4:8])[0]
        off = 8
    if len(payload) < off + 3:
        return None
    seq = payload[off : off + 3]
    seq_num = (seq[0] << 16) | (seq[1] << 8) | seq[2]
    return msg_type, teid, seq_num


def parse_pfcp(payload):
    if len(payload) < 8:
        return None
    msg_type = payload[1]
    seq = struct.unpack("!I", payload[4:8])[0] & 0xFFFFFF
    seid = None
    off = 8
    if payload[0] & 0x01:  # S flag
        if len(payload) < 16:
            return None
        seid = struct.unpack("!Q", payload[8:16])[0]
        off = 16
    return msg_type, seid, seq


def scan_diameter_markers(raw):
    hits = []
    if b"ims-g" in raw:
        hits.append("ims-g")
    if b"Charging-Rule" in raw:
        hits.append("Charging-Rule")
    # Diameter version 1 at start (heuristic)
    if len(raw) >= 4 and raw[0] == 1:
        cmd = struct.unpack("!I", raw[4:8])[0] if len(raw) >= 8 else 0
        app = struct.unpack("!I", raw[8:12])[0] if len(raw) >= 12 else 0
        if app in (16777238, 16777236, 4):  # Gx, Rx, common
            hits.append(f"diam-app-{app}")
    return hits


def main():
    print("FILE:", PCAP)
    print("size:", os.path.getsize(PCAP))
    pkts = rdpcap(PCAP)
    print("packets:", len(pkts))

    gtp_events = []
    pfcp_events = []
    diam_hits = []
    ips = Counter()

    for p in pkts:
        if not p.haslayer(UDP):
            continue
        u = p[UDP]
        raw = bytes(u.payload)
        if not raw:
            continue
        src = p[IP].src if p.haslayer(IP) else "?"
        dst = p[IP].dst if p.haslayer(IP) else "?"
        ips[(src, int(u.sport))] += 1
        ips[(dst, int(u.dport))] += 1

        markers = scan_diameter_markers(raw)
        if markers:
            diam_hits.append((float(p.time), src, dst, int(u.sport), int(u.dport), markers))

        if u.sport == GTP_PORT or u.dport == GTP_PORT:
            parsed = parse_gtpc(raw)
            if parsed:
                t, teid, seq = parsed
                if t in GTP_TYPES:
                    gtp_events.append(
                        {
                            "ts": float(p.time),
                            "type": t,
                            "teid": teid,
                            "seq": seq,
                            "src": src,
                            "dst": dst,
                        }
                    )
        if u.sport == PFCP_PORT or u.dport == PFCP_PORT:
            parsed = parse_pfcp(raw)
            if parsed:
                t, seid, seq = parsed
                if t in PFCP_TYPES:
                    pfcp_events.append(
                        {
                            "ts": float(p.time),
                            "type": t,
                            "seid": seid,
                            "seq": seq,
                            "src": src,
                            "dst": dst,
                        }
                    )

    print("\n=== Endpoints (IP:port) ===")
    for (ip, port), n in ips.most_common(15):
        print(f"  {ip}:{port}  ({n} pkts)")

    print("\n=== Diameter / ims-g search ===")
    if not diam_hits:
        print("  NONE — no Diameter (Gx/Rx) or 'ims-g' strings in this capture")
    else:
        for h in diam_hits[:50]:
            print(f"  {fmt_ts(h[0])} {h[1]}:{h[3]} -> {h[2]}:{h[4]} {h[5]}")

    print("\n=== GTP-C summary ===")
    gtp_counts = Counter(e["type"] for e in gtp_events)
    for t, n in sorted(gtp_counts.items(), key=lambda x: -x[1]):
        print(f"  {GTP_TYPES.get(t, t)}: {n}")

    rare = [e for e in gtp_events if e["type"] in (95, 96, 97, 98, 99, 100)]
    print(f"\n=== Dedicated bearer GTP (Create/Update/Delete Bearer): {len(rare)} ===")
    for e in rare[:30]:
        print(
            f"  {fmt_ts(e['ts'])} {GTP_TYPES[e['type']]} "
            f"seq=0x{e['seq']:06x} teid=0x{e['teid'] or 0:x} {e['src']}->{e['dst']}"
        )

    print("\n=== PFCP Session Modification (voice bearer hint) ===")
    mod = [e for e in pfcp_events if e["type"] in (52, 53)]
    print(f"  SessionMod req/rsp: {sum(1 for e in mod if e['type']==52)} / {sum(1 for e in mod if e['type']==53)}")

    # Target UE from prior analysis
    TARGET = 0x4F9C3
    ue = [e for e in gtp_events if e["teid"] == TARGET and e["type"] in (34, 35, 170, 171, 95, 96)]
    print(f"\n=== Target UE SGW TEID 0x{TARGET:x}: {len(ue)} GTP events ===")
    for e in ue[:20]:
        print(f"  {fmt_ts(e['ts'])} {GTP_TYPES[e['type']]} seq=0x{e['seq']:06x}")

    # Time range
    if gtp_events:
        gtp_events.sort(key=lambda x: x["ts"])
        print(f"\n=== Capture window ===")
        print(f"  {fmt_ts(gtp_events[0]['ts'])} -> {fmt_ts(gtp_events[-1]['ts'])}")


if __name__ == "__main__":
    main()
