#!/usr/bin/env python3
"""Focused MBR analysis: per-TEID stats, IMSI UE, MBR->RAB cycles."""
import os
import struct
from collections import defaultdict
from datetime import datetime

from scapy.all import IP, UDP, rdpcap

GTP_PORT = 2123
MBR_REQ, MBR_RSP = 34, 35
RAB_REQ, RAB_RSP = 170, 171

# From journalctl for IMSI 432129951588409
TARGET_SGW_TEID = 0x4F9C3
TARGET_MME_TEID = 0x3A980


def parse_gtpc(payload):
    if len(payload) < 8:
        return None
    flags = payload[0]
    msg_type = payload[1]
    off = 4
    teid = None
    if flags & 0x08:
        if len(payload) < off + 4:
            return None
        teid = struct.unpack("!I", payload[off : off + 4])[0]
        off += 4
    if len(payload) < off + 3:
        return None
    seq = payload[off : off + 3]
    seq_num = (seq[0] << 16) | (seq[1] << 8) | seq[2]
    return msg_type, teid, seq_num


def fmt_ts(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.") + f"{int((ts % 1) * 1000):03d}"


def analyze(fp):
    print("=" * 80)
    print("FILE:", fp)
    events = []
    for p in rdpcap(fp):
        if not p.haslayer(UDP):
            continue
        udp = p[UDP]
        if udp.sport != GTP_PORT and udp.dport != GTP_PORT:
            continue
        parsed = parse_gtpc(bytes(p[UDP].payload))
        if not parsed:
            continue
        msg_type, teid, seq_num = parsed
        if msg_type not in (MBR_REQ, MBR_RSP, RAB_REQ, RAB_RSP):
            continue
        src = p[IP].src
        dst = p[IP].dst
        events.append(
            {
                "ts": float(p.time),
                "type": msg_type,
                "teid": teid,
                "seq": seq_num,
                "src": src,
                "dst": dst,
            }
        )
    events.sort(key=lambda e: e["ts"])

    # Global counts
    mbr_req = sum(1 for e in events if e["type"] == MBR_REQ)
    mbr_rsp = sum(1 for e in events if e["type"] == MBR_RSP)
    print(f"  Total MBR req/rsp: {mbr_req}/{mbr_rsp}")

    # Latency all pairs
    pending = {}
    latencies = []
    for e in events:
        if e["type"] == MBR_REQ:
            pending[(e["seq"], e["src"], e["dst"])] = e
        elif e["type"] == MBR_RSP:
            k = (e["seq"], e["dst"], e["src"])
            req = pending.pop(k, None)
            if req:
                latencies.append((e["ts"] - req["ts"]) * 1000)
    if latencies:
        print(
            f"  MBR latency ms: min={min(latencies):.1f} "
            f"max={max(latencies):.1f} avg={sum(latencies)/len(latencies):.1f} "
            f"n={len(latencies)}"
        )

    # Top SGW TEIDs in MBR requests (MME->SGW uses SGW TEID)
    teid_counts = defaultdict(int)
    for e in events:
        if e["type"] == MBR_REQ and e["src"].startswith("10.234.241.3"):
            teid_counts[e["teid"] or 0] += 1
    top = sorted(teid_counts.items(), key=lambda x: -x[1])[:10]
    print("  Top SGW TEIDs in MBR req (MME->SGW):")
    for teid, cnt in top:
        mark = " <-- target UE" if teid == TARGET_SGW_TEID else ""
        print(f"    0x{teid:x}: {cnt}{mark}")

    # Target UE timeline
    ue = [e for e in events if e["teid"] in (TARGET_SGW_TEID, TARGET_MME_TEID)]
    print(f"  Events for target TEIDs (0x{TARGET_SGW_TEID:x}/0x{TARGET_MME_TEID:x}): {len(ue)}")
    for e in ue:
        names = {34: "MBR-req", 35: "MBR-rsp", 170: "RAB-req", 171: "RAB-rsp"}
        print(
            f"    {fmt_ts(e['ts'])} {names[e['type']]} seq=0x{e['seq']:06x} "
            f"teid=0x{e['teid'] or 0:x} {e['src']}->{e['dst']}"
        )

    # MBR -> RAB gap for target UE (connected duration proxy)
    ue_mbr = [e for e in ue if e["type"] == MBR_RSP]
    ue_rab = [e for e in ue if e["type"] == RAB_REQ]
    if ue_mbr and ue_rab:
        print("  Target UE: MBR-rsp -> next RAB-req gaps:")
        ri = 0
        for m in ue_mbr:
            while ri < len(ue_rab) and ue_rab[ri]["ts"] <= m["ts"]:
                ri += 1
            if ri < len(ue_rab):
                gap = (ue_rab[ri]["ts"] - m["ts"]) * 1000
                print(f"    {fmt_ts(m['ts'])} -> {fmt_ts(ue_rab[ri]['ts'])} = {gap:.0f} ms")

    # Duplicate sequence numbers (true retransmissions)
    seen = {}
    retrans = []
    for e in events:
        if e["type"] != MBR_REQ:
            continue
        k = (e["seq"], e["src"], e["dst"], e["teid"])
        if k in seen:
            retrans.append(e)
        else:
            seen[k] = e
    print(f"  True MBR retransmissions (same seq+teid+dir): {len(retrans)}")
    for r in retrans[:5]:
        print(f"    {fmt_ts(r['ts'])} seq=0x{r['seq']:06x} teid=0x{r['teid'] or 0:x}")


def main():
    for fp in [
        r"c:\Capture\debug1.pcap",
        r"c:\Capture\debug2.pcap",
        r"c:\Capture\debug3.pcap",
    ]:
        if os.path.exists(fp):
            analyze(fp)


if __name__ == "__main__":
    main()
