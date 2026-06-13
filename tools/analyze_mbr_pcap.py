#!/usr/bin/env python3
"""Analyze GTPv2 Modify Bearer traffic in PCAP files."""
import os
import struct
import sys
from datetime import datetime

from scapy.all import IP, UDP, rdpcap

GTP_PORT = 2123
MBR_REQ, MBR_RSP = 34, 35
RAB_REQ, RAB_RSP = 170, 171
CS_REQ, CS_RSP = 32, 33

TYPE_NAMES = {
    34: "ModifyBearerReq",
    35: "ModifyBearerRsp",
    170: "ReleaseAccessBearersReq",
    171: "ReleaseAccessBearersRsp",
    32: "CreateSessionReq",
    33: "CreateSessionRsp",
}


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
    return {"type": msg_type, "teid": teid, "seq": seq_num, "flags": flags}


def fmt_ts(ts):
    base = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    ms = int((ts % 1) * 1000)
    return f"{base}.{ms:03d}"


def analyze_file(fp):
    print("=" * 80)
    print("FILE:", fp)
    if not os.path.exists(fp):
        print("  MISSING")
        return
    print("  size:", os.path.getsize(fp))
    pkts = rdpcap(fp)
    gtpc = []
    for p in pkts:
        if not p.haslayer(UDP):
            continue
        udp = p[UDP]
        if udp.sport != GTP_PORT and udp.dport != GTP_PORT:
            continue
        raw = bytes(p[UDP].payload)
        info = parse_gtpc(raw)
        if not info:
            continue
        if info["type"] not in (
            MBR_REQ,
            MBR_RSP,
            RAB_REQ,
            RAB_RSP,
            CS_REQ,
            CS_RSP,
        ):
            continue
        ts = float(p.time)
        src = p[IP].src if p.haslayer(IP) else "?"
        dst = p[IP].dst if p.haslayer(IP) else "?"
        gtpc.append(
            {
                **info,
                "ts": ts,
                "src": src,
                "dst": dst,
                "sport": int(udp.sport),
                "dport": int(udp.dport),
            }
        )
    gtpc.sort(key=lambda x: x["ts"])
    print("  GTP-C relevant packets:", len(gtpc))
    for g in gtpc:
        tname = TYPE_NAMES.get(g["type"], f"type{g['type']}")
        print(
            f"  {fmt_ts(g['ts'])} {g['src']}:{g['sport']} -> "
            f"{g['dst']}:{g['dport']} {tname} "
            f"seq=0x{g['seq']:06x} teid=0x{g['teid'] or 0:x}"
        )

    pending = {}
    retrans = []
    orphans_rsp = []
    pairs = []
    for g in gtpc:
        if g["type"] == MBR_REQ:
            key = (g["seq"], g["src"], g["dst"])
            if key in pending:
                retrans.append(g)
            else:
                pending[key] = g
        elif g["type"] == MBR_RSP:
            matched = None
            for k, req in pending.items():
                if k[0] == g["seq"] and req["dst"] == g["src"] and req["src"] == g["dst"]:
                    matched = k
                    break
            if matched:
                req = pending.pop(matched)
                delta_ms = (g["ts"] - req["ts"]) * 1000
                pairs.append((req, g, delta_ms))
            else:
                orphans_rsp.append(g)

    if pairs:
        print("  MBR req/rsp pairs:")
        for req, rsp, delta_ms in pairs:
            print(
                f"    seq=0x{req['seq']:06x} teid=0x{req['teid'] or 0:x} "
                f"{req['src']}->{req['dst']} latency={delta_ms:.1f}ms"
            )

    unmatched = [v for v in pending.values() if v["type"] == MBR_REQ]
    print("  Unmatched MBR requests:", len(unmatched))
    print("  MBR retransmissions:", len(retrans))
    print("  Orphan MBR responses:", len(orphans_rsp))
    if unmatched:
        print("  Pending requests:")
        for req in unmatched:
            print(
                f"    seq=0x{req['seq']:06x} from {req['src']} "
                f"teid=0x{req['teid'] or 0:x} at {fmt_ts(req['ts'])}"
            )
    if retrans:
        print("  Retransmissions:")
        for r in retrans:
            print(
                f"    seq=0x{r['seq']:06x} at {fmt_ts(r['ts'])} "
                f"{r['src']}->{r['dst']}"
            )


def main():
    files = sys.argv[1:] or [
        r"c:\Capture\debug1.pcap",
        r"c:\Capture\debug2.pcap",
        r"c:\Capture\debug3.pcap",
    ]
    for fp in files:
        analyze_file(fp)


if __name__ == "__main__":
    main()
