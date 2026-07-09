#!/usr/bin/env python3
"""Parse GTPv2 Create Session messages from a pcap (Scapy)."""
import struct
import sys
from collections import Counter
from datetime import datetime, timezone

from scapy.all import IP, UDP, rdpcap

PCAP = sys.argv[1] if len(sys.argv) > 1 else r"c:\Capture\mcidebug7.pcap"
TARGET_TEIDS = {0x72FE6, 0x95A08}
GTPV2_PORT = 2123

CAUSE_NAMES = {
    16: "Request accepted",
    64: "Context not found",
    70: "Mandatory IE missing",
    72: "System failure",
    73: "No resources available",
    74: "Semantic error in TFT",
    75: "Syntactic error in TFT",
    78: "Missing or unknown APN",
    89: "Service denied",
    103: "Conditional IE missing",
}

MSG = {32: "Create Session Request", 33: "Create Session Response"}


def parse_gtpv2(payload):
    if len(payload) < 4:
        return None
    flags = payload[0]
    if ((flags >> 5) & 7) != 2:
        return None
    msg_type = payload[1]
    length = struct.unpack("!H", payload[2:4])[0]
    off = 4
    teid = 0
    if flags & 0x08:
        if len(payload) < 12:
            return None
        teid = struct.unpack("!I", payload[4:8])[0]
        off = 12
    body = payload[off : 4 + length] if 4 + length <= len(payload) else payload[off:]
    cause = None
    has_fteid = False
    i = 0
    while i + 4 <= len(body):
        ie_type = body[i]
        ie_len = struct.unpack("!H", body[i + 1 : i + 3])[0]
        if i + 4 + ie_len > len(body):
            break
        ie_data = body[i + 4 : i + 4 + ie_len]
        if ie_type == 2 and ie_len >= 1:
            cause = ie_data[0]
        elif ie_type == 87:
            has_fteid = True
        i += 4 + ie_len
    return {
        "msg_type": msg_type,
        "teid": teid,
        "cause": cause,
        "has_fteid": has_fteid,
        "body_len": len(body),
    }


def ts_fmt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.") + f"{int((ts % 1) * 1000):03d}"


results = []
pkts = rdpcap(PCAP)
for p in pkts:
    if not p.haslayer(UDP):
        continue
    u = p[UDP]
    if int(u.dport) != GTPV2_PORT and int(u.sport) != GTPV2_PORT:
        continue
    g = parse_gtpv2(bytes(u.payload))
    if not g or g["msg_type"] not in (32, 33):
        continue
    src = p[IP].src if p.haslayer(IP) else "?"
    dst = p[IP].dst if p.haslayer(IP) else "?"
    results.append((float(p.time), g, src, dst))

print(f"PCAP: {PCAP}")
print(f"Packets total: {len(pkts)}")
print(f"GTPv2 Create Session messages: {len(results)}")
print()

print("=== Messages for MME TEIDs 0x72fe6 / 0x95a08 (from MME log) ===")
for ts, g, src, dst in sorted(results):
    if g["teid"] not in TARGET_TEIDS:
        continue
    c = g["cause"]
    cname = CAUSE_NAMES.get(c, f"cause {c}") if c is not None else "no cause IE"
    mname = MSG.get(g["msg_type"], str(g["msg_type"]))
    print(
        f"{ts_fmt(ts)} {mname} TEID=0x{g['teid']:x} Cause={c} ({cname}) "
        f"F-TEID={g['has_fteid']} body={g['body_len']}B {src}->{dst}"
    )

print()
print("=== ALL Create Session Response around 21:27:00 UTC ===")
for ts, g, src, dst in sorted(results):
    if g["msg_type"] != 33:
        continue
    t = ts_fmt(ts)
    if not t.startswith("21:27:00"):
        continue
    c = g["cause"]
    cname = CAUSE_NAMES.get(c, f"cause {c}") if c is not None else "no cause IE"
    print(
        f"{t} CSR TEID=0x{g['teid']:x} Cause={c} ({cname}) "
        f"F-TEID={g['has_fteid']} body={g['body_len']}B {src}->{dst}"
    )

print()
print("=== Cause distribution in ALL CSR ===")
cnt = Counter()
for _, g, _, _ in results:
    if g["msg_type"] == 33:
        cnt[g["cause"]] += 1
for k, v in sorted(cnt.items(), key=lambda x: (x[0] is None, x[0] or 0)):
    label = CAUSE_NAMES.get(k, "?") if k is not None else "missing"
    print(f"  Cause {k} ({label}): {v}x")
print(f"Total CSR: {sum(cnt.values())}, Cause 103 on wire: {cnt.get(103, 0)}")
