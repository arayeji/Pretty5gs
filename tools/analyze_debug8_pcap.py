#!/usr/bin/env python3
"""Analyze debug8.pcap for Create Bearer / PFCP / Diameter failure."""
import struct
from datetime import datetime
from scapy.all import IP, UDP, TCP, rdpcap

PCAP = r"c:\Capture\debug8.pcap"
GTP = 2123
PFCP = 8805
DIAM = 3868

PFCP_IE = {19: "Cause", 114: "FailedRuleID"}


def gtpc_type(raw):
    return raw[1] if len(raw) >= 2 else None


def gtpc_teid(raw):
    if len(raw) < 8 or not (raw[0] & 0x08):
        return 0
    return struct.unpack("!I", raw[4:8])[0]


def gtpc_cause(raw):
    if len(raw) < 12:
        return None
    flags = raw[0]
    ln = struct.unpack("!H", raw[2:4])[0]
    off = 8 if flags & 0x08 else 4
    body = raw[off + 3 : 4 + ln]
    o = 0
    while o + 5 <= len(body):
        if body[o] == 2:
            return body[o + 4]
        ie_len = struct.unpack("!H", body[o + 1 : o + 3])[0]
        o += 4 + ie_len
    return None


def pfcp_walk(raw):
    off = 8 if raw[0] & 0x01 else 4
    ies = []
    while off + 4 <= len(raw):
        t = struct.unpack("!H", raw[off : off + 2])[0]
        ln = struct.unpack("!H", raw[off + 2 : off + 4])[0]
        data = raw[off + 4 : off + 4 + ln]
        ies.append((t, ln, data))
        off += 4 + ln
    return ies


def pfcp_summary(raw):
    parts = []
    for t, ln, data in pfcp_walk(raw):
        name = PFCP_IE.get(t, f"IE{t}")
        if t == 19 and ln >= 1:
            parts.append(f"Cause={data[0]}")
        elif t == 114 and ln >= 5:
            parts.append(f"FailedRule type={data[0]} id={struct.unpack('!I', data[1:5])[0]}")
        elif t == 1 and ln >= 2:
            parts.append(f"CreatePDR id={struct.unpack('!H', data[:2])[0]}")
        elif t == 3 and ln >= 4:
            parts.append(f"CreateFAR id={struct.unpack('!I', data[:4])[0]}")
        elif t == 6 and ln >= 4:
            parts.append(f"CreateURR id={struct.unpack('!I', data[:4])[0]}")
        else:
            txt = data.decode("latin-1", "replace")
            if "reference" in txt or "nonexist" in txt:
                parts.append(repr(txt[:60]))
    return "; ".join(parts[:12])


events = []
for p in rdpcap(PCAP):
    if not p.haslayer(IP):
        continue
    ts = float(p.time)
    src, dst = p[IP].src, p[IP].dst
    if p.haslayer(UDP):
        u = p[UDP]
        raw = bytes(u.payload)
        if u.sport == GTP or u.dport == GTP:
            t = gtpc_type(raw)
            if t in (95, 96, 34, 35):
                name = {95: "CreateBearerReq", 96: "CreateBearerRsp", 34: "ModBearerReq", 35: "ModBearerRsp"}.get(t)
                events.append((ts, "GTP", name, src, dst, len(raw), gtpc_cause(raw) if t == 96 else None, ""))
        if u.sport == PFCP or u.dport == PFCP:
            t = gtpc_type(raw)
            if t in (52, 53):
                name = "SessionModReq" if t == 52 else "SessionModRsp"
                extra = pfcp_summary(raw) if t == 53 and len(raw) > 30 else ""
                if t == 52 and len(raw) > 80:
                    extra = pfcp_summary(raw)
                events.append((ts, "PFCP", name, src, dst, len(raw), None, extra))
    if p.haslayer(TCP):
        t = p[TCP]
        if t.sport == DIAM or t.dport == DIAM:
            raw = bytes(t.payload)
            if len(raw) >= 8:
                cmd = (raw[5] << 16) | (raw[6] << 8) | raw[7]
                app = struct.unpack("!I", raw[8:12])[0]
                apps = {16777238: "Gx", 16777236: "Rx"}
                if app in apps and cmd in (258, 265, 272, 275):
                    events.append((ts, "DIAM", f"{apps[app]} cmd={cmd}", src, dst, len(raw), None, ""))

print("=" * 72)
print("Create Bearer pairs:")
for e in sorted(events):
    if e[2] in ("CreateBearerReq", "CreateBearerRsp"):
        dt = datetime.fromtimestamp(e[0])
        c = f" cause={e[6]}" if e[6] is not None else ""
        print(f"  {dt.strftime('%H:%M:%S.%f')[:-3]} {e[2]:16} {e[3]}->{e[4]} len={e[5]}{c}")

cbr = [e for e in events if e[2] == "CreateBearerReq"]
if cbr:
    t0 = cbr[0][0]
    print(f"\nTimeline around first CreateBearerReq ({datetime.fromtimestamp(t0)}):")
    for e in sorted(events):
        if t0 - 3 <= e[0] <= t0 + 0.05:
            dt = datetime.fromtimestamp(e[0])
            x = f" [{e[7]}]" if e[7] else ""
            print(f"  {dt.strftime('%H:%M:%S.%f')[:-3]} {e[1]:4} {e[2]:16} {e[3]}->{e[4]} len={e[5]}{x}")

print("\nLarge PFCP SessionModReq (>100B) near any CreateBearerReq:")
for req in [e for e in events if e[2] == "CreateBearerReq"]:
    t0 = req[0]
    for e in sorted(events):
        if e[2] == "SessionModReq" and e[5] > 100 and abs(e[0] - t0) < 0.01:
            dt = datetime.fromtimestamp(e[0])
            print(f"  {dt.strftime('%H:%M:%S.%f')[:-3]} len={e[5]} {e[3]}->{e[4]}")
            print(f"    {e[7]}")
