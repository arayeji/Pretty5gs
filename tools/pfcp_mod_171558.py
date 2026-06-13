#!/usr/bin/env python3
from datetime import datetime
from scapy.all import IP, UDP, rdpcap

PCAP = r"c:\Capture\debug3.pcap"
PFCP = 8805

for p in rdpcap(PCAP):
    if not p.haslayer(UDP):
        continue
    u = p[UDP]
    if u.sport != PFCP and u.dport != PFCP:
        continue
    raw = bytes(u.payload)
    if len(raw) < 2:
        continue
    t = raw[1]
    if t not in (50, 51):
        continue
    ts = datetime.fromtimestamp(float(p.time))
    if ts.hour == 17 and ts.minute == 15 and 58 <= ts.second <= 59:
        name = "ModReq" if t == 50 else "ModRsp"
        cause = None
        # rough scan for cause IE 19 in PFCP
        if t == 51 and len(raw) > 20:
            for i in range(8, len(raw) - 2):
                if raw[i] == 19:  # Cause IE type
                    cause = raw[i + 3] if i + 3 < len(raw) else None
                    break
        print(f"{ts.strftime('%H:%M:%S.%f')[:-3]} {name} {p[IP].src}->{p[IP].dst} len={len(raw)} cause={cause}")
