#!/usr/bin/env python3
"""Find PFCP around Create Bearer failure in debug3.pcap."""
import struct
from datetime import datetime
from scapy.all import IP, UDP, rdpcap

PCAP = r"c:\Capture\debug3.pcap"
PFCP = 8805
GTP = 2123

PFCP_TYPES = {50: "SessionModReq", 51: "SessionModRsp", 52: "SessionDelReq", 53: "SessionDelRsp"}

def pfcp_type(payload):
    if len(payload) < 2:
        return None
    return payload[1]

def gtpc_type(payload):
    if len(payload) < 2:
        return None
    return payload[1]

events = []
for p in rdpcap(PCAP):
    if not p.haslayer(UDP):
        continue
    u = p[UDP]
    ts = float(p.time)
    src, dst = p[IP].src, p[IP].dst
    raw = bytes(u.payload)
    if u.dport == PFCP or u.sport == PFCP:
        t = pfcp_type(raw)
        events.append((ts, "PFCP", PFCP_TYPES.get(t, f"type{t}"), src, dst, len(raw)))
    if u.dport == GTP or u.sport == GTP:
        t = gtpc_type(raw)
        if t in (95, 96):
            events.append((ts, "GTP", "CreateBearerReq" if t == 95 else "CreateBearerRsp", src, dst, len(raw)))

# Window around first Create Bearer
t0 = None
for ts, proto, name, src, dst, ln in events:
    if name == "CreateBearerReq":
        t0 = ts
        break

if t0:
    print(f"Window +/- 50ms around first Create Bearer ({datetime.fromtimestamp(t0)})")
    for ts, proto, name, src, dst, ln in events:
        if abs(ts - t0) <= 0.05:
            print(f"  {datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]} {proto:4} {name:18} {src}->{dst} len={ln}")
