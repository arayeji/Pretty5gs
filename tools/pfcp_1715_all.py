#!/usr/bin/env python3
from datetime import datetime
from scapy.all import IP, UDP, rdpcap

PCAP = r"c:\Capture\debug3.pcap"
PFCP = 8805
NAMES = {50: "ModReq", 51: "ModRsp", 52: "DelReq", 53: "DelRsp", 1: "HeartbeatReq", 2: "HeartbeatRsp"}

mods = []
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
    ts = float(p.time)
    dt = datetime.fromtimestamp(ts)
    if dt.hour == 17 and dt.minute in (15, 16):
        mods.append((ts, t, p[IP].src, p[IP].dst, len(raw)))

print(f"PFCP messages 17:15-17:16: {len(mods)}")
for ts, t, src, dst, ln in mods:
    dt = datetime.fromtimestamp(ts)
    if dt.second >= 58 or dt.minute == 16:
        print(f"{dt.strftime('%H:%M:%S.%f')[:-3]} {NAMES.get(t,f't{t}'):8} {src}->{dst} len={ln}")
