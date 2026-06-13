#!/usr/bin/env python3
"""Decode Create Bearer + PFCP Session Mod around failure."""
import struct
from datetime import datetime
from scapy.all import IP, UDP, rdpcap

PCAP = r"c:\Capture\debug3.pcap"
PFCP = 8805
GTP = 2123

PFCP_NAMES = {
    52: "SessionModReq",
    53: "SessionModRsp",
    54: "SessionDelReq",
    55: "SessionDelRsp",
}

def pfcp_cause(payload):
    """Find PFCP Cause IE (type 19)."""
    off = 8 if len(payload) > 8 and payload[0] & 0x01 else 4
    while off + 4 <= len(payload):
        ie_type = payload[off]
        ie_len = struct.unpack("!H", payload[off + 1 : off + 3])[0]
        if ie_type == 19 and ie_len >= 1:
            return payload[off + 4]
        off += 4 + ie_len
    return None


def decode_gtpc_cause(payload):
    flags = payload[0]
    length = struct.unpack("!H", payload[2:4])[0]
    off = 8 if flags & 0x08 else 4
    body = payload[off + 3 : 4 + length]
    if len(body) >= 6 and body[0] == 2:
        return body[4]
    return None


events = []
for p in rdpcap(PCAP):
    if not p.haslayer(UDP):
        continue
    u = p[UDP]
    raw = bytes(u.payload)
    ts = float(p.time)
    src, dst = p[IP].src, p[IP].dst
    if u.sport == PFCP or u.dport == PFCP:
        if len(raw) >= 2:
            t = raw[1]
            if t in PFCP_NAMES:
                events.append(
                    (
                        ts,
                        PFCP_NAMES[t],
                        src,
                        dst,
                        len(raw),
                        pfcp_cause(raw) if t == 53 else None,
                    )
                )
    if (u.sport == GTP or u.dport == GTP) and len(raw) >= 2:
        t = raw[1]
        if t in (95, 96):
            events.append(
                (
                    ts,
                    "CreateBearerReq" if t == 95 else "CreateBearerRsp",
                    src,
                    dst,
                    len(raw),
                    decode_gtpc_cause(raw) if t == 96 else None,
                )
            )

for ts, name, src, dst, ln, cause in sorted(events):
    dt = datetime.fromtimestamp(ts)
    if dt.hour == 17 and dt.minute == 15 and dt.second >= 58:
        extra = f" cause={cause}" if cause is not None else ""
        print(f"{dt.strftime('%H:%M:%S.%f')[:-3]} {name:16} {src}->{dst} len={ln}{extra}")
    if dt.hour == 17 and dt.minute == 16 and dt.second <= 4:
        extra = f" cause={cause}" if cause is not None else ""
        print(f"{dt.strftime('%H:%M:%S.%f')[:-3]} {name:16} {src}->{dst} len={ln}{extra}")
