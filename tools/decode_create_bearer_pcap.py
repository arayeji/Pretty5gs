#!/usr/bin/env python3
"""Decode Create Bearer Request/Response from debug3.pcap."""
import struct
from scapy.all import IP, UDP, rdpcap

PCAP = r"c:\Capture\debug3.pcap"
GTP = 2123

CAUSE_NAMES = {
    16: "REQUEST_ACCEPTED",
    64: "CONTEXT_NOT_FOUND",
    72: "SEMANTIC_ERROR_IN_TFT",
    74: "SEMANTIC_ERROR_IN_TFT_OPERATION",
    77: "MANDATORY_IE_MISSING",
}


def decode_gtpc(payload):
    if len(payload) < 8:
        return None
    flags, msg_type = payload[0], payload[1]
    length = struct.unpack("!H", payload[2:4])[0]
    off = 4
    teid = 0
    if flags & 0x08:
        teid = struct.unpack("!I", payload[4:8])[0]
        off = 8
    seq = payload[off : off + 3]
    seq_num = (seq[0] << 16) | (seq[1] << 8) | seq[2]
    body = payload[off + 3 : 4 + length]
    return {
        "type": msg_type,
        "teid": teid,
        "seq": seq_num,
        "len": len(payload),
        "body_len": len(body),
        "body": body,
    }


def find_cause_ie(body):
    """Walk GTPv2 IEs looking for Cause (type 2)."""
    off = 0
    causes = []
    while off + 4 <= len(body):
        ie_type = body[off]
        ie_len = struct.unpack("!H", body[off + 1 : off + 3])[0]
        inst = body[off + 3]
        ie_data = body[off + 4 : off + 4 + ie_len]
        if ie_type == 2 and len(ie_data) >= 1:
            causes.append(
                {
                    "value": ie_data[0],
                    "pce": ie_data[1] if len(ie_data) > 1 else None,
                    "inst": inst,
                }
            )
        off += 4 + ie_len
    return causes


def find_bearer_tft(body):
    off = 0
    while off + 4 <= len(body):
        ie_type = body[off]
        ie_len = struct.unpack("!H", body[off + 1 : off + 3])[0]
        ie_data = body[off + 4 : off + 4 + ie_len]
        if ie_type == 84:  # Bearer TFT
            return ie_data
        off += 4 + ie_len
    return None


for p in rdpcap(PCAP):
    if not p.haslayer(UDP):
        continue
    u = p[UDP]
    if u.sport != GTP and u.dport != GTP:
        continue
    raw = bytes(u.payload)
    d = decode_gtpc(raw)
    if not d or d["type"] not in (95, 96):
        continue
    from datetime import datetime

    ts = datetime.fromtimestamp(float(p.time)).strftime("%H:%M:%S.") + f"{int((float(p.time) % 1) * 1000):03d}"
    name = "CreateBearerReq" if d["type"] == 95 else "CreateBearerRsp"
    src = p[IP].src
    dst = p[IP].dst
    print("=" * 70)
    print(f"{ts} {name} {src} -> {dst}")
    print(f"  pkt_len={d['len']} teid=0x{d['teid']:x} seq=0x{d['seq']:06x}")
    causes = find_cause_ie(d["body"])
    for c in causes:
        cv = c["value"]
        print(
            f"  Cause IE: {cv} ({CAUSE_NAMES.get(cv, 'unknown')}) "
            f"pce={c['pce']} inst={c['inst']}"
        )
    if d["type"] == 96:
        print(f"  body hex: {d['body'].hex()}")
        # Cause IE type 2: T(1) L(2) I(1) V(1) [off(1)]
        if len(d["body"]) >= 5 and d["body"][0] == 2:
            cv = d["body"][4]
            print(f"  Cause (manual): {cv} ({CAUSE_NAMES.get(cv, 'unknown')})")
