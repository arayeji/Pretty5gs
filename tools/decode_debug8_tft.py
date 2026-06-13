#!/usr/bin/env python3
"""Decode TFT from debug8.pcap Create Bearer Request."""
import socket
import struct
from datetime import datetime
from scapy.all import IP, UDP, rdpcap

PCAP = r"c:\Capture\debug8.pcap"
GTP = 2123
CAUSE = {16: "ACCEPTED", 70: "MAND_IE_MISSING", 77: "SYNTACTIC_PF"}
TFT_OP = {
    1: "CREATE_NEW_TFT",
    2: "DELETE_EXISTING_TFT",
    3: "ADD_PF",
    4: "REPLACE_PF",
    5: "DELETE_PF",
    6: "NO_TFT_OPERATION",
}
DIR = {0: "pre-rel7", 1: "uplink", 2: "downlink", 3: "bidirectional"}


def ipv4(u32):
    return socket.inet_ntoa(struct.pack("!I", u32))


def decode_gtpc(raw):
    flags, mt = raw[0], raw[1]
    ln = struct.unpack("!H", raw[2:4])[0]
    off = 8 if flags & 8 else 4
    return mt, raw[off + 4 : 4 + ln]


def walk(body):
    off = 0
    while off + 4 <= len(body):
        t = body[off]
        ln = struct.unpack("!H", body[off + 1 : off + 3])[0]
        d = body[off + 4 : off + 4 + ln]
        yield t, ln, d
        if t == 93:
            yield from walk(d)
        off += 4 + ln


def decode_tft(data):
    op = (data[0] >> 5) & 7
    e = (data[0] >> 4) & 1
    n = data[0] & 0xF
    lines = [f"op={op} ({TFT_OP.get(op, op)}) ebit={e} n_pf={n}"]
    o = 1
    for _ in range(n):
        if o + 3 > len(data):
            break
        id_dir = data[o]
        o += 1
        pf_id = id_dir & 0xF
        direction = (id_dir >> 4) & 3
        prec = data[o]
        o += 1
        plen = data[o]
        o += 1
        pf = data[o : o + plen]
        o += plen
        comps = []
        co = 0
        while co < len(pf):
            ct = pf[co]
            co += 1
            if ct == 48:
                comps.append(f"proto={pf[co]}")
                co += 1
            elif ct in (16, 17):
                addr = struct.unpack("!I", pf[co : co + 4])[0]
                co += 4
                mask = struct.unpack("!I", pf[co : co + 4])[0]
                co += 4
                lab = "remote" if ct == 16 else "local"
                comps.append(f"IPv4-{lab} {ipv4(addr)} mask=0x{mask:08x}")
            elif ct == 80:
                port = struct.unpack("!H", pf[co : co + 2])[0]
                co += 2
                comps.append(f"remote-port {port}")
            elif ct == 64:
                port = struct.unpack("!H", pf[co : co + 2])[0]
                co += 2
                comps.append(f"local-port {port}")
            elif ct == 81:
                lo = struct.unpack("!H", pf[co : co + 2])[0]
                co += 2
                hi = struct.unpack("!H", pf[co : co + 2])[0]
                co += 2
                comps.append(f"remote-port-range {lo}-{hi}")
            elif ct == 65:
                lo = struct.unpack("!H", pf[co : co + 2])[0]
                co += 2
                hi = struct.unpack("!H", pf[co : co + 2])[0]
                co += 2
                comps.append(f"local-port-range {lo}-{hi}")
            else:
                comps.append(f"unknown type {ct}")
                break
        lines.append(
            f"  PF{pf_id} dir={direction} ({DIR.get(direction, direction)}) "
            f"prec={prec} -> {' | '.join(comps)}"
        )
    return "\n".join(lines)


for p in rdpcap(PCAP):
    if not p.haslayer(UDP):
        continue
    u = p[UDP]
    if u.sport != GTP and u.dport != GTP:
        continue
    raw = bytes(u.payload)
    mt, body = decode_gtpc(raw)
    if mt != 95:
        continue
    ts = datetime.fromtimestamp(float(p.time)).strftime("%H:%M:%S.%f")[:-3]
    print("=" * 60)
    print(f"{ts} CreateBearerReq {p[IP].src} -> {p[IP].dst} len={len(raw)}")
    tft = None
    for t, ln, d in walk(body):
        if t == 73 and ln >= 1:
            print(f"  Linked EBI={d[0]}")
        if t == 87 and ln >= 1:
            print(f"  Bearer EBI={d[0]}")
        if t == 84:
            tft = d
            print(f"  TFT raw ({ln}): {d.hex()}")
    if tft:
        print(decode_tft(tft))
    break
