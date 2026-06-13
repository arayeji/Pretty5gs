#!/usr/bin/env python3
"""Detailed timeline for debug5.pcap VoLTE bearer attempt."""
import struct
from datetime import datetime
from scapy.all import IP, UDP, TCP, rdpcap

PCAP = r"c:\Capture\debug5.pcap"
T0 = None  # set to first CreateBearerReq timestamp


def pfcp_rsp_info(raw):
    off = 8 if raw[0] & 0x01 else 4
    cause = None
    err = b""
    while off + 4 <= len(raw):
        t = struct.unpack("!H", raw[off : off + 2])[0]
        ln = struct.unpack("!H", raw[off + 2 : off + 4])[0]
        data = raw[off + 4 : off + 4 + ln]
        if t == 19 and ln >= 1:
            cause = data[0]
        if b"reference" in data or b"nonexistent" in data:
            err = data
        off += 4 + ln
    return cause, err.decode("latin-1", "replace") if err else ""


def diam_info(raw):
    if len(raw) < 20:
        return {}
    cmd = (raw[5] << 16) | (raw[6] << 8) | raw[7]
    app = struct.unpack("!I", raw[8:12])[0]
    apps = {16777238: "Gx", 16777236: "Rx"}
    # walk AVPs
    cc_type = None
    cc_num = None
    session_id = None
    rule_names = []
    off = 20
    while off + 8 <= len(raw):
        code = struct.unpack("!I", raw[off : off + 4])[0]
        fl = struct.unpack("!I", raw[off + 4 : off + 8])[0]
        ln = fl & 0x00FFFFFF
        if ln < 8:
            break
        data = raw[off + 8 : off + ln]
        if code == 416 and len(data) >= 4:
            cc_type = struct.unpack("!I", data[:4])[0]
        elif code == 415 and len(data) >= 4:
            cc_num = struct.unpack("!I", data[:4])[0]
        elif code == 263:
            session_id = data.decode("utf-8", "replace").split(";")[0][-40:]
        elif code == 1005 and len(data) > 4:  # Charging-Rule-Name
            rule_names.append(data[4:].decode("utf-8", "replace"))
        elif code == 1006:  # Charging-Rule-Install grouped - skip deep
            pass
        pad = (4 - (ln % 4)) % 4
        off += ln + pad
    cc_names = {1: "INITIAL", 2: "UPDATE", 3: "TERMINATION", 4: "EVENT"}
    return {
        "app": apps.get(app, str(app)),
        "cmd": cmd,
        "cc_type": cc_names.get(cc_type, cc_type),
        "cc_num": cc_num,
        "session": session_id,
        "rules": rule_names[:4],
    }


events = []
for p in rdpcap(PCAP):
    if not p.haslayer(IP):
        continue
    ts = float(p.time)
    src, dst = p[IP].src, p[IP].dst
    if p.haslayer(UDP):
        u = p[UDP]
        raw = bytes(u.payload)
        if (u.sport == 2123 or u.dport == 2123) and len(raw) >= 2:
            t = raw[1]
            if t == 95:
                if T0 is None:
                    T0 = ts
                events.append((ts, "GTP", "CreateBearerReq", src, dst, len(raw), None, ""))
            elif t == 96:
                c = 74 if b"\x4a\x00" in raw else None
                events.append((ts, "GTP", "CreateBearerRsp", src, dst, len(raw), c, ""))
        if (u.sport == 8805 or u.dport == 8805) and len(raw) >= 2:
            t = raw[1]
            if t == 52:
                events.append((ts, "PFCP", "SessionModReq", src, dst, len(raw), None, ""))
            elif t == 53:
                c, err = pfcp_rsp_info(raw)
                events.append((ts, "PFCP", "SessionModRsp", src, dst, len(raw), c, err))
    if p.haslayer(TCP):
        t = p[TCP]
        if t.sport == 3868 or t.dport == 3868:
            raw = bytes(t.payload)
            if len(raw) < 20:
                continue
            d = diam_info(raw)
            if d.get("app") in ("Gx", "Rx"):
                events.append(
                    (
                        ts,
                        "DIAM",
                        f"{d['app']} cmd={d['cmd']} {d.get('cc_type','')}",
                        src,
                        dst,
                        len(raw),
                        None,
                        ",".join(d.get("rules") or []) or d.get("session", ""),
                    )
                )

if T0 is None:
    print("No Create Bearer in pcap")
    raise SystemExit

print(f"Window: first CreateBearerReq at {datetime.fromtimestamp(T0)}")
for e in sorted(events):
    ts, proto, name, src, dst, ln, cause, extra = e
    if not (T0 - 6 <= ts <= T0 + 0.5):
        continue
    dt = datetime.fromtimestamp(ts)
    c = f" cause={cause}" if cause is not None else ""
    x = f" [{extra}]" if extra else ""
    print(f"{dt.strftime('%H:%M:%S.%f')[:-3]} {proto:4} {name:28} {src}->{dst} len={ln}{c}{x}")
