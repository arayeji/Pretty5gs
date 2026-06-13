#!/usr/bin/env python3
"""Analyze debug5.pcap: GTP Create Bearer, PFCP mod, Diameter Gx/Rx."""
import struct
from collections import defaultdict
from datetime import datetime
from scapy.all import IP, UDP, TCP, rdpcap

PCAP = r"c:\Capture\debug5.pcap"
GTP = 2123
PFCP = 8805
DIAM = 3868

GTP_NAMES = {
    95: "CreateBearerReq",
    96: "CreateBearerRsp",
    97: "UpdateBearerReq",
    98: "UpdateBearerRsp",
    34: "ModifyBearerReq",
    35: "ModifyBearerRsp",
    32: "CreateSessionReq",
    33: "CreateSessionRsp",
}
PFCP_NAMES = {52: "SessionModReq", 53: "SessionModRsp", 54: "SessionDelReq", 55: "SessionDelRsp"}
CAUSE74 = 74


def gtpc_teid(payload):
    if len(payload) < 8:
        return 0
    if payload[0] & 0x08:
        return struct.unpack("!I", payload[4:8])[0]
    return 0


def gtpc_cause(payload):
    flags = payload[0]
    length = struct.unpack("!H", payload[2:4])[0]
    off = 8 if flags & 0x08 else 4
    body = payload[off + 3 : 4 + length]
    o = 0
    while o + 4 <= len(body):
        if body[o] == 2:
            return body[o + 4] if o + 4 < len(body) else None
        ie_len = struct.unpack("!H", body[o + 1 : o + 3])[0]
        o += 4 + ie_len
    return None


def pfcp_cause(payload):
    off = 8 if payload[0] & 0x01 else 4
    while off + 4 <= len(payload):
        t = struct.unpack("!H", payload[off : off + 2])[0]
        ln = struct.unpack("!H", payload[off + 2 : off + 4])[0]
        if t == 19 and ln >= 1:
            return payload[off + 4]
        off += 4 + ln
    return None


def diam_app_cmd(payload):
    """Rough Diameter Application-ID + Command-Code from CER/CER-like."""
    if len(payload) < 20:
        return None, None
    # Version(1) len(3) flags(1) cmd(3) app(4) hop(4) end(4)
    cmd = (payload[5] << 16) | (payload[6] << 8) | payload[7]
    app = struct.unpack("!I", payload[8:12])[0]
    return app, cmd


def diam_avp_search(payload, avp_code):
    """Find first AVP uint32 value (very rough)."""
    if len(payload) < 20:
        return []
    off = 20
    found = []
    while off + 8 <= len(payload):
        code = struct.unpack("!I", payload[off : off + 4])[0]
        flen = struct.unpack("!I", payload[off + 4 : off + 8])[0]
        avp_len = flen & 0x00FFFFFF
        if avp_len < 8:
            break
        data = payload[off + 8 : off + avp_len]
        if code == avp_code and len(data) >= 4:
            found.append(struct.unpack("!I", data[:4])[0])
        pad = (4 - (avp_len % 4)) % 4
        off += avp_len + pad
    return found


APP = {16777238: "Gx", 16777236: "Rx", 16777251: "S6a", 16777216: "Cx"}
CMD = {
    258: "ReAuthReq/AA", 272: "CCReq", 275: "SessionTerm",
    265: "AAReq", 274: "ASReq", 275: "STReq",
}


events = []
diam_events = []

for p in rdpcap(PCAP):
    if not p.haslayer(IP):
        continue
    ts = float(p.time)
    src, dst = p[IP].src, p[IP].dst

    if p.haslayer(UDP):
        u = p[UDP]
        raw = bytes(u.payload)
        if u.sport == GTP or u.dport == GTP:
            if len(raw) >= 2:
                t = raw[1]
                if t in GTP_NAMES:
                    events.append(
                        {
                            "ts": ts,
                            "proto": "GTP",
                            "name": GTP_NAMES[t],
                            "src": src,
                            "dst": dst,
                            "teid": gtpc_teid(raw),
                            "len": len(raw),
                            "cause": gtpc_cause(raw) if t == 96 else None,
                        }
                    )
        if u.sport == PFCP or u.dport == PFCP:
            if len(raw) >= 2:
                t = raw[1]
                if t in PFCP_NAMES:
                    events.append(
                        {
                            "ts": ts,
                            "proto": "PFCP",
                            "name": PFCP_NAMES[t],
                            "src": src,
                            "dst": dst,
                            "teid": 0,
                            "len": len(raw),
                            "cause": pfcp_cause(raw) if t == 53 else None,
                        }
                    )

    if p.haslayer(TCP):
        t = p[TCP]
        if t.sport == DIAM or t.dport == DIAM:
            raw = bytes(t.payload)
            if len(raw) < 20:
                continue
            app, cmd = diam_app_cmd(raw)
            if app in APP:
                cc = diam_avp_search(raw, 263)  # CC-Request-Type / Session-Id rough
                cc_type = diam_avp_search(raw, 416)  # CC-Request-Type
                diam_events.append(
                    {
                        "ts": ts,
                        "app": APP.get(app, str(app)),
                        "cmd": cmd,
                        "src": src,
                        "dst": dst,
                        "len": len(raw),
                        "cc_type": cc_type[0] if cc_type else None,
                    }
                )


print("=" * 72)
print(f"PCAP: {PCAP}")
print(f"Total GTP/PFCP events: {len(events)}")
print(f"Total Diameter (Gx/Rx/S6a/Cx) events: {len(diam_events)}")

# Create Bearer failures
cbr_fail = [e for e in events if e["name"] == "CreateBearerRsp" and e.get("cause") == CAUSE74]
print(f"\nCreate Bearer Response with cause 74: {len(cbr_fail)}")

if cbr_fail:
    print("\n--- Create Bearer cause-74 episodes ---")
    for e in cbr_fail:
        dt = datetime.fromtimestamp(e["ts"])
        print(f"\n{dt.strftime('%H:%M:%S.%f')[:-3]} CreateBearerRsp {e['src']}->{e['dst']} teid=0x{e['teid']:x}")
        t0, t1 = e["ts"] - 0.05, e["ts"] + 0.02
        for x in sorted(events, key=lambda z: z["ts"]):
            if t0 <= x["ts"] <= t1:
                dt2 = datetime.fromtimestamp(x["ts"])
                c = f" cause={x['cause']}" if x.get("cause") is not None else ""
                print(
                    f"  {dt2.strftime('%H:%M:%S.%f')[:-3]} {x['proto']:4} {x['name']:16} "
                    f"{x['src']}->{x['dst']} len={x['len']}{c}"
                )
        for d in sorted(diam_events, key=lambda z: z["ts"]):
            if t0 - 2 <= d["ts"] <= t1 + 2:
                dt2 = datetime.fromtimestamp(d["ts"])
                ct = f" CC-Type={d['cc_type']}" if d["cc_type"] is not None else ""
                print(
                    f"  {dt2.strftime('%H:%M:%S.%f')[:-3]} DIAM {d['app']:3} cmd={d['cmd']} "
                    f"{d['src']}->{d['dst']} len={d['len']}{ct}"
                )

# All Create Bearer pairs
cbr = [e for e in events if e["name"] in ("CreateBearerReq", "CreateBearerRsp")]
print(f"\n--- All Create Bearer (S5/S11) ---")
for e in sorted(cbr, key=lambda z: z["ts"]):
    dt = datetime.fromtimestamp(e["ts"])
    c = f" cause={e['cause']}" if e.get("cause") is not None else ""
    print(
        f"{dt.strftime('%H:%M:%S.%f')[:-3]} {e['name']:16} {e['src']}->{e['dst']} "
        f"teid=0x{e['teid']:x} len={e['len']}{c}"
    )

# Diameter summary by app
print("\n--- Diameter summary ---")
by_app = defaultdict(int)
for d in diam_events:
    by_app[d["app"]] += 1
for app, n in sorted(by_app.items()):
    print(f"  {app}: {n} messages")

# Gx RAR/CC around first Create Bearer req
cbr_req = [e for e in events if e["name"] == "CreateBearerReq"]
if cbr_req:
    t0 = cbr_req[0]["ts"] - 5
    t1 = cbr_req[0]["ts"] + 1
    print(f"\n--- Diameter +/-5s before first CreateBearerReq ---")
    for d in sorted(diam_events, key=lambda z: z["ts"]):
        if t0 <= d["ts"] <= t1:
            dt = datetime.fromtimestamp(d["ts"])
            ct = f" CC-Type={d['cc_type']}" if d["cc_type"] is not None else ""
            print(
                f"{dt.strftime('%H:%M:%S.%f')[:-3]} {d['app']:3} cmd={d['cmd']} "
                f"{d['src']}->{d['dst']}{ct}"
            )
