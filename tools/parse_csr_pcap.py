#!/usr/bin/env python3
"""Compare Create Session Request IEs in pcap (Open5GS vs reference)."""
import struct
import sys
from scapy.all import rdpcap, UDP, IP, Raw

IE = {
    1: "IMSI", 2: "Cause", 3: "Recovery", 71: "APN", 72: "AMBR", 73: "EBI",
    75: "MEI", 76: "MSISDN", 77: "Indication", 78: "PCO", 79: "PAA",
    80: "Bearer_QoS", 81: "Charging_Characteristics", 82: "Charging_ID",
    83: "Bearer_TFT", 84: "F-TEID", 86: "Selection_Mode", 87: "PDN_Type",
    88: "ULI", 89: "Serving_Network", 90: "RAT_Type", 92: "APN_Restriction",
    93: "Bearer_Context", 94: "Bearer_Context_removed", 95: "UE_Time_Zone",
    114: "EPCO", 127: "Private_Extension", 177: "MME_FQ-CSID", 178: "SGW_FQ-CSID",
}

# Open5GS mme-s11-build.c CSR IEs (attach, conditional noted)
OPEN5GS_ALWAYS = {
    "IMSI", "ULI", "Serving_Network", "RAT_Type", "Sender_F-TEID",
    "PGW_S5C_F-TEID", "APN", "Selection_Mode", "PDN_Type", "Indication",
    "PAA", "APN_Restriction", "Bearer_Context", "UE_Time_Zone",
}
OPEN5GS_OPTIONAL = {
    "MEI", "MSISDN", "AMBR", "PCO", "EPCO", "Charging_Characteristics",
}


def parse_ie_list(buf):
    pos = 0
    items = []
    while pos + 4 <= len(buf):
        t = buf[pos]
        ln = struct.unpack(">H", buf[pos + 1 : pos + 3])[0]
        inst = buf[pos + 3]
        pos += 4
        val = buf[pos : pos + ln]
        pos += ln
        name = IE.get(t, f"IE_{t}")
        items.append((t, name, ln, inst, val))
    return items


def apn_decode(val):
    labels = []
    j = 0
    while j < len(val):
        l = val[j]
        j += 1
        if l:
            labels.append(val[j : j + l].decode("ascii", "replace"))
            j += l
    return ".".join(labels)


def csr_body(raw):
    if len(raw) < 8 or (raw[0] >> 5) != 2 or raw[1] != 32:
        return None
    pos = 8 if (raw[0] & 0x08) else 4
    if raw[0] & 0x02:
        pos += 4
    return raw[pos:]


def top_and_bearer(ies):
    top = set()
    bearer = set()
    for t, name, ln, inst, val in ies:
        if t in (93, 94):
            for t2, n2, ln2, inst2, val2 in parse_ie_list(val):
                bearer.add(n2)
        else:
            top.add(name)
            if name == "F-TEID":
                top.add("Sender_or_other_F-TEID")
    return top, bearer


def main():
    if len(sys.argv) < 2:
        print("usage: parse_csr_pcap.py <file.pcap>", file=sys.stderr)
        sys.exit(1)
    pcap = sys.argv[1]
    pkts = rdpcap(pcap)

    o5_top = set()
    o5_bearer = set()
    ref_top = set()
    ref_bearer = set()
    o5_frame = None
    ref_frame = None

    for i, p in enumerate(pkts):
        if not (p.haslayer(UDP) and p.haslayer(Raw) and p.haslayer(IP)):
            continue
        if p[UDP].dport != 2123 and p[UDP].sport != 2123:
            continue
        body = csr_body(bytes(p[Raw].load))
        if body is None:
            continue
        ies = parse_ie_list(body)
        src, dst = p[IP].src, p[IP].dst
        top, bearer = top_and_bearer(ies)

        if src == "127.0.0.1" and dst == "127.0.0.2":
            o5_top |= top
            o5_bearer |= bearer
            o5_frame = (i + 1, ies)
        if src == "203.0.113.2":
            ref_top |= top
            ref_bearer |= bearer
            ref_frame = (i + 1, ies)

    def print_frame(label, frame):
        if not frame:
            return
        num, ies = frame
        print(f"=== {label} (frame {num}) ===")
        for t, name, ln, inst, val in ies:
            if t in (93, 94):
                print(f"  {name}:")
                for t2, n2, ln2, inst2, val2 in parse_ie_list(val):
                    extra = ""
                    if n2 == "F-TEID" and len(val2) >= 2:
                        extra = f" iftype={val2[1]}"
                    print(f"    {n2} (len={ln2}){extra}")
            elif name == "APN":
                print(f"  APN: {apn_decode(val)}")
            elif name == "Serving_Network":
                print(f"  Serving_Network: {val.hex()}")
            elif name == "F-TEID" and len(val) >= 2:
                print(f"  F-TEID: len={ln} iftype={val[1]} addr={val[2:].hex()}")
            else:
                print(f"  {name} (len={ln})")
        print()

    print_frame("Open5GS MME -> SGWC", o5_frame)
    print_frame("Reference (203.0.113.2 -> PGW/SMF)", ref_frame)

    # Map F-TEID names
    def normalize_top(s):
        out = set()
        for n in s:
            if n in ("F-TEID", "Sender_or_other_F-TEID"):
                out.add("F-TEID_present")
            else:
                out.add(n)
        return out

    o5n = normalize_top(o5_top)
    refn = normalize_top(ref_top)

    print("=== Top-level IEs in REF but NOT in Open5GS capture ===")
    for x in sorted(refn - o5n):
        print(f"  - {x}")
    print("=== Top-level IEs in Open5GS capture but NOT in REF ===")
    for x in sorted(o5n - refn):
        print(f"  - {x}")

    print("=== Bearer-context IEs in REF but NOT in Open5GS ===")
    for x in sorted(ref_bearer - o5_bearer):
        print(f"  - {x}")
    print("=== Bearer-context IEs in Open5GS but NOT in REF ===")
    for x in sorted(o5_bearer - ref_bearer):
        print(f"  - {x}")

    print("=== Open5GS code sends (attach) but absent in your Open5GS CSR ===")
    code_map = {
        "Sender_F-TEID": "F-TEID (S11 MME)",
        "PGW_S5C_F-TEID": "F-TEID (PGW S5-C)",
        "ULI": "ULI",
        "Serving_Network": "Serving_Network",
        "RAT_Type": "RAT_Type",
    }
    captured = o5n.copy()
    for code_name, cap_name in code_map.items():
        if code_name in OPEN5GS_ALWAYS and cap_name not in captured and "F-TEID" not in captured:
            pass
    missing_vs_code = []
    if "ULI" not in o5_top:
        missing_vs_code.append("ULI (User Location Information)")
    if "Serving_Network" not in o5_top:
        missing_vs_code.append("Serving_Network")
    if "RAT_Type" not in o5_top:
        missing_vs_code.append("RAT_Type")
    fteid_count = sum(1 for t, n, ln, inst, val in (o5_frame[1] if o5_frame else []) if n == "F-TEID")
    if fteid_count < 2:
        missing_vs_code.append("Second F-TEID (PGW S5-C) — only one F-TEID in packet?")
    for x in missing_vs_code:
        print(f"  - {x}")

    print("=== Optional in Open5GS code, check REF ===")
    for x in sorted(OPEN5GS_OPTIONAL):
        in_o5 = x in o5_top or (x == "PCO" and "PCO" in o5_top) or (x == "EPCO" and "EPCO" in o5_top)
        in_ref = x in ref_top or (x == "PCO" and "PCO" in ref_top)
        print(f"  {x}: Open5GS_cap={in_o5} Ref={in_ref}")


if __name__ == "__main__":
    main()
