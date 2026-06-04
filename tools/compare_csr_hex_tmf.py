#!/usr/bin/env python3
"""Compare user CSR hex with Huawei 44_SGW TMF embedded CSR."""
import struct
from pathlib import Path

USER_HEX = (
    "4820010d00000000001ff0000100080034123169334523f94c0006008999112921544b"
    "000800539617018129401056000d001834f264684c34f26407dfb00b5300030034f264"
    "52000100064d000a000010000000000200000057000900860005f41c2ee00b1347001a"
    "00064d43494e4554066d6e63303131066d636334333204677072738000010000630001"
    "00014f00050001000000007f00010000480008000010624e004189374e002900808021"
    "1001000010810600000000830600000000000d00000a00000500001000c02306010000"
    "0600005d002c0049000100055700090284531aaa2c2ee00b12500016006c0900000000"
    "0000000000000000000000000000000000007200020000005f0002000800"
)

N = {
    1: "IMSI", 2: "Cause", 3: "Recovery", 71: "APN", 72: "AMBR", 75: "MEI",
    76: "MSISDN", 77: "Indication", 78: "PCO", 79: "PAA", 80: "Bearer_QoS",
    82: "RAT", 83: "Serving_Network", 86: "ULI", 87: "F-TEID",
    93: "Bearer_Context", 95: "Charging_Char", 99: "PDN_Type",
    109: "PDN_Connection", 114: "UE_Time_Zone", 127: "APN_Restriction",
    128: "Selection_Mode", 73: "EBI",
}
IFT = {4: "S5-SGW-U", 6: "S5-SGW-C", 7: "S5-PGW-C", 10: "S11-MME-C"}


def parse_ies(buf):
    pos = 0
    items = []
    while pos + 4 <= len(buf):
        t = buf[pos]
        ln = int.from_bytes(buf[pos + 1 : pos + 3], "big")
        inst = buf[pos + 3]
        val = buf[pos + 4 : pos + 4 + ln]
        pos += 4 + ln
        items.append((t, N.get(t, f"IE_{t}"), ln, inst, val))
    return items


def apn(v):
    labels = []
    j = 0
    while j < len(v):
        l = v[j]
        j += 1
        if l:
            labels.append(v[j : j + l].decode())
            j += l
    return ".".join(labels)


def fteid_str(val):
    it = val[0] & 0x3F
    teid = int.from_bytes(val[1:5], "big")
    ip = ".".join(str(b) for b in val[5:9]) if len(val) >= 9 else val[5:].hex()
    return f"if={it}({IFT.get(it, it)}) teid=0x{teid:08x} ip={ip}"


def ie_map(items):
    m = {}
    fteid_n = 0
    for t, name, ln, inst, val in items:
        if name == "APN":
            m["APN"] = apn(val)
        elif name == "F-TEID":
            m[f"F-TEID_top_{fteid_n}"] = fteid_str(val)
            fteid_n += 1
        elif name == "Bearer_Context":
            for t2, n2, ln2, i2, v2 in parse_ies(val):
                if n2 == "F-TEID":
                    m["Bearer_F-TEID"] = fteid_str(v2)
                elif n2 == "EBI":
                    m["EBI"] = v2[0]
                elif n2 == "Bearer_QoS":
                    m["Bearer_QoS"] = f"len={ln2}"
        else:
            m[name] = f"present len={ln}"
    m["_types"] = [n for _, n, _, _, _ in items]
    return m


def csr_body(blob, off):
    if (blob[off] >> 5) != 2 or blob[off + 1] != 32:
        return None
    h = off + 12 if blob[off] & 0x08 else off + 8
    ln = int.from_bytes(blob[off + 2 : off + 4], "big")
    return blob[h : off + 4 + ln]


def main():
    user = bytes.fromhex(USER_HEX)
    tmf_path = Path(
        "."
        r"\44_SGW_S5_S8_Interface_Trace_20260601_201200+0300_0.tmf"
    )
    data = tmf_path.read_bytes()

    u_items = parse_ies(user[12:])
    # First unique CSR in TMF (offset 287)
    t_body = csr_body(data, 287)
    t_items = parse_ies(t_body)

    um = ie_map(u_items)
    tm = ie_map(t_items)

    print("=== One Create Session Request: your hex vs 44_SGW TMF ===\n")
    print("USER IE order:", um["_types"])
    print("TMF  IE order:", tm["_types"])
    print()

    only_t = [x for x in tm["_types"] if x not in um["_types"]]
    only_u = [x for x in um["_types"] if x not in tm["_types"]]
    print("IE types in TMF only:", only_t or "(none)")
    print("IE types in your hex only:", only_u or "(none)")
    print()

    keys = sorted(
        set(k for k in um if not k.startswith("_"))
        | set(k for k in tm if not k.startswith("_"))
    )
    print(f"{'Field':<18} {'Your hex':<42} {'TMF 44_SGW':<42}")
    print("-" * 102)
    for k in keys:
        print(f"{k:<18} {str(um.get(k, '—')):<42} {str(tm.get(k, '—')):<42}")


if __name__ == "__main__":
    main()
