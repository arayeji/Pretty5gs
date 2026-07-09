#!/usr/bin/env python3
from scapy.all import rdpcap, UDP, Raw
from scapy.layers.inet import IP
from collections import defaultdict
import struct
import sys

pcap_path = sys.argv[1] if len(sys.argv) > 1 else r"c:\Capture\pfafterv2.pcap"
HOME_SMF = "127.0.0.4"
SGWC = "127.0.0.3"
MME = "127.0.0.2"

def gtpv2(pkt):
    if IP not in pkt or UDP not in pkt:
        return None
    d = bytes(pkt[Raw].load)
    if len(d) < 11 or (d[0] >> 5) != 2:
        return None
    mt = d[1]
    teid = struct.unpack("!I", d[4:8])[0]
    seq = struct.unpack("!I", b"\x00" + d[8:11])[0] >> 8
    causes = []
    i = 11
    while i + 3 <= len(d):
        ie = d[i]
        ln = struct.unpack("!H", d[i + 1:i + 3])[0]
        val = d[i + 3:i + 3 + ln]
        if ie == 2 and val:
            causes.append(val[0])
        i += 3 + ln
    return dict(mt=mt, teid=teid, seq=seq, causes=causes,
                src=pkt[IP].src, dst=pkt[IP].dst, t=float(pkt.time))

def pfcp(pkt):
    if IP not in pkt or UDP not in pkt:
        return None
    if pkt[UDP].dport != 8805 and pkt[UDP].sport != 8805:
        return None
    d = bytes(pkt[Raw].load)
    flags = d[0]
    mt = d[1]
    off = 12 if flags & 1 else 4
    if len(d) < off + 4:
        return None
    seid = struct.unpack("!Q", d[4:12])[0] if flags & 1 else None
    cause = None
    i = off + 4
    while i + 4 <= len(d):
        t = struct.unpack("!H", d[i:i + 2])[0]
        ln = struct.unpack("!H", d[i + 2:i + 4])[0]
        val = d[i + 4:i + 4 + ln]
        if t == 19 and val:
            cause = val[0]
        i += 4 + ln
    return dict(mt=mt, seid=seid, cause=cause,
                src=pkt[IP].src, dst=pkt[IP].dst, t=float(pkt.time))

pcap = rdpcap(pcap_path)
gtp = [g for p in pcap if (g := gtpv2(p))]
pf = [p for p in (pfcp(x) for x in pcap) if p]
t0 = min(x["t"] for x in gtp)

def uniq_tx(msgs, mt, src, dst):
    return set(m["seq"] for m in msgs if m["mt"] == mt and m["src"] == src and m["dst"] == dst)

home_csr = uniq_tx(gtp, 32, SGWC, HOME_SMF)
home_csr_rsp_ok = sum(1 for m in gtp if m["mt"] == 33 and m["src"] == HOME_SMF
                      and m["dst"] == SGWC and 16 in m["causes"])
home_dsr = uniq_tx(gtp, 36, SGWC, HOME_SMF)
home_dsr_rsp = uniq_tx(gtp, 37, HOME_SMF, SGWC)
s11_csr = uniq_tx(gtp, 32, MME, SGWC)
s11_csr_rsp_ok = sum(1 for m in gtp if m["mt"] == 33 and m["src"] == SGWC
                    and m["dst"] == MME and 16 in m["causes"])
s11_dsr = uniq_tx(gtp, 36, MME, SGWC)
roam_csr = [m for m in gtp if m["mt"] == 32 and m["src"] == SGWC
            and m["dst"].startswith("185.5.")]
roam_csr_u = len(set((m["seq"], m["dst"]) for m in roam_csr))

print("=== GTP unique transactions (508s post-restart) ===")
print("S11  CSR unique seq:", len(s11_csr), " CSRsp accept:", s11_csr_rsp_ok)
print("S11  DSR unique seq:", len(s11_dsr))
print("Home S5 CSR unique seq:", len(home_csr), " CSRsp accept:", home_csr_rsp_ok)
print("Home S5 DSR unique seq:", len(home_dsr), " DSRsp unique seq:", len(home_dsr_rsp))
print("Roam S5 CSR unique (seq,pgw):", roam_csr_u)
print("Home SMF net (unique CSR-DSR):", len(home_csr) - len(home_dsr))

SGWC_PFCP = "127.0.0.3"
est = set()
ok = set()
dele = set()
for m in pf:
    if m["mt"] == 50 and m["src"] == SGWC_PFCP:
        est.add(m["seid"])
    if m["mt"] == 51 and m["src"] == "127.0.0.6" and m["cause"] == 1:
        ok.add(m["seid"])
    if m["mt"] == 54 and m["src"] == SGWC_PFCP:
        dele.add(m["seid"])
print("SGW-U PFCP est req seids:", len(est), " accepted:", len(ok), " del req seids:", len(dele))

SMF_PFCP = "127.0.0.4"
est2 = set()
ok2 = set()
del2 = set()
for m in pf:
    if m["mt"] == 50 and m["src"] == SMF_PFCP:
        est2.add(m["seid"])
    if m["mt"] == 51 and m["src"] == "127.0.0.7" and m["cause"] == 1:
        ok2.add(m["seid"])
    if m["mt"] == 54 and m["src"] == SMF_PFCP:
        del2.add(m["seid"])
print("PGW-U PFCP est req seids:", len(est2), " accepted:", len(ok2), " del req seids:", len(del2))

b = defaultdict(set)
for m in gtp:
    if m["mt"] == 32 and m["src"] == MME and m["dst"] == SGWC:
        b[int((m["t"] - t0) // 60)].add(m["seq"])
print("S11 CSR unique seq per minute:", {k: len(v) for k, v in sorted(b.items())})

b2 = defaultdict(lambda: {"c": set(), "d": set()})
for m in gtp:
    bn = int((m["t"] - t0) // 60)
    if m["mt"] == 32 and m["src"] == SGWC and m["dst"] == HOME_SMF:
        b2[bn]["c"].add(m["seq"])
    if m["mt"] == 36 and m["src"] == SGWC and m["dst"] == HOME_SMF:
        b2[bn]["d"].add(m["seq"])
print("Home S5 per minute unique CSR/DSR net:")
for k in sorted(b2):
    c = len(b2[k]["c"])
    d = len(b2[k]["d"])
    print("  min%d: csr=%d dsr=%d net=%d" % (k, c, d, c - d))
