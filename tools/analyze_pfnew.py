from scapy.all import rdpcap, UDP, Raw, IP
from collections import Counter, defaultdict
import struct

pcap = rdpcap(r'c:\Capture\pfnew.pcap')
SGWC='127.0.0.3'; SMF='127.0.0.4'; MME='127.0.0.2'; SGWU='127.0.0.6'
t0 = float(pcap[0].time)

def gtp2(pkt):
    try:
        d = bytes(pkt[Raw].load)
        if (d[0] >> 5) != 2: return None
        mt = d[1]
        has_teid = bool(d[0] & 0x08)
        off = 12 if has_teid else 8
        cause = None
        i = off
        while i+4 <= len(d):
            ie_t = d[i]
            ie_l = struct.unpack('!H', d[i+1:i+3])[0]
            if ie_t == 2 and ie_l >= 2:
                cause = d[i+4]
            i += 4 + ie_l
        return mt, cause
    except:
        return None

def pfcp_parse(pkt):
    try:
        d = bytes(pkt[Raw].load)
        mt = d[1]
        i = 8
        cause = None
        while i+4 <= len(d):
            t = struct.unpack('!H', d[i:i+2])[0]
            l = struct.unpack('!H', d[i+2:i+4])[0]
            if t == 19 and l >= 1:
                cause = d[i+4]
            i += 4 + l
        return mt, cause
    except:
        return None

# GTPv2 summary
gtp_msgs = defaultdict(list)
for p in pcap:
    if IP not in p or UDP not in p: continue
    if p[UDP].dport != 2123 and p[UDP].sport != 2123: continue
    r = gtp2(p)
    if not r: continue
    mt, cause = r
    gtp_msgs[(p[IP].src, p[IP].dst, mt)].append(cause)

print('=== GTPv2 message summary ===')
for (src, dst, mt), causes in sorted(gtp_msgs.items(), key=lambda x: -len(x[1])):
    cc = Counter(c for c in causes if c is not None)
    print(f'  {src} -> {dst}  type={mt}  count={len(causes)}  causes={dict(cc)}')

# PFCP summary
pfcp_msgs = defaultdict(list)
for p in pcap:
    if IP not in p or UDP not in p: continue
    if p[UDP].dport != 8805 and p[UDP].sport != 8805: continue
    r = pfcp_parse(p)
    if not r: continue
    mt, cause = r
    pfcp_msgs[(p[IP].src, p[IP].dst, mt)].append(cause)

print()
print('=== PFCP message summary ===')
for (src, dst, mt), causes in sorted(pfcp_msgs.items(), key=lambda x: -len(x[1])):
    cc = Counter(c for c in causes if c is not None)
    print(f'  {src} -> {dst}  pfcp_type={mt}  count={len(causes)}  causes={dict(cc)}')

# S11 CSR success vs failure
s11_csr_rsp = gtp_msgs.get((SGWC, MME, 33), [])
print()
print('=== S11 CSR Response causes (SGWC->MME) ===')
print(Counter(c for c in s11_csr_rsp if c is not None))
success_s11 = sum(1 for c in s11_csr_rsp if c == 16)
fail_s11 = sum(1 for c in s11_csr_rsp if c != 16 and c is not None)
print(f'  Success (cause=16): {success_s11}')
print(f'  Failure: {fail_s11}')

# S5 CSR responses
s5_csr_rsp = gtp_msgs.get((SMF, SGWC, 33), [])
print()
print('=== S5 CSR Response causes (SMF->SGWC) visible in pcap ===')
print(Counter(c for c in s5_csr_rsp if c is not None))
print(f'  (Note: same-machine S5 may route via loopback, not seen in pcap)')
