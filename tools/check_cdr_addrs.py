#!/usr/bin/env python3
"""Dump address fields from CDR records inside GTP' DTRR packets.

Walks the BER structure of each record and prints every 4-byte
[0]-tagged address it finds, with the enclosing outer tag, so byte
order problems (reversed IPs) are immediately visible.
"""
import sys
from scapy.all import rdpcap, UDP, Raw

def ber_iter(buf, off, end):
    """Yield (tag_no, constructed, value_off, value_len) for TLVs in buf[off:end]."""
    while off < end:
        if off + 2 > end:
            return
        first = buf[off]
        constructed = bool(first & 0x20)
        tag = first & 0x1f
        off += 1
        if tag == 0x1f:
            tag = buf[off]
            off += 1
        ln = buf[off]
        off += 1
        if ln & 0x80:
            n = ln & 0x7f
            ln = 0
            for i in range(n):
                ln = (ln << 8) | buf[off]
                off += 1
        yield tag, constructed, off, ln
        off += ln

def walk(buf, off, end, path, out):
    for tag, cons, voff, vlen in ber_iter(buf, off, end):
        p = path + [tag]
        if cons:
            walk(buf, voff, voff + vlen, p, out)
        else:
            if vlen == 4 and tag == 0:
                ip = ".".join(str(b) for b in buf[voff:voff+vlen])
                out.append(("/".join(map(str, p)), ip))

def parse_dtrr(data):
    if len(data) < 6 or data[1] != 0xf0:
        return None
    plen = (data[2] << 8) | data[3]
    p = data[6:6+plen]
    off = 0
    while off < len(p):
        tag = p[off]
        if tag == 126:
            off += 2
            continue
        if off + 3 > len(p):
            break
        ilen = (p[off+1] << 8) | p[off+2]
        val = p[off+3:off+3+ilen]
        off += 3 + ilen
        if tag == 252:
            rb = val[4:]
            recs = []
            o = 0
            while o + 2 <= len(rb):
                rl = (rb[o] << 8) | rb[o+1]
                o += 2
                recs.append(rb[o:o+rl])
                o += rl
            return recs
    return None

def main():
    path = sys.argv[1]
    pkts = rdpcap(path)
    nrec = 0
    for pkt in pkts:
        if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
            continue
        recs = parse_dtrr(bytes(pkt[Raw].load))
        if not recs:
            continue
        for rec in recs:
            nrec += 1
            if nrec > 6:
                return
            # outer: [78] SGWRecord or [79] PGWRecord
            for tag, cons, voff, vlen in ber_iter(rec, 0, len(rec)):
                rtype = {78: "SGWRecord", 79: "PGWRecord",
                         84: "SGWRecord(84)", 85: "PGWRecord(85)"}.get(
                             tag, "rec[%d]" % tag)
                out = []
                walk(rec, voff, voff + vlen, [], out)
                print("--- %s #%d" % (rtype, nrec))
                for p, ip in out:
                    print("    tagpath [%s] -> %s" % (p, ip))

if __name__ == "__main__":
    main()
