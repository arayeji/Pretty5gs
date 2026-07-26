#!/usr/bin/env python3
"""Dump address tag paths for PGWRecords (outer tag 79/85) in DTRR captures."""
import sys
from collections import Counter
from scapy.all import rdpcap, UDP, Raw

def ber_iter(buf, off, end):
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
        elif vlen == 4:
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
    want = int(sys.argv[2]) if len(sys.argv) > 2 else 79
    pkts = rdpcap(path)
    types = Counter()
    shown = 0
    for pkt in pkts:
        if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
            continue
        recs = parse_dtrr(bytes(pkt[Raw].load))
        if not recs:
            continue
        for rec in recs:
            for tag, cons, voff, vlen in ber_iter(rec, 0, len(rec)):
                types[tag] += 1
                if tag == want and shown < 5:
                    shown += 1
                    out = []
                    walk(rec, voff, voff + vlen, [], out)
                    print("--- record tag %d #%d" % (tag, shown))
                    for p, ip in out:
                        print("    tagpath [%s] -> %s" % (p, ip))
    print("record outer-tag counts:", dict(types))

if __name__ == "__main__":
    main()
