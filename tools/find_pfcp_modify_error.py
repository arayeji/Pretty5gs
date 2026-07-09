#!/usr/bin/env python3
"""
Find the PFCP Session Modification Request whose Session Modification Response
returned a failure cause (default: 73 = RULE_CREATION_MODIFICATION_FAILURE),
then decode the offending FAR operations in that request.

Matches the SGW-U / VPP error:
  "SGW-U rejected PFCP Session Modification PFCP cause[73] ... ufar a: unexpected operation"

Usage:
  python tools/find_pfcp_modify_error.py [pcap] [cause]
Defaults:
  pcap  = c:\\Capture\\pfcperror3.pcap
  cause = 73
"""
import struct
import sys

from scapy.all import rdpcap, UDP, Raw
from scapy.layers.inet import IP

PCAP = sys.argv[1] if len(sys.argv) > 1 else r"c:\Capture\pfcperror3.pcap"
WANT_CAUSE = int(sys.argv[2]) if len(sys.argv) > 2 else 73

# PFCP message types (TS 29.244)
MT = {
    52: "SessionModificationRequest",
    53: "SessionModificationResponse",
    50: "SessionEstablishmentRequest",
    51: "SessionEstablishmentResponse",
    54: "SessionDeletionRequest",
    55: "SessionDeletionResponse",
    56: "SessionReportRequest",
    57: "SessionReportResponse",
}

# PFCP IE types we care about
IE_CAUSE = 19
IE_OFFENDING_IE = 40
IE_CREATE_PDR = 1
IE_CREATE_FAR = 3
IE_UPDATE_PDR = 9
IE_UPDATE_FAR = 10
IE_REMOVE_PDR = 15
IE_REMOVE_FAR = 16
IE_UPDATE_BAR = 86
IE_APPLY_ACTION = 44
IE_FAR_ID = 108
IE_PDR_ID = 56
IE_UPD_FWD_PARAMS = 11

GROUPED = {
    IE_CREATE_PDR, IE_CREATE_FAR, IE_UPDATE_PDR, IE_UPDATE_FAR,
    IE_REMOVE_PDR, IE_REMOVE_FAR, IE_UPDATE_BAR, IE_UPD_FWD_PARAMS,
    7, 8,  # create/update URR-ish (not strictly needed)
}

IE_NAME = {
    IE_CAUSE: "Cause", IE_OFFENDING_IE: "OffendingIE",
    IE_CREATE_PDR: "CreatePDR", IE_CREATE_FAR: "CreateFAR",
    IE_UPDATE_PDR: "UpdatePDR", IE_UPDATE_FAR: "UpdateFAR",
    IE_REMOVE_PDR: "RemovePDR", IE_REMOVE_FAR: "RemoveFAR",
    IE_UPDATE_BAR: "UpdateBAR", IE_APPLY_ACTION: "ApplyAction",
    IE_FAR_ID: "FAR_ID", IE_PDR_ID: "PDR_ID",
    IE_UPD_FWD_PARAMS: "UpdateForwardingParameters",
}

# Apply Action is a per-octet bitmap (TS 29.244 8.2.26).
# octet 1: DROP FORW BUFF NOCP DUPL IPMA IPMD DFRT (bit1..bit8)
# octet 2: EDRT BDPN DDPN
APPLY_OCT1 = [
    (0x01, "DROP"), (0x02, "FORW"), (0x04, "BUFF"), (0x08, "NOCP"),
    (0x10, "DUPL"), (0x20, "IPMA"), (0x40, "IPMD"), (0x80, "DFRT"),
]
APPLY_OCT2 = [(0x01, "EDRT"), (0x02, "BDPN"), (0x04, "DDPN")]


def apply_action_str(raw_bytes):
    if not raw_bytes:
        return "(empty)"
    names = [n for bit, n in APPLY_OCT1 if raw_bytes[0] & bit]
    if len(raw_bytes) >= 2:
        names += [n for bit, n in APPLY_OCT2 if raw_bytes[1] & bit]
    return "|".join(names) if names else "(none)"


def parse_pfcp(d):
    if len(d) < 8:
        return None
    flags = d[0]
    if (flags >> 5) != 1:  # PFCP version 1
        return None
    mt = d[1]
    has_seid = flags & 0x01
    if has_seid:
        if len(d) < 16:
            return None
        seid = struct.unpack("!Q", d[4:12])[0]
        seq = struct.unpack("!I", b"\x00" + d[12:15])[0]
        i = 16
    else:
        seid = None
        seq = struct.unpack("!I", b"\x00" + d[4:7])[0]
        i = 8
    return dict(mt=mt, seid=seid, seq=seq, ies=d[i:])


def iter_ies(buf):
    i = 0
    while i + 4 <= len(buf):
        t = struct.unpack("!H", buf[i:i + 2])[0]
        ln = struct.unpack("!H", buf[i + 2:i + 4])[0]
        val = buf[i + 4:i + 4 + ln]
        yield t, val
        i += 4 + ln


def ie_summary(t, val):
    """One-line summary for a leaf/known IE."""
    if t == IE_APPLY_ACTION:
        return "ApplyAction=%s [%s]" % (apply_action_str(val), val.hex())
    if t == IE_FAR_ID and len(val) >= 4:
        return "FAR_ID=%d" % struct.unpack("!I", val[:4])[0]
    if t == IE_PDR_ID and len(val) >= 2:
        return "PDR_ID=%d" % struct.unpack("!H", val[:2])[0]
    if t == IE_CAUSE and val:
        return "Cause=%d" % val[0]
    if t == IE_OFFENDING_IE and len(val) >= 2:
        ot = struct.unpack("!H", val[:2])[0]
        return "OffendingIE=%s(%d)" % (IE_NAME.get(ot, "?"), ot)
    return None


def dump_ies(buf, indent=8):
    pad = " " * indent
    for t, val in iter_ies(buf):
        name = IE_NAME.get(t, "IE-%d" % t)
        summ = ie_summary(t, val)
        if t in GROUPED:
            print("%s%s {" % (pad, name))
            dump_ies(val, indent + 4)
            print("%s}" % pad)
        elif summ:
            print("%s%s" % (pad, summ))
        else:
            print("%s%s len=%d %s" % (pad, name, len(val),
                                      val.hex() if len(val) <= 24 else
                                      val[:24].hex() + "..."))


def decode_far_ops(ies):
    """Return human-readable list of FAR/PDR operations in a modification req."""
    ops = []
    for t, val in iter_ies(ies):
        if t in (IE_UPDATE_FAR, IE_CREATE_FAR):
            far_id = None
            apply_action = None
            for st, sv in iter_ies(val):
                if st == IE_FAR_ID and len(sv) >= 4:
                    far_id = struct.unpack("!I", sv[:4])[0]
                elif st == IE_APPLY_ACTION and sv:
                    apply_action = sv
            aa = (apply_action_str(apply_action)
                  if apply_action is not None else "-")
            ops.append("%s FAR_ID=%s ApplyAction=%s" % (
                IE_NAME[t], far_id, aa))
        elif t in (IE_REMOVE_FAR,):
            far_id = None
            for st, sv in iter_ies(val):
                if st == IE_FAR_ID and len(sv) >= 4:
                    far_id = struct.unpack("!I", sv[:4])[0]
            ops.append("RemoveFAR FAR_ID=%s" % far_id)
        elif t in (IE_REMOVE_PDR, IE_CREATE_PDR, IE_UPDATE_PDR):
            pdr_id = None
            for st, sv in iter_ies(val):
                if st == IE_PDR_ID and len(sv) >= 2:
                    pdr_id = struct.unpack("!H", sv[:2])[0]
            ops.append("%s PDR_ID=%s" % (IE_NAME[t], pdr_id))
        elif t == IE_UPDATE_BAR:
            ops.append("UpdateBAR")
    return ops


def main():
    pkts = rdpcap(PCAP)
    parsed = []  # (frame_no, time, src, dst, pfcp)
    for idx, p in enumerate(pkts, 1):
        if IP not in p or UDP not in p or Raw not in p:
            continue
        if p[UDP].dport != 8805 and p[UDP].sport != 8805:
            continue
        pf = parse_pfcp(bytes(p[Raw].load))
        if pf:
            parsed.append((idx, float(p.time), p[IP].src, p[IP].dst, pf))

    # Index modification requests by sequence number
    req_by_seq = {}
    for rec in parsed:
        _, _, _, _, pf = rec
        if pf["mt"] == 52:
            req_by_seq.setdefault(pf["seq"], []).append(rec)

    # Find modification responses carrying the failure cause
    hits = []
    for rec in parsed:
        _, _, _, _, pf = rec
        if pf["mt"] != 53:
            continue
        cause = None
        offending = None
        for t, val in iter_ies(pf["ies"]):
            if t == IE_CAUSE and val:
                cause = val[0]
            elif t == IE_OFFENDING_IE and len(val) >= 2:
                offending = struct.unpack("!H", val[:2])[0]
        if cause == WANT_CAUSE:
            hits.append((rec, offending))

    print("PCAP:", PCAP)
    print("Looking for Session Modification Response with cause =", WANT_CAUSE)
    print("Total PFCP packets:", len(parsed))
    print("Matching failure responses:", len(hits))
    print("=" * 78)

    if not hits:
        print("No Session Modification Response with cause", WANT_CAUSE, "found.")
        # Show what causes DO appear, to help.
        seen = {}
        for rec in parsed:
            pf = rec[4]
            if pf["mt"] == 53:
                for t, val in iter_ies(pf["ies"]):
                    if t == IE_CAUSE and val:
                        seen[val[0]] = seen.get(val[0], 0) + 1
        print("Modification-response causes present:", seen)
        return

    t0 = min(r[1] for r in parsed)
    for (rec, offending) in hits:
        rframe, rtime, rsrc, rdst, rpf = rec
        print("FAILED Session Modification RESPONSE")
        print("  frame=%d  t=+%.3fs  %s -> %s" %
              (rframe, rtime - t0, rsrc, rdst))
        print("  SEID(local)=0x%x  seq=%d  cause=%d  offending_ie=%s" %
              (rpf["seid"] or 0, rpf["seq"], WANT_CAUSE,
               (IE_NAME.get(offending, offending)
                if offending is not None else "-")))

        matches = req_by_seq.get(rpf["seq"], [])
        if not matches:
            print("  (no Modification Request with seq=%d found)" % rpf["seq"])
            print("-" * 78)
            continue

        for (qframe, qtime, qsrc, qdst, qpf) in matches:
            print("  --> matching Session Modification REQUEST")
            print("      frame=%d  t=+%.3fs  %s -> %s" %
                  (qframe, qtime - t0, qsrc, qdst))
            print("      SEID(remote)=0x%x  seq=%d" %
                  (qpf["seid"] or 0, qpf["seq"]))
            ops = decode_far_ops(qpf["ies"])
            if ops:
                print("      operations:")
                for o in ops:
                    print("        - " + o)
            else:
                print("      operations: (none decoded)")
            print("      full IE tree:")
            dump_ies(qpf["ies"], indent=8)
            # raw hex of the request payload for Wireshark cross-check
            raw = bytes(pkts[qframe - 1][Raw].load)
            print("      raw(%dB)=%s" % (len(raw), raw.hex()))

        # Session history toward the UPF that rejected: did PDR/FAR id get
        # created earlier and never removed? (stale-rule hypothesis)
        upf = rdst  # the node that sent the failure response is the UPF
        seid = rpf["seid"]
        print("  session history toward UPF %s for SEID 0x%x:" % (upf, seid))
        for (hframe, htime, hsrc, hdst, hpf) in parsed:
            if hpf["seid"] != seid:
                continue
            # requests addressed to the UPF, or its responses
            if not (hdst == upf or hsrc == upf):
                continue
            label = MT.get(hpf["mt"], "MT-%d" % hpf["mt"])
            extra = ""
            if hpf["mt"] in (50, 52):  # establishment / modification request
                extra = "  ops=[%s]" % ", ".join(decode_far_ops(hpf["ies"]))
            elif hpf["mt"] in (51, 53):  # responses -> show cause
                for t, val in iter_ies(hpf["ies"]):
                    if t == IE_CAUSE and val:
                        extra = "  cause=%d" % val[0]
            print("    +%.3fs f%d %-28s %s->%s seq=%d%s" % (
                htime - t0, hframe, label, hsrc, hdst, hpf["seq"], extra))
        print("-" * 78)


if __name__ == "__main__":
    main()
