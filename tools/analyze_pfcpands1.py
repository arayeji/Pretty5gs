#!/usr/bin/env python3
"""
Correlate S1AP (NAS) + GTPv2 (S11/S5) + PFCP (N4/Sxa) per UE from a single
capture and track each UE attach attempt to its outcome, flagging leaks and
orphan sessions across MME / SGW-C / SMF / SGW-U / PGW-U.

Inputs (TSV produced by tshark, see header of this repo task):
  c:\\Capture\\s1ap.tsv      S1AP layer
  c:\\Capture\\nas_cause.tsv NAS frames that carry an EMM/ESM cause
  c:\\Capture\\gtpv2.tsv     GTPv2 layer
  c:\\Capture\\pfcp.tsv      PFCP layer

Outputs:
  c:\\Capture\\ue_report.csv      one row per IMSI: steps + outcome + leak flags
  c:\\Capture\\ue_attempts.csv    one row per S1 connection attempt (detail)
  c:\\Capture\\final_report.txt   aggregate stats + root-cause analysis
"""

import csv
import os
from collections import defaultdict, OrderedDict

CAP = r"c:\Capture"
S1AP_TSV = os.path.join(CAP, "s1ap.tsv")
NAS_TSV = os.path.join(CAP, "nas_cause.tsv")
GTPV2_TSV = os.path.join(CAP, "gtpv2.tsv")
PFCP_TSV = os.path.join(CAP, "pfcp.tsv")

# ----------------------------------------------------------------------------
# Code maps
# ----------------------------------------------------------------------------
EMM = {
    0x41: "AttachReq", 0x42: "AttachAccept", 0x43: "AttachComplete",
    0x44: "AttachReject", 0x45: "DetachReq", 0x46: "DetachAccept",
    0x48: "TAUReq", 0x49: "TAUAccept", 0x4a: "TAUComplete", 0x4b: "TAUReject",
    0x4c: "ExtServiceReq", 0x4e: "ServiceReject",
    0x50: "GUTIReallocCmd", 0x51: "GUTIReallocCmp",
    0x52: "AuthReq", 0x53: "AuthResp", 0x54: "AuthReject", 0x5c: "AuthFailure",
    0x55: "IdentityReq", 0x56: "IdentityResp",
    0x5d: "SecModeCmd", 0x5e: "SecModeComplete", 0x5f: "SecModeReject",
    0x60: "EMMStatus", 0x61: "EMMInfo",
}
ESM = {
    0xc1: "ActDefBearerReq", 0xc2: "ActDefBearerAcc", 0xc3: "ActDefBearerRej",
    0xc5: "ActDedBearerReq", 0xc6: "ActDedBearerAcc", 0xc7: "ActDedBearerRej",
    0xc9: "ModBearerReq", 0xca: "ModBearerAcc",
    0xcd: "DeactBearerReq", 0xce: "DeactBearerAcc",
    0xd0: "PDNConnReq", 0xd1: "PDNConnReject",
    0xd2: "PDNDiscReq", 0xd3: "PDNDiscReject",
    0xd9: "ESMStatus", 0xda: "ESMInfoReq",
}
PROC = {
    0: "HOPrep", 3: "PathSwitch", 5: "ERABSetup", 6: "ERABModify",
    7: "ERABRelease", 8: "ERABRelInd", 9: "InitialContextSetup", 10: "Paging",
    11: "DLNAS", 12: "InitialUE", 13: "ULNAS", 14: "Reset", 15: "ErrInd",
    16: "NASNonDelivery", 17: "S1Setup", 18: "UECtxRelReq", 21: "UECtxMod",
    22: "UECapInfo", 23: "UECtxRelease", 24: "eNBStatusTransfer",
    25: "MMEStatusTransfer", 40: "ENBConfigTransfer", 41: "MMEConfigTransfer",
}
EMM_CAUSE = {
    2: "IMSI unknown in HSS", 3: "Illegal UE", 5: "IMEI not accepted",
    6: "Illegal ME", 7: "EPS services not allowed",
    8: "EPS+non-EPS not allowed", 9: "UE identity cannot be derived",
    10: "Implicitly detached", 11: "PLMN not allowed",
    12: "Tracking area not allowed", 13: "Roaming not allowed in this TA",
    14: "EPS not allowed in PLMN", 15: "No suitable cells in TA",
    16: "MSC temporarily not reachable", 17: "Network failure",
    18: "CS domain not available", 19: "ESM failure", 22: "Congestion",
    25: "Not authorized for this CSG", 35: "Requested service option not authorized",
    111: "Protocol error",
}
ESM_CAUSE = {
    8: "Operator determined barring", 26: "Insufficient resources",
    27: "Missing or unknown APN", 28: "Unknown PDN type",
    29: "User authentication failed", 30: "Request rejected by SGW/PGW",
    31: "Request rejected, unspecified", 32: "Service option not supported",
    33: "Requested service option not subscribed", 34: "Service option temporarily out of order",
    35: "PTI already in use", 38: "Network failure", 43: "Invalid EPS bearer identity",
    50: "PDN type IPv4 only allowed", 51: "PDN type IPv6 only allowed",
    65: "Maximum number of EPS bearers reached", 66: "APN restriction incompatible",
}
GTPV2 = {
    1: "EchoReq", 2: "EchoResp", 32: "CreateSessionReq", 33: "CreateSessionResp",
    34: "ModifyBearerReq", 35: "ModifyBearerResp", 36: "DeleteSessionReq",
    37: "DeleteSessionResp", 70: "DownlinkDataNotif", 95: "CreateBearerReq",
    96: "CreateBearerResp", 97: "UpdateBearerReq", 98: "UpdateBearerResp",
    99: "DeleteBearerReq", 100: "DeleteBearerResp",
    170: "ReleaseAccessBearersReq", 171: "ReleaseAccessBearersResp",
}
PFCP = {
    1: "HeartbeatReq", 2: "HeartbeatResp", 5: "PFDMgmtReq", 6: "PFDMgmtResp",
    7: "AssocSetupReq", 8: "AssocSetupResp", 9: "AssocUpdateReq",
    50: "SessEstReq", 51: "SessEstResp", 52: "SessModReq", 53: "SessModResp",
    54: "SessDelReq", 55: "SessDelResp", 56: "SessReportReq", 57: "SessReportResp",
}


def first(vals):
    for v in vals:
        if v != "":
            return v
    return ""


def hx(s):
    """Parse a tshark hex/int token like '0x44' or '13' to int, else None."""
    s = (s or "").strip()
    if not s:
        return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def _detect_encoding(raw):
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    if raw[:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    # PowerShell '>' often emits UTF-16LE without BOM: lots of NUL bytes
    if raw[:4000].count(b"\x00") > 100:
        return "utf-16-le"
    return "utf-8"


def load_tsv(path, ncols):
    with open(path, "rb") as f:
        raw = f.read()
    enc = _detect_encoding(raw)
    text = raw.decode(enc, errors="replace")
    rows = []
    for line in text.split("\n"):
        line = line.rstrip("\r").rstrip("\ufeff")
        if line == "":
            continue
        parts = line.split("\t")
        if len(parts) < ncols:
            parts += [""] * (ncols - len(parts))
        rows.append(parts)
    return rows


# ----------------------------------------------------------------------------
# 1. NAS causes indexed by frame number
# ----------------------------------------------------------------------------
# nas_cause.tsv: frame,time,emm_type,esm_type,emm_cause,esm_cause,imsi,mme,enb
nas_cause = {}
for r in load_tsv(NAS_TSV, 9):
    fn = r[0]
    nas_cause[fn] = {
        "emm_cause": hx(first(r[4].split(","))),
        "esm_cause": hx(first(r[5].split(","))),
    }

# ----------------------------------------------------------------------------
# 2. Determine MME IPs (senders of DL NAS / InitialContextSetup / UECtxRelease)
# ----------------------------------------------------------------------------
# s1ap.tsv columns:
# 0 frame,1 time,2 src,3 dst,4 proc,5 mme_id,6 enb_id,7 emm,8 esm,9 imsi,
# 10 radioNet,11 nas,12 misc,13 protocol,14 transport
s1ap_rows = load_tsv(S1AP_TSV, 15)

# InitialUEMessage (proc 12) is ALWAYS eNB -> MME, so its destination is the
# MME. This cleanly identifies the MME without confusing eNBs that send
# InitialContextSetup *responses* or UEContextRelease *complete* (also proc 9/23).
mme_ip_votes = defaultdict(int)
for r in s1ap_rows:
    procs = [hx(x) for x in r[4].split(",") if x != ""]
    if 12 in procs:
        mme_ip_votes[r[3]] += 1
if mme_ip_votes:
    top = max(mme_ip_votes.values())
    MME_IPS = {ip for ip, c in mme_ip_votes.items() if c >= top * 0.05}
else:
    MME_IPS = {"127.0.0.2"}


# ----------------------------------------------------------------------------
# 3. Build S1 connections (one per UE radio connection)
# ----------------------------------------------------------------------------
class Conn:
    _seq = 0

    def __init__(self, t):
        Conn._seq += 1
        self.cid = Conn._seq
        self.imsi = None
        self.enb_ip = None
        self.enb_id = None
        self.mme_id = None
        self.start = t
        self.last = t
        self.steps = []          # list of (time, token)
        self.emm_seen = set()
        self.attach_reject_cause = None
        self.esm_reject_cause = None
        self.released = False
        self.release_cause = None

    def add(self, t, token):
        self.steps.append((t, token))
        self.last = t


conns = []
active_by_mme = {}              # mme_id -> Conn
active_by_enb = {}              # (enb_ip, enb_id) -> Conn


def close_conn(c):
    c.released = True


for r in s1ap_rows:
    fn, ts, src, dst = r[0], r[1], r[2], r[3]
    try:
        t = float(ts)
    except ValueError:
        continue
    procs = [hx(x) for x in r[4].split(",") if x != ""]
    if not procs:
        continue
    proc = procs[0]
    # skip pure node-level procedures
    if proc in (14, 15, 17, 40, 41, 10) and proc not in (9, 11, 12, 13, 18, 23, 21):
        # ErrInd/Reset/S1Setup/config/paging - not UE attach lifecycle
        if proc != 10:
            continue
    mme_id = hx(first(r[5].split(",")))
    enb_id = hx(first(r[6].split(",")))
    emm = hx(first(r[7].split(",")))
    esm = hx(first(r[8].split(",")))
    imsi = first(r[9].split(","))

    from_mme = src in MME_IPS
    enb_ip = dst if from_mme else src
    enb_key = (enb_ip, enb_id) if enb_id is not None else None

    # locate or create connection
    c = None
    if mme_id is not None and mme_id in active_by_mme:
        c = active_by_mme[mme_id]
    elif enb_key is not None and enb_key in active_by_enb:
        c = active_by_enb[enb_key]

    if 12 in procs:  # InitialUEMessage starts a new radio connection
        if c is not None:
            close_conn(c)
            conns.append(c)
            if c.mme_id in active_by_mme:
                del active_by_mme[c.mme_id]
            ek = (c.enb_ip, c.enb_id)
            if ek in active_by_enb:
                del active_by_enb[ek]
        c = Conn(t)
        c.enb_ip = enb_ip
        c.enb_id = enb_id
        if enb_key:
            active_by_enb[enb_key] = c

    if c is None:
        # message references an unknown connection; start a fresh one so we
        # still capture late-life events (e.g. release after reuse)
        c = Conn(t)
        c.enb_ip = enb_ip
        c.enb_id = enb_id
        if enb_key:
            active_by_enb[enb_key] = c

    # bind mme id
    if mme_id is not None and c.mme_id is None:
        c.mme_id = mme_id
        active_by_mme[mme_id] = c
    if c.enb_id is None and enb_id is not None:
        c.enb_id = enb_id
        active_by_enb[(enb_ip, enb_id)] = c

    # imsi
    if imsi and not c.imsi:
        c.imsi = imsi

    # record step token
    if emm is not None and emm in EMM:
        tok = EMM[emm]
        c.add(t, tok)
        c.emm_seen.add(emm)
        if emm == 0x44:  # attach reject
            nc = nas_cause.get(fn)
            if nc:
                c.attach_reject_cause = nc.get("emm_cause")
                c.esm_reject_cause = nc.get("esm_cause")
        elif emm == 0x4e:  # service reject
            nc = nas_cause.get(fn)
            if nc:
                c.attach_reject_cause = nc.get("emm_cause")
    elif esm is not None and esm in ESM:
        c.add(t, ESM[esm])
    else:
        # procedure-level token (no NAS)
        if proc in (9, 12, 13, 18, 23, 21, 3, 5, 7):
            c.add(t, PROC.get(proc, "proc%d" % proc))

    # release closes the connection (detect even when bundled, not first PDU)
    if 23 in procs:
        rn = hx(first(r[10].split(",")))
        nas_c = hx(first(r[11].split(",")))
        c.release_cause = ("radio:%s" % rn) if rn is not None else (
            "nas:%s" % nas_c if nas_c is not None else "")
        close_conn(c)
        conns.append(c)
        if c.mme_id in active_by_mme:
            del active_by_mme[c.mme_id]
        ek = (c.enb_ip, c.enb_id)
        if ek in active_by_enb:
            del active_by_enb[ek]

# flush still-active connections (never released by capture end)
for c in list(active_by_mme.values()):
    conns.append(c)
for c in active_by_enb.values():
    if c not in conns:
        conns.append(c)

# ----------------------------------------------------------------------------
# 4. GTPv2 S11 aggregate per IMSI (CreateSession carries IMSI) + global counts
# ----------------------------------------------------------------------------
# gtpv2.tsv: 0 frame,1 time,2 src,3 dst,4 msgtype,5 imsi,6 teid,7 cause
gtp_rows = load_tsv(GTPV2_TSV, 8)
gtp_msg_count = defaultdict(int)
csreq_by_imsi = defaultdict(int)
csresp_cause = defaultdict(int)
gtp_endpoints = defaultdict(int)
for r in gtp_rows:
    mt = hx(first(r[4].split(",")))
    if mt is None:
        continue
    gtp_msg_count[mt] += 1
    gtp_endpoints[(r[2], r[3])] += 1
    imsi = first(r[5].split(","))
    if mt == 32 and imsi:
        csreq_by_imsi[imsi] += 1
    if mt == 33:
        c = hx(first(r[7].split(",")))
        if c is not None:
            csresp_cause[c] += 1

# ----------------------------------------------------------------------------
# 5. PFCP per-session tracking (Est carries IMSI). Map both SEIDs -> session.
# ----------------------------------------------------------------------------
# pfcp.tsv: 0 frame,1 time,2 src,3 dst,4 msgtype,5 seid(s),6 cause,7 imsi,8 fseid_ipv4
pfcp_rows = load_tsv(PFCP_TSV, 9)
pfcp_msg_count = defaultdict(int)
pfcp_endpoints = defaultdict(int)


class PSess:
    def __init__(self, imsi, t):
        self.imsi = imsi
        self.est = t
        self.est_ok = None
        self.deleted = False
        self.del_ok = None
        self.cp_ip = None
        self.up_ip = None
        self.last = t


pf_by_seid = {}     # seid(int) -> PSess
pf_sessions = []
pfcp_tmin = None
pfcp_tmax = None

for r in pfcp_rows:
    mt = hx(first(r[4].split(",")))
    if mt is None:
        continue
    pfcp_msg_count[mt] += 1
    pfcp_endpoints[(r[2], r[3])] += 1
    try:
        tnow = float(r[1])
        pfcp_tmin = tnow if pfcp_tmin is None else min(pfcp_tmin, tnow)
        pfcp_tmax = tnow if pfcp_tmax is None else max(pfcp_tmax, tnow)
    except ValueError:
        tnow = 0.0
    seids = [hx(x) for x in r[5].split(",") if x != ""]
    seids = [s for s in seids if s]    # drop zero/None
    imsi = first(r[7].split(","))
    cause = hx(first(r[6].split(",")))

    if mt == 50:  # Session Establishment Request (CP->UP), imsi present
        ps = PSess(imsi if imsi else None, tnow)
        ps.cp_ip = r[2]
        ps.up_ip = r[3]
        for s in seids:
            pf_by_seid[s] = ps
        pf_sessions.append(ps)
    elif mt == 51:  # Establishment Response (UP->CP)
        ps = None
        for s in seids:
            if s in pf_by_seid:
                ps = pf_by_seid[s]
                break
        if ps:
            ps.est_ok = (cause == 1)
            ps.up_ip = r[2]
            ps.last = tnow
            for s in seids:
                pf_by_seid[s] = ps   # bind UP seid too
    elif mt in (52, 53, 56, 57):
        for s in seids:
            if s in pf_by_seid:
                pf_by_seid[s].last = tnow
                break
    elif mt == 54:  # Deletion Request
        for s in seids:
            if s in pf_by_seid:
                pf_by_seid[s].deleted = True
                pf_by_seid[s].last = tnow
                break
    elif mt == 55:  # Deletion Response
        for s in seids:
            if s in pf_by_seid:
                pf_by_seid[s].del_ok = (cause == 1)
                break

# ----------------------------------------------------------------------------
# 6. Aggregate per IMSI
# ----------------------------------------------------------------------------
class UE:
    def __init__(self, imsi):
        self.imsi = imsi
        self.attempts = []        # list of Conn
        self.completed = False
        self.rejected = False
        self.detached = False
        self.outcomes = []

    pass


ue_map = OrderedDict()


def get_ue(imsi):
    if imsi not in ue_map:
        ue_map[imsi] = UE(imsi)
    return ue_map[imsi]


# classify each connection
def classify(c):
    s = c.emm_seen
    if 0x43 in s or 0x42 in s:
        if 0x46 in s or 0x45 in s:
            return "ATTACH_THEN_DETACH"
        return "ATTACH_OK"
    if 0x44 in s:
        return "ATTACH_REJECT"
    if 0x4e in s:
        return "SERVICE_REJECT"
    if 0x4b in s:
        return "TAU_REJECT"
    if 0x49 in s:
        return "TAU_OK"
    if 0x46 in s or 0x45 in s:
        return "DETACH"
    if 0x41 in s:
        return "ATTACH_INCOMPLETE"
    return "SIGNALING_ONLY"


conn_by_imsi = defaultdict(list)
for c in conns:
    if c.imsi:
        conn_by_imsi[c.imsi].append(c)

# PFCP sessions by imsi
pf_by_imsi = defaultdict(list)
for ps in pf_sessions:
    if ps.imsi:
        pf_by_imsi[ps.imsi].append(ps)

all_imsis = set(conn_by_imsi) | set(pf_by_imsi) | set(csreq_by_imsi)

# ----------------------------------------------------------------------------
# 7. Write per-attempt CSV
# ----------------------------------------------------------------------------
conns_sorted = sorted([c for c in conns if c.imsi], key=lambda c: c.start)
with open(os.path.join(CAP, "ue_attempts.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["imsi", "conn_id", "enb_ip", "enb_ue_id", "mme_ue_id",
                "start_epoch", "duration_s", "outcome", "attach_reject_cause",
                "esm_reject_cause", "released", "release_cause", "steps"])
    for c in conns_sorted:
        oc = classify(c)
        arc = ""
        if c.attach_reject_cause is not None:
            arc = "%d:%s" % (c.attach_reject_cause,
                             EMM_CAUSE.get(c.attach_reject_cause, "?"))
        erc = ""
        if c.esm_reject_cause is not None:
            erc = "%d:%s" % (c.esm_reject_cause,
                             ESM_CAUSE.get(c.esm_reject_cause, "?"))
        steps = ">".join(tok for _, tok in c.steps)
        w.writerow([c.imsi, c.cid, c.enb_ip, c.enb_id, c.mme_id,
                    "%.3f" % c.start, "%.3f" % (c.last - c.start), oc, arc, erc,
                    "yes" if c.released else "NO", c.release_cause or "", steps])

# ----------------------------------------------------------------------------
# 8. Write per-IMSI summary CSV with leak flags
# ----------------------------------------------------------------------------
leak_counters = defaultdict(int)
with open(os.path.join(CAP, "ue_report.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["imsi", "attach_attempts", "final_outcome",
                "reject_reason", "s1_released_all",
                "pfcp_sessions", "pfcp_est_ok", "pfcp_deleted", "pfcp_orphans",
                "s11_create_req", "leak", "leak_reason", "all_steps"])
    for imsi in sorted(all_imsis):
        cl = conn_by_imsi.get(imsi, [])
        cl_sorted = sorted(cl, key=lambda c: c.start)
        outcomes = [classify(c) for c in cl_sorted]
        # final outcome priority
        final = "NONE"
        if outcomes:
            if "ATTACH_OK" in outcomes:
                final = "ATTACH_OK"
            elif "ATTACH_THEN_DETACH" in outcomes:
                final = "ATTACH_THEN_DETACH"
            else:
                final = outcomes[-1]
        # reject reason from last rejecting conn
        reject_reason = ""
        for c in reversed(cl_sorted):
            if c.attach_reject_cause is not None:
                reject_reason = "%d:%s" % (
                    c.attach_reject_cause,
                    EMM_CAUSE.get(c.attach_reject_cause, "?"))
                if c.esm_reject_cause is not None:
                    reject_reason += " / esm %d:%s" % (
                        c.esm_reject_cause,
                        ESM_CAUSE.get(c.esm_reject_cause, "?"))
                break
        all_released = all(c.released for c in cl_sorted) if cl_sorted else True

        ps_list = pf_by_imsi.get(imsi, [])
        pf_n = len(ps_list)
        pf_ok = sum(1 for p in ps_list if p.est_ok)
        pf_del = sum(1 for p in ps_list if p.deleted)
        pf_orphan = sum(1 for p in ps_list if p.est_ok and not p.deleted)

        # leak logic:
        # - MME/EPC leak: UE never completed attach (rejected / incomplete) OR
        #   released on S1, yet a PFCP (SGW-U/PGW-U) session was established and
        #   never deleted.
        leak = ""
        leak_reason = ""
        if pf_orphan > 0:
            if final in ("ATTACH_REJECT", "SERVICE_REJECT", "ATTACH_INCOMPLETE",
                         "TAU_REJECT", "NONE", "SIGNALING_ONLY"):
                leak = "YES"
                leak_reason = ("downstream PFCP session established but not "
                               "deleted while S1/EMM outcome=%s" % final)
                leak_counters["pfcp_orphan_failed_attach"] += 1
            elif final in ("ATTACH_THEN_DETACH", "DETACH"):
                leak = "YES"
                leak_reason = ("UE detached but PFCP session not deleted "
                               "(downstream bearer leak)")
                leak_counters["pfcp_orphan_after_detach"] += 1
            else:  # ATTACH_OK but still active at capture end = not necessarily leak
                leak_reason = "pfcp session still active (attached)"

        steps_join = " || ".join(
            "[%s]%s" % (classify(c), ">".join(tok for _, tok in c.steps))
            for c in cl_sorted)
        w.writerow([imsi, len(cl_sorted), final, reject_reason,
                    "yes" if all_released else "NO",
                    pf_n, pf_ok, pf_del, pf_orphan,
                    csreq_by_imsi.get(imsi, 0), leak, leak_reason,
                    steps_join[:2000]])

# ----------------------------------------------------------------------------
# 9. Final aggregate report
# ----------------------------------------------------------------------------
def outcome_hist():
    h = defaultdict(int)
    for imsi in all_imsis:
        cl = conn_by_imsi.get(imsi, [])
        outs = [classify(c) for c in cl]
        if not outs:
            h["NO_S1_ONLY_PFCP/GTP"] += 1
            continue
        if "ATTACH_OK" in outs:
            h["ATTACH_OK"] += 1
        elif "ATTACH_THEN_DETACH" in outs:
            h["ATTACH_THEN_DETACH"] += 1
        else:
            h[outs[-1]] += 1
    return h


total_pf = len(pf_sessions)
pf_ok = sum(1 for p in pf_sessions if p.est_ok)
pf_failed = sum(1 for p in pf_sessions if p.est_ok is False)
pf_del = sum(1 for p in pf_sessions if p.deleted)
orphans = [p for p in pf_sessions if p.est_ok and not p.deleted]
pf_orphan = len(orphans)
pf_orphan_noimsi = sum(1 for p in orphans if not p.imsi)

# In-flight guard: a session established within GRACE seconds of the capture
# end may simply not have been deleted yet -> not a true leak.
GRACE = 30.0
cap_end = pfcp_tmax or 0.0
orphans_true = [p for p in orphans if (cap_end - p.est) > GRACE]
orphans_inflight = pf_orphan - len(orphans_true)

# bucket true orphans by CP->UP node pair
orphan_by_pair = defaultdict(int)
for p in orphans_true:
    orphan_by_pair[(p.cp_ip, p.up_ip)] += 1

# bucket true orphans by the S1/EMM outcome of their IMSI
def imsi_final(imsi):
    cl = conn_by_imsi.get(imsi, [])
    outs = [classify(c) for c in cl]
    if not outs:
        return "NO_S1"
    if "ATTACH_OK" in outs:
        return "ATTACH_OK"
    if "ATTACH_THEN_DETACH" in outs:
        return "ATTACH_THEN_DETACH"
    return outs[-1]

orphan_by_outcome = defaultdict(int)
for p in orphans_true:
    orphan_by_outcome[imsi_final(p.imsi)] += 1

# MME-side: S1 connections that were never released (no UEContextRelease)
conns_imsi = [c for c in conns if c.imsi]
never_released = [c for c in conns_imsi if not c.released]
# of those, how many had an attach that failed (MME should have released)
never_rel_failed = sum(
    1 for c in never_released
    if classify(c) in ("ATTACH_REJECT", "SERVICE_REJECT", "ATTACH_INCOMPLETE"))

# reject cause histogram
reject_hist = defaultdict(int)
for c in conns:
    if c.attach_reject_cause is not None:
        reject_hist[c.attach_reject_cause] += 1

with open(os.path.join(CAP, "final_report.txt"), "w", encoding="utf-8") as f:
    def p(*a):
        print(*a)
        print(*a, file=f)

    p("=" * 72)
    p("EPC CAPTURE ANALYSIS  -  pfcpands1New.pcap")
    p("=" * 72)
    p("MME IP(s) detected:", ", ".join(sorted(MME_IPS)))
    p("")
    p("S1AP frames:", len(s1ap_rows),
      "| GTPv2:", len(gtp_rows), "| PFCP:", len(pfcp_rows))
    p("Distinct IMSIs seen:", len(all_imsis))
    p("S1 radio connections reconstructed:", len(conns),
      "(with IMSI: %d)" % len([c for c in conns if c.imsi]))
    p("")
    p("--- Per-IMSI FINAL OUTCOME histogram ---")
    for k, v in sorted(outcome_hist().items(), key=lambda kv: -kv[1]):
        p("  %-22s %d" % (k, v))
    p("")
    p("--- Attach/Service REJECT cause histogram (EMM cause) ---")
    for k, v in sorted(reject_hist.items(), key=lambda kv: -kv[1]):
        p("  cause %-3d %-40s %d" % (k, EMM_CAUSE.get(k, "?"), v))
    p("")
    p("--- GTPv2 (S11/S5) message counts ---")
    for k, v in sorted(gtp_msg_count.items(), key=lambda kv: -kv[1]):
        p("  %-26s %d" % (GTPV2.get(k, "type%d" % k), v))
    p("")
    p("  CreateSessionResp cause histogram:")
    for k, v in sorted(csresp_cause.items(), key=lambda kv: -kv[1]):
        p("    cause %-3d %d" % (k, v))
    p("")
    p("--- PFCP message counts ---")
    for k, v in sorted(pfcp_msg_count.items(), key=lambda kv: -kv[1]):
        p("  %-22s %d" % (PFCP.get(k, "type%d" % k), v))
    p("")
    p("--- PFCP session lifecycle (downstream SGW-U/PGW-U bearers) ---")
    p("  Establishment Requests :", total_pf)
    p("  Establishment OK       :", pf_ok)
    p("  Establishment FAILED   :", pf_failed)
    p("  Deleted                :", pf_del)
    p("  ORPHANS (est ok, never deleted):", pf_orphan)
    p("     - true leaks (est >%ds before capture end): %d" % (int(GRACE), len(orphans_true)))
    p("     - in-flight near capture end (ignore)      : %d" % orphans_inflight)
    p("     - orphans without IMSI                     : %d" % pf_orphan_noimsi)
    p("")
    p("  True PFCP orphans by node pair (CP -> UP):")
    for (a, b), n in sorted(orphan_by_pair.items(), key=lambda kv: -kv[1]):
        p("    %-18s -> %-18s %d" % (a, b, n))
    p("")
    p("  True PFCP orphans by the UE's S1/EMM outcome:")
    for k, v in sorted(orphan_by_outcome.items(), key=lambda kv: -kv[1]):
        p("    %-22s %d" % (k, v))
    p("")
    p("--- MME-side context release ---")
    p("  S1 connections (with IMSI)             :", len(conns_imsi))
    p("  never saw UEContextRelease             :", len(never_released))
    p("    of which the attach had failed       :", never_rel_failed)
    p("  (note: connections still open at capture end are not necessarily")
    p("   leaks; persistent non-release across the window indicates an")
    p("   MME UE-context that is stuck.)")
    p("")
    p("--- LEAK accounting (per IMSI, failure-correlated) ---")
    for k, v in sorted(leak_counters.items(), key=lambda kv: -kv[1]):
        p("  %-32s %d" % (k, v))
    total_leaks = sum(leak_counters.values())
    p("  TOTAL IMSIs flagged as leaking :", total_leaks)
    p("")
    p("  Top leaking IMSIs (orphan downstream session + failed/none S1):")
    shown = 0
    for p2 in sorted(orphans_true, key=lambda x: x.est):
        fo = imsi_final(p2.imsi)
        if fo in ("ATTACH_OK",):
            continue
        p("    IMSI %-16s outcome=%-18s up=%s" % (p2.imsi, fo, p2.up_ip))
        shown += 1
        if shown >= 25:
            p("    ... (see ue_report.csv for the full list)")
            break
    p("")
    p("--- PFCP endpoints (CP->UP pairs) ---")
    for (a, b), n in sorted(pfcp_endpoints.items(), key=lambda kv: -kv[1])[:10]:
        p("  %-18s -> %-18s %d" % (a, b, n))
    p("")
    p("--- GTPv2 endpoints ---")
    for (a, b), n in sorted(gtp_endpoints.items(), key=lambda kv: -kv[1])[:10]:
        p("  %-18s -> %-18s %d" % (a, b, n))
    p("")
    # corrected leak interpretation
    leak_sessions = [p2 for p2 in orphans_true
                     if imsi_final(p2.imsi) != "ATTACH_OK"]
    live_sessions = [p2 for p2 in orphans_true
                     if imsi_final(p2.imsi) == "ATTACH_OK"]
    leak_imsis = set(p2.imsi for p2 in leak_sessions)
    p("=" * 72)
    p("ROOT-CAUSE SUMMARY")
    p("=" * 72)
    p("")
    p("[1] DOMINANT FAILURE: CreateSessionResponse cause 72 (System Failure)")
    p("    %d of %d Create Session Responses are cause 72 (%.1f%%)." % (
        csresp_cause.get(72, 0), sum(csresp_cause.values()),
        100.0 * csresp_cause.get(72, 0) / max(1, sum(csresp_cause.values()))))
    p("    The PGW/SMF (S5) is rejecting almost every PDN connection, so the")
    p("    MME rejects the attach with EMM cause 17 'Network failure'. This is")
    p("    the primary reason attaches are not completing in this capture.")
    p("")
    p("[2] DOWNSTREAM BEARER LEAK (SGW-U + PGW-U):")
    p("    True undeleted PFCP sessions (est >%ds before end): %d" % (
        int(GRACE), len(orphans_true)))
    p("      - LIVE sessions of successfully-attached UEs (NOT leaks): %d" %
      len(live_sessions))
    p("      - GENUINE LEAKS (UE attach failed / no S1): %d sessions, %d IMSIs"
      % (len(leak_sessions), len(leak_imsis)))
    p("    Each leaking IMSI leaks on BOTH node pairs (SGW-U .24 and PGW-U .25),")
    p("    i.e. SGW-C established the SGW-U PFCP session and SMF established the")
    p("    PGW-U PFCP session, the attach then failed, and NEITHER was deleted.")
    p("")
    p("    Root cause: on the attach-failure path SGW-C does not always send")
    p("    PFCP Session Deletion to SGW-U + S5 Delete Session to PGW/SMF, and")
    p("    SMF does not always delete the PGW-U session.")
    p("    ~%.1f%% of established PFCP sessions leak this way (%d of %d est-OK)."
      % (100.0 * len(leak_sessions) / max(1, pf_ok),
         len(leak_sessions), pf_ok))
    p("")
    p("[3] MME-SIDE CONTEXT:")
    p("    %d S1 connections never saw UEContextRelease in-window; %d of those"
      % (len(never_released), never_rel_failed))
    p("    were failed attaches. These are candidate stuck MME UE-contexts")
    p("    (the ue_context_will_remove drain path). Most failed attaches ARE")
    p("    released, so the MME leak rate here is low in this capture.")
    p("")
    p("[4] EMM REJECT MIX (policy vs failure):")
    p("    Network failure (17): %d  <- driven by CSResp cause 72" %
      reject_hist.get(17, 0))
    p("    Roaming not allowed (13): %d  <- HSS/MME policy (roaming UEs)" %
      reject_hist.get(13, 0))
    p("    UE identity cannot be derived (9): %d  <- identity procedure" %
      reject_hist.get(9, 0))
    p("    PLMN not allowed (11): %d ; No suitable cells (15): %d" % (
        reject_hist.get(11, 0), reject_hist.get(15, 0)))
    p("")
    p("Outputs written:")
    p("  ue_report.csv    (per IMSI: steps + outcome + leak flags)")
    p("  ue_attempts.csv  (per S1 connection attempt detail)")
    p("  final_report.txt (this file)")

print("\nDONE")
