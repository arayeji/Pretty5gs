"""Send/skip decision (spec section 4 + the final APN-IE rule).

Gate order:
  1. APN-IE rule (final requirement): only UEs whose Attach Request carried NO
     APN IE are eligible. If the UE supplied an APN it is configured -> skip. If
     we could not decode the Attach Request's APN state -> skip (we must not
     guess that a UE is unconfigured).
  2. Change detection / rate window:
       - no record            -> SEND (new_subscriber)
       - IMEI changed         -> SEND (imei_change)   [SV change ignored]
       - resend interval due  -> SEND (resend_interval)
       - otherwise            -> SKIP (recent)
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Decision:
    send: bool
    reason: str


def decide(record, session, cfg, now: float) -> Decision:
    # --- final requirement: APN-IE presence gate -----------------------
    if session.apn_present is True:
        return Decision(False, "ue_supplied_apn")
    if session.apn_present is None:
        # undecodable / GUTI attach where we never saw the PDN request:
        # cannot confirm the UE is unconfigured, so do not send.
        return Decision(False, "apn_unknown")

    # --- change detection ----------------------------------------------
    if record is None or record.last_sent is None:
        return Decision(True, "new_subscriber")

    if cfg.send_on_imei_change and _imei_changed(record, session, cfg):
        return Decision(True, "imei_change")

    if now - record.last_sent >= cfg.resend_interval_hours * 3600.0:
        return Decision(True, "resend_interval")

    return Decision(False, "recent")


def _imei_changed(record, session, cfg) -> bool:
    if cfg.ignore_sv_change:
        cur, prev = session.imei, record.imei          # compare 14-digit IMEI
    else:
        cur = session.imeisv                            # SV counts as a change
        prev = (record.imei or "") + (record.sv or "") if record.imei else None
    if not cur or not prev:
        return False  # missing IMEI -> IMEI tracking disabled for this decision
    return cur != prev
