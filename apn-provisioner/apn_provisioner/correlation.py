"""Per-UE session correlation (spec 3.2).

The IMSI is absent from most attaches (GUTI/S-TMSI re-attach), so we accumulate
IMSI, IMEISV, the APN-IE presence and attach completion across the messages of
one S1AP association and evaluate only at Attach Complete.

Key: (eNB association, ENB_UE_S1AP_ID). ENB_UE_S1AP_ID is present in every
UE-associated message from the eNB (the MME allocates MME_UE_S1AP_ID later), so
it is the stable session handle; we learn MME_UE_S1AP_ID and index by it too so
downlink messages map back. Entries expire on UEContextRelease or after a
timeout (default 60s).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .nas_decoder import NasFields
from .s1ap import S1apEvent, is_release


@dataclass
class Session:
    src_ip: str
    enb_ue_id: int
    mme_ue_id: int | None = None
    imsi: str | None = None
    guti: bytes | None = None
    imeisv: str | None = None
    imei: str | None = None
    sv: str | None = None
    masked_imeisv: str | None = None
    apn_present: bool | None = None
    nas_decode_error: bool = False
    attach_complete: bool = False
    triggered: bool = False
    created: float = field(default_factory=time.time)
    updated: float = field(default_factory=time.time)


class CorrelationTable:
    def __init__(self, timeout_sec: float = 60.0):
        self.timeout = timeout_sec
        self._by_enb: dict[tuple, Session] = {}
        self._mme_index: dict[tuple, tuple] = {}

    def __len__(self) -> int:
        return len(self._by_enb)

    def _locate(self, src_ip: str, ev: S1apEvent) -> Session | None:
        if ev.enb_ue_id is not None:
            key = (src_ip, ev.enb_ue_id)
            s = self._by_enb.get(key)
            if s:
                return s
        if ev.mme_ue_id is not None:
            enb_key = self._mme_index.get((src_ip, ev.mme_ue_id))
            if enb_key:
                return self._by_enb.get(enb_key)
        return None

    def update(self, src_ip: str, ev: S1apEvent,
               nas: NasFields | None) -> Session | None:
        """Fold one message into its session; return the session iff this message
        is the Attach Complete trigger point (once per session). Used by the
        offline pcap decoder path (production uses MME event datagrams)."""
        if is_release(ev.proc):
            self._remove(src_ip, ev)
            return None

        sess = self._locate(src_ip, ev)
        if sess is None:
            if ev.enb_ue_id is None:
                return None  # cannot anchor a session without an eNB UE id
            sess = Session(src_ip=src_ip, enb_ue_id=ev.enb_ue_id)
            self._by_enb[(src_ip, ev.enb_ue_id)] = sess

        sess.updated = time.time()
        if ev.mme_ue_id is not None and sess.mme_ue_id is None:
            sess.mme_ue_id = ev.mme_ue_id
            self._mme_index[(src_ip, ev.mme_ue_id)] = (src_ip, sess.enb_ue_id)
        if ev.masked_imeisv and not sess.imeisv:
            sess.masked_imeisv = ev.masked_imeisv

        if nas is not None:
            self._apply_nas(sess, nas)

        if sess.attach_complete and not sess.triggered:
            sess.triggered = True
            return sess
        return None

    def _apply_nas(self, sess: Session, nas: NasFields) -> None:
        if nas.decode_error:
            sess.nas_decode_error = True
            return
        if nas.imsi:
            sess.imsi = nas.imsi
        if nas.guti:
            sess.guti = nas.guti
        if nas.imeisv:
            sess.imeisv = nas.imeisv
            sess.imei = nas.imei
            sess.sv = nas.sv
        if nas.apn_present is not None:
            sess.apn_present = nas.apn_present
        if nas.msg_type == "EMMAttachComplete":
            sess.attach_complete = True

    def _remove(self, src_ip: str, ev: S1apEvent) -> None:
        key = None
        if ev.enb_ue_id is not None:
            key = (src_ip, ev.enb_ue_id)
        elif ev.mme_ue_id is not None:
            key = self._mme_index.get((src_ip, ev.mme_ue_id))
        if key and key in self._by_enb:
            sess = self._by_enb.pop(key)
            if sess.mme_ue_id is not None:
                self._mme_index.pop((src_ip, sess.mme_ue_id), None)

    def expire(self, now: float | None = None) -> int:
        now = now or time.time()
        stale = [k for k, s in self._by_enb.items()
                 if now - s.updated > self.timeout]
        for k in stale:
            sess = self._by_enb.pop(k)
            if sess.mme_ue_id is not None:
                self._mme_index.pop((sess.src_ip, sess.mme_ue_id), None)
        return len(stale)
