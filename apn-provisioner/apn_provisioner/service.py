"""Service orchestration (spec section 4 + 5).

Wires the S1 source -> decode -> correlate -> decide -> rate-limit -> send
pipeline and logs every decision (sent / skipped-why / failed-why) with IMSI,
IMEI, APN and segment count (spec 5.7). Passive on the network side: the only
write action is submit_sm (spec 5.6).
"""
from __future__ import annotations

import logging
import os
import random
import time

from . import cp_builder
from .config import Config
from .correlation import CorrelationTable, Session
from .decision import decide
from .metrics import Metrics
from .nas_decoder import decode_nas
from .rate_limiter import RateLimiter
from .s1ap import decode_s1ap, is_release
from .store import Record, Store
from .subscriber import Subscriber
from .validator import MalformedError, decode_wbxml, decode_wsp_push

log = logging.getLogger("apn_provisioner")

_UPLINK_PROCS = {"InitialUEMessage", "UplinkNASTransport"}


class Service:
    def __init__(self, cfg: Config, store: Store, subscriber_lookup,
                 sender, metrics: Metrics | None = None):
        self.cfg = cfg
        self.store = store
        self.subscribers = subscriber_lookup
        self.sender = sender
        self.metrics = metrics or Metrics()
        self.corr = CorrelationTable(cfg.correlation_timeout_sec)
        self.rate = RateLimiter(
            dedup_window_sec=cfg.dedup_window_sec,
            global_max_per_sec=cfg.global_max_per_sec,
            max_sends_per_sub_per_day=cfg.max_sends_per_sub_per_day,
            breaker_per_min=cfg.breaker_per_min,
            breaker_resume_per_min=cfg.breaker_resume_per_min,
        )
        self._last_expire = 0.0

    # --- offline S1AP pipeline (pcap modes / decoder tests) -------------
    def process(self, assoc: str, payload: bytes) -> None:
        """Decode one S1AP PDU and fold it into correlation (offline path)."""
        ev = decode_s1ap(payload)
        if ev is None:
            return
        if ev.proc in _UPLINK_PROCS:
            self.metrics.attaches_seen += 1

        nas = None
        if ev.nas_pdu:
            nas = decode_nas(ev.nas_pdu, uplink=ev.proc in _UPLINK_PROCS)

        trigger = self.corr.update(assoc, ev, nas)

        # keep the GUTI->IMSI map fresh whenever both are visible (spec 3.2a)
        sess = trigger
        if sess and sess.imsi and sess.guti:
            self.store.learn_guti(sess.guti, sess.imsi)

        if not is_release(ev.proc):
            self._maybe_expire()

        if trigger is not None:
            self._on_trigger(trigger)

    def process_attach_event(self, evt) -> None:
        """Primary path: an MME attach-event datagram. The MME already
        resolved the IMSI and gated on 'no APN IE', so we skip S1AP/NAS decode
        and correlation entirely and go straight to the decision pipeline."""
        self.metrics.attaches_seen += 1
        imei = evt.imei
        sv = None
        if evt.imeisv and len(evt.imeisv) >= 16:
            imei = imei or evt.imeisv[:14]
            sv = evt.imeisv[14:16]
        sess = Session(
            src_ip="mme", enb_ue_id=0,
            imsi=evt.imsi,
            imei=imei,
            sv=sv,
            imeisv=evt.imeisv,
            apn_present=False,          # MME emitted this only for no-APN UEs
            attach_complete=True,
        )
        self._on_trigger(sess, msisdn_hint=evt.msisdn)

    def _maybe_expire(self) -> None:
        now = time.time()
        if now - self._last_expire >= 5.0:
            self.corr.expire(now)
            self._last_expire = now

    # --- trigger handling (Attach Complete) -----------------------------
    def _on_trigger(self, sess: Session, msisdn_hint: str | None = None) -> None:
        imsi = sess.imsi or (self.store.resolve_guti(sess.guti) if sess.guti else None)
        if not imsi:
            self.metrics.guti_unresolved += 1
            log.info("SKIP guti_unresolved assoc=%s enb_ue=%s mtmsi=%s",
                     sess.src_ip, sess.enb_ue_id,
                     hex(sess.guti_mtmsi) if getattr(sess, "guti_mtmsi", None) else None)
            self.metrics.skip("guti_unresolved")
            return
        sess.imsi = imsi
        self.metrics.correlations_resolved += 1
        if sess.guti:
            self.store.learn_guti(sess.guti, imsi)

        sub = self.subscribers.lookup(imsi)
        if sub is None:
            log.info("SKIP no_subscriber imsi=%s", imsi)
            self.metrics.skip("no_subscriber")
            return
        if not sub.msisdn and msisdn_hint:
            sub.msisdn = msisdn_hint  # MME-provided MSISDN when HSS lacks it

        record = self.store.get_record(imsi)
        now = time.time()
        dec = decide(record, sess, self.cfg, now)
        if not dec.send:
            log.info("SKIP %s imsi=%s imei=%s apn=%s apn_present=%s",
                     dec.reason, imsi, sess.imei, sub.apn, sess.apn_present)
            self.metrics.skip(dec.reason)
            return

        ok, rl_reason = self.rate.check(imsi, now)
        if not ok:
            log.warning("SKIP ratelimit=%s imsi=%s (breaker_open=%s)",
                        rl_reason, imsi, self.rate.breaker_open)
            self.metrics.skip(rl_reason)
            return

        self._send(sub, sess, record, dec.reason, now)

    def _send(self, sub: Subscriber, sess: Session, record: Record | None,
              reason: str, now: float) -> None:
        ref = random.randint(0, 255)
        msg = cp_builder.build_message(sub.imsi, sub.msisdn, sub.apn, ref)

        # validate before sending; refuse to send malformed output (spec 2.6)
        try:
            parsed = decode_wsp_push(msg.wsp_pdu)
            decode_wbxml(parsed.wbxml)
            if parsed.mac != msg.mac_hex or parsed.sec != "NETWPIN":
                raise MalformedError("content-type/MAC mismatch")
        except MalformedError as e:
            log.error("FAIL validation imsi=%s: %s", sub.imsi, e)
            self.metrics.failures += 1
            return

        confidence = "authoritative" if sess.imei else (
            "masked" if sess.masked_imeisv else "none")

        if self.cfg.dry_run:
            log.info(
                "DRY-RUN would send reason=%s imsi=%s msisdn=%s apn=%s imei=%s "
                "sv=%s conf=%s segments=%d mac=%s wsp_hex=%s",
                reason, sub.imsi, sub.msisdn, sub.apn, sess.imei, sess.sv,
                confidence, msg.segment_count, msg.mac_hex, msg.wsp_pdu.hex())
            self.metrics.skip("dry_run")
            self._persist(sub, sess, record, confidence, now, sent=False,
                          result="dry_run")
            return

        self.rate.start_send(sub.imsi, now)
        success = False
        try:
            self.sender.send_segments(sub.msisdn, msg.segments)
            success = True
            self.metrics.sends += 1
            log.info("SENT reason=%s imsi=%s msisdn=%s apn=%s imei=%s sv=%s "
                     "conf=%s segments=%d mac=%s", reason, sub.imsi, sub.msisdn,
                     sub.apn, sess.imei, sess.sv, confidence, msg.segment_count,
                     msg.mac_hex)
        except Exception as e:
            self.metrics.failures += 1
            log.error("FAIL send imsi=%s apn=%s: %s", sub.imsi, sub.apn, e)
        finally:
            self.rate.finish_send(sub.imsi, time.time(), success)
        self._persist(sub, sess, record, confidence, now, sent=success,
                      result="sent" if success else "send_failed")

    def _persist(self, sub, sess, record, confidence, now, *, sent, result):
        send_count = (record.send_count if record else 0) + (1 if sent else 0)
        self.store.upsert_record(Record(
            imsi=sub.imsi,
            imei=sess.imei or (record.imei if record else None),
            imei_confidence=confidence,
            sv=sess.sv or (record.sv if record else None),
            msisdn=sub.msisdn,
            apn=sub.apn,
            last_sent=now if sent else (record.last_sent if record else None),
            send_count=send_count,
            last_result=result,
        ))

    # --- run loop -------------------------------------------------------
    def run(self, source) -> None:
        from .s1_source import AttachEvent

        log.info("apn-provisioner starting (dry_run=%s, s1_source=%s)",
                 self.cfg.dry_run, self.cfg.s1_source.mode)
        last_metrics = time.time()
        try:
            for item in source.events():
                try:
                    if isinstance(item, AttachEvent):
                        self.process_attach_event(item)
                    else:  # S1Frame (offline pcap modes)
                        self.process(item.assoc, item.payload)
                except Exception:
                    log.exception("error processing attach event")
                if time.time() - last_metrics >= 30.0:
                    log.info("counters %s", self.metrics.render())
                    last_metrics = time.time()
        finally:
            log.info("counters %s", self.metrics.render())


def build_and_run(cfg: Config) -> None:
    logging.basicConfig(
        level=getattr(logging, cfg.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    os.makedirs(os.path.dirname(cfg.state_db_path) or ".", exist_ok=True)
    store = Store(cfg.state_db_path)

    subscriber_lookup = None
    sender = None
    if not cfg.dry_run or cfg.mongo.uri:
        from .subscriber import SubscriberLookup
        subscriber_lookup = SubscriberLookup(
            cfg.mongo.uri, cfg.mongo.db, cfg.mongo.collection)
    if not cfg.dry_run:
        from .smpp_client import SmppSender
        sender = SmppSender(
            host=cfg.smpp.host, port=cfg.smpp.port,
            system_id=cfg.smpp.system_id, password=cfg.smpp.password,
            source_addr=cfg.smpp.source_addr, segment_gap_sec=cfg.smpp.segment_gap_sec)

    from .s1_source import build_source
    source = build_source(cfg.s1_source)

    svc = Service(cfg, store, subscriber_lookup, sender)
    svc.run(source)
