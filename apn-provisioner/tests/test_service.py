from apn_provisioner.config import Config
from apn_provisioner.service import Service
from apn_provisioner.store import Store
from apn_provisioner.subscriber import Subscriber
from tests import nas_fixtures as fx

IMSI = "432129951539038"
IMEISV = "3512340678901512"
ASSOC = "10.0.0.10<->10.0.0.20"


class FakeLookup:
    def __init__(self, subs):
        self.subs = subs

    def lookup(self, imsi):
        return self.subs.get(imsi)


class FakeSender:
    def __init__(self):
        self.sent = []

    def send_segments(self, msisdn, segments):
        self.sent.append((msisdn, segments))


def _attach_sequence(apn):
    ar = fx.make_attach_request(fx.make_imsi_id(IMSI),
                                fx.make_pdn_connectivity_request(apn))
    return [
        fx.s1ap_initial_ue(555, ar),
        fx.s1ap_uplink_nas(42, 555, fx.make_security_mode_complete(IMEISV)),
        fx.s1ap_uplink_nas(42, 555, fx.make_attach_complete()),
    ]


def _make_service(tmp_path, dry_run):
    cfg = Config()
    cfg.dry_run = dry_run
    store = Store(str(tmp_path / "s.db"))
    lookup = FakeLookup({IMSI: Subscriber(IMSI, "989951079038", "hiweb")})
    sender = FakeSender()
    return Service(cfg, store, lookup, sender), sender, store


def test_dry_run_would_send_for_ue_without_apn(tmp_path):
    svc, sender, store = _make_service(tmp_path, dry_run=True)
    for p in _attach_sequence(apn=None):
        svc.process(ASSOC, p)
    assert svc.metrics.correlations_resolved == 1
    assert svc.metrics.skips["dry_run"] == 1
    assert sender.sent == []  # nothing actually sent
    rec = store.get_record(IMSI)
    assert rec.last_result == "dry_run"
    assert rec.imei == IMEISV[:14]


def test_ue_with_apn_is_skipped(tmp_path):
    svc, sender, store = _make_service(tmp_path, dry_run=True)
    for p in _attach_sequence(apn="someapn.mnc012"):
        svc.process(ASSOC, p)
    assert svc.metrics.skips["ue_supplied_apn"] == 1
    assert sender.sent == []


def test_live_send_path(tmp_path):
    svc, sender, store = _make_service(tmp_path, dry_run=False)
    for p in _attach_sequence(apn=None):
        svc.process(ASSOC, p)
    assert svc.metrics.sends == 1
    assert len(sender.sent) == 1
    msisdn, segments = sender.sent[0]
    assert msisdn == "989951079038"
    assert len(segments) >= 2  # concatenated
    rec = store.get_record(IMSI)
    assert rec.last_result == "sent"
    assert rec.last_sent is not None


def test_no_subscriber_skipped(tmp_path):
    cfg = Config(); cfg.dry_run = True
    store = Store(str(tmp_path / "s.db"))
    svc = Service(cfg, store, FakeLookup({}), FakeSender())
    for p in _attach_sequence(apn=None):
        svc.process(ASSOC, p)
    assert svc.metrics.skips["no_subscriber"] == 1


def test_unresolved_guti_skipped(tmp_path):
    cfg = Config(); cfg.dry_run = True
    store = Store(str(tmp_path / "s.db"))
    svc = Service(cfg, store, FakeLookup({}), FakeSender())
    ar = fx.make_attach_request(fx.make_guti_id(mtmsi=0x11223344),
                                fx.make_pdn_connectivity_request(None))
    svc.process(ASSOC, fx.s1ap_initial_ue(555, ar))
    svc.process(ASSOC, fx.s1ap_uplink_nas(42, 555, fx.make_attach_complete()))
    assert svc.metrics.guti_unresolved == 1
    assert svc.metrics.skips["guti_unresolved"] == 1


def test_attach_event_dry_run_would_send(tmp_path):
    """Primary path: an MME attach-event datagram drives the decision pipeline
    directly (no S1AP decode, no GUTI map)."""
    from apn_provisioner.s1_source import AttachEvent
    svc, sender, store = _make_service(tmp_path, dry_run=True)
    svc.process_attach_event(AttachEvent(
        imsi=IMSI, msisdn="989951079038", imei=IMEISV[:14], imeisv=IMEISV,
        mcc="432", mnc="12", apn_absent=True))
    assert svc.metrics.correlations_resolved == 1
    assert svc.metrics.skips["dry_run"] == 1
    assert sender.sent == []
    rec = store.get_record(IMSI)
    assert rec.imei == IMEISV[:14]
    assert rec.sv == IMEISV[14:16]


def test_attach_event_live_send_uses_msisdn_hint(tmp_path):
    """When the HSS record lacks an MSISDN, the MME-supplied one is used."""
    from apn_provisioner.s1_source import AttachEvent
    cfg = Config(); cfg.dry_run = False
    store = Store(str(tmp_path / "s.db"))
    lookup = FakeLookup({IMSI: Subscriber(IMSI, "", "hiweb")})  # no MSISDN in HSS
    sender = FakeSender()
    svc = Service(cfg, store, lookup, sender)
    svc.process_attach_event(AttachEvent(
        imsi=IMSI, msisdn="989951079038", imei=IMEISV[:14], imeisv=IMEISV,
        apn_absent=True))
    assert svc.metrics.sends == 1
    assert sender.sent[0][0] == "989951079038"


def test_guti_resolves_after_learning(tmp_path):
    """A GUTI-only re-attach resolves once the IMSI<->GUTI was learned earlier."""
    cfg = Config(); cfg.dry_run = True
    store = Store(str(tmp_path / "s.db"))
    svc = Service(cfg, store, FakeLookup({IMSI: Subscriber(IMSI, "989", "hiweb")}),
                  FakeSender())
    guti = fx.make_guti_id(mtmsi=0x55667788)
    store.learn_guti(guti, IMSI)  # learned from an earlier attach with IMSI
    ar = fx.make_attach_request(guti, fx.make_pdn_connectivity_request(None))
    svc.process(ASSOC, fx.s1ap_initial_ue(555, ar))
    svc.process(ASSOC, fx.s1ap_uplink_nas(42, 555, fx.make_attach_complete()))
    assert svc.metrics.correlations_resolved == 1
    assert svc.metrics.skips["dry_run"] == 1
