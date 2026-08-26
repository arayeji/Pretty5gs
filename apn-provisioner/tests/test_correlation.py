from apn_provisioner.correlation import CorrelationTable
from apn_provisioner.nas_decoder import decode_nas
from apn_provisioner.s1ap import decode_s1ap
from tests import nas_fixtures as fx

IMSI = "432129951539038"
IMEISV = "3512340678901512"
ASSOC = "10.0.0.10<->10.0.0.20"
UPLINK = {"InitialUEMessage", "UplinkNASTransport"}


def _feed(corr, payload):
    ev = decode_s1ap(payload)
    nas = None
    if ev.nas_pdu:
        nas = decode_nas(ev.nas_pdu, uplink=ev.proc in UPLINK)
    return corr.update(ASSOC, ev, nas)


def test_full_attach_triggers_on_complete():
    corr = CorrelationTable()
    ar = fx.make_attach_request(fx.make_imsi_id(IMSI),
                                fx.make_pdn_connectivity_request(None))
    assert _feed(corr, fx.s1ap_initial_ue(555, ar)) is None
    smc = fx.make_security_mode_complete(IMEISV)
    assert _feed(corr, fx.s1ap_uplink_nas(42, 555, smc)) is None
    ac = fx.make_attach_complete()
    trig = _feed(corr, fx.s1ap_uplink_nas(42, 555, ac))
    assert trig is not None
    assert trig.imsi == IMSI
    assert trig.imei == IMEISV[:14]
    assert trig.apn_present is False
    assert trig.mme_ue_id == 42


def test_trigger_only_once():
    corr = CorrelationTable()
    ar = fx.make_attach_request(fx.make_imsi_id(IMSI),
                                fx.make_pdn_connectivity_request(None))
    _feed(corr, fx.s1ap_initial_ue(555, ar))
    assert _feed(corr, fx.s1ap_uplink_nas(42, 555, fx.make_attach_complete())) is not None
    # a duplicate Attach Complete must not re-trigger
    assert _feed(corr, fx.s1ap_uplink_nas(42, 555, fx.make_attach_complete())) is None


def test_guti_only_attach_has_no_imsi():
    corr = CorrelationTable()
    ar = fx.make_attach_request(fx.make_guti_id(mtmsi=0xAABBCCDD),
                                fx.make_pdn_connectivity_request(None))
    _feed(corr, fx.s1ap_initial_ue(777, ar))
    trig = _feed(corr, fx.s1ap_uplink_nas(9, 777, fx.make_attach_complete()))
    assert trig.imsi is None
    assert trig.guti is not None


def test_release_expires_session():
    corr = CorrelationTable()
    ar = fx.make_attach_request(fx.make_imsi_id(IMSI),
                                fx.make_pdn_connectivity_request(None))
    _feed(corr, fx.s1ap_initial_ue(555, ar))
    assert len(corr) == 1
    _feed(corr, fx.s1ap_ue_context_release(42, 555))
    assert len(corr) == 0


def test_timeout_expiry():
    corr = CorrelationTable(timeout_sec=0.0)
    ar = fx.make_attach_request(fx.make_imsi_id(IMSI),
                                fx.make_pdn_connectivity_request(None))
    _feed(corr, fx.s1ap_initial_ue(555, ar))
    import time
    time.sleep(0.01)
    assert corr.expire() == 1
    assert len(corr) == 0
