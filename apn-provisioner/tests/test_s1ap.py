from apn_provisioner.s1ap import decode_s1ap, is_release
from tests import nas_fixtures as fx


def test_initial_ue_message():
    nas = fx.make_attach_request(fx.make_imsi_id("432129951539038"),
                                 fx.make_pdn_connectivity_request(None))
    payload = fx.s1ap_initial_ue(enb_ue_id=555, nas_pdu=nas)
    ev = decode_s1ap(payload)
    assert ev.proc == "InitialUEMessage"
    assert ev.enb_ue_id == 555
    assert ev.mme_ue_id is None
    assert ev.nas_pdu == nas


def test_uplink_nas_transport_ids():
    nas = fx.make_security_mode_complete("3512340678901512")
    payload = fx.s1ap_uplink_nas(mme_ue_id=42, enb_ue_id=555, nas_pdu=nas)
    ev = decode_s1ap(payload)
    assert ev.proc == "UplinkNASTransport"
    assert ev.mme_ue_id == 42
    assert ev.enb_ue_id == 555
    assert ev.nas_pdu == nas


def test_ue_context_release_detected():
    payload = fx.s1ap_ue_context_release(mme_ue_id=42, enb_ue_id=555)
    ev = decode_s1ap(payload)
    assert is_release(ev.proc)


def test_garbage_is_none():
    assert decode_s1ap(b"\x00\x01\x02\x03") is None
