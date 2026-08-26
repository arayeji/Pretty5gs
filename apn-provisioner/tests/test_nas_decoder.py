from apn_provisioner.nas_decoder import decode_nas, parse_eps_mobile_identity
from tests import nas_fixtures as fx

IMSI = "432129951539038"
IMEISV = "3512340678901512"  # 14-digit IMEI + 2-digit SV


def test_attach_request_imsi_no_apn():
    esm = fx.make_pdn_connectivity_request(apn=None)
    nas = fx.make_attach_request(fx.make_imsi_id(IMSI), esm)
    f = decode_nas(nas, uplink=True)
    assert f.msg_type == "EMMAttachRequest"
    assert f.imsi == IMSI
    assert f.apn_present is False  # UE did NOT set an APN -> eligible


def test_attach_request_imsi_with_apn():
    esm = fx.make_pdn_connectivity_request(apn="someapn.mnc012")
    nas = fx.make_attach_request(fx.make_imsi_id(IMSI), esm)
    f = decode_nas(nas, uplink=True)
    assert f.imsi == IMSI
    assert f.apn_present is True  # UE set an APN -> NOT eligible


def test_attach_request_guti_only():
    esm = fx.make_pdn_connectivity_request(apn=None)
    nas = fx.make_attach_request(fx.make_guti_id(mtmsi=0xC0DECAFE), esm)
    f = decode_nas(nas, uplink=True)
    assert f.imsi is None  # common re-attach path: no IMSI in the clear
    assert f.guti is not None
    assert f.guti_mtmsi == 0xC0DECAFE


def test_identity_response_imsi():
    f = decode_nas(fx.make_identity_response(IMSI), uplink=True)
    assert f.msg_type == "EMMIdentityResponse"
    assert f.imsi == IMSI


def test_security_mode_complete_with_imeisv():
    f = decode_nas(fx.make_security_mode_complete(IMEISV), uplink=True)
    assert f.msg_type == "EMMSecurityModeComplete"
    assert f.imeisv == IMEISV
    assert f.imei == IMEISV[:14]
    assert f.sv == IMEISV[14:16]


def test_security_mode_complete_without_imeisv():
    f = decode_nas(fx.make_security_mode_complete(None), uplink=True)
    assert f.imeisv is None
    assert f.imei is None  # session with no IMEISV -> IMEI tracking disabled


def test_undecodable_nas_flags_error():
    f = decode_nas(b"\xff\xff\xff\xff", uplink=True)
    assert f.decode_error is True


def test_imsi_identity_roundtrip():
    ident = parse_eps_mobile_identity(fx.make_imsi_id(IMSI))
    assert ident["imsi"] == IMSI
