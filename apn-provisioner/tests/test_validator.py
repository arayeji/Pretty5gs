import pytest

from apn_provisioner import cp_builder as cp
from apn_provisioner.validator import (
    MalformedError,
    decode_wbxml,
    decode_wsp_push,
    run_tshark_validation,
)


def _find_char(root, ctype):
    return [c for c in root.children if c.attrs.get("type") == ctype]


def test_roundtrip_wbxml_structure():
    apn = "hiweb"
    wbxml = cp.build_wbxml(apn)
    root = decode_wbxml(wbxml)
    assert root.tag == "wap-provisioningdoc"
    assert root.attrs["version"] == "1.0"

    boot = _find_char(root, "BOOTSTRAP")[0]
    parms = {p.attrs["name"]: p.attrs.get("value", "") for p in boot.children}
    assert parms["NAME"] == "HiWEB"

    napdef = _find_char(root, "NAPDEF")[0]
    np = {p.attrs["name"]: p.attrs.get("value", "") for p in napdef.children}
    assert np["NAPID"] == "HIWEBGPRS"
    assert np["BEARER"] == "GSM-GPRS"
    assert np["NAME"] == "HiWEB Internet"
    assert np["NAP-ADDRESS"] == apn  # dynamic APN from HSS
    assert np["NAP-ADDRTYPE"] == "APN"
    assert "INTERNET" in np  # flag parm, empty value

    app = _find_char(root, "APPLICATION")[0]
    ap = {p.attrs["name"]: p.attrs.get("value", "") for p in app.children}
    assert ap["APPID"] == "w2"
    assert ap["NAME"] == "HiWEB Internet"  # NAME stays on code page 0
    assert ap["TO-NAPID"] == "HIWEBGPRS"  # links back to the NAPDEF


def test_dynamic_apn_flows_through():
    wbxml = cp.build_wbxml("internet.myoperator")
    root = decode_wbxml(wbxml)
    napdef = _find_char(root, "NAPDEF")[0]
    np = {p.attrs["name"]: p.attrs.get("value", "") for p in napdef.children}
    assert np["NAP-ADDRESS"] == "internet.myoperator"


def test_roundtrip_wsp_push():
    msg = cp.build_message("432129951539038", "989951079038", "hiweb", ref=3)
    parsed = decode_wsp_push(msg.wsp_pdu)
    assert parsed.content_type == "application/vnd.wap.connectivity-wbxml"
    assert parsed.sec == "NETWPIN"
    assert parsed.mac == msg.mac_hex
    # the WBXML carried inside must itself re-parse
    root = decode_wbxml(parsed.wbxml)
    assert root.tag == "wap-provisioningdoc"


def test_malformed_is_rejected():
    with pytest.raises(MalformedError):
        decode_wbxml(b"\x00\x01\x02")


def test_tshark_validation_optional():
    msg = cp.build_message("432129951539038", "989951079038", "hiweb", ref=3)
    out = run_tshark_validation(msg.wsp_pdu)
    if out is None:
        pytest.skip("tshark not installed; run on a host with tshark (see README)")
    assert "WAP Binary XML" in out
    assert "NETWPIN" in out
