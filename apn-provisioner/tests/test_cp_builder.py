import pytest

from apn_provisioner import cp_builder as cp


def test_wbxml_header():
    w = cp.build_wbxml("hiweb")
    assert w[:4] == bytes([0x03, 0x0B, 0x6A, 0x00])


def test_value_length_short_and_long():
    assert cp.encode_value_length(10) == bytes([10])
    assert cp.encode_value_length(31) == bytes([0x1F, 31])
    # the real content-type is > 30 bytes, so it MUST use the long form and
    # never leak a raw length byte that renders as "Sapplication/..."
    ct = cp.build_content_type("A" * 40)
    assert ct[0] == 0x1F


def test_uintvar():
    assert cp.uintvar(0) == b"\x00"
    assert cp.uintvar(127) == b"\x7f"
    assert cp.uintvar(128) == bytes([0x81, 0x00])
    assert cp.uintvar(84) == b"\x54"


def test_mac_must_be_uppercase():
    with pytest.raises(ValueError):
        cp.build_content_type("a" * 40)
    with pytest.raises(ValueError):
        cp.build_content_type("ABC")


def test_udh_format():
    segs = cp.segment(b"X" * 200, ref=0x5A)
    assert len(segs) == 2
    udh = segs[0][:12]
    # 0B 05 04 0B84 23F0 00 03 ref tot seq
    assert udh == bytes([0x0B, 0x05, 0x04, 0x0B, 0x84, 0x23, 0xF0, 0x00, 0x03, 0x5A, 2, 1])
    assert segs[1][9:12] == bytes([0x5A, 2, 2])
    for s in segs:
        assert len(s) <= 140


def test_segment_payload_is_128():
    segs = cp.segment(b"Y" * 128, ref=1)
    assert len(segs) == 1
    assert len(segs[0]) == 140  # 12 UDH + 128 payload


GOLDEN_WBXML_HIWEB = (
    "030b6a00c54601c65601870706034869574542000101c65501871106034849574542"
    "475052530001871006ab0187070603486957454220496e7465726e65740001870806"
    "0368697765620001870906890187140101c6000155018736000006037732000187070"
    "603486957454220496e7465726e65740001870001220000060348495745424750525"
    "300010101"
)


def test_wbxml_golden_bytes():
    # Regression pin. This MUST also be diffed against the on-server reference
    # (/tmp/send_multi.py) as the authoritative acceptance gate -- see README.
    assert cp.build_wbxml("hiweb").hex() == GOLDEN_WBXML_HIWEB.replace(" ", "")


def test_mac_golden_for_example_subscriber():
    msg = cp.build_message("432129951539038", "989951079038", "hiweb", ref=0x2A)
    assert msg.mac_hex == "346A77ECD1ED230CC996F553551E0E8B63F0E9EB"


def test_build_message_two_segments_for_full_doc():
    msg = cp.build_message("432129951539038", "989951079038", "hiweb", ref=7)
    # the secured document is ~234 bytes -> MUST concatenate (spec 2.2)
    assert msg.wsp_pdu.__len__() > 140
    assert msg.segment_count >= 2
    assert len(msg.mac_hex) == 40
