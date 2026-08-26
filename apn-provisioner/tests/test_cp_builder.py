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


# Authoritative acceptance gate (spec 2.2 / 2.4): values reproduced from the
# real captured send to IMSI 432129951539038 / APN "hiweb". Verified against the
# reference build_full.py output (byte-identical WBXML) -- see the on-server
# diff in the README. The NETWPIN MAC is an HMAC-SHA1 over the WBXML document,
# so reproducing this MAC proves our WBXML is byte-identical to the proven one.
# NOTE: the true on-wire MAC begins "A177" (the "4177" in the prose spec was a
# one-char transcription slip; the raw seg1 hex is 0x41='A').
REF_IMSI = "432129951539038"
REF_APN = "hiweb"
REF_MAC = "A177E1653F7B3A67DE18355FA04B4232B0604D80"
REF_WBXML_HEX = (
    "030b6a00c54603312e300001c65601870706034869574542000101c65501871106034849574542"
    "475052530001871006ab0187070603486957454220496e7465726e6574000187080603686977656"
    "20001870906890187140101c6000155018736060377320001870000070603486957454220496e746"
    "5726e65740001870001220603484957454247505253000101000001"
)


def test_wbxml_matches_reference_bytes():
    # Byte-exact match to the reference build_full.py document (spec 2.3).
    assert cp.build_wbxml(REF_APN).hex() == REF_WBXML_HEX
    assert len(cp.build_wbxml(REF_APN)) == 146


def test_wbxml_matches_reference_mac():
    # If the MAC matches, the document bytes match (HMAC has no practical
    # preimage/collision), so this is the strongest single byte-exactness gate.
    from apn_provisioner.imsi import netwpin_mac
    assert netwpin_mac(REF_IMSI, cp.build_wbxml(REF_APN)) == REF_MAC


def test_reference_sizes_and_segmentation():
    # Spec 2.2: WBXML 146 B -> WSP 234 B -> 2 segments (140 + 118 octets).
    msg = cp.build_message(REF_IMSI, "989951079038", REF_APN, ref=0x55)
    assert len(msg.wbxml) == 146
    assert len(msg.wsp_pdu) == 234
    assert msg.mac_hex == REF_MAC
    assert msg.segment_count == 2
    assert len(msg.segments[0]) == 140
    assert len(msg.segments[1]) == 118
