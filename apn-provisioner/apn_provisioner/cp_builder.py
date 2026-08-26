"""OMA Client Provisioning (CP) document + WSP Push + SMS segmentation builder.

This is a faithful reimplementation of the proven-working sender described in
spec sections 2.3-2.5. The output MUST byte-match the reference implementation
(/tmp/send_multi.py on the MSC host); tests/test_validator.py re-parses the
output and asserts every field, and the README documents the tshark/reference
acceptance gate.

Nothing here talks to the network or depends on live captures, so it is fully
unit-testable offline.
"""
from __future__ import annotations

from dataclasses import dataclass

from .imsi import netwpin_mac

# --- WBXML profile constants --------------------------------------------
# Fixed provisioning-profile identity for HiWEB. Only NAP-ADDRESS (the APN) is
# per-subscriber (spec 2.3); everything else is shipped verbatim.
NAPID = "HIWEBGPRS"
BOOTSTRAP_NAME = "HiWEB"
NAP_NAME = "HiWEB Internet"
APPID = "w2"

# WBXML header: v1.3, public id PROV 1.0 (0x0B), charset UTF-8 (0x6A), no strtbl
WBXML_HEADER = bytes([0x03, 0x0B, 0x6A, 0x00])


def _istr(t: str) -> bytes:
    """WBXML inline string: 0x03 <utf-8> 0x00."""
    return b"\x03" + t.encode("utf-8") + b"\x00"


def build_wbxml(apn: str) -> bytes:
    """Build the OMA CP provisioning document for the given APN.

    This is a byte-faithful port of the proven-working `build_full.py`
    (spec 2.3). The exact byte layout is load-bearing: (1) the NETWPIN MAC is
    an HMAC over these bytes, so any change silently breaks handset acceptance;
    (2) the reference was validated on the wire (RP-ACKed). tests assert this
    reproduces the golden seg1/seg2 from spec 2.2 byte for byte. Do NOT
    "simplify" the version inline value, the value-marker (0x06) code-page
    handling, or the BOOTSTRAP+APPLICATION shape -- each fixes a real bug.
    """
    if not apn:
        raise ValueError("APN must be non-empty")

    b = bytearray(WBXML_HEADER)

    # <wap-provisioningdoc version="1.0">  -- 0x46 is generic "version=",
    # so the value "1.0" follows as an inline string (NOT a self-contained tok).
    b += b"\xc5" + b"\x46" + _istr("1.0") + b"\x01"

    # BOOTSTRAP: names the provisioning profile
    b += b"\xc6" + b"\x56" + b"\x01"                 # <characteristic BOOTSTRAP>
    b += b"\x87" + b"\x07" + b"\x06" + _istr(BOOTSTRAP_NAME) + b"\x01"  # NAME
    b += b"\x01"

    # NAPDEF: the actual APN. Each parm is 0x87 <name> 0x06 <value> 0x01, where
    # <value> is an inline string or a well-known value token (0xAB/0x89).
    b += b"\xc6" + b"\x55" + b"\x01"                 # <characteristic NAPDEF>
    for tok, val in (
        (b"\x11", _istr(NAPID)),        # NAPID
        (b"\x10", b"\xab"),             # BEARER = GSM-GPRS
        (b"\x07", _istr(NAP_NAME)),     # NAME
        (b"\x08", _istr(apn)),          # NAP-ADDRESS = APN  <-- per-subscriber
        (b"\x09", b"\x89"),             # NAP-ADDRTYPE = APN
    ):
        b += b"\x87" + tok + b"\x06" + val + b"\x01"
    b += b"\x87\x14\x01"                             # INTERNET (flag parm)
    b += b"\x01"

    # APPLICATION (attribute code page 1) referencing the NAPDEF. The value
    # marker 0x06 is emitted on the CURRENT code page (page 1 for APPID/TO-NAPID)
    # -- do not switch to page 0 for it.
    b += b"\xc6" + b"\x00\x01" + b"\x55" + b"\x01"   # SWITCH_PAGE 1, APPLICATION
    b += b"\x87" + b"\x36" + b"\x06" + _istr(APPID) + b"\x01"          # APPID=w2
    b += b"\x87" + b"\x00\x00" + b"\x07" + b"\x06" + _istr(NAP_NAME) + b"\x01"  # NAME (page 0)
    b += b"\x87" + b"\x00\x01" + b"\x22" + b"\x06" + _istr(NAPID) + b"\x01"     # TO-NAPID (page 1)
    b += b"\x01"
    b += b"\x00\x00"                                 # back to code page 0
    b += b"\x01"                                     # </wap-provisioningdoc>

    return bytes(b)


# --- WSP encoding helpers ------------------------------------------------
CONTENT_TYPE = b"application/vnd.wap.connectivity-wbxml\x00"
SEC_PARAM = bytes([0x91, 0x80])  # (0x11|0x80) SEC=0 NETWPIN


def uintvar(n: int) -> bytes:
    """WSP multi-byte unsigned integer (uintvar)."""
    if n < 0:
        raise ValueError("uintvar cannot encode negatives")
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    return bytes(reversed(out))


def encode_value_length(n: int) -> bytes:
    """WSP value-length: short-length (<=30) or 0x1F + uintvar (spec 2.3)."""
    if n <= 30:
        return bytes([n])
    return bytes([0x1F]) + uintvar(n)


def build_content_type(mac_hex: str) -> bytes:
    """Constructed content-type field with SEC=NETWPIN + MAC (spec 2.3)."""
    if len(mac_hex) != 40 or mac_hex != mac_hex.upper():
        raise ValueError("MAC must be 40 uppercase hex chars")
    mac_param = bytes([0x92]) + mac_hex.encode("ascii") + b"\x00"
    value = CONTENT_TYPE + SEC_PARAM + mac_param
    return encode_value_length(len(value)) + value


def build_wsp_push(wbxml: bytes, mac_hex: str) -> bytes:
    """WSP Push PDU: TID, PDU-type, headers-length, content-type, WBXML (2.3)."""
    ct_field = build_content_type(mac_hex)
    return bytes([0x01, 0x06]) + uintvar(len(ct_field)) + ct_field + wbxml


# --- SMS concatenation (spec 2.2) ---------------------------------------
DEST_PORT = 0x0B84  # 2948
SRC_PORT = 0x23F0   # 9200
MAX_TPDU = 140
UDH_LEN = 12
SEG_PAYLOAD = MAX_TPDU - UDH_LEN  # 128


def _udh(ref: int, total: int, seq: int) -> bytes:
    return bytes([
        0x0B,                       # UDHL = 11
        0x05, 0x04,                 # port addressing, 16-bit
        (DEST_PORT >> 8) & 0xFF, DEST_PORT & 0xFF,
        (SRC_PORT >> 8) & 0xFF, SRC_PORT & 0xFF,
        0x00, 0x03,                 # concatenation, 8-bit ref
        ref & 0xFF, total & 0xFF, seq & 0xFF,
    ])


def segment(pdu: bytes, ref: int) -> list[bytes]:
    """Split a WSP PDU into UDH+payload short_message octets (<=140 each)."""
    chunks = [pdu[i:i + SEG_PAYLOAD] for i in range(0, len(pdu), SEG_PAYLOAD)]
    if not chunks:
        chunks = [b""]
    total = len(chunks)
    segments = []
    for seq, chunk in enumerate(chunks, start=1):
        sm = _udh(ref, total, seq) + chunk
        assert len(sm) <= MAX_TPDU, "segment exceeds 140 octets"
        segments.append(sm)
    return segments


@dataclass(frozen=True)
class ProvisioningMessage:
    """Everything needed to send one provisioning SMS, plus artifacts to log."""

    imsi: str
    msisdn: str
    apn: str
    wbxml: bytes
    mac_hex: str
    wsp_pdu: bytes
    segments: list[bytes]

    @property
    def segment_count(self) -> int:
        return len(self.segments)


def build_message(imsi: str, msisdn: str, apn: str, ref: int) -> ProvisioningMessage:
    """Build the full provisioning message for a subscriber (spec 2.1-2.5)."""
    wbxml = build_wbxml(apn)
    mac_hex = netwpin_mac(imsi, wbxml)
    wsp_pdu = build_wsp_push(wbxml, mac_hex)
    segments = segment(wsp_pdu, ref)
    return ProvisioningMessage(
        imsi=imsi, msisdn=msisdn, apn=apn, wbxml=wbxml,
        mac_hex=mac_hex, wsp_pdu=wsp_pdu, segments=segments,
    )
