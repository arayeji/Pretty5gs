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

# --- WBXML global tokens -------------------------------------------------
WBXML_HEADER = bytes([0x03, 0x0B, 0x6A, 0x00])  # v1.3, PROV 1.0, UTF-8, no strtbl
SWITCH_PAGE = 0x00
END = 0x01
STR_I = 0x03  # inline string start
CONTENT = 0x40
ATTRS = 0x80

# --- Tag tokens (tag code page 0) ---------------------------------------
TAG_WAPPROV = 0x05
TAG_CHARACTERISTIC = 0x06
TAG_PARM = 0x07

# --- Attribute-start tokens, keyed by (code_page, token) ----------------
# Only the tokens this document needs; values mirror the OMA ProvCont tables
# that tshark's WSP dissector implements.
A_VERSION_10 = (0, 0x46)   # version="1.0"
A_VALUE = (0, 0x06)        # value= (generic, inline value follows)
A_NAME_NAME = (0, 0x07)    # name="NAME"
A_NAME_NAPADDRESS = (0, 0x08)   # name="NAP-ADDRESS"
A_NAME_NAPADDRTYPE = (0, 0x09)  # name="NAP-ADDRTYPE"
A_NAME_BEARER = (0, 0x10)  # name="BEARER"
A_NAME_NAPID = (0, 0x11)   # name="NAPID"
A_NAME_INTERNET = (0, 0x14)  # name="INTERNET"
A_TYPE_NAPDEF = (0, 0x55)  # type="NAPDEF"
A_TYPE_BOOTSTRAP = (0, 0x56)  # type="BOOTSTRAP"
# Code page 1
A_TYPE_APPLICATION = (1, 0x55)  # type="APPLICATION"
A_NAME_APPID = (1, 0x36)   # name="APPID"
A_NAME_TONAPID = (1, 0x22)  # name="TO-NAPID"

# --- Attribute-value tokens (code page 0) -------------------------------
V_APN = 0x89       # "APN"
V_GSM_GPRS = 0xAB  # "GSM-GPRS"
V_IPV4 = 0x85      # "IPV4"


class _WbxmlWriter:
    """Emits a WBXML byte stream, tracking the current attribute code page."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.attr_page = 0

    def _attr_token(self, token: tuple[int, int]) -> None:
        page, code = token
        if page != self.attr_page:
            self.buf += bytes([SWITCH_PAGE, page])
            self.attr_page = page
        self.buf.append(code)

    def inline(self, text: str) -> None:
        self.buf.append(STR_I)
        self.buf += text.encode("utf-8")
        self.buf.append(0x00)

    def parm_inline(self, name_token: tuple[int, int], value: str) -> None:
        """<parm name="X" value="<inline>"/>"""
        self.buf.append(TAG_PARM | ATTRS)
        self._attr_token(name_token)
        self._attr_token(A_VALUE)
        self.inline(value)
        self.buf.append(END)

    def parm_token(self, name_token: tuple[int, int], value_token: int) -> None:
        """<parm name="X" value="<well-known token>"/>"""
        self.buf.append(TAG_PARM | ATTRS)
        self._attr_token(name_token)
        self._attr_token(A_VALUE)
        # value token lives on attribute code page 0
        if self.attr_page != 0:
            self.buf += bytes([SWITCH_PAGE, 0])
            self.attr_page = 0
        self.buf.append(value_token)
        self.buf.append(END)

    def parm_flag(self, name_token: tuple[int, int]) -> None:
        """<parm name="X"/> (no value)"""
        self.buf.append(TAG_PARM | ATTRS)
        self._attr_token(name_token)
        self.buf.append(END)

    def char_open(self, type_token: tuple[int, int]) -> None:
        self.buf.append(TAG_CHARACTERISTIC | ATTRS | CONTENT)
        self._attr_token(type_token)
        self.buf.append(END)  # end of attribute list

    def close(self) -> None:
        self.buf.append(END)  # end of element content


def build_wbxml(apn: str) -> bytes:
    """Build the OMA CP provisioning document for the given APN (spec 2.5)."""
    if not apn:
        raise ValueError("APN must be non-empty")
    w = _WbxmlWriter()
    # <wap-provisioningdoc version="1.0">
    w.buf.append(TAG_WAPPROV | ATTRS | CONTENT)
    w._attr_token(A_VERSION_10)
    w.buf.append(END)

    # BOOTSTRAP
    w.char_open(A_TYPE_BOOTSTRAP)
    w.parm_inline(A_NAME_NAME, "HiWEB")
    w.close()

    # NAPDEF
    w.char_open(A_TYPE_NAPDEF)
    w.parm_inline(A_NAME_NAPID, "HIWEBGPRS")
    w.parm_token(A_NAME_BEARER, V_GSM_GPRS)
    w.parm_inline(A_NAME_NAME, "HiWEB Internet")
    w.parm_inline(A_NAME_NAPADDRESS, apn)
    w.parm_token(A_NAME_NAPADDRTYPE, V_APN)
    w.parm_flag(A_NAME_INTERNET)
    w.close()

    # APPLICATION (attribute code page 1 for APPID/TO-NAPID; NAME stays page 0)
    w.char_open(A_TYPE_APPLICATION)
    w.parm_inline(A_NAME_APPID, "w2")
    w.parm_inline(A_NAME_NAME, "HiWEB Internet")
    w.parm_inline(A_NAME_TONAPID, "HIWEBGPRS")
    w.close()

    # </wap-provisioningdoc>
    w.close()
    return WBXML_HEADER + bytes(w.buf)


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
