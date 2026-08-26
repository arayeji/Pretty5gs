"""Validation harness for the CP builder (spec 2.6).

Two independent checks:

1. decode_wsp_push / decode_wbxml -- a pure-Python re-parser of the bytes the
   builder produced. Always runs; the round trip catches structural mistakes
   (wrong value-length, dropped END tokens, mis-paged attributes) without any
   external tooling.

2. run_tshark_validation -- wraps the produced PDU in a synthetic pcap and runs
   `tshark -V`, exactly as the spec's "build this, it caught three real bugs"
   step. Auto-skips (returns None) when tshark is not installed so CI still runs;
   the README documents running it on a host that has tshark as the acceptance
   gate.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

# Reverse token tables (mirror cp_builder). value is None => generic, value
# supplied by the following inline string / value token.
_ATTR_START = {
    (0, 0x46): ("version", None),   # generic "version="; inline value follows
    (0, 0x06): ("value", None),
    (0, 0x07): ("name", "NAME"),
    (0, 0x08): ("name", "NAP-ADDRESS"),
    (0, 0x09): ("name", "NAP-ADDRTYPE"),
    (0, 0x10): ("name", "BEARER"),
    (0, 0x11): ("name", "NAPID"),
    (0, 0x14): ("name", "INTERNET"),
    (0, 0x55): ("type", "NAPDEF"),
    (0, 0x56): ("type", "BOOTSTRAP"),
    (1, 0x55): ("type", "APPLICATION"),
    (1, 0x36): ("name", "APPID"),
    (1, 0x22): ("name", "TO-NAPID"),
}
_VALUE_TOKEN = {0x89: "APN", 0xAB: "GSM-GPRS", 0x85: "IPV4"}
_TAG = {0x05: "wap-provisioningdoc", 0x06: "characteristic", 0x07: "parm"}


class MalformedError(Exception):
    """Raised when the produced bytes do not parse -- treat as a build failure."""


@dataclass
class Element:
    tag: str
    attrs: dict = field(default_factory=dict)
    children: list = field(default_factory=list)


class _Reader:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def u8(self) -> int:
        if self.i >= len(self.d):
            raise MalformedError("unexpected end of WBXML")
        b = self.d[self.i]
        self.i += 1
        return b

    def cstr(self) -> str:
        end = self.d.find(b"\x00", self.i)
        if end < 0:
            raise MalformedError("unterminated inline string")
        s = self.d[self.i:end].decode("utf-8")
        self.i = end + 1
        return s


def decode_wbxml(wbxml: bytes) -> Element:
    if wbxml[:1] != b"\x03":
        raise MalformedError("bad WBXML version byte")
    r = _Reader(wbxml)
    r.u8()  # version 0x03
    r.u8()  # public id 0x0B
    r.u8()  # charset 0x6A
    strtbl_len = r.u8()
    if strtbl_len != 0:
        raise MalformedError("unexpected string table")
    root = _read_element(r, page=[0])
    return root


def _read_element(r: _Reader, page: list) -> Element:
    tagb = r.u8()
    base = tagb & 0x3F
    has_attrs = bool(tagb & 0x80)
    has_content = bool(tagb & 0x40)
    if base not in _TAG:
        raise MalformedError(f"unknown tag token 0x{base:02X}")
    el = Element(tag=_TAG[base])
    if has_attrs:
        _read_attrs(r, el, page)
    if has_content:
        while True:
            b = r.d[r.i]
            if b == 0x01:  # END of content
                r.i += 1
                break
            if b == 0x00:  # SWITCH_PAGE on the tag code page (all tags are p0)
                r.i += 1
                r.u8()  # consume target page
                continue
            el.children.append(_read_element(r, page))
    return el


def _read_attrs(r: _Reader, el: Element, page: list) -> None:
    pending = None  # attribute name awaiting a value
    while True:
        b = r.u8()
        if b == 0x01:  # END of attribute list
            if pending is not None:
                el.attrs[pending] = ""
            break
        if b == 0x00:  # SWITCH_PAGE
            page[0] = r.u8()
            continue
        if b == 0x03:  # inline string value
            if pending is None:
                raise MalformedError("inline value with no attribute")
            el.attrs[pending] = r.cstr()
            pending = None
            continue
        if b >= 0x80:  # well-known attribute value token
            if pending is None:
                raise MalformedError("value token with no attribute")
            if b not in _VALUE_TOKEN:
                raise MalformedError(f"unknown value token 0x{b:02X}")
            el.attrs[pending] = _VALUE_TOKEN[b]
            pending = None
            continue
        if b == 0x06:  # "value=" marker, valid on the current code page
            if pending is not None:
                el.attrs[pending] = ""
            pending = "value"
            continue
        # attribute-start token
        key = (page[0], b)
        if key not in _ATTR_START:
            raise MalformedError(f"unknown attr-start (page {page[0]}, 0x{b:02X})")
        name, val = _ATTR_START[key]
        if pending is not None:  # previous attr had no explicit value (flag)
            el.attrs[pending] = ""
            pending = None
        if val is None:
            pending = name
        else:
            el.attrs[name] = val


@dataclass
class WspPush:
    tid: int
    content_type: str
    sec: str
    mac: str
    wbxml: bytes


def _read_uintvar(d: bytes, i: int) -> tuple[int, int]:
    n = 0
    while True:
        b = d[i]
        i += 1
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            return n, i


def decode_wsp_push(pdu: bytes) -> WspPush:
    if pdu[1] != 0x06:
        raise MalformedError("not a WSP Push PDU")
    tid = pdu[0]
    headers_len, i = _read_uintvar(pdu, 2)
    ct_field = pdu[i:i + headers_len]
    wbxml = pdu[i + headers_len:]
    # value-length
    vl = ct_field[0]
    if vl <= 30:
        j = 1
    elif vl == 0x1F:
        _, j = _read_uintvar(ct_field, 1)
    else:
        raise MalformedError(f"bad content-type value-length 0x{vl:02X}")
    value = ct_field[j:]
    nul = value.find(b"\x00")
    if nul < 0:
        raise MalformedError("content-type media not terminated")
    media = value[:nul].decode("ascii")
    if not media.startswith("application/vnd.wap.connectivity-wbxml"):
        raise MalformedError(f"unexpected media type {media!r}")
    rest = value[nul + 1:]
    sec = mac = None
    k = 0
    while k < len(rest):
        p = rest[k]
        if p == 0x91:  # SEC
            secval = rest[k + 1]
            sec = {0x80: "NETWPIN", 0x81: "USERPIN", 0x82: "USERNETWPIN"}.get(
                secval, f"0x{secval:02X}")
            k += 2
        elif p == 0x92:  # MAC (text-string)
            end = rest.find(b"\x00", k + 1)
            mac = rest[k + 1:end].decode("ascii")
            k = end + 1
        else:
            raise MalformedError(f"unknown content-type param 0x{p:02X}")
    return WspPush(tid=tid, content_type=media, sec=sec, mac=mac, wbxml=wbxml)


def run_tshark_validation(pdu: bytes) -> str | None:
    """Wrap the PDU in a pcap and run tshark -V; return output, or None if tshark
    is unavailable. Raises MalformedError if tshark reports a malformed packet."""
    tshark = shutil.which("tshark")
    if not tshark:
        return None
    from scapy.all import Ether, IP, UDP, Raw, wrpcap  # local import

    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=40000, dport=9200) / Raw(pdu)
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, [pkt])
        path = f.name
    out = subprocess.run(
        [tshark, "-r", path, "-V", "-o", "wsp.udp_ports:9200"],
        capture_output=True, text=True, timeout=30,
    ).stdout
    if "Malformed Packet: WSP" in out or "Malformed Packet" in out:
        raise MalformedError("tshark reports malformed WSP packet")
    return out
