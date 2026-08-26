"""IMSI -> 3GPP semi-octet (TBCD) key derivation for the NETWPIN MAC (spec 2.4).

The NETWPIN MAC is HMAC-SHA1 over the WBXML document, keyed by the IMSI encoded
as a TS 24.008 mobile-identity semi-octet string:

    byte0 = (digit1 << 4) | (0x9 if odd number of digits else 0x1)
    then each remaining digit pair -> byte = (next_digit << 4) | this_digit
    an odd tail is padded with 0xF in the high nibble

Verified against the OMA worked example and a real subscriber from this network
(see tests/test_imsi.py):

    310170212226432 -> 39 01 71 20 21 22 46 23
    432129951539038 -> 49 23 21 99 15 35 09 83
"""
from __future__ import annotations

import hashlib
import hmac


def imsi_to_semi_octets(imsi: str) -> bytes:
    """Encode an IMSI digit string into its TS 24.008 semi-octet key bytes."""
    if not imsi or not imsi.isdigit():
        raise ValueError(f"IMSI must be a non-empty digit string, got {imsi!r}")
    digits = [int(c) for c in imsi]
    odd = (len(digits) % 2) == 1
    out = [(digits[0] << 4) | (0x9 if odd else 0x1)]
    rest = digits[1:]
    for i in range(0, len(rest), 2):
        low = rest[i]
        high = rest[i + 1] if i + 1 < len(rest) else 0xF
        out.append((high << 4) | low)
    return bytes(out)


def netwpin_mac(imsi: str, wbxml: bytes) -> str:
    """Return the uppercase 40-hex-char NETWPIN MAC for a WBXML document.

    Handsets compare the MAC case-sensitively, so the hex MUST be uppercase.
    """
    key = imsi_to_semi_octets(imsi)
    digest = hmac.new(key, wbxml, hashlib.sha1).hexdigest()
    return digest.upper()
