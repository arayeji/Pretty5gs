"""EPS NAS decoding (spec 3.1, 3.2, 3.4 and the final APN-IE rule).

Extracts, from the messages of one attach, exactly the facts the service needs:

* IMSI (Attach Request with IMSI identity, or Identity Response)
* GUTI (Attach Request with GUTI identity) as an opaque key -- we deliberately
  do NOT reconstruct an IMSI from the GUTI PLMN, because this network has a
  documented history of GUTI-PLMN encoding bugs (spec 3.2).
* IMEISV (Security Mode Complete) -> IMEI (first 14) + SV (last 2), tracked
  separately so a firmware bump is not seen as a device change (spec 3.4).
* Whether the Attach Request's PDN-Connectivity-Request carried an APN IE. Only
  UEs that did NOT set an APN are provisioned (final requirement).
* A new GUTI issued in Attach Accept / GUTI Reallocation Command, to keep the
  learned GUTI->IMSI map fresh (spec 3.2 option a).

NAS is integrity-protected but not ciphered (EEA0, spec section 1), so these
IEs are readable in a passive capture. If a message fails to decode we set
decode_error and the caller degrades rather than silently dropping the UE.
"""
from __future__ import annotations

from dataclasses import dataclass

from pycrate_mobile import NAS

# EPS mobile identity type-of-identity (TS 24.301 9.9.3.12)
ID_TYPE_IMSI = 1
ID_TYPE_IMEI = 2
ID_TYPE_IMEISV = 3
ID_TYPE_GUTI = 6


@dataclass
class NasFields:
    msg_type: str = "Other"
    imsi: str | None = None
    guti: bytes | None = None          # raw EPS mobile identity, used as opaque key
    guti_mtmsi: int | None = None
    imeisv: str | None = None
    imei: str | None = None            # first 14 digits of IMEISV
    sv: str | None = None              # last 2 digits of IMEISV
    apn_present: bool | None = None    # Attach Request only; None => unknown
    new_guti: bytes | None = None      # from Attach Accept / GUTI Reallocation
    decode_error: bool = False


def _decode_bcd_identity(b: bytes) -> tuple[int, str]:
    """Decode a TS 24.008/24.301 semi-octet mobile identity -> (type, digits)."""
    if not b:
        return (0, "")
    type_ = b[0] & 0x07
    odd = (b[0] >> 3) & 1
    digits = [b[0] >> 4]
    for byte in b[1:]:
        digits.append(byte & 0x0F)
        digits.append(byte >> 4)
    if not odd and digits and digits[-1] == 0x0F:
        digits = digits[:-1]
    return type_, "".join("%X" % d for d in digits)


def parse_eps_mobile_identity(b: bytes) -> dict:
    """Return {'type', 'imsi'|'imei'|'imeisv', 'guti', 'mtmsi'} for a raw IE V."""
    if not b:
        return {"type": 0}
    type_ = b[0] & 0x07
    if type_ == ID_TYPE_IMSI:
        _, digits = _decode_bcd_identity(b)
        return {"type": type_, "imsi": digits}
    if type_ in (ID_TYPE_IMEI, ID_TYPE_IMEISV):
        _, digits = _decode_bcd_identity(b)
        return {"type": type_, "imeisv": digits}
    if type_ == ID_TYPE_GUTI:
        # GUTI: flags(1) PLMN(3) MMEGI(2) MMEC(1) M-TMSI(4). Keep raw as key;
        # do not trust the PLMN decode (spec 3.2).
        mtmsi = int.from_bytes(b[7:11], "big") if len(b) >= 11 else None
        return {"type": type_, "guti": bytes(b), "mtmsi": mtmsi}
    return {"type": type_}


def _apn_present(esm_bytes: bytes) -> bool | None:
    """True/False if the PDN-Connectivity-Request carried an APN IE, else None."""
    if not esm_bytes:
        return None
    msg, err = NAS.parse_NASLTE_MO(esm_bytes)
    if err or msg is None or msg._name != "ESMPDNConnectivityRequest":
        return None
    try:
        return not msg["APN"].get_trans()
    except Exception:
        return None


def decode_nas(nas_bytes: bytes, uplink: bool = True) -> NasFields:
    """Decode one NAS message and pull out the fields the service cares about."""
    if not nas_bytes:
        return NasFields(decode_error=True)
    parse = NAS.parse_NASLTE_MO if uplink else NAS.parse_NASLTE_MT
    msg, err = parse(nas_bytes)
    if err or msg is None:
        # Could be a genuinely ciphered NAS (ciphering_order changed away from
        # EEA0) -- flag it so the caller can fall back (spec 3.4 / section 1).
        return NasFields(decode_error=True)

    name = msg._name
    f = NasFields(msg_type=name)

    if name == "EMMAttachRequest":
        ident = parse_eps_mobile_identity(_ie_value(msg, "EPSID", tlv=False))
        _apply_ident(f, ident)
        esm = _ie_value(msg, "ESMContainer", lve=True)
        f.apn_present = _apn_present(esm)

    elif name == "EMMIdentityResponse":
        ident = parse_eps_mobile_identity(_ie_value(msg, "ID", tlv=False))
        _apply_ident(f, ident)

    elif name == "EMMSecurityModeComplete":
        v = _ie_value(msg, "IMEISV", tlv=True)
        if v:
            _apply_ident(f, parse_eps_mobile_identity(v))

    elif name in ("EMMAttachAccept", "EMMGUTIReallocationCommand"):
        guti = _find_guti_in(msg)
        if guti:
            f.new_guti = guti

    return f


def _ie_value(msg, field: str, tlv: bool = False, lve: bool = False) -> bytes:
    """Return the raw value octets of a NAS IE.

    pycrate decodes identities into sub-fields, so we recover the on-wire value
    by stripping the length/tag prefix from the IE's own bytes:
      tlv=False (Type4LV):  1-byte length prefix
      tlv=True  (Type4TLV): tag + 1-byte length prefix
      lve=True  (Type6LVE): 2-byte length prefix
    """
    try:
        field_obj = msg[field]
        if field_obj.get_trans():  # optional IE absent
            return b""
        raw = field_obj.to_bytes()
    except Exception:
        return b""
    if lve:
        return raw[2:]
    if tlv:
        return raw[2:]
    return raw[1:]


def _apply_ident(f: NasFields, ident: dict) -> None:
    if ident.get("imsi"):
        f.imsi = ident["imsi"]
    if ident.get("guti"):
        f.guti = ident["guti"]
        f.guti_mtmsi = ident.get("mtmsi")
    if ident.get("imeisv"):
        imeisv = ident["imeisv"]
        f.imeisv = imeisv
        if len(imeisv) >= 14:
            f.imei = imeisv[:14]
            f.sv = imeisv[14:16]


def _find_guti_in(msg) -> bytes | None:
    """Best-effort GUTI extraction from Attach Accept / GUTI Reallocation."""
    for fname in ("GUTI", "EPSID"):
        try:
            if fname in [c._name for c in msg._content] and not msg[fname].get_trans():
                v = msg[fname]["V"].to_bytes()
                ident = parse_eps_mobile_identity(v)
                if ident.get("guti"):
                    return ident["guti"]
        except Exception:
            continue
    return None
