"""S1AP PDU decoding (spec 3.1).

Pulls the correlation IDs, the embedded NAS-PDU, and (for the fallback in 3.4)
the Masked IMEISV out of each S1AP message. We match IEs by the decoded value's
type name rather than by hardcoded IE ids, which is robust across S1AP releases.
"""
from __future__ import annotations

from dataclasses import dataclass

from pycrate_asn1dir import S1AP

_PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU


@dataclass
class S1apEvent:
    proc: str = "Other"
    enb_ue_id: int | None = None
    mme_ue_id: int | None = None
    nas_pdu: bytes | None = None
    masked_imeisv: str | None = None


def decode_s1ap(payload: bytes) -> S1apEvent | None:
    """Decode one S1AP PDU. Returns None if it is not decodable S1AP."""
    try:
        _PDU.from_aper(payload)
        choice, body = _PDU.get_val()
    except Exception:
        return None
    try:
        msg_name, content = body["value"]
    except Exception:
        return None

    ev = S1apEvent(proc=msg_name)
    ies = content.get("protocolIEs", []) if isinstance(content, dict) else []
    for ie in ies:
        try:
            vname, vval = ie["value"]
        except Exception:
            continue
        if vname == "ENB-UE-S1AP-ID":
            ev.enb_ue_id = int(vval)
        elif vname == "MME-UE-S1AP-ID":
            ev.mme_ue_id = int(vval)
        elif vname == "NAS-PDU":
            ev.nas_pdu = bytes(vval)
        elif vname == "MaskedIMEISV":
            ev.masked_imeisv = _bitstr_to_digits(vval)
        elif vname == "UE-S1AP-IDs":
            # UEContextReleaseCommand carries the id pair here
            try:
                kind, pair = vval
                if kind == "uE-S1AP-ID-pair":
                    ev.mme_ue_id = int(pair["mME-UE-S1AP-ID"])
                    ev.enb_ue_id = int(pair["eNB-UE-S1AP-ID"])
                elif kind == "mME-UE-S1AP-ID":
                    ev.mme_ue_id = int(pair)
            except Exception:
                pass
    return ev


def is_release(proc: str) -> bool:
    return proc.startswith("UEContextRelease")


def is_initial_context_setup(proc: str) -> bool:
    return proc == "InitialContextSetupRequest"


def _bitstr_to_digits(val) -> str | None:
    """Masked IMEISV is a 64-bit string of BCD; masked nibbles read as 0xF."""
    try:
        ival, blen = val  # pycrate BIT STRING -> (int, length)
        raw = ival.to_bytes((blen + 7) // 8, "big")
    except Exception:
        try:
            raw = bytes(val)
        except Exception:
            return None
    nibbles = []
    for b in raw:
        nibbles.append(b >> 4)
        nibbles.append(b & 0x0F)
    return "".join("%X" % n for n in nibbles)
