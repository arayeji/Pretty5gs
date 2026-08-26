"""Test helpers that build spec-accurate S1AP + EPS NAS byte payloads and pcaps.

These are hand-encoded per TS 24.301 (EPS mobile identity, APN IE) so they are an
independent anchor for the extraction logic -- not merely pycrate encoding fed
back into pycrate. Real captured pcaps from the network can be dropped into
tests/fixtures/pcaps/real/ and are exercised by the same assertions
(see test_real_pcaps.py).
"""
from __future__ import annotations

from pycrate_asn1dir import S1AP

# S1AP procedure codes / IE ids
PC_INITIAL_UE = 12
PC_DOWNLINK_NAS = 11
PC_UPLINK_NAS = 13
PC_ICS = 9
PC_UE_CTX_REL = 23
IE_MME_UE_ID = 0
IE_ENB_UE_ID = 8
IE_NAS_PDU = 26


def encode_bcd_identity(digits: str, type_: int) -> bytes:
    """Inverse of nas_decoder._decode_bcd_identity (semi-octet mobile identity)."""
    ds = [int(c) for c in digits]
    odd = len(ds) % 2 == 1
    b0 = (ds[0] << 4) | ((1 if odd else 0) << 3) | (type_ & 0x07)
    out = [b0]
    rest = ds[1:]
    for i in range(0, len(rest), 2):
        low = rest[i]
        high = rest[i + 1] if i + 1 < len(rest) else 0xF
        out.append((high << 4) | low)
    return bytes(out)


def make_imsi_id(imsi: str) -> bytes:
    return encode_bcd_identity(imsi, 1)


def make_imeisv_id(imeisv: str) -> bytes:
    return encode_bcd_identity(imeisv, 3)


def make_guti_id(plmn=b"\x00\xf1\x10", mmegi=b"\x80\x01", mmec=1, mtmsi=0xC0DECAFE) -> bytes:
    return bytes([0xF6]) + plmn + mmegi + bytes([mmec]) + mtmsi.to_bytes(4, "big")


def encode_apn(apn: str) -> bytes:
    out = bytearray()
    for label in apn.split("."):
        b = label.encode("ascii")
        out.append(len(b))
        out += b
    return bytes(out)


def make_pdn_connectivity_request(apn: str | None) -> bytes:
    # PD/EBT=0x02, PTI=0x01, Type=0xD0 (PDN CONNECTIVITY REQUEST), PDNType|RequestType=0x11
    buf = bytearray([0x02, 0x01, 0xD0, 0x11])
    if apn is not None:
        v = encode_apn(apn)
        buf += bytes([0x28, len(v)]) + v  # APN IE, IEI 0x28
    return bytes(buf)


def make_attach_request(eps_id: bytes, esm: bytes) -> bytes:
    # EMM header: sec hdr 0 + PD 7 = 0x07; msg type Attach Request = 0x41
    buf = bytearray([0x07, 0x41])
    # EPS attach type (low) + NAS KSI (high). 0x02 = EPS attach, KSI 0
    buf.append(0x02)
    # EPSID as Type4LV: length + value
    buf.append(len(eps_id))
    buf += eps_id
    # UENetCap (Type4LV) minimal
    buf += bytes([0x02, 0x00, 0x00])
    # ESMContainer Type6LVE: 2-byte length + value
    buf += len(esm).to_bytes(2, "big") + esm
    return bytes(buf)


def make_identity_response(imsi: str) -> bytes:
    idv = make_imsi_id(imsi)
    # EMM header 0x07, msg type Identity Response 0x56, ID Type4LV
    return bytes([0x07, 0x56, len(idv)]) + idv


def make_security_mode_complete(imeisv: str | None) -> bytes:
    buf = bytearray([0x07, 0x5E])  # EMM, Security Mode Complete
    if imeisv is not None:
        v = make_imeisv_id(imeisv)
        buf += bytes([0x23, len(v)]) + v  # IMEISV IE, IEI 0x23, Type4TLV
    return bytes(buf)


def make_attach_complete() -> bytes:
    # EMM 0x07, Attach Complete 0x43, ESMContainer (empty-ish activate default ok)
    esm = bytes([0x02, 0x00, 0xC2])  # minimal ESM message
    return bytes([0x07, 0x43]) + len(esm).to_bytes(2, "big") + esm


def wrap_s1ap(proc: int, msg_name: str, ies: list) -> bytes:
    pdu = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
    val = ("initiatingMessage", {
        "procedureCode": proc,
        "criticality": "ignore",
        "value": (msg_name, {"protocolIEs": ies}),
    })
    pdu.set_val(val)
    return pdu.to_aper()


def s1ap_initial_ue(enb_ue_id: int, nas_pdu: bytes) -> bytes:
    ies = [
        {"id": IE_ENB_UE_ID, "criticality": "reject", "value": ("ENB-UE-S1AP-ID", enb_ue_id)},
        {"id": IE_NAS_PDU, "criticality": "reject", "value": ("NAS-PDU", nas_pdu)},
    ]
    return wrap_s1ap(PC_INITIAL_UE, "InitialUEMessage", ies)


def s1ap_uplink_nas(mme_ue_id: int, enb_ue_id: int, nas_pdu: bytes) -> bytes:
    ies = [
        {"id": IE_MME_UE_ID, "criticality": "reject", "value": ("MME-UE-S1AP-ID", mme_ue_id)},
        {"id": IE_ENB_UE_ID, "criticality": "reject", "value": ("ENB-UE-S1AP-ID", enb_ue_id)},
        {"id": IE_NAS_PDU, "criticality": "reject", "value": ("NAS-PDU", nas_pdu)},
    ]
    return wrap_s1ap(PC_UPLINK_NAS, "UplinkNASTransport", ies)


def s1ap_downlink_nas(mme_ue_id: int, enb_ue_id: int, nas_pdu: bytes) -> bytes:
    ies = [
        {"id": IE_MME_UE_ID, "criticality": "reject", "value": ("MME-UE-S1AP-ID", mme_ue_id)},
        {"id": IE_ENB_UE_ID, "criticality": "reject", "value": ("ENB-UE-S1AP-ID", enb_ue_id)},
        {"id": IE_NAS_PDU, "criticality": "reject", "value": ("NAS-PDU", nas_pdu)},
    ]
    return wrap_s1ap(PC_DOWNLINK_NAS, "DownlinkNASTransport", ies)


def s1ap_ue_context_release(mme_ue_id: int, enb_ue_id: int) -> bytes:
    ies = [{
        "id": 99, "criticality": "reject",
        "value": ("UE-S1AP-IDs", ("uE-S1AP-ID-pair", {
            "mME-UE-S1AP-ID": mme_ue_id, "eNB-UE-S1AP-ID": enb_ue_id})),
    }]
    return wrap_s1ap(PC_UE_CTX_REL, "UEContextReleaseCommand", ies)


def write_pcap(path: str, s1ap_payloads: list, src_ip: str = "10.0.0.10",
               dst_ip: str = "10.0.0.20") -> None:
    """Write S1AP payloads as SCTP DATA chunks (PPID 18) into a pcap."""
    from scapy.all import Ether, IP, SCTP, SCTPChunkData, wrpcap

    pkts = []
    for i, payload in enumerate(s1ap_payloads):
        chunk = SCTPChunkData(proto_id=18, stream_seq=i, data=payload)
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / SCTP(sport=36412, dport=36412) / chunk
        pkts.append(pkt)
    wrpcap(path, pkts)
