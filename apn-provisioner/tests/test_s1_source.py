import os
import time

from apn_provisioner.s1ap import decode_s1ap
from apn_provisioner.s1_source import iter_s1ap_from_pcap, parse_event_payload
from tests import nas_fixtures as fx

IMSI = "432129951539038"


def test_pcap_roundtrip(tmp_path):
    ar = fx.make_attach_request(fx.make_imsi_id(IMSI),
                                fx.make_pdn_connectivity_request(None))
    payloads = [
        fx.s1ap_initial_ue(555, ar),
        fx.s1ap_uplink_nas(42, 555, fx.make_attach_complete()),
    ]
    path = str(tmp_path / "cap.pcap")
    fx.write_pcap(path, payloads)

    got = list(iter_s1ap_from_pcap(path))
    assert len(got) == 2
    assert "<->" in got[0].assoc
    ev = decode_s1ap(got[0].payload)
    assert ev.proc == "InitialUEMessage"
    assert ev.enb_ue_id == 555


def _event_payload(imsi, msisdn="989951079038", imei="351234067890151",
                   imeisv="3512340678901512", mcc="432", mnc="12"):
    return (f"event=attach imsi={imsi} msisdn={msisdn} imei={imei} "
            f"imeisv={imeisv} mcc={mcc} mnc={mnc} apn_absent=1\n")


def test_parse_event_payload():
    evt = parse_event_payload(_event_payload(IMSI))
    assert evt is not None
    assert evt.imsi == IMSI
    assert evt.msisdn == "989951079038"
    assert evt.imei == "351234067890151"
    assert evt.imeisv == "3512340678901512"
    assert evt.mcc == "432" and evt.mnc == "12"
    assert evt.apn_absent is True


def test_parse_event_payload_handles_missing_fields():
    evt = parse_event_payload(
        "event=attach imsi=432000000000001 "
        "msisdn=- imei=- imeisv=- mcc=432 mnc=12 apn_absent=1")
    assert evt is not None
    assert evt.imsi == "432000000000001"
    assert evt.msisdn is None
    assert evt.imei is None
    assert evt.imeisv is None


def test_parse_event_payload_ignores_junk():
    assert parse_event_payload("some unrelated line") is None
    assert parse_event_payload("event=attach msisdn=123") is None  # no imsi


def test_unix_datagram_source_end_to_end(tmp_path):
    """Bind the UNIX datagram source and prove a sent datagram round-trips."""
    import socket
    import threading
    from apn_provisioner.s1_source import UnixDatagramEventSource

    path = str(tmp_path / "events.sock")
    src = UnixDatagramEventSource(path)
    out = []

    def consume():
        for evt in src.events():
            out.append(evt)
            break  # one event is enough for the test

    t = threading.Thread(target=consume, daemon=True)
    t.start()

    for _ in range(50):  # wait for bind
        if os.path.exists(path):
            break
        time.sleep(0.02)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    c.sendto(_event_payload(IMSI).encode(), path)
    c.close()
    t.join(timeout=2.0)

    assert len(out) == 1
    assert out[0].imsi == IMSI
    assert out[0].msisdn == "989951079038"
