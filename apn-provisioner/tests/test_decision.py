from dataclasses import dataclass

from apn_provisioner.decision import decide
from apn_provisioner.store import Record


@dataclass
class Cfg:
    resend_interval_hours: float = 24.0
    send_on_imei_change: bool = True
    ignore_sv_change: bool = True


@dataclass
class Sess:
    apn_present: bool | None = False
    imei: str | None = "35123406789015"
    imeisv: str | None = "3512340678901501"
    sv: str | None = "01"
    masked_imeisv: str | None = None


CFG = Cfg()
NOW = 1_000_000.0


def test_ue_supplied_apn_is_skipped():
    d = decide(None, Sess(apn_present=True), CFG, NOW)
    assert d.send is False and d.reason == "ue_supplied_apn"


def test_apn_unknown_is_skipped():
    d = decide(None, Sess(apn_present=None), CFG, NOW)
    assert d.send is False and d.reason == "apn_unknown"


def test_new_subscriber_sends():
    d = decide(None, Sess(), CFG, NOW)
    assert d.send is True and d.reason == "new_subscriber"


def test_imei_change_sends():
    rec = Record(imsi="1", imei="00000000000000", sv="01", last_sent=NOW - 60)
    d = decide(rec, Sess(imei="35123406789015"), CFG, NOW)
    assert d.send is True and d.reason == "imei_change"


def test_sv_change_alone_does_not_send():
    rec = Record(imsi="1", imei="35123406789015", sv="01", last_sent=NOW - 60)
    d = decide(rec, Sess(imei="35123406789015", sv="09",
                         imeisv="3512340678901509"), CFG, NOW)
    assert d.send is False and d.reason == "recent"


def test_resend_interval():
    rec = Record(imsi="1", imei="35123406789015", sv="01",
                 last_sent=NOW - 25 * 3600)
    d = decide(rec, Sess(imei="35123406789015"), CFG, NOW)
    assert d.send is True and d.reason == "resend_interval"


def test_recent_is_skipped():
    rec = Record(imsi="1", imei="35123406789015", sv="01", last_sent=NOW - 3600)
    d = decide(rec, Sess(imei="35123406789015"), CFG, NOW)
    assert d.send is False and d.reason == "recent"
