from apn_provisioner.subscriber import select_subscriber


def test_default_indicator_slice_and_first_session():
    doc = {
        "imsi": "432129951539038",
        "msisdn": ["989951079038"],
        "slice": [
            {"sst": 1, "session": [{"name": "other"}]},
            {"sst": 1, "default_indicator": True,
             "session": [{"name": "hiweb"}, {"name": "ims"}]},
        ],
    }
    sub = select_subscriber(doc)
    assert sub.apn == "hiweb"          # default slice, first session
    assert sub.msisdn == "989951079038"


def test_falls_back_to_first_slice():
    doc = {"imsi": "1", "msisdn": ["9"],
           "slice": [{"session": [{"name": "firstapn"}]}]}
    assert select_subscriber(doc).apn == "firstapn"


def test_missing_msisdn_skips():
    doc = {"imsi": "1", "msisdn": [], "slice": [{"session": [{"name": "a"}]}]}
    assert select_subscriber(doc) is None


def test_missing_apn_skips():
    doc = {"imsi": "1", "msisdn": ["9"], "slice": [{"session": [{}]}]}
    assert select_subscriber(doc) is None


def test_empty_doc():
    assert select_subscriber({}) is None
    assert select_subscriber(None) is None
