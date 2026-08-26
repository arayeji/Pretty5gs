from apn_provisioner.store import Record, Store


def test_record_roundtrip(tmp_path):
    st = Store(str(tmp_path / "s.db"))
    assert st.get_record("111") is None
    st.upsert_record(Record(imsi="111", imei="12345678901234", sv="01",
                            msisdn="989", apn="hiweb", last_sent=100.0,
                            send_count=1, last_result="sent"))
    r = st.get_record("111")
    assert r.imei == "12345678901234"
    assert r.apn == "hiweb"
    assert r.send_count == 1
    # update
    st.upsert_record(Record(imsi="111", imei="99999999999999", send_count=2))
    r2 = st.get_record("111")
    assert r2.imei == "99999999999999"
    assert r2.send_count == 2


def test_guti_map_survives_reopen(tmp_path):
    path = str(tmp_path / "g.db")
    st = Store(path)
    guti = bytes.fromhex("f600f110800101c0decafe")
    st.learn_guti(guti, "432129951539038")
    assert st.resolve_guti(guti) == "432129951539038"
    st.close()
    st2 = Store(path)
    assert st2.resolve_guti(guti) == "432129951539038"  # persisted across restart
