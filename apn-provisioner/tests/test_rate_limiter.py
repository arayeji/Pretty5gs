from apn_provisioner.rate_limiter import RateLimiter


def make(**kw):
    defaults = dict(dedup_window_sec=60, global_max_per_sec=1000,
                    max_sends_per_sub_per_day=5, breaker_per_min=1000,
                    breaker_resume_per_min=5)
    defaults.update(kw)
    return RateLimiter(**defaults)


def test_dedup_recent_blocks():
    rl = make()
    ok, _ = rl.check("1", 100.0)
    assert ok
    rl.start_send("1", 100.0)
    rl.finish_send("1", 100.0, True)
    ok, reason = rl.check("1", 110.0)  # within 60s window
    assert not ok and reason == "duplicate_recent"
    ok, _ = rl.check("1", 200.0)  # after window
    assert ok


def test_in_flight_blocks():
    rl = make()
    rl.start_send("1", 100.0)
    ok, reason = rl.check("1", 105.0)
    assert not ok and reason == "in_flight"


def test_per_sub_per_day_cap():
    rl = make(max_sends_per_sub_per_day=2, dedup_window_sec=0)
    for t in (0, 10, 20):
        ok, reason = rl.check("1", t)
        if ok:
            rl.start_send("1", t)
            rl.finish_send("1", t, True)
    ok, reason = rl.check("1", 30)
    assert not ok and reason == "rate_sub_day"


def test_circuit_breaker_opens_and_recovers():
    rl = make(breaker_per_min=3, breaker_resume_per_min=1, dedup_window_sec=0)
    t = 0.0
    for i in range(3):
        ok, _ = rl.check(str(i), t)
        assert ok
        rl.start_send(str(i), t)
        rl.finish_send(str(i), t, True)
        t += 0.1
    # 4th send in same minute -> breaker trips
    ok, reason = rl.check("x", t)
    assert not ok and reason == "circuit_open"
    assert rl.breaker_open
    # once the minute has passed, rate falls and sends resume
    ok, reason = rl.check("y", t + 61)
    assert ok
