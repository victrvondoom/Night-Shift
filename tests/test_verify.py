"""Recovery is proven by four independent checks, not by a successful API call."""

import time
from datetime import UTC, datetime, timedelta

import pytest

from beacon.remediation import verify

RULE = {"name": "DemoDbErrors", "query": "sum(rate(errors[30s])) > 0"}


@pytest.fixture()
def prom(monkeypatch):
    state = {
        "firing": False,
        "last_fired": time.time() - 5,
        "breaching": False,
        "rule": RULE,
    }
    monkeypatch.setattr(verify.prom, "alert_rule", lambda name: state["rule"])
    monkeypatch.setattr(
        verify.prom,
        "query",
        lambda expr, **k: (
            [{"value": [0, "1"]}]
            if (state["firing"] if "ALERTS" in expr else state["breaching"])
            else []
        ),
    )
    monkeypatch.setattr(
        verify.prom,
        "query_range",
        lambda expr, **k: (
            [{"values": [[state["last_fired"], "1"]]}] if state["last_fired"] else []
        ),
    )
    monkeypatch.setattr(
        verify,
        "verify_health",
        lambda url: verify.VerifyCheck("app_health", True, "GET -> 200"),
    )
    return state


def _run(post=True, after=None):
    fix_at = after or datetime.now(tz=UTC) - timedelta(seconds=20)
    return verify.verify_all(
        "DemoDbErrors",
        after=fix_at,
        postcondition=lambda: post,
        health_url="http://x.svc/ready",
    )


def test_all_four_checks_pass(prom):
    result = _run()
    assert result.ok and [c.name for c in result.checks] == [
        "alarm_ok_after_fix",
        "metric_zero",
        "postcondition",
        "app_health",
    ]


def test_still_firing_alert_fails(prom):
    prom["firing"] = True
    assert not _run().ok


def test_alert_that_cleared_before_the_fix_does_not_pass(prom):
    prom["last_fired"] = time.time() - 600
    result = _run(after=datetime.now(tz=UTC) - timedelta(seconds=30))
    assert not result.ok and "before the fix" in result.checks[0].detail


def test_alert_that_never_fired_does_not_pass(prom):
    prom["last_fired"] = None
    assert not _run().checks[0].ok


def test_expression_still_breaching_fails(prom):
    prom["breaching"] = True
    result = _run()
    assert not result.ok and not result.checks[1].ok


def test_postcondition_false_or_raising_fails(prom):
    assert not _run(post=False).ok

    def boom():
        raise RuntimeError("api down")

    result = verify.verify_all(
        "DemoDbErrors", after=datetime.now(tz=UTC), postcondition=boom
    )
    assert not result.checks[2].ok and "api down" in result.checks[2].detail


def test_prometheus_outage_is_a_failed_check_not_a_pass(prom, monkeypatch):
    def down(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(verify.prom, "alert_rule", down)
    assert not _run().ok


def test_health_check_is_required_and_restricted(monkeypatch):
    assert not verify.verify_health("").ok
    assert not verify.verify_health("http://169.254.169.254/latest/meta-data").ok
    assert not verify.verify_health("file:///etc/passwd").ok
    assert verify.health_url_allowed("http://demo-api.demo.svc:8080/ready")
    assert not verify.verify_health("http://127.0.0.1:1/ready").ok  # refused connection
