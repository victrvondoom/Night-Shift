"""One approval, one execution: under retries, under races, and never when disabled."""

from concurrent.futures import ThreadPoolExecutor

from beacon import approvals, remediate

PARAMS = {"namespace": "demo", "name": "demo-api"}
VERIFIED = {"evidence": "typed_console"}


def _approval(tables, incident):
    return approvals.create(
        incident["incident_id"],
        "deployment.restart",
        PARAMS,
        source="voice",
        channel="typed",
        transcript_quote="approve fix 1",
        fix_id=1,
        table_name=tables["APPROVALS_TABLE_NAME"],
        attestation=VERIFIED,
    )


def _event(incident, record):
    return {
        "approval_id": record["approval_id"],
        "incident_id": incident["incident_id"],
        "action": "deployment.restart",
        "params": PARAMS,
    }


def test_approval_is_consumed_exactly_once_under_race(tables):
    t = tables["APPROVALS_TABLE_NAME"]
    rec = approvals.create(
        "i1",
        "deployment.restart",
        PARAMS,
        source="voice",
        channel="typed",
        transcript_quote="approve fix 1",
        table_name=t,
    )
    with ThreadPoolExecutor(max_workers=16) as pool:
        wins = list(
            pool.map(
                lambda _: approvals.mark_used(rec["approval_id"], table_name=t),
                range(64),
            )
        )
    assert wins.count(True) == 1


def test_execute_runs_once_and_replays_on_retry(tables, incident, cluster):
    event = _event(incident, _approval(tables, incident))
    first = remediate.execute(event)
    again = remediate.execute(event)
    assert first["ok"] and first["idempotent_replay"] is False
    assert again["ok"] and again["idempotent_replay"] is True
    assert again["executed_at"] == first["executed_at"]
    assert cluster["restarts"] == 1


def test_concurrent_executes_apply_the_change_once(tables, incident, cluster):
    event = _event(incident, _approval(tables, incident))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: remediate.execute(event), range(8)))
    assert cluster["restarts"] == 1
    assert (
        sum(1 for r in results if r.get("ok") and not r.get("idempotent_replay")) == 1
    )


def test_execute_without_an_approval_is_refused(tables, incident, cluster):
    out = remediate.execute({**_event(incident, {"approval_id": "missing"})})
    assert not out["ok"] and out["error"] == "no approval record"
    assert cluster["restarts"] == 0


def test_approval_for_other_params_is_refused(tables, incident, cluster):
    event = {
        **_event(incident, _approval(tables, incident)),
        "params": {**PARAMS, "name": "x"},
    }
    out = remediate.execute(event)
    assert not out["ok"] and cluster["restarts"] == 0


def test_execute_honours_the_kill_switch(tables, incident, cluster, monkeypatch):
    monkeypatch.setenv("APPLY_ENABLED", "false")
    out = remediate.execute(_event(incident, _approval(tables, incident)))
    assert not out["ok"] and "disabled" in out["error"]
    assert cluster["restarts"] == 0


def test_loop_escalates_when_verification_never_passes(tables, incident, cluster):
    from beacon import store

    cluster["verify_ok"] = False
    out = remediate.run_all(_event(incident, _approval(tables, incident)))
    assert out == {"ok": False, "final": "escalated", "stage": "verify", "attempts": 2}
    got = store.get_incident(
        incident["incident_id"], table_name=tables["INCIDENTS_TABLE_NAME"]
    )
    assert got["status"] == "escalated"  # a successful patch call is not recovery


def test_loop_resolves_only_after_verification(tables, incident, cluster):
    from beacon import store

    out = remediate.run_all(_event(incident, _approval(tables, incident)))
    assert out["final"] == "resolved"
    got = store.get_incident(
        incident["incident_id"], table_name=tables["INCIDENTS_TABLE_NAME"]
    )
    events = [e["event"] for e in got["timeline"]]
    assert (
        events.index("executed")
        < events.index("verify_attempt")
        < events.index("resolved")
    )
