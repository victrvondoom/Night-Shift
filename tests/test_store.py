"""Ledgers on real PostgreSQL (JSONB)."""

from beacon import approvals, contracts, store
from beacon.events import TriggerInfo, TriggerType

PARAMS = {"namespace": "demo", "name": "demo-api"}


def _incident(tables, alarm="DemoApiDown", **kw):
    return store.put_incident(
        "STATUS: High",
        TriggerInfo(TriggerType.ALARM, alarm_name=alarm, labels={"namespace": "demo"}),
        table_name=tables["INCIDENTS_TABLE_NAME"],
        **kw,
    )


def test_incident_round_trip_keeps_alert_labels(tables):
    t = tables["INCIDENTS_TABLE_NAME"]
    iid = _incident(tables, rca_json={"status": "High"}, timeline=[{"event": "x"}])
    got = store.get_incident(iid, table_name=t)
    assert got["alarm_name"] == "DemoApiDown"
    assert got["alert_labels"] == {"namespace": "demo"}
    assert got["status"] == "awaiting_engineer" and got["woken"] is True


def test_timeline_append_and_status_patch(tables):
    t = tables["INCIDENTS_TABLE_NAME"]
    iid = _incident(tables)
    store.append_timeline(iid, "executed", table_name=t, detail={"code": "Restarted"})
    store.update_status(iid, "remediating", table_name=t, extra={"executed_at": "now"})
    got = store.get_incident(iid, table_name=t)
    assert [e["event"] for e in got["timeline"]] == ["executed"]
    assert got["status"] == "remediating" and got["executed_at"] == "now"


def test_usage_is_added_atomically(tables):
    t = tables["INCIDENTS_TABLE_NAME"]
    iid = _incident(tables)
    store.add_usage(iid, {"input_tokens": 10}, table_name=t)
    store.add_usage(iid, {"input_tokens": 5, "output_tokens": 2}, table_name=t)
    assert store.get_incident(iid, table_name=t)["usage"] == {
        "input_tokens": 15,
        "output_tokens": 2,
    }


def test_open_incident_dedup_ignores_resolved(tables):
    t = tables["INCIDENTS_TABLE_NAME"]
    iid = _incident(tables)
    assert store.find_open_incident("DemoApiDown", table_name=t)["incident_id"] == iid
    assert store.find_open_incident("Other", table_name=t) is None
    store.update_status(iid, "resolved", table_name=t)
    assert store.find_open_incident("DemoApiDown", table_name=t) is None


def test_missing_incident_is_empty(tables):
    assert store.get_incident("nope", table_name=tables["INCIDENTS_TABLE_NAME"]) == {}


def test_proposal_expires_when_withdrawn(tables):
    t = tables["APPROVALS_TABLE_NAME"]
    approvals.create_proposal(
        "i1",
        1,
        "deployment.restart",
        PARAMS,
        blast_radius="b",
        dry_run={"ok": True},
        table_name=t,
    )
    assert approvals.get_proposal("i1", 1, table_name=t) is not None
    assert approvals.withdraw_proposal("i1", 1, reason="barge-in", table_name=t)
    assert approvals.get_proposal("i1", 1, table_name=t) is None
    assert (
        approvals.get_proposal_raw("i1", 1, table_name=t)["withdrawn_reason"]
        == "barge-in"
    )


def test_approval_validity_is_bound_to_action_and_params(tables):
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
    assert approvals.is_valid(rec, "deployment.restart", PARAMS) is None
    assert "different action" in approvals.is_valid(rec, "deployment.rollback", PARAMS)
    assert "different params" in approvals.is_valid(
        rec, "deployment.restart", {**PARAMS, "name": "other"}
    )


def test_match_is_scoped_to_alarm_action_and_exact_params(tables):
    t = tables["CONTRACTS_TABLE_NAME"]
    c = contracts.put(
        alarm_name="DemoApiDown",
        action="deployment.restart",
        params=PARAMS,
        days=7,
        max_uses=2,
        transcript_quote="grant contract",
        granted_by="typed",
        incident_id="i1",
        table_name=t,
    )
    assert contracts.match("DemoApiDown", "deployment.restart", PARAMS, table_name=t)
    assert contracts.match("Other", "deployment.restart", PARAMS, table_name=t) is None
    assert (
        contracts.match("DemoApiDown", "deployment.rollback", PARAMS, table_name=t)
        is None
    )
    assert (
        contracts.match(
            "DemoApiDown", "deployment.restart", {**PARAMS, "name": "x"}, table_name=t
        )
        is None
    )
    assert contracts.use(c["contract_id"], table_name=t)
    assert contracts.use(c["contract_id"], table_name=t)
    assert not contracts.use(c["contract_id"], table_name=t)  # exhausted
    assert (
        contracts.match("DemoApiDown", "deployment.restart", PARAMS, table_name=t)
        is None
    )


def test_revoked_contract_cannot_be_used(tables):
    t = tables["CONTRACTS_TABLE_NAME"]
    c = contracts.put(
        alarm_name="A",
        action="deployment.restart",
        params=PARAMS,
        days=1,
        max_uses=3,
        transcript_quote="q",
        granted_by="typed",
        incident_id="i",
        table_name=t,
    )
    contracts.revoke(c["contract_id"], table_name=t)
    assert not contracts.use(c["contract_id"], table_name=t)
