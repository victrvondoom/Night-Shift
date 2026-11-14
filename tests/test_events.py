from beacon.events import TriggerType, firing_alerts, parse_event

ALERT = {
    "status": "firing",
    "labels": {"alertname": "DemoDbErrors", "namespace": "demo", "severity": "page"},
    "annotations": {
        "description": "db unreachable",
        "beacon_health_url": "http://demo-api.demo.svc:8080/ready",
    },
    "startsAt": "2026-11-14T03:00:00Z",
    "fingerprint": "abc",
}


def test_only_firing_alerts_are_taken(beacon_config):
    payload = {"alerts": [ALERT, {**ALERT, "status": "resolved"}, "junk"]}
    assert firing_alerts(payload) == [ALERT]


def test_alert_becomes_an_alarm_trigger_with_labels(beacon_config):
    trigger = parse_event({"alert": ALERT}, beacon_config)
    assert trigger.trigger_type is TriggerType.ALARM
    assert (
        trigger.alarm_name == "DemoDbErrors"
        and trigger.alarm_reason == "db unreachable"
    )
    assert trigger.labels["namespace"] == "demo"
    assert trigger.annotations["beacon_health_url"].endswith("/ready")
    assert "Alert: DemoDbErrors" in trigger.format_context()


def test_pushed_logs_and_schedule(beacon_config):
    assert (
        parse_event({"logs": "ERROR x", "selector": "{a=1}"}, beacon_config).raw_logs
        == "ERROR x"
    )
    assert parse_event({}, beacon_config).trigger_type is TriggerType.SCHEDULE
