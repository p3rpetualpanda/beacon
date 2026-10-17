from __future__ import annotations

import duckdb
import pytest

from beacon import dashboard
from beacon.detect import run_rule
from tests.test_detections import RULES, RULES_DIR, load_fixture


@pytest.fixture
def alerting(con: duckdb.DuckDBPyConnection) -> duckdb.DuckDBPyConnection:
    """R03 fires three times (critical) and R20 once (medium) on their test events."""
    for rule_id, folder in (("R03", "R03_lsass_memory_access"), ("R20", "R20_ssh_brute_force")):
        load_fixture(con, RULES_DIR / folder / "positive.jsonl")
        con.execute(
            "UPDATE events SET event_id = ? || event_id WHERE event_id LIKE 'fixture-%'",
            [rule_id],
        )
        run_rule(con, next(r for r in RULES if r.rule_id == rule_id))
    return con


def test_severity_and_status_counts(alerting: duckdb.DuckDBPyConnection) -> None:
    assert dashboard.alerts_by_severity(alerting) == [
        {"severity": "critical", "alerts": 3},
        {"severity": "medium", "alerts": 1},
    ]
    assert dashboard.alerts_by_status(alerting) == [{"status": "new", "alerts": 4}]


def test_noisiest_rules_skips_silent_ones(alerting: duckdb.DuckDBPyConnection) -> None:
    rows = dashboard.noisiest_rules(alerting)
    assert [(r["rule_id"], r["hits"]) for r in rows] == [("R03", 3), ("R20", 1)]
    assert dashboard.noisiest_rules(alerting, limit=1)[0]["rule_id"] == "R03"


def test_alert_queue_filters_and_orders_newest_first(
    alerting: duckdb.DuckDBPyConnection,
) -> None:
    queue = dashboard.alert_queue(alerting)
    assert len(queue) == 4
    assert queue == sorted(queue, key=lambda r: r["ts"], reverse=True)
    assert {r["rule_id"] for r in dashboard.alert_queue(alerting, rule_ids=["R20"])} == {"R20"}
    assert dashboard.alert_queue(alerting, statuses=["closed"]) == []


def test_evidence_and_verdicts(alerting: duckdb.DuckDBPyConnection) -> None:
    (r20,) = dashboard.alert_queue(alerting, rule_ids=["R20"])
    evidence = dashboard.alert_evidence(alerting, r20["alert_id"])
    assert len(evidence) == r20["evidence"] == 10
    assert {e["src_ip"] for e in evidence} == {"203.0.113.5"}

    assert dashboard.set_alert_status(alerting, r20["alert_id"], "true_positive")
    assert (
        dashboard.alert_queue(alerting, statuses=["true_positive"])[0]["alert_id"]
        == (r20["alert_id"])
    )
    assert not dashboard.set_alert_status(alerting, "no-such-alert", "closed")
    with pytest.raises(ValueError, match="status must be one of"):
        dashboard.set_alert_status(alerting, r20["alert_id"], "pwned")


def test_events_per_dataset_uses_the_latest_load(con: duckdb.DuckDBPyConnection) -> None:
    con.execute(
        "INSERT INTO data_quality VALUES "
        "('2026-01-01', 'a', 10, 0, 0, 10, NULL, NULL, 0, 0, NULL), "
        "('2026-01-02', 'a', 12, 1, 1, 10, NULL, NULL, 0, 0, NULL), "
        "('2026-01-01', 'b', 50, 0, 0, 50, NULL, NULL, 0, 0, NULL)"
    )
    rows = dashboard.events_per_dataset(con)
    assert [(r["dataset"], r["events"], r["rejected"]) for r in rows] == [
        ("b", 50, 0),
        ("a", 10, 1),
    ]


def test_status_order_and_empty_filters(alerting: duckdb.DuckDBPyConnection) -> None:
    (r20,) = dashboard.alert_queue(alerting, rule_ids=["R20"])
    dashboard.set_alert_status(alerting, r20["alert_id"], "false_positive")
    assert [r["status"] for r in dashboard.alerts_by_status(alerting)] == [
        "new",
        "false_positive",
    ]
    # An empty filter is no filter, so a cleared multiselect shows everything.
    assert len(dashboard.alert_queue(alerting, statuses=[], rule_ids=[])) == 4
    assert dashboard.alert_queue(alerting, statuses=["new"], rule_ids=["R20"]) == []


def test_evidence_counts_distinct_existing_events(alerting: duckdb.DuckDBPyConnection) -> None:
    alerting.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, summary, event_ids) VALUES "
        "('dup', 'R03', '2020-01-01', 'x', ['R03fixture-1', 'R03fixture-1', 'R03fixture-2'])"
    )
    (row,) = [r for r in dashboard.alert_queue(alerting) if r["alert_id"] == "dup"]
    assert row["evidence"] == 2
    evidence = dashboard.alert_evidence(alerting, "dup")
    assert [e["event_id"] for e in evidence] == ["R03fixture-1", "R03fixture-2"]
