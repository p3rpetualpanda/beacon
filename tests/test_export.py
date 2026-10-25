"""Export beacon alerts as OCSF Detection Finding contract v1 findings."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import duckdb
import jsonschema
import pytest

from beacon import __version__
from beacon.detect import Rule, run_rule
from beacon.export import ExportError, findings
from tests.test_detections import RULES, load_fixture, rule_folder

EVIDENCE_KEYS = {
    "event_id",
    "ts",
    "source",
    "event_code",
    "event_action",
    "event_outcome",
    "host_name",
    "user_name",
    "process_name",
    "process_command_line",
    "parent_process_name",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
}


def rule_by_id(rule_id: str) -> Rule:
    (rule,) = [rule for rule in RULES if rule.rule_id == rule_id]
    return rule


def _insert_rule(con: duckdb.DuckDBPyConnection) -> None:
    con.execute(
        "INSERT INTO rules (rule_id, name, technique, tactic, severity, description) "
        "VALUES ('R99', 'Synthetic rule', 'T1059.001', 'Execution', 'medium', 'test rule')"
    )


def _insert_event(con: duckdb.DuckDBPyConnection, event_id: str, minute: int) -> None:
    con.execute(
        "INSERT INTO events (event_id, ts, ts_source, dataset, source, event_code) "
        "VALUES (?, TIMESTAMP '2020-05-02 10:00:00' + ? * INTERVAL 1 MINUTE, "
        "'utc_field', 'fixture', 'sysmon', '4688')",
        [event_id, minute],
    )


def test_finding_fields_for_r05(con: duckdb.DuckDBPyConnection) -> None:
    rule = rule_by_id("R05")
    load_fixture(con, rule_folder(rule) / "positive.jsonl")
    run_rule(con, rule)

    out = findings(con)
    assert len(out) == 3
    f = out[0]
    assert f["schema_version"] == "1.0"
    assert (f["class_uid"], f["category_uid"], f["activity_id"], f["type_uid"]) == (
        2004,
        2,
        1,
        200401,
    )
    assert (f["severity_id"], f["severity"]) == (3, "Medium")
    assert (f["status_id"], f["status"]) == (1, "New")
    assert f["metadata"]["product"] == {
        "name": "beacon",
        "vendor_name": "p3rpetualpanda",
        "version": __version__,
    }
    assert f["finding_info"]["analytic"] == {
        "uid": "R05",
        "name": "Encoded PowerShell",
        "type_id": 1,
        "type": "Rule",
    }
    assert f["finding_info"]["attacks"] == [
        {"technique": {"uid": "T1059.001"}, "tactic": {"name": "Execution"}}
    ]
    assert f["unmapped"]["environment"] == "fixture"
    assert f["unmapped"]["entities"]["hosts"] == ["scranton"]
    assert f["unmapped"]["evidence_total"] == len(f["unmapped"]["evidence"])
    assert set(f["unmapped"]["evidence"][0]) == EVIDENCE_KEYS
    assert f["finding_info"]["first_seen_time"] <= f["finding_info"]["last_seen_time"]
    assert f["time"] == 1588413600000  # 2020-05-02 10:00:00 UTC


def test_entities_never_contain_null(con: duckdb.DuckDBPyConnection) -> None:
    _insert_rule(con)
    con.execute(
        "INSERT INTO events "
        "(event_id, ts, ts_source, dataset, source, event_code, host_name, process_name) "
        "VALUES ('e1', TIMESTAMP '2020-05-02 10:00:00', 'utc_field', 'fixture', 'sysmon', '4688', "
        "'host-a', 'cmd.exe'), "
        "('e2', TIMESTAMP '2020-05-02 10:01:00', 'utc_field', 'fixture', 'powershell', '4104', "
        "NULL, NULL)"
    )
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
        "VALUES ('a1', 'R99', TIMESTAMP '2020-05-02 10:02:00', 'fixture', 'test', ['e1', 'e2'])"
    )

    (f,) = findings(con)
    assert f["unmapped"]["entities"] == {
        "hosts": ["host-a"],
        "users": [],
        "src_ips": [],
        "dst_ips": [],
        "processes": ["cmd.exe"],
    }


def test_evidence_capped_at_50(con: duckdb.DuckDBPyConnection) -> None:
    _insert_rule(con)
    ids = [f"e{i}" for i in range(1, 61)]
    for i, event_id in enumerate(ids):
        _insert_event(con, event_id, i)
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ["a1", "R99", "2020-05-02 11:00:00", "fixture", "test", ids],
    )

    (f,) = findings(con)
    evidence = f["unmapped"]["evidence"]
    assert len(evidence) == 50
    assert f["unmapped"]["evidence_total"] == 60
    assert [e["event_id"] for e in evidence] == ids[:50]  # first 50 by ts


def test_missing_evidence_raises(con: duckdb.DuckDBPyConnection) -> None:
    _insert_rule(con)
    _insert_event(con, "e1", 0)
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
        "VALUES ('missing-1', 'R99', TIMESTAMP '2020-05-02 10:00:00', 'fixture', 'test', "
        "['e1', 'nope'])"
    )

    with pytest.raises(ExportError, match="missing-1"):
        findings(con)


@pytest.mark.parametrize(
    ("beacon_status", "status_id", "status"),
    [
        ("new", 1, "New"),
        ("triaged", 2, "In Progress"),
        ("true_positive", 4, "Resolved"),
        ("false_positive", 4, "Resolved"),
        ("closed", 4, "Resolved"),
    ],
)
def test_status_mapping(
    con: duckdb.DuckDBPyConnection, beacon_status: str, status_id: int, status: str
) -> None:
    _insert_rule(con)
    _insert_event(con, "e1", 0)
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
        "VALUES ('a1', 'R99', TIMESTAMP '2020-05-02 10:00:00', 'fixture', 'test', ['e1'])"
    )
    con.execute("UPDATE alerts SET status = ? WHERE alert_id = 'a1'", [beacon_status])

    (f,) = findings(con)
    assert (f["status_id"], f["status"]) == (status_id, status)
    assert f["unmapped"]["beacon_status"] == beacon_status


def test_only_filters_rules(con: duckdb.DuckDBPyConnection) -> None:
    rule = rule_by_id("R05")
    load_fixture(con, rule_folder(rule) / "positive.jsonl")
    run_rule(con, rule)
    # A second rule's alert; the R05 fixture is the only one loaded, because load_fixture's
    # fixture-N event ids would collide for a second file in the same database.
    _insert_rule(con)
    _insert_event(con, "e1", 0)
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
        "VALUES ('a1', 'R99', TIMESTAMP '2020-05-02 10:00:00', 'fixture', 'test', ['e1'])"
    )

    out = findings(con, only=["R05"])
    assert out
    assert {f["finding_info"]["analytic"]["uid"] for f in out} == {"R05"}
    assert {f["finding_info"]["analytic"]["uid"] for f in findings(con)} == {"R05", "R99"}


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "contracts" / "detection-finding-v1.schema.json"


def _validate(finding: dict[str, Any]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
    jsonschema.validate(finding, schema, cls=jsonschema.Draft202012Validator)


def _walk(finding: dict[str, Any], dotted: str) -> tuple[dict[str, Any], str]:
    *parents, leaf = dotted.split(".")
    node = finding
    for key in parents:
        node = node[key]
    return node, leaf


def drop(dotted: str) -> Any:
    def apply(finding: dict[str, Any]) -> None:
        node, leaf = _walk(finding, dotted)
        del node[leaf]

    return apply


def set_(dotted: str, value: Any) -> Any:
    def apply(finding: dict[str, Any]) -> None:
        node, leaf = _walk(finding, dotted)
        node[leaf] = value

    return apply


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_every_rule_exports_valid_findings(con: duckdb.DuckDBPyConnection, rule: Rule) -> None:
    load_fixture(con, rule_folder(rule) / "positive.jsonl")
    run_rule(con, rule)
    out = findings(con)
    assert out
    for finding in out:
        _validate(finding)


@pytest.mark.parametrize(
    "breakage",
    [
        drop("finding_info.uid"),
        set_("severity_id", 9),
        set_("schema_version", "2.0"),
        set_("surprise", 1),
        set_("unmapped.entities.hosts", [None]),
        set_("unmapped.evidence", [{}] * 51),
        set_("finding_info.attacks", [{"technique": {"uid": "bad"}, "tactic": {"name": "x"}}]),
    ],
)
def test_schema_rejects_broken_findings(con: duckdb.DuckDBPyConnection, breakage: Any) -> None:
    rule = rule_by_id("R05")
    load_fixture(con, rule_folder(rule) / "positive.jsonl")
    run_rule(con, rule)
    broken = copy.deepcopy(findings(con)[0])
    _validate(broken)  # valid before the breakage
    breakage(broken)
    with pytest.raises(jsonschema.ValidationError):
        _validate(broken)
