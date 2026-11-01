"""Export beacon alerts as OCSF Detection Finding contract v1 findings."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import duckdb
import jsonschema
import pytest

from beacon import __version__, cli, db
from beacon.detect import Rule, run_rule
from beacon.export import ExportError, findings, write_jsonl
from beacon.load import load_event_codes
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


def pad_evidence(count: int) -> Any:
    """Make `count` otherwise-valid evidence rows, so only the maxItems cap can reject them."""

    def apply(finding: dict[str, Any]) -> None:
        finding["unmapped"]["evidence"] = [finding["unmapped"]["evidence"][0]] * count

    return apply


def test_schema_accepts_exactly_50_evidence_rows(con: duckdb.DuckDBPyConnection) -> None:
    rule = rule_by_id("R05")
    load_fixture(con, rule_folder(rule) / "positive.jsonl")
    run_rule(con, rule)
    finding = copy.deepcopy(findings(con)[0])
    pad_evidence(50)(finding)
    _validate(finding)


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
        pad_evidence(51),
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


def _r05_db(path: Path) -> None:
    con = db.connect(path)
    load_event_codes(con)
    rule = rule_by_id("R05")
    load_fixture(con, rule_folder(rule) / "positive.jsonl")
    run_rule(con, rule)
    con.close()


def test_export_is_byte_identical_and_lf_only(
    con: duckdb.DuckDBPyConnection, tmp_path: Path
) -> None:
    rule = rule_by_id("R05")
    load_fixture(con, rule_folder(rule) / "positive.jsonl")
    run_rule(con, rule)
    a, b = tmp_path / "x" / "a.jsonl", tmp_path / "b.jsonl"
    assert write_jsonl(findings(con), a) == 3
    write_jsonl(findings(con), b)
    assert a.read_bytes() == b.read_bytes()
    assert b"\r\n" not in a.read_bytes()
    assert chr(0x2013).encode() in a.read_bytes()  # raw UTF-8, not a backslash-u escape
    times = [json.loads(line)["time"] for line in a.read_text("utf-8").splitlines()]
    assert times == sorted(times)


def test_cli_export_alerts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    database, out = tmp_path / "b.duckdb", tmp_path / "out.jsonl"
    _r05_db(database)
    assert cli.main(["export-alerts", "--db", str(database), "--out", str(out)]) == 0
    assert "3 findings in" in capsys.readouterr().out
    assert len(out.read_text("utf-8").splitlines()) == 3


def test_cli_unknown_rule_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    database, out = tmp_path / "b.duckdb", tmp_path / "out.jsonl"
    _r05_db(database)
    code = cli.main(["export-alerts", "--db", str(database), "--out", str(out), "--only", "R77"])
    assert code == 2
    assert "R77" in capsys.readouterr().err
    assert not out.exists()


def test_cli_missing_evidence_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    database, out = tmp_path / "b.duckdb", tmp_path / "out.jsonl"
    _r05_db(database)
    con = db.connect(database)
    con.execute("UPDATE alerts SET event_ids = list_append(event_ids, 'nope')")
    con.close()
    assert cli.main(["export-alerts", "--db", str(database), "--out", str(out)]) == 2
    assert capsys.readouterr().err.startswith("cannot export findings")
    assert not out.exists()


def test_cli_empty_export_exits_2_and_keeps_existing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database, out = tmp_path / "empty.duckdb", tmp_path / "out.jsonl"
    db.connect(database).close()
    out.write_text("previous export\n", encoding="utf-8")
    assert cli.main(["export-alerts", "--db", str(database), "--out", str(out)]) == 2
    assert "no alerts" in capsys.readouterr().err
    assert out.read_text("utf-8") == "previous export\n"


def test_null_dataset_raises(con: duckdb.DuckDBPyConnection) -> None:
    _insert_rule(con)
    _insert_event(con, "e1", 0)
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
        "VALUES ('nulldata-1', 'R99', TIMESTAMP '2020-05-02 10:00:00', NULL, 'test', ['e1'])"
    )
    with pytest.raises(ExportError, match="nulldata-1"):
        findings(con)


def test_unknown_status_raises_export_error(con: duckdb.DuckDBPyConnection) -> None:
    _insert_rule(con)
    _insert_event(con, "e1", 0)
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
        "VALUES ('badstatus-1', 'R99', TIMESTAMP '2020-05-02 10:00:00', 'fixture', 't', ['e1'])"
    )
    con.execute("UPDATE alerts SET status = 'escalated'")
    with pytest.raises(ExportError, match=r"badstatus-1.*escalated"):
        findings(con)


def test_unknown_severity_raises_export_error(con: duckdb.DuckDBPyConnection) -> None:
    _insert_rule(con)
    _insert_event(con, "e1", 0)
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
        "VALUES ('badsev-1', 'R99', TIMESTAMP '2020-05-02 10:00:00', 'fixture', 't', ['e1'])"
    )
    con.execute("UPDATE rules SET severity = 'urgent'")
    with pytest.raises(ExportError, match=r"badsev-1.*urgent"):
        findings(con)


def test_write_jsonl_failure_keeps_previous_file(tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    out.write_text("previous export\n", encoding="utf-8")

    def items() -> Iterator[dict[str, Any]]:
        yield {"a": 1}
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        write_jsonl(items(), out)
    assert out.read_text("utf-8") == "previous export\n"
    assert [p.name for p in tmp_path.iterdir()] == ["out.jsonl"]


def test_evidence_ordered_by_microsecond(con: duckdb.DuckDBPyConnection) -> None:
    _insert_rule(con)
    # Same millisecond, so only the microseconds say which came first; ids sort the other way.
    for event_id, stamp in (("a-late", "10:00:00.000900"), ("z-early", "10:00:00.000100")):
        con.execute(
            "INSERT INTO events (event_id, ts, ts_source, dataset, source, event_code) "
            "VALUES (?, CAST(? AS TIMESTAMP), 'utc_field', 'fixture', 'zeek', 'conn')",
            [event_id, f"2020-05-02 {stamp}"],
        )
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
        "VALUES ('us-1', 'R99', TIMESTAMP '2020-05-02 10:01:00', 'fixture', 't', "
        "['a-late', 'z-early'])"
    )
    (f,) = findings(con)
    assert [e["event_id"] for e in f["unmapped"]["evidence"]] == ["z-early", "a-late"]


def test_entities_cover_events_beyond_the_evidence_cap(con: duckdb.DuckDBPyConnection) -> None:
    _insert_rule(con)
    for i in range(60):
        con.execute(
            "INSERT INTO events (event_id, ts, ts_source, dataset, source, event_code, host_name) "
            "VALUES (?, TIMESTAMP '2020-05-02 10:00:00' + ? * INTERVAL 1 MINUTE, 'utc_field', "
            "'fixture', 'sysmon', '4688', ?)",
            [f"e{i}", i, f"host-{i:02d}"],
        )
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
        "VALUES ('big-1', 'R99', TIMESTAMP '2020-05-02 12:00:00', 'fixture', 't', ?)",
        [[f"e{i}" for i in range(60)]],
    )
    (f,) = findings(con)
    assert len(f["unmapped"]["evidence"]) == 50
    assert len(f["unmapped"]["entities"]["hosts"]) == 60
    assert f["finding_info"]["last_seen_time"] > f["finding_info"]["first_seen_time"]


def test_cli_missing_database_exits_2_without_creating_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database = tmp_path / "typo.duckdb"
    assert cli.main(["export-alerts", "--db", str(database), "--out", str(tmp_path / "o")]) == 2
    assert "not found" in capsys.readouterr().err
    assert not database.exists()


def test_cli_duckdb_error_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "b.duckdb"
    _r05_db(database)

    def locked(*args: Any, **kwargs: Any) -> Any:
        raise duckdb.IOException("database is locked")

    monkeypatch.setattr("beacon.export.findings", locked)
    assert cli.main(["export-alerts", "--db", str(database), "--out", str(tmp_path / "o")]) == 2
    assert capsys.readouterr().err.startswith("cannot export findings")
