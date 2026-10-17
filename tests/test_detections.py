from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from beacon import cli
from beacon.db import connect
from beacon.detect import (
    Rule,
    RuleError,
    apply_verdicts,
    export_verdicts,
    load_rules,
    run_rule,
)

RULES_DIR = Path(__file__).parents[1] / "detections"
RULES = load_rules(RULES_DIR)


def load_fixture(con: duckdb.DuckDBPyConnection, path: Path) -> None:
    """Insert a JSON-lines file of partial `events` rows, filling the columns rules don't use."""
    con.execute(
        "INSERT INTO events BY NAME "
        "SELECT * REPLACE (CAST(ts AS TIMESTAMP) AS ts), "
        "'fixture-' || row_number() OVER () AS event_id, "
        "'fixture' AS ts_source, 'fixture' AS dataset "
        "FROM read_json(?, format = 'newline_delimited')",
        [str(path)],
    )


def rule_folder(rule: Rule) -> Path:
    (folder,) = RULES_DIR.glob(f"{rule.rule_id}_*")
    return folder


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_rule_fires_on_positive_fixture(con: duckdb.DuckDBPyConnection, rule: Rule) -> None:
    load_fixture(con, rule_folder(rule) / "positive.jsonl")
    assert run_rule(con, rule) >= 1


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_rule_is_quiet_on_negative_fixture(con: duckdb.DuckDBPyConnection, rule: Rule) -> None:
    load_fixture(con, rule_folder(rule) / "negative.jsonl")
    assert run_rule(con, rule) == 0


# Positive fixtures that log one launch in both Sysmon and Security 4688 must alert once per
# launch, and each extra case (renamed tool, quoted payload, task under Microsoft) must fire.
@pytest.mark.parametrize(
    ("rule_id", "alerts"), [("R03", 3), ("R05", 3), ("R06", 2), ("R07", 3), ("R16", 3)]
)
def test_positive_fixture_alert_counts(
    con: duckdb.DuckDBPyConnection, rule_id: str, alerts: int
) -> None:
    (rule,) = [r for r in RULES if r.rule_id == rule_id]
    load_fixture(con, rule_folder(rule) / "positive.jsonl")
    assert run_rule(con, rule) == alerts


def test_phase_2_rules_are_present() -> None:
    expected = ["R01", "R02", "R03", "R05", "R06", "R07", "R08", "R09", "R12", "R13", "R16", "R20"]
    assert [r.rule_id for r in RULES] == expected


def load_one_lsass_access(con: duckdb.DuckDBPyConnection) -> Rule:
    """Load R03's first positive event only, and return R03."""
    (rule,) = [r for r in RULES if r.rule_id == "R03"]
    load_fixture(con, rule_folder(rule) / "positive.jsonl")
    con.execute("DELETE FROM events WHERE event_id <> 'fixture-1'")
    return rule


def test_rerun_keeps_alert_status(con: duckdb.DuckDBPyConnection) -> None:
    rule = load_one_lsass_access(con)
    run_rule(con, rule)
    con.execute("UPDATE alerts SET status = 'true_positive'")
    assert run_rule(con, rule) == 1
    assert con.execute("SELECT status FROM alerts").fetchall() == [("true_positive",)]

    # A triaged alert survives even when the rule stops producing it; a new one is removed.
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, summary, event_ids) "
        "VALUES ('stale', 'R03', now(), 'old', ['x'])"
    )
    con.execute("DELETE FROM events")
    assert run_rule(con, rule) == 0
    assert con.execute("SELECT status FROM alerts").fetchall() == [("true_positive",)]


def test_precision_counts_hits_in_datasets_with_the_technique(
    con: duckdb.DuckDBPyConnection,
) -> None:
    rule = load_one_lsass_access(con)
    con.execute(
        "INSERT INTO events BY NAME SELECT * REPLACE ('other' AS dataset, 'e2' AS event_id) "
        "FROM events"
    )
    con.execute(
        "INSERT INTO datasets (name, attack_techniques) VALUES "
        "('fixture', ['T1003']), ('other', ['T1059.001']), ('unlabelled', [])"
    )
    con.execute(
        "INSERT INTO events BY NAME SELECT * REPLACE ('unlabelled' AS dataset, 'e3' AS event_id) "
        "FROM events WHERE dataset = 'fixture'"
    )
    run_rule(con, rule)
    row = con.execute(
        "SELECT hits, true_positives, precision FROM rule_performance WHERE rule_id = 'R03'"
    ).fetchone()
    # The unlabelled dataset's hit counts as a hit but is left out of precision.
    assert row == (3, 1, 0.5)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda t: t.replace("severity: high", "severity: urgent"), "severity"),
        (lambda t: t.replace("technique: T1110.001", "technique: brute"), "technique"),
        (lambda t: t.replace("id: R01", "id: R99"), "id must"),
        (lambda t: t + "extra: 1\n", "exactly"),
    ],
)
def test_load_rules_rejects_bad_metadata(tmp_path: Path, change: object, message: str) -> None:
    source = RULES_DIR / "R01_brute_force_then_success"
    folder = tmp_path / source.name
    folder.mkdir()
    for name in ("rule.sql", "rule.kql"):
        (folder / name).write_text((source / name).read_text(encoding="utf-8"), encoding="utf-8")
    text = (source / "rule.yml").read_text(encoding="utf-8")
    (folder / "rule.yml").write_text(change(text), encoding="utf-8")  # type: ignore[operator]
    with pytest.raises(RuleError, match=message):
        load_rules(tmp_path)


def test_detect_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_path = tmp_path / "b.duckdb"
    con = connect(db_path)
    load_fixture(con, RULES_DIR / "R03_lsass_memory_access" / "positive.jsonl")
    con.close()
    assert cli.main(["detect", "--db", str(db_path), "--rules-dir", str(RULES_DIR)]) == 0
    out = capsys.readouterr().out
    assert "R03  LSASS memory access" in out and "3 alerts" in out
    assert cli.main(["detect", "--db", str(db_path), "--only", "R77"]) == 2
    missing = str(tmp_path / "nowhere")
    assert cli.main(["detect", "--db", str(db_path), "--rules-dir", missing]) == 2
    bad = tmp_path / "bad" / "R01_x"
    bad.mkdir(parents=True)
    (bad / "rule.yml").write_text("id: [unclosed", encoding="utf-8")
    assert cli.main(["detect", "--db", str(db_path), "--rules-dir", str(bad.parent)]) == 2


def test_verdicts_decide_precision_before_labels(con: duckdb.DuckDBPyConnection) -> None:
    rule = load_one_lsass_access(con)
    con.execute("INSERT INTO datasets (name, attack_techniques) VALUES ('fixture', ['T1003'])")
    run_rule(con, rule)
    assert con.execute(
        "SELECT precision, verdicts FROM rule_performance WHERE rule_id = 'R03'"
    ).fetchone() == (1.0, 0)
    # The label says true; an analyst's false_positive overrides it.
    con.execute("UPDATE alerts SET status = 'false_positive'")
    assert con.execute(
        "SELECT precision, verdicts FROM rule_performance WHERE rule_id = 'R03'"
    ).fetchone() == (0.0, 1)


def test_verdicts_round_trip_through_a_file(con: duckdb.DuckDBPyConnection, tmp_path: Path) -> None:
    rule = load_one_lsass_access(con)
    run_rule(con, rule)
    (alert_id,) = con.execute("SELECT alert_id FROM alerts").fetchone() or ("",)
    path = tmp_path / "verdicts.csv"
    path.write_text(
        f"alert_id,status,reason\n{alert_id},true_positive,dumpert\ngone,closed,\n",
        encoding="utf-8",
    )
    assert apply_verdicts(con, path) == (1, ["gone"], [])
    assert con.execute("SELECT status FROM alerts").fetchall() == [("true_positive",)]

    # A verdict saved later in the dashboard wins over the file on the next detect run...
    con.execute("UPDATE alerts SET status = 'false_positive'")
    assert apply_verdicts(con, path) == (0, ["gone"], [alert_id])
    assert con.execute("SELECT status FROM alerts").fetchall() == [("false_positive",)]

    # ...and export copies it into the file, keeping reasons and rows for other databases.
    assert export_verdicts(con, path) == 2
    assert path.read_text(encoding="utf-8") == (
        f"alert_id,status,reason\n{alert_id},false_positive,dumpert\ngone,closed,\n"
    )
    assert not path.with_suffix(".csv.tmp").exists()


def test_verdict_files_saved_by_excel_are_read(
    con: duckdb.DuckDBPyConnection, tmp_path: Path
) -> None:
    rule = load_one_lsass_access(con)
    run_rule(con, rule)
    (alert_id,) = con.execute("SELECT alert_id FROM alerts").fetchone() or ("",)
    path = tmp_path / "verdicts.csv"
    path.write_bytes(f"﻿alert_id,status,reason\r\n {alert_id} , closed ,x\r\n".encode())
    assert apply_verdicts(con, path) == (1, [], [])
    assert con.execute("SELECT status FROM alerts").fetchall() == [("closed",)]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("id,status,reason\nx,closed,\n", "columns must be"),
        ("alert_id,status,reason\nx,pwned,\n", "invalid status"),
        ("alert_id,status,reason\nx,new,\n", "invalid status"),
        ("alert_id,status,reason\nx,closed,\nx,triaged,\n", "listed twice"),
        ("alert_id,status,reason\nx,closed\n", "exactly 3 columns"),
        ("alert_id,status,reason\nx,closed,a,b\n", "exactly 3 columns"),
        ("alert_id,status,reason\n ,closed,\n", "no alert_id"),
    ],
)
def test_apply_verdicts_rejects_bad_files(
    con: duckdb.DuckDBPyConnection, tmp_path: Path, body: str, message: str
) -> None:
    path = tmp_path / "verdicts.csv"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(RuleError, match=message):
        apply_verdicts(con, path)


def test_detect_and_export_verdicts_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db_path = tmp_path / "b.duckdb"
    con = connect(db_path)
    load_fixture(con, RULES_DIR / "R03_lsass_memory_access" / "positive.jsonl")
    con.close()
    verdicts = tmp_path / "verdicts.csv"
    base = ["--db", str(db_path)]
    assert (
        cli.main(["detect", *base, "--rules-dir", str(RULES_DIR), "--verdicts", str(verdicts)]) == 0
    )
    assert cli.main(["export-verdicts", *base, "--out", str(verdicts)]) == 0
    assert "0 verdicts in" in capsys.readouterr().out
    verdicts.write_text("bad header\n", encoding="utf-8")
    assert cli.main(["export-verdicts", *base, "--out", str(verdicts)]) == 2

    verdicts.write_text("alert_id,status,reason\nx,pwned,\n", encoding="utf-8")
    args = ["detect", *base, "--rules-dir", str(RULES_DIR), "--verdicts", str(verdicts)]
    assert cli.main(args) == 2
