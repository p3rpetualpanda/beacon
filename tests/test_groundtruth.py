from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from beacon import cli
from beacon.db import connect
from beacon.groundtruth import GroundTruthError, load_ground_truth, navigator_layer, store

GROUND_TRUTH = Path(__file__).parents[1] / "detections" / "ground_truth.yml"


def step(technique: str, step_id: str = "1.A", dataset: str = "d1") -> dict[str, str]:
    return {"dataset": dataset, "step": step_id, "technique": technique, "plan_name": "x"}


def add_rule(con: duckdb.DuckDBPyConnection, rule_id: str, technique: str) -> None:
    con.execute("INSERT INTO rules VALUES (?, 'n', ?, 't', 'low', '')", [rule_id, technique])


def add_alert(
    con: duckdb.DuckDBPyConnection,
    rule_id: str,
    dataset: str = "d1",
    status: str = "new",
) -> None:
    con.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids, status) "
        "VALUES (?, ?, now(), ?, 's', ['e'], ?)",
        [f"{rule_id}-{dataset}-{status}", rule_id, dataset, status],
    )


def recall(con: duckdb.DuckDBPyConnection) -> dict[tuple[str, str], tuple[bool, list[str]]]:
    rows = con.execute("SELECT step, technique, detected, rules FROM rule_recall").fetchall()
    return {(s, t): (d, r) for s, t, d, r in rows}


def test_same_technique_is_detected(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003.001")])
    add_rule(con, "R01", "T1003.001")
    add_alert(con, "R01")
    assert recall(con)[("1.A", "T1003.001")] == (True, ["R01"])


def test_sub_technique_alert_covers_parent_step(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003")])
    add_rule(con, "R01", "T1003.001")
    add_alert(con, "R01")
    assert recall(con)[("1.A", "T1003")][0] is True


def test_parent_alert_covers_sub_technique_step(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003.001")])
    add_rule(con, "R01", "T1003")
    add_alert(con, "R01")
    assert recall(con)[("1.A", "T1003.001")][0] is True


def test_sibling_sub_technique_is_a_miss(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003.001")])
    add_rule(con, "R01", "T1003.002")
    add_alert(con, "R01")
    assert recall(con)[("1.A", "T1003.001")] == (False, [])


def test_prefix_lookalike_is_a_miss(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003")])
    add_rule(con, "R01", "T10030")
    add_alert(con, "R01")
    assert recall(con)[("1.A", "T1003")][0] is False


def test_alert_in_another_dataset_is_a_miss(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003")])
    add_rule(con, "R01", "T1003")
    add_alert(con, "R01", dataset="other")
    assert recall(con)[("1.A", "T1003")][0] is False


def test_false_positive_verdict_does_not_count(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003")])
    add_rule(con, "R01", "T1003")
    add_alert(con, "R01", status="false_positive")
    assert recall(con)[("1.A", "T1003")][0] is False


def test_rules_are_listed_once_and_sorted(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003")])
    add_rule(con, "R02", "T1003")
    add_rule(con, "R01", "T1003")
    add_alert(con, "R02")
    add_alert(con, "R01")
    add_alert(con, "R01", status="triaged")
    assert recall(con)[("1.A", "T1003")][1] == ["R01", "R02"]


def test_store_replaces_rows(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003"), step("T1059", "1.B")])
    store(con, [step("T1003")])
    assert len(recall(con)) == 1


def test_store_rolls_back_on_bad_rows(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003")])
    with pytest.raises(duckdb.Error):
        store(con, [step("T1059"), {"dataset": "d1"}])
    assert list(recall(con)) == [("1.A", "T1003")]


def test_navigator_layer_scores_by_recall(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003", "1.A"), step("T1003", "1.B"), step("T1059", "1.C")])
    add_rule(con, "R01", "T1003")
    # one alert covers both T1003 steps, so T1003 scores 100 and T1059 scores 0
    add_alert(con, "R01")
    layer = navigator_layer(con)
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores == {"T1003": 100, "T1059": 0}
    assert layer["domain"] == "enterprise-attack"


def test_navigator_layer_partial_score(con: duckdb.DuckDBPyConnection) -> None:
    store(con, [step("T1003", "1.A", "d1"), step("T1003", "2.A", "d2")])
    add_rule(con, "R01", "T1003")
    add_alert(con, "R01", dataset="d1")
    (tech,) = navigator_layer(con)["techniques"]
    assert tech["score"] == 50


def test_shipped_file_is_valid() -> None:
    rows = load_ground_truth(GROUND_TRUTH)
    assert {r["dataset"] for r in rows} == {"apt29_day1_host", "apt29_day2_host"}
    assert len(rows) == len({(r["dataset"], r["step"], r["technique"]) for r in rows})


@pytest.mark.parametrize(
    "text",
    [
        "steps: []",
        "steps: [{dataset: d, step: '1.A', technique: 'T12', plan_name: x}]",
        "steps: [{dataset: d, step: '1.A', technique: T1003}]",
        "steps: [{dataset: d, step: '1.A', technique: T1003, plan_name: x},"
        " {dataset: d, step: '1.A', technique: T1003, plan_name: y}]",
        "- not a mapping",
    ],
)
def test_bad_file_is_rejected(tmp_path: Path, text: str) -> None:
    path = tmp_path / "gt.yml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(GroundTruthError):
        load_ground_truth(path)


def test_detect_prints_recall(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], con: duckdb.DuckDBPyConnection
) -> None:
    db_file = tmp_path / "b.duckdb"
    con.close()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    gt = tmp_path / "gt.yml"
    gt.write_text(
        "steps: [{dataset: d1, step: '1.A', technique: T1003, plan_name: x},"
        " {dataset: d1, step: '1.B', technique: T1059, plan_name: y}]",
        encoding="utf-8",
    )
    code = cli.main(
        ["detect", "--db", str(db_file), "--rules-dir", str(rules_dir), "--ground-truth", str(gt)]
    )
    assert code == 0
    assert "d1" in capsys.readouterr().out


def test_coverage_writes_layer(tmp_path: Path) -> None:
    db_file = tmp_path / "b.duckdb"
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    layer = tmp_path / "layer.json"
    gt = tmp_path / "gt.yml"
    gt.write_text("steps: [{dataset: d1, step: '1.A', technique: T1003, plan_name: x}]")
    args = [
        "detect",
        "--db",
        str(db_file),
        "--rules-dir",
        str(rules_dir),
        "--ground-truth",
        str(gt),
    ]
    assert cli.main(args) == 0
    assert cli.main(["coverage", "--db", str(db_file), "--layer", str(layer)]) == 0
    assert '"techniqueID": "T1003"' in layer.read_text(encoding="utf-8")


def test_coverage_missing_database_is_not_created(tmp_path: Path) -> None:
    db_file = tmp_path / "typo.duckdb"
    assert cli.main(["coverage", "--db", str(db_file), "--layer", str(tmp_path / "l.json")]) == 2
    assert not db_file.exists()


def test_coverage_without_ground_truth_fails(tmp_path: Path) -> None:
    db_file = tmp_path / "e.duckdb"
    connect(db_file).close()
    layer = tmp_path / "layer.json"
    assert cli.main(["coverage", "--db", str(db_file), "--layer", str(layer)]) == 2
    assert not layer.exists()
