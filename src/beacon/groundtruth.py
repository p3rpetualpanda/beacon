"""Ground truth for recall: which techniques an emulation is documented to contain."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import duckdb
import yaml

from beacon.ingest.fetch import TECHNIQUE_RE

DEFAULT_GROUND_TRUTH = Path("detections/ground_truth.yml")
FIELDS = ("dataset", "step", "technique", "plan_name")


class GroundTruthError(ValueError):
    """ground_truth.yml is missing, malformed or lists a row twice."""


def load_ground_truth(path: Path = DEFAULT_GROUND_TRUTH) -> list[dict[str, str]]:
    """Read and validate the rows; fail on the first bad one rather than skip it."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    rows = doc.get("steps") if isinstance(doc, dict) else None
    if not isinstance(rows, list) or not rows:
        raise GroundTruthError(f"{path}: needs a non-empty `steps` list")
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        if not isinstance(row, dict) or sorted(row) != sorted(FIELDS):
            raise GroundTruthError(f"{path}: every step needs exactly {', '.join(FIELDS)}: {row}")
        for field in ("dataset", "step", "plan_name"):
            if not isinstance(row[field], str) or not row[field].strip():
                raise GroundTruthError(f"{path}: {field} must be non-empty text in {row}")
        if not TECHNIQUE_RE.fullmatch(str(row["technique"])):
            raise GroundTruthError(f"{path}: bad technique in {row}")
        key = (row["dataset"], row["step"], row["technique"])
        if key in seen:
            raise GroundTruthError(f"{path}: duplicate row {key}")
        seen.add(key)
    return [{k: str(row[k]) for k in FIELDS} for row in rows]


def store(con: duckdb.DuckDBPyConnection, rows: list[dict[str, str]]) -> None:
    """Replace the table's rows in one transaction, so a bad row keeps the old ones."""
    con.execute("BEGIN TRANSACTION")
    try:
        con.execute("DELETE FROM ground_truth")
        con.executemany(
            "INSERT INTO ground_truth VALUES ($dataset, $step, $technique, $plan_name)", rows
        )
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise


def recall_by_dataset(con: duckdb.DuckDBPyConnection) -> list[tuple[str, int, int]]:
    """(dataset, rows detected, rows in ground truth)."""
    return [
        (d, int(hit), int(total))
        for d, hit, total in con.execute(
            "SELECT dataset, count(*) FILTER (WHERE detected), count(*) "
            "FROM rule_recall GROUP BY dataset ORDER BY dataset"
        ).fetchall()
    ]


def navigator_layer(con: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    """An ATT&CK Navigator layer: each ground-truth technique scored 0-100 by recall."""
    rows = con.execute(
        "SELECT technique, count(*) FILTER (WHERE detected), count(*) "
        "FROM rule_recall GROUP BY technique ORDER BY technique"
    ).fetchall()
    return {
        "name": "Beacon recall on the APT29 emulation",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": "Share of ground-truth steps per technique that a Beacon rule alerted on.",
        "gradient": {"colors": ["#ffffff", "#2e7d32"], "minValue": 0, "maxValue": 100},
        "techniques": [
            {
                "techniqueID": tech,
                "score": round(100 * hit / total),
                "comment": f"{hit} of {total} ground-truth rows detected",
            }
            for tech, hit, total in rows
        ],
    }
