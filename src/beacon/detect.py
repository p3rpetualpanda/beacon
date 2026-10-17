"""Run the SQL detection rules in detections/ and record their hits in `alerts`.

Each rule is a folder holding rule.yml (metadata), rule.sql (a SELECT over `events`) and
rule.kql (the same logic for Microsoft Sentinel). rule.sql must return the columns
ts, dataset, host_name, user_name, summary and event_ids (the evidence, as VARCHAR[]).
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

import duckdb
import yaml

from beacon.dashboard import STATUSES, set_alert_status
from beacon.ingest.fetch import TECHNIQUE_RE

DEFAULT_RULES_DIR = Path("detections")
# Reviewed analyst verdicts, kept in git so precision can be rebuilt from scratch.
DEFAULT_VERDICTS = DEFAULT_RULES_DIR / "verdicts.csv"
VERDICT_FIELDS = ["alert_id", "status", "reason"]
SEVERITIES = ("low", "medium", "high", "critical")
RULE_ID_RE = re.compile(r"^R\d{2}$")
FIELDS = ("id", "name", "technique", "tactic", "severity", "description")


class RuleError(ValueError):
    """A rule folder is missing a file or its rule.yml has bad values."""


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    technique: str
    tactic: str
    severity: str
    description: str
    sql: str


def load_rules(rules_dir: Path = DEFAULT_RULES_DIR) -> list[Rule]:
    """Read and validate every rule folder under rules_dir, sorted by rule id."""
    rules = [_load_rule(folder) for folder in sorted(rules_dir.iterdir()) if folder.is_dir()]
    ids = [rule.rule_id for rule in rules]
    if len(ids) != len(set(ids)):
        raise RuleError(f"{rules_dir}: duplicate rule ids")
    return rules


def _load_rule(folder: Path) -> Rule:
    meta = yaml.safe_load((folder / "rule.yml").read_text(encoding="utf-8"))
    if not isinstance(meta, dict) or sorted(meta) != sorted(FIELDS):
        raise RuleError(f"{folder}: rule.yml must have exactly {', '.join(FIELDS)}")
    if not RULE_ID_RE.fullmatch(str(meta["id"])) or not folder.name.startswith(f"{meta['id']}_"):
        raise RuleError(f"{folder}: id must look like R01 and match the folder name")
    if not TECHNIQUE_RE.fullmatch(str(meta["technique"])):
        raise RuleError(f"{folder}: technique must look like T1234 or T1234.001")
    if meta["severity"] not in SEVERITIES:
        raise RuleError(f"{folder}: severity must be one of {', '.join(SEVERITIES)}")
    if not (folder / "rule.kql").is_file():
        raise RuleError(f"{folder}: rule.kql is missing")
    return Rule(
        rule_id=meta["id"],
        name=meta["name"],
        technique=meta["technique"],
        tactic=meta["tactic"],
        severity=meta["severity"],
        description=meta["description"],
        sql=(folder / "rule.sql").read_text(encoding="utf-8").strip().rstrip(";"),
    )


def run_rule(con: duckdb.DuckDBPyConnection, rule: Rule) -> int:
    """Run one rule in a transaction and return how many alerts it produces now.

    Alerts it still produces keep their status. Alerts it no longer produces are removed while
    still 'new'; ones an analyst has triaged are kept, so re-running never loses a verdict.
    """
    con.execute("BEGIN TRANSACTION")
    try:
        con.execute(
            "INSERT OR REPLACE INTO rules VALUES (?, ?, ?, ?, ?, ?)",
            [rule.rule_id, rule.name, rule.technique, rule.tactic, rule.severity, rule.description],
        )
        # rule.sql comes from the repo's own detections/ folder, not from user input.
        con.execute(
            "CREATE OR REPLACE TEMP TABLE rule_hits AS "  # noqa: S608  # nosec B608
            "SELECT md5($rule_id || list_sort(event_ids)::VARCHAR) AS alert_id, "
            "$rule_id AS rule_id, ts, dataset, host_name, user_name, "
            # A NULL field inside printf() makes the whole summary NULL; fall back to the rule name.
            "coalesce(summary, $rule_name) AS summary, event_ids "
            f"FROM ({rule.sql})",
            {"rule_id": rule.rule_id, "rule_name": rule.name},
        )
        con.execute(
            "DELETE FROM alerts WHERE rule_id = ? AND status = 'new' "
            "AND alert_id NOT IN (SELECT alert_id FROM rule_hits)",
            [rule.rule_id],
        )
        con.execute(
            "INSERT OR IGNORE INTO alerts BY NAME "
            "SELECT DISTINCT ON (alert_id) * FROM rule_hits ORDER BY alert_id, ts"
        )
        (count,) = con.execute("SELECT count(DISTINCT alert_id) FROM rule_hits").fetchone() or (0,)
        con.execute("DROP TABLE rule_hits")
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    return int(count)


def read_verdicts(path: Path) -> dict[str, tuple[str, str]]:
    """Read a verdicts file into {alert_id: (status, reason)}, rejecting anything ambiguous."""
    # utf-8-sig: a file saved from Excel on Windows starts with a byte-order mark.
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != VERDICT_FIELDS:
            raise RuleError(f"{path}: columns must be {', '.join(VERDICT_FIELDS)}")
        verdicts: dict[str, tuple[str, str]] = {}
        for row in reader:
            alert_id, status = row["alert_id"].strip(), row["status"].strip()
            if alert_id in verdicts:
                raise RuleError(f"{path}: alert {alert_id} is listed twice")
            # A file never sets 'new': run_rule deletes new alerts its rule no longer raises.
            if status not in STATUSES or status == "new":
                raise RuleError(f"{path}: alert {alert_id} has an invalid status {status!r}")
            verdicts[alert_id] = (status, row["reason"].strip())
    return verdicts


def apply_verdicts(con: duckdb.DuckDBPyConnection, path: Path) -> tuple[int, list[str]]:
    """Give each listed alert its file verdict, unless it already has one in the database.

    The database wins over the file, so a verdict saved in the dashboard is never undone by
    re-running detect; `export_verdicts` copies it into the file. Applied in one transaction.
    Returns how many were applied and the ids of listed alerts that don't exist.
    """
    verdicts = read_verdicts(path)
    applied, missing = 0, []
    con.execute("BEGIN TRANSACTION")
    try:
        for alert_id, (status, _) in verdicts.items():
            row = con.execute("SELECT status FROM alerts WHERE alert_id = ?", [alert_id]).fetchone()
            if row is None:
                missing.append(alert_id)
            elif row[0] == "new":
                set_alert_status(con, alert_id, status)
                applied += 1
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    return applied, missing


def export_verdicts(con: duckdb.DuckDBPyConnection, path: Path) -> int:
    """Merge the database's verdicts into path and return how many the file now holds.

    Rows already in the file are kept (even for alerts not in this database) with their
    reasons; the database's status wins where both have one. The file is replaced in one step.
    """
    verdicts = read_verdicts(path) if path.exists() else {}
    for alert_id, status in con.execute(
        "SELECT alert_id, status FROM alerts WHERE status <> 'new'"
    ).fetchall():
        verdicts[alert_id] = (status, verdicts.get(alert_id, ("", ""))[1])
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(VERDICT_FIELDS)
        writer.writerows([a, s, r] for a, (s, r) in sorted(verdicts.items()))
    tmp.replace(path)
    return len(verdicts)
