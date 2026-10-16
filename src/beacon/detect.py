"""Run the SQL detection rules in detections/ and record their hits in `alerts`.

Each rule is a folder holding rule.yml (metadata), rule.sql (a SELECT over `events`) and
rule.kql (the same logic for Microsoft Sentinel). rule.sql must return the columns
ts, dataset, host_name, user_name, summary and event_ids (the evidence, as VARCHAR[]).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import duckdb
import yaml

from beacon.ingest.fetch import TECHNIQUE_RE

DEFAULT_RULES_DIR = Path("detections")
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
            "$rule_id AS rule_id, ts, dataset, host_name, user_name, summary, event_ids "
            f"FROM ({rule.sql})",
            {"rule_id": rule.rule_id},
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
