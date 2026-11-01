"""Export beacon alerts as OCSF Detection Finding contract v1 findings.

Beacon owns the contract (see docs/superpowers/plans/2026-10-20-alert-export-contract.md and
the design spec section 4 in the ThreatLens repo); ThreatLens vendors a copy of the schema.
Beacon-specific detail lives under OCSF's `unmapped` object in v1.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import duckdb

from beacon import __version__

CONTRACT_VERSION = "1.0"
# Checked against schema.ocsf.io for the latest 1.x release at implementation time (2026-10-25).
OCSF_VERSION = "1.9.0"
MAX_EVIDENCE = 50

# rule.yml severity (validated in detect.load_rules) -> (OCSF severity_id, caption).
SEVERITIES: dict[str, tuple[int, str]] = {
    "low": (2, "Low"),
    "medium": (3, "Medium"),
    "high": (4, "High"),
    "critical": (5, "Critical"),
}
# alerts.status -> (OCSF status_id, caption).
STATUSES: dict[str, tuple[int, str]] = {
    "new": (1, "New"),
    "triaged": (2, "In Progress"),
    "true_positive": (4, "Resolved"),
    "false_positive": (4, "Resolved"),
    "closed": (4, "Resolved"),
}


class ExportError(ValueError):
    """The export cannot be built for an alert; the alert id is named in the message."""


def findings(
    con: duckdb.DuckDBPyConnection, only: Sequence[str] | None = None
) -> list[dict[str, Any]]:
    """Build contract v1 findings for every alert, sorted by (time, finding_info.uid).

    `only` limits the export to these rule ids. Raises ExportError naming the alert if any of
    its evidence event ids is missing from `events`.
    """
    alerts = _query(
        con,
        """
        SELECT a.alert_id, a.rule_id, epoch_ms(a.ts) AS ts_ms, a.dataset, a.summary, a.status,
               len(list_distinct(a.event_ids)) AS evidence_total,
               r.name, r.technique, r.tactic, r.severity
        FROM alerts a
        JOIN rules r USING (rule_id)
        WHERE $only IS NULL OR len($only) = 0 OR a.rule_id IN (SELECT unnest($only))
        """,
        {"only": list(only) if only is not None else None},
    )
    ids = {"ids": [a["alert_id"] for a in alerts]}
    # Entities, sources and first/last seen cover every evidence event; only the rows are capped.
    summary = {
        row["alert_id"]: row
        for row in _query(
            con,
            """
            SELECT a.alert_id, count(DISTINCT e.event_id) AS found,
                   min(epoch_ms(e.ts)) AS first_ms, max(epoch_ms(e.ts)) AS last_ms,
                   list_sort(list_distinct(list(e.source))) AS sources,
                   list_sort(list_distinct(list(e.host_name))) AS hosts,
                   list_sort(list_distinct(list(e.user_name))) AS users,
                   list_sort(list_distinct(list(e.src_ip))) AS src_ips,
                   list_sort(list_distinct(list(e.dst_ip))) AS dst_ips,
                   list_sort(list_distinct(list(e.process_name))) AS processes
            FROM alerts a, unnest(a.event_ids) AS u(event_id)
            JOIN events e USING (event_id)
            WHERE a.alert_id IN (SELECT unnest($ids))
            GROUP BY a.alert_id
            """,
            ids,
        )
    }
    by_alert: dict[str, list[dict[str, Any]]] = {a["alert_id"]: [] for a in alerts}
    # Order by the full timestamp (Zeek has microseconds), then keep the first MAX_EVIDENCE.
    for event in _query(
        con,
        """
        SELECT * EXCLUDE (rn) FROM (
            SELECT *, row_number() OVER (PARTITION BY alert_id ORDER BY ts, event_id) AS rn
            FROM (
                SELECT DISTINCT a.alert_id, e.event_id, e.ts, e.source,
                       e.event_code, e.event_action, e.event_outcome,
                       e.host_name, e.user_name, e.process_name, e.process_command_line,
                       e.parent_process_name, e.src_ip, e.src_port, e.dst_ip, e.dst_port
                FROM alerts a, unnest(a.event_ids) AS u(event_id)
                JOIN events e USING (event_id)
                WHERE a.alert_id IN (SELECT unnest($ids))
            )
        ) WHERE rn <= $cap ORDER BY alert_id, rn
        """,
        {**ids, "cap": MAX_EVIDENCE},
    ):
        by_alert[event["alert_id"]].append(event)

    out = []
    for alert in alerts:
        found = summary.get(alert["alert_id"], {}).get("found", 0)
        if found != alert["evidence_total"]:
            raise ExportError(f"alert {alert['alert_id']}: evidence event(s) missing from events")
        out.append(_finding(alert, summary[alert["alert_id"]], by_alert[alert["alert_id"]]))
    out.sort(key=lambda f: (f["time"], f["finding_info"]["uid"]))
    return out


def write_jsonl(items: Iterable[dict[str, Any]], path: Path) -> int:
    """Write one compact, key-sorted JSON object per line (UTF-8, LF); return the count.

    Same input gives the same bytes on Windows and Linux, and non-ASCII text stays as UTF-8.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write beside the target and swap in at the end, so a failure keeps the previous export.
    tmp = path.with_name(path.name + ".tmp")
    count = 0
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as fh:
            for item in items:
                fh.write(
                    json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                )
                fh.write("\n")
                count += 1
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)
    return count


def _finding(
    alert: dict[str, Any], summary: dict[str, Any], evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    if alert["dataset"] is None:
        raise ExportError(f"alert {alert['alert_id']}: dataset is NULL (becomes the environment)")
    for field, known in (("severity", SEVERITIES), ("status", STATUSES)):
        if alert[field] not in known:
            raise ExportError(f"alert {alert['alert_id']}: unknown {field} {alert[field]!r}")
    return {
        "schema_version": CONTRACT_VERSION,
        "class_uid": 2004,
        "category_uid": 2,
        "activity_id": 1,
        "type_uid": 200401,
        "time": int(alert["ts_ms"]),
        "severity_id": SEVERITIES[alert["severity"]][0],
        "severity": SEVERITIES[alert["severity"]][1],
        "status_id": STATUSES[alert["status"]][0],
        "status": STATUSES[alert["status"]][1],
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "beacon", "vendor_name": "p3rpetualpanda", "version": __version__},
        },
        "finding_info": {
            "uid": alert["alert_id"],
            "title": alert["name"],
            "desc": alert["summary"],
            "first_seen_time": summary["first_ms"],
            "last_seen_time": summary["last_ms"],
            "analytic": {
                "uid": alert["rule_id"],
                "name": alert["name"],
                "type_id": 1,
                "type": "Rule",
            },
            "attacks": [
                {"technique": {"uid": alert["technique"]}, "tactic": {"name": alert["tactic"]}}
            ],
        },
        "unmapped": {
            "environment": alert["dataset"],
            "data_sources": summary["sources"],
            "beacon_status": alert["status"],
            "entities": {
                "hosts": summary["hosts"],
                "users": summary["users"],
                "src_ips": summary["src_ips"],
                "dst_ips": summary["dst_ips"],
                "processes": summary["processes"],
            },
            "evidence": [_evidence_row(event) for event in evidence],
            "evidence_total": int(alert["evidence_total"]),
        },
    }


def _evidence_row(event: dict[str, Any]) -> dict[str, Any]:
    # Exactly the 15 evidence keys of spec section 4; missing values are JSON null.
    return {
        "event_id": event["event_id"],
        "ts": event["ts"].strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "source": event["source"],
        "event_code": event["event_code"],
        "event_action": event["event_action"],
        "event_outcome": event["event_outcome"],
        "host_name": event["host_name"],
        "user_name": event["user_name"],
        "process_name": event["process_name"],
        "process_command_line": event["process_command_line"],
        "parent_process_name": event["parent_process_name"],
        "src_ip": event["src_ip"],
        "src_port": event["src_port"],
        "dst_ip": event["dst_ip"],
        "dst_port": event["dst_port"],
    }


def _query(
    con: duckdb.DuckDBPyConnection, sql: str, params: dict[str, Any]
) -> list[dict[str, Any]]:
    cur = con.execute(sql, params)
    names = [column[0] for column in cur.description]
    return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]
