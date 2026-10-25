"""Export beacon alerts as OCSF Detection Finding contract v1 findings.

Beacon owns the contract (see docs/superpowers/plans/2026-10-20-alert-export-contract.md and
the design spec section 4 in the ThreatLens repo); ThreatLens vendors a copy of the schema.
Beacon-specific detail lives under OCSF's `unmapped` object in v1.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
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
    by_alert: dict[str, list[dict[str, Any]]] = {a["alert_id"]: [] for a in alerts}
    if alerts:
        events = _query(
            con,
            """
            SELECT DISTINCT a.alert_id, e.event_id, epoch_ms(e.ts) AS ts_ms, e.ts, e.source,
                   e.event_code, e.event_action, e.event_outcome,
                   e.host_name, e.user_name, e.process_name, e.process_command_line,
                   e.parent_process_name, e.src_ip, e.src_port, e.dst_ip, e.dst_port
            FROM alerts a, unnest(a.event_ids) AS u(event_id)
            JOIN events e USING (event_id)
            WHERE a.alert_id IN (SELECT unnest($ids))
            """,
            {"ids": [a["alert_id"] for a in alerts]},
        )
        for event in events:
            by_alert[event["alert_id"]].append(event)

    out = []
    for alert in alerts:
        evidence = by_alert[alert["alert_id"]]
        if len(evidence) != alert["evidence_total"]:
            raise ExportError(f"alert {alert['alert_id']}: evidence event(s) missing from events")
        evidence.sort(key=lambda e: (e["ts_ms"], e["event_id"]))
        out.append(_finding(alert, evidence))
    out.sort(key=lambda f: (f["time"], f["finding_info"]["uid"]))
    return out


def _finding(alert: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    ts_ms = [event["ts_ms"] for event in events]
    if not ts_ms:
        raise ExportError(f"alert {alert['alert_id']}: no evidence events")
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
            "first_seen_time": min(ts_ms),
            "last_seen_time": max(ts_ms),
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
            "data_sources": _strings(event["source"] for event in events),
            "beacon_status": alert["status"],
            "entities": {
                "hosts": _strings(event["host_name"] for event in events),
                "users": _strings(event["user_name"] for event in events),
                "src_ips": _strings(event["src_ip"] for event in events),
                "dst_ips": _strings(event["dst_ip"] for event in events),
                "processes": _strings(event["process_name"] for event in events),
            },
            "evidence": [_evidence_row(event) for event in events][:MAX_EVIDENCE],
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


def _strings(values: Iterable[Any]) -> list[str]:
    """Sorted, de-duplicated non-NULL values; an empty list, never [null]."""
    return sorted({value for value in values if value is not None})


def _query(
    con: duckdb.DuckDBPyConnection, sql: str, params: dict[str, Any]
) -> list[dict[str, Any]]:
    cur = con.execute(sql, params)
    names = [column[0] for column in cur.description]
    return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]
