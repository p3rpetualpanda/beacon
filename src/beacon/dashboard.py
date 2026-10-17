"""Queries behind the SOC dashboard (app/streamlit_app.py).

Each function takes a DuckDB connection and returns plain rows (a list of dicts), so the
dashboard holds layout only and every panel can be tested without Streamlit.
"""

from __future__ import annotations

from typing import Any

import duckdb

STATUSES = ("new", "triaged", "true_positive", "false_positive", "closed")
EVIDENCE_LIMIT = 200


def _rows(con: duckdb.DuckDBPyConnection, sql: str, params: object = None) -> list[dict[str, Any]]:
    cursor = con.execute(sql, params)
    names = [d[0] for d in cursor.description or []]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def alerts_by_severity(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    return _rows(
        con,
        """
        SELECT r.severity, count(*) AS alerts
        FROM alerts a JOIN rules r USING (rule_id)
        GROUP BY r.severity
        ORDER BY list_position(['critical', 'high', 'medium', 'low'], r.severity), r.severity
        """,
    )


def alerts_by_status(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    return _rows(
        con,
        "SELECT status, count(*) AS alerts FROM alerts GROUP BY status "
        "ORDER BY list_position($statuses, status), status",
        {"statuses": list(STATUSES)},
    )


def noisiest_rules(con: duckdb.DuckDBPyConnection, limit: int = 5) -> list[dict[str, Any]]:
    return _rows(
        con,
        "SELECT rule_id, name, hits, precision FROM rule_performance WHERE hits > 0 "
        "ORDER BY hits DESC, rule_id LIMIT ?",
        [limit],
    )


def events_per_dataset(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    return _rows(
        con,
        """
        SELECT dataset, rows_loaded AS events, rows_rejected AS rejected,
               duplicates_dropped AS duplicates, min_ts AS first_event, max_ts AS last_event
        FROM data_quality
        QUALIFY row_number() OVER (
            PARTITION BY dataset ORDER BY loaded_at DESC, rows_loaded DESC
        ) = 1
        ORDER BY events DESC, dataset
        """,
    )


def alert_queue(
    con: duckdb.DuckDBPyConnection,
    *,
    statuses: list[str] | None = None,
    rule_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Alerts newest first, optionally filtered by status and rule.

    An empty or missing filter means no filter, so clearing a filter shows every alert.
    `evidence` counts distinct event ids, the same events alert_evidence returns.
    """
    return _rows(
        con,
        """
        SELECT a.alert_id, a.ts, a.rule_id, r.name AS rule, r.severity, a.status,
               a.host_name, a.user_name, a.dataset, a.summary,
               len(list_distinct(a.event_ids)) AS evidence
        FROM alerts a JOIN rules r USING (rule_id)
        WHERE ($statuses IS NULL OR list_contains($statuses, a.status))
          AND ($rule_ids IS NULL OR list_contains($rule_ids, a.rule_id))
        ORDER BY a.ts DESC, a.alert_id
        """,
        {"statuses": statuses or None, "rule_ids": rule_ids or None},
    )


def alert_evidence(con: duckdb.DuckDBPyConnection, alert_id: str) -> list[dict[str, Any]]:
    """The events an alert points at, oldest first (at most EVIDENCE_LIMIT)."""
    return _rows(
        con,
        """
        SELECT e.ts, e.source, e.event_code, e.event_action, e.host_name, e.user_name,
               e.process_name, e.process_command_line, e.src_ip, e.dst_ip, e.event_id
        FROM events e
        WHERE e.event_id IN (SELECT unnest(event_ids) FROM alerts WHERE alert_id = ?)
        ORDER BY e.ts, e.event_id
        LIMIT ?
        """,
        [alert_id, EVIDENCE_LIMIT],
    )


def set_alert_status(con: duckdb.DuckDBPyConnection, alert_id: str, status: str) -> bool:
    """Record an analyst's verdict. Returns False when no such alert exists."""
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    row = con.execute(
        "UPDATE alerts SET status = ? WHERE alert_id = ? RETURNING alert_id", [status, alert_id]
    ).fetchone()
    return row is not None
