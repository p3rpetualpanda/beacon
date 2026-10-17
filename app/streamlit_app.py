"""Beacon SOC dashboard: an overview page and an alert queue. Run with `make dashboard`.

Layout only: every number comes from beacon.dashboard, which is unit-tested.
"""

from __future__ import annotations

import os
from pathlib import Path

import duckdb
import streamlit as st

from beacon import dashboard, db

DB_PATH = Path(os.environ.get("BEACON_DB", db.DEFAULT_DB))
STATUS_LABELS = {
    "new": "New",
    "triaged": "Triaged",
    "true_positive": "True positive",
    "false_positive": "False positive",
    "closed": "Closed",
}


@st.cache_resource
def connection() -> duckdb.DuckDBPyConnection:
    # Read-only, so `make quality` and other readers can open the database while this runs.
    return duckdb.connect(str(DB_PATH), read_only=True)


def save_verdict(alert_id: str, status: str) -> None:
    """Swap the read-only connection for a short read-write one, just for the update."""
    connection().close()
    connection.clear()
    con = db.connect(DB_PATH)
    try:
        dashboard.set_alert_status(con, alert_id, status)
    finally:
        con.close()


def overview(con: duckdb.DuckDBPyConnection) -> None:
    st.title("Overview")
    by_status = {r["status"]: r["alerts"] for r in dashboard.alerts_by_status(con)}
    datasets = dashboard.events_per_dataset(con)
    cols = st.columns(4)
    cols[0].metric("Alerts", sum(by_status.values()))
    cols[1].metric("Open (new or triaged)", by_status.get("new", 0) + by_status.get("triaged", 0))
    cols[2].metric("Events loaded", f"{sum(d['events'] for d in datasets):,}")
    cols[3].metric("Datasets", len(datasets))

    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by severity")
        st.bar_chart(dashboard.alerts_by_severity(con), x="severity", y="alerts", horizontal=True)
    with right:
        st.subheader("Alerts by status")
        st.bar_chart(dashboard.alerts_by_status(con), x="status", y="alerts", horizontal=True)

    st.subheader("Noisiest rules")
    st.caption(
        "Precision counts a hit as true when its dataset is documented to contain the rule's "
        "ATT&CK technique. Blank means no labelled dataset to score against."
    )
    st.dataframe(
        dashboard.noisiest_rules(con),
        hide_index=True,
        column_config={"precision": st.column_config.NumberColumn(format="percent")},
    )

    st.subheader("Events per dataset")
    st.dataframe(datasets, hide_index=True)


def alert_queue(con: duckdb.DuckDBPyConnection) -> None:
    st.title("Alert queue")
    rules = sorted({r["rule_id"] for r in dashboard.alert_queue(con)})
    f1, f2 = st.columns(2)
    statuses = f1.multiselect(
        "Status", list(STATUS_LABELS), default=["new", "triaged"], format_func=STATUS_LABELS.get
    )
    rule_ids = f2.multiselect("Rule", rules)
    queue = dashboard.alert_queue(con, statuses=statuses, rule_ids=rule_ids)
    st.caption(f"{len(queue):,} alerts")
    picked = st.dataframe(
        queue,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        column_order=[
            "ts",
            "rule_id",
            "rule",
            "severity",
            "status",
            "host_name",
            "user_name",
            "summary",
            "evidence",
        ],
    )
    rows = picked.selection.rows
    if not rows:
        st.info("Select an alert to see its evidence and record a verdict.")
        return

    alert = queue[rows[0]]
    st.subheader(f"{alert['rule_id']}: {alert['rule']}")
    st.write(alert["summary"])
    current = list(STATUS_LABELS).index(alert["status"])
    verdict = st.radio(
        "Verdict",
        list(STATUS_LABELS),
        index=current,
        horizontal=True,
        format_func=STATUS_LABELS.get,
    )
    st.caption(
        "An alert set back to New is removed on the next `make detect` if its rule no "
        "longer fires; any other verdict is kept."
    )
    if verdict != alert["status"] and st.button("Save verdict"):
        save_verdict(alert["alert_id"], verdict)
        st.rerun()

    st.subheader("Evidence")
    evidence = dashboard.alert_evidence(con, alert["alert_id"])
    if len(evidence) < alert["evidence"]:
        st.caption(f"Showing {len(evidence):,} of {alert['evidence']:,} events.")
    st.dataframe(evidence, hide_index=True)


st.set_page_config(page_title="Beacon", layout="wide")
if not DB_PATH.exists():
    st.error(f"{DB_PATH} not found. Run `make load` and `make detect` first.")
    st.stop()

page = st.navigation(
    [
        st.Page(lambda: overview(connection()), title="Overview", url_path="overview"),
        st.Page(lambda: alert_queue(connection()), title="Alert queue", url_path="alerts"),
    ]
)
page.run()
