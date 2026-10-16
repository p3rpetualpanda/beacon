"""Load raw datasets into the normalised `events` table and record data quality.

Each dataset is loaded in one transaction: its old rows are deleted, the new rows are
inserted, and a `data_quality` row records what was read, rejected and de-duplicated.
Reloading a dataset therefore always gives the same table.
"""

from __future__ import annotations

import csv
import json
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from importlib import resources
from pathlib import Path

import duckdb

from beacon.db import read_sql
from beacon.ingest import linux_auth
from beacon.ingest.fetch import Dataset
from beacon.ingest.otrf import extract_json, extract_tar_log

# Local-to-UTC offsets are rounded to the nearest 15 minutes, the smallest real time-zone step.
OFFSET_STEP_S = 900


@dataclass(frozen=True)
class LoadResult:
    dataset: str
    rows_read: int
    rows_rejected: int
    duplicates_dropped: int
    rows_loaded: int
    ts_offset_hours: float | None


def load_event_codes(con: duckdb.DuckDBPyConnection) -> int:
    """Replace event_code_map with the contents of the shipped event_codes.csv."""
    text = resources.files("beacon.normalise").joinpath("event_codes.csv").read_text("utf-8")
    rows = [
        (r["source"], r["event_code"], r["category"], r["action"], r["outcome"] or None)
        for r in csv.DictReader(text.splitlines())
    ]
    con.execute("DELETE FROM event_code_map")
    con.executemany("INSERT INTO event_code_map VALUES (?, ?, ?, ?, ?)", rows)
    return len(rows)


def load_windows_json(
    con: duckdb.DuckDBPyConnection, dataset: Dataset, json_path: Path
) -> LoadResult:
    """Normalise one OTRF JSON-lines file of Windows events into `events`."""
    con.execute("BEGIN TRANSACTION")
    try:
        con.execute(
            "CREATE OR REPLACE TEMP TABLE raw_stage AS "
            "SELECT json AS j FROM read_ndjson_objects(?, ignore_errors = true)",
            [str(json_path)],
        )
        rows_read = _scalar(con, "SELECT count(*) FROM raw_stage")
        offset_s = infer_offset_seconds(con)

        con.execute("DELETE FROM events WHERE dataset = ?", [dataset.name])
        con.execute(read_sql("windows.sql"), {"dataset": dataset.name, "offset_s": offset_s})

        rows_rejected = _scalar(
            con,
            "SELECT count(*) FROM stage_typed WHERE event_code IS NULL "
            "OR coalesce(utc_ts, local_ts + to_seconds($offset_s)) IS NULL",
            {"offset_s": offset_s},
        )
        rows_loaded = _scalar(con, "SELECT count(*) FROM events WHERE dataset = ?", [dataset.name])
        result = LoadResult(
            dataset=dataset.name,
            rows_read=rows_read,
            rows_rejected=rows_rejected,
            duplicates_dropped=rows_read - rows_rejected - rows_loaded,
            rows_loaded=rows_loaded,
            ts_offset_hours=None if offset_s is None else offset_s / 3600,
        )
        record_quality(con, result)
        upsert_dataset(con, dataset)
        con.execute("DROP TABLE IF EXISTS stage_typed")
        con.execute("DROP TABLE IF EXISTS raw_stage")
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    return result


def infer_offset_seconds(con: duckdb.DuckDBPyConnection) -> int | None:
    """Work out how far the staged records' local timestamps are from UTC.

    NXLog writes `EventTime` in the collector's local time with no zone. Sysmon records also
    carry `UtcTime`, so the median gap between the two gives the offset. Files without Sysmon
    fall back to the gap between NXLog's UTC `@timestamp` and its local `EventReceivedTime`.
    Returns None when neither pair exists, in which case only UTC fields are trusted.
    """
    sysmon_gap = _scalar_or_none(
        con,
        """
        SELECT median(epoch(try_strptime(j->>'UtcTime', '%Y-%m-%d %H:%M:%S.%g'))
                      - epoch(try_strptime(coalesce(j->>'EventTime', j->>'TimeCreated'),
                                           ['%Y-%m-%d %H:%M:%S.%g', '%Y-%m-%d %H:%M:%S',
                                            '%Y-%m-%dT%H:%M:%S.%gZ', '%Y-%m-%dT%H:%M:%SZ'])))
        FROM raw_stage
        """,
    )
    gap = sysmon_gap
    if gap is None:
        gap = _scalar_or_none(
            con,
            """
            SELECT median(epoch(try_cast(j->>'@timestamp' AS TIMESTAMPTZ) AT TIME ZONE 'UTC')
                          - epoch(try_strptime(j->>'EventReceivedTime', '%Y-%m-%d %H:%M:%S')))
            FROM raw_stage
            """,
        )
    if gap is None:
        return None
    return round(float(gap) / OFFSET_STEP_S) * OFFSET_STEP_S


def record_quality(con: duckdb.DuckDBPyConnection, result: LoadResult) -> None:
    stats = con.execute(
        """
        SELECT min(ts), max(ts),
               100.0 * count(*) FILTER (WHERE host_name IS NULL) / nullif(count(*), 0),
               100.0 * count(*) FILTER (WHERE user_name IS NULL) / nullif(count(*), 0)
        FROM events WHERE dataset = ?
        """,
        [result.dataset],
    ).fetchone()
    if stats is None:  # pragma: no cover - an aggregate always returns one row
        stats = (None, None, None, None)
    con.execute(
        "INSERT INTO data_quality VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            datetime.now(UTC).replace(tzinfo=None),
            result.dataset,
            result.rows_read,
            result.rows_rejected,
            result.duplicates_dropped,
            result.rows_loaded,
            *stats,
            result.ts_offset_hours,
        ],
    )


def upsert_dataset(con: duckdb.DuckDBPyConnection, dataset: Dataset) -> None:
    _upsert_dataset_row(
        con,
        [
            dataset.name,
            dataset.description,
            dataset.source,
            dataset.licence,
            dataset.format,
            list(dataset.attack_techniques),
        ],
    )


def _upsert_dataset_row(con: duckdb.DuckDBPyConnection, row: list[object]) -> None:
    con.execute("INSERT OR REPLACE INTO datasets VALUES (?, ?, ?, ?, ?, ?)", row)


def load_zeek_json(con: duckdb.DuckDBPyConnection, dataset: Dataset, json_path: Path) -> LoadResult:
    """Normalise one OTRF Zeek JSON-lines file (all log types combined) into `events`."""
    con.execute("BEGIN TRANSACTION")
    try:
        con.execute(
            "CREATE OR REPLACE TEMP TABLE raw_stage AS "
            "SELECT json AS j FROM read_ndjson_objects(?, ignore_errors = true)",
            [str(json_path)],
        )
        rows_read = _scalar(con, "SELECT count(*) FROM raw_stage")
        con.execute("DELETE FROM events WHERE dataset = ?", [dataset.name])
        con.execute(read_sql("zeek.sql"), {"dataset": dataset.name})
        rows_rejected = _scalar(
            con, "SELECT count(*) FROM stage_typed WHERE ts IS NULL OR stream IS NULL"
        )
        rows_loaded = _scalar(con, "SELECT count(*) FROM events WHERE dataset = ?", [dataset.name])
        result = LoadResult(
            dataset=dataset.name,
            rows_read=rows_read,
            rows_rejected=rows_rejected,
            duplicates_dropped=rows_read - rows_rejected - rows_loaded,
            rows_loaded=rows_loaded,
            ts_offset_hours=None,
        )
        record_quality(con, result)
        upsert_dataset(con, dataset)
        con.execute("DROP TABLE IF EXISTS stage_typed")
        con.execute("DROP TABLE IF EXISTS raw_stage")
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    return result


def load_dataset(
    con: duckdb.DuckDBPyConnection, dataset: Dataset, raw_dir: Path, interim_dir: Path
) -> LoadResult | None:
    """Extract and load one manifest dataset. Returns None for formats not loaded this way."""
    if dataset.format == "zeek":
        return load_zeek_json(con, dataset, raw_dir / dataset.path)
    if dataset.format == "linux_auth" and dataset.syslog_year is not None:
        log = extract_tar_log(raw_dir / dataset.path, interim_dir / "auth" / f"{dataset.name}.log")
        # shortcut: the archive's time zone isn't recorded, so its syslog times are read as UTC.
        result = load_auth_log(con, log, dataset=dataset.name, year=dataset.syslog_year)
        upsert_dataset(con, dataset)  # replace the generic row load_auth_log writes
        return result
    if dataset.format != "otrf_windows":
        return None
    archive = raw_dir / dataset.path
    json_path = extract_json(archive, interim_dir / "otrf" / f"{dataset.name}.json")
    return load_windows_json(con, dataset, json_path)


def load_auth_log(
    con: duckdb.DuckDBPyConnection,
    path: Path,
    *,
    dataset: str,
    year: int,
    tz: tzinfo = UTC,
) -> LoadResult:
    """Parse a Linux auth.log and load its SSH events as source `linux_auth`."""
    with path.open(encoding="utf-8", errors="replace") as handle:
        lines = handle.readlines()
    parsed = list(linux_auth.parse_lines(lines, year=year, tz=tz))
    unique = {event.event_id: event for event in parsed}
    rows = [
        {
            "event_id": e.event_id,
            "ts": e.ts.isoformat(),
            "event_code": e.event_code,
            "host_name": e.host_name,
            "process_id": e.process_id,
            "user_name": e.user_name,
            "src_ip": e.src_ip,
            "src_port": e.src_port,
            "raw": json.dumps({"message": e.raw, "auth_method": e.auth_method}),
        }
        for e in unique.values()
    ]

    con.execute("BEGIN TRANSACTION")
    try:
        con.execute(
            "CREATE OR REPLACE TEMP TABLE auth_stage (event_id VARCHAR, ts TIMESTAMP, "
            "event_code VARCHAR, host_name VARCHAR, process_id BIGINT, user_name VARCHAR, "
            "src_ip VARCHAR, src_port INTEGER, raw JSON)"
        )
        if rows:
            # Passing Python rows to DuckDB took minutes for the 655k-line Loghub log; a
            # JSON-lines file that DuckDB reads itself takes seconds.
            with tempfile.TemporaryDirectory() as tmp:
                staged = Path(tmp) / "auth.jsonl"
                staged.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
                con.execute(
                    "INSERT INTO auth_stage SELECT * FROM read_json(?, format = "
                    "'newline_delimited', columns = {event_id: 'VARCHAR', ts: 'TIMESTAMP', "
                    "event_code: 'VARCHAR', host_name: 'VARCHAR', process_id: 'BIGINT', "
                    "user_name: 'VARCHAR', src_ip: 'VARCHAR', src_port: 'INTEGER', "
                    "raw: 'VARCHAR'})",
                    [str(staged)],
                )
        con.execute("DELETE FROM events WHERE dataset = ?", [dataset])
        con.execute(
            """
            INSERT OR IGNORE INTO events BY NAME
            SELECT a.event_id, a.ts, 'syslog' AS ts_source, $dataset AS dataset,
                   'linux_auth' AS source, a.event_code, m.category AS event_category,
                   m.action AS event_action, m.outcome AS event_outcome, a.host_name,
                   a.process_id, a.user_name, a.src_ip, a.src_port,
                   'ssh' AS network_protocol, a.raw
            FROM auth_stage a
            LEFT JOIN event_code_map m ON m.source = 'linux_auth' AND m.event_code = a.event_code
            """,
            {"dataset": dataset},
        )
        rows_loaded = _scalar(con, "SELECT count(*) FROM events WHERE dataset = ?", [dataset])
        result = LoadResult(
            dataset=dataset,
            rows_read=len(parsed),
            rows_rejected=0,
            duplicates_dropped=len(parsed) - rows_loaded,
            rows_loaded=rows_loaded,
            ts_offset_hours=None,
        )
        record_quality(con, result)
        _upsert_dataset_row(
            con,
            [
                dataset,
                f"SSH authentication events from {path.name}",
                "Linux auth.log",
                "own data",
                "linux_auth",
                [],
            ],
        )
        con.execute("DROP TABLE auth_stage")
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    return result


def _scalar(con: duckdb.DuckDBPyConnection, sql: str, params: object = None) -> int:
    row = con.execute(sql, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _scalar_or_none(con: duckdb.DuckDBPyConnection, sql: str) -> float | None:
    row = con.execute(sql).fetchone()
    return None if row is None or row[0] is None else float(row[0])
