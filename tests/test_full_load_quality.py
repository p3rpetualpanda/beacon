"""Data-quality checks on the full database built by `make load`.

These run against data/beacon.duckdb (or $BEACON_DB) and are skipped when it has not been
built, as in CI, which only has the committed samples. Run them with `make quality`.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import duckdb
import pytest

DB = Path(os.environ.get("BEACON_DB", "data/beacon.duckdb"))
pytestmark = pytest.mark.skipif(not DB.exists(), reason=f"{DB} not built; run `make load`")

# Rows read from each source file, and the UTC day its activity happened on.
EXPECTED = {
    "apt29_day1_host": (196_081, date(2020, 5, 2)),
    "apt29_day2_host": (587_286, date(2020, 5, 2)),
    "lsass_dump_comsvcs": (184, date(2020, 10, 18)),
    "psexec_empire": (4_348, date(2020, 9, 20)),
    "wmi_exec_empire": (6_383, date(2020, 9, 21)),
    "run_keys_empire": (40_569, date(2020, 9, 4)),
}


@pytest.fixture(scope="module")
def con() -> Iterator[duckdb.DuckDBPyConnection]:
    connection = duckdb.connect(str(DB), read_only=True)
    yield connection
    connection.close()


def latest_quality(con: duckdb.DuckDBPyConnection) -> dict[str, tuple[Any, ...]]:
    rows = con.execute(
        """
        SELECT dataset, rows_read, rows_rejected, duplicates_dropped, rows_loaded,
               min_ts, max_ts, pct_null_host
        FROM data_quality
        QUALIFY row_number() OVER (PARTITION BY dataset ORDER BY loaded_at DESC) = 1
        """
    ).fetchall()
    return {r[0]: r[1:] for r in rows}


def test_every_record_is_accounted_for(con: duckdb.DuckDBPyConnection) -> None:
    quality = latest_quality(con)
    assert set(EXPECTED) <= set(quality)
    for name, (expected_read, _) in EXPECTED.items():
        read, rejected, duplicates, loaded, *_ = quality[name]
        assert read == expected_read, name
        assert rejected == 0, name
        assert read == rejected + duplicates + loaded, name


def test_duplicates_match_the_profiled_count(con: duckdb.DuckDBPyConnection) -> None:
    quality = latest_quality(con)
    assert sum(int(quality[name][2]) for name in EXPECTED) == 1_640


def test_events_table_matches_quality_log(con: duckdb.DuckDBPyConnection) -> None:
    quality = latest_quality(con)
    counts = dict(con.execute("SELECT dataset, count(*) FROM events GROUP BY 1").fetchall())
    for name in EXPECTED:
        assert counts[name] == quality[name][3], name


def test_timestamps_fall_on_the_documented_day(con: duckdb.DuckDBPyConnection) -> None:
    quality = latest_quality(con)
    for name, (_, day) in EXPECTED.items():
        min_ts, max_ts = quality[name][4], quality[name][5]
        assert min_ts.date() == day, name
        assert max_ts - min_ts < timedelta(hours=1), name


def test_sources_agree_on_time(con: duckdb.DuckDBPyConnection) -> None:
    """Security events (local time + inferred offset) line up with Sysmon (UTC) per host."""
    gaps = con.execute(
        """
        SELECT dataset, host_name,
               abs(epoch(min(ts) FILTER (WHERE source = 'winsec'))
                   - epoch(min(ts) FILTER (WHERE source = 'sysmon'))) AS gap_s
        FROM events GROUP BY ALL
        HAVING count(*) FILTER (WHERE source = 'winsec') > 100
           AND count(*) FILTER (WHERE source = 'sysmon') > 100
        """
    ).fetchall()
    assert gaps
    assert all(gap < 600 for *_, gap in gaps), gaps


def test_core_fields_are_populated(con: duckdb.DuckDBPyConnection) -> None:
    row = con.execute(
        """
        -- Zeek records come from a network sensor, so they name IPs rather than a host.
        SELECT count(*) FILTER (WHERE host_name IS NULL AND source <> 'zeek'),
               count(*) FILTER (WHERE event_category IS NOT NULL) / count(*),
               count(*) FILTER (WHERE source = 'sysmon' AND event_code = '1'
                                AND (process_path IS NULL OR user_name IS NULL)),
               count(*) FILTER (WHERE event_code = '4624' AND logon_type IS NULL)
        FROM events
        """
    ).fetchone()
    assert row is not None
    null_hosts, mapped_share, bad_process_events, bad_logons = row
    assert null_hosts == 0
    assert mapped_share > 0.95
    assert bad_process_events == 0
    assert bad_logons == 0


def test_event_ids_are_unique(con: duckdb.DuckDBPyConnection) -> None:
    assert con.execute("SELECT count(*) - count(DISTINCT event_id) FROM events").fetchone() == (0,)


def test_zeek_conn_and_dns_have_network_fields(con: duckdb.DuckDBPyConnection) -> None:
    row = con.execute(
        """
        SELECT count(*) FILTER (WHERE event_code = 'conn'),
               count(*) FILTER (WHERE event_code = 'conn' AND (src_ip IS NULL OR dst_ip IS NULL
                                                             OR dst_port IS NULL)),
               count(*) FILTER (WHERE event_code = 'dns' AND dns_query IS NULL)
        FROM events WHERE source = 'zeek'
        """
    ).fetchone()
    assert row is not None
    conns, bad_conns, dns_without_query = row
    assert conns > 1000
    assert bad_conns == 0
    assert dns_without_query < 10
