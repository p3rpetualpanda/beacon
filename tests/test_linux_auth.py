from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import duckdb

from beacon.ingest.linux_auth import parse_lines
from beacon.load import load_auth_log
from tests.conftest import AUTH_SAMPLE


def test_parses_ssh_events_and_skips_other_lines() -> None:
    events = list(parse_lines(AUTH_SAMPLE.read_text().splitlines(), year=2025))
    codes = [e.event_code for e in events]
    assert codes == [
        "ssh_login_failure",
        "ssh_login_failure",
        "ssh_invalid_user",
        "ssh_login_success",
        "ssh_login_success",
        "ssh_login_success",
    ]
    failure = events[1]
    assert (failure.user_name, failure.src_ip, failure.src_port, failure.auth_method) == (
        "admin",
        "203.0.113.9",
        50124,
        "password",
    )
    assert events[3].auth_method == "publickey"


def test_syslog_year_rolls_over_at_new_year() -> None:
    events = list(parse_lines(AUTH_SAMPLE.read_text().splitlines(), year=2025))
    assert events[0].ts == datetime(2025, 12, 31, 23, 59, 58)
    assert events[2].ts == datetime(2026, 1, 1, 0, 0, 1)


def test_syslog_time_zone_is_converted_to_utc() -> None:
    line = "Jul  4 10:00:00 web sshd[9]: Invalid user test from 192.0.2.1"
    (event,) = parse_lines([line], year=2026, tz=ZoneInfo("Europe/London"))
    assert event.ts == datetime(2026, 7, 4, 9, 0, 0)
    assert event.src_port is None


def test_rfc3339_lines_carry_their_own_offset() -> None:
    events = list(parse_lines(AUTH_SAMPLE.read_text().splitlines(), year=2000))
    deploy = events[-1]
    assert deploy.ts == datetime(2026, 6, 1, 8, 15, 0, 250000)
    assert (deploy.host_name, deploy.user_name, deploy.src_ip) == (
        "bastion",
        "deploy",
        "2001:db8::5",
    )


def test_load_auth_log(con: duckdb.DuckDBPyConnection) -> None:
    result = load_auth_log(con, AUTH_SAMPLE, dataset="lab", year=2025)
    assert (result.rows_read, result.duplicates_dropped, result.rows_loaded) == (6, 1, 5)
    rows = con.execute(
        "SELECT event_category, event_outcome, count(*) FROM events "
        "WHERE source = 'linux_auth' GROUP BY ALL ORDER BY ALL"
    ).fetchall()
    assert rows == [("authentication", "failure", 3), ("authentication", "success", 2)]
    assert con.execute("SELECT format FROM datasets WHERE name = 'lab'").fetchone() == (
        "linux_auth",
    )
