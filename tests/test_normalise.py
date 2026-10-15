"""Normalisation of OTRF Windows records, checked against known records in the samples."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import duckdb

from beacon.load import load_dataset, load_windows_json
from tests.conftest import APT29_SAMPLE, LSASS_SAMPLE, make_dataset, zip_json

RTLO = "‮"


def one(con: duckdb.DuckDBPyConnection, sql: str, params: object = None) -> tuple[object, ...]:
    row = con.execute(sql, params).fetchone()
    assert row is not None
    return tuple(row)


def test_apt29_sample_loads_every_record(con: duckdb.DuckDBPyConnection) -> None:
    result = load_windows_json(con, make_dataset("apt29"), APT29_SAMPLE)
    assert result.rows_read == 151
    assert result.rows_loaded == 151
    assert result.rows_rejected == 0
    # The APT29 lab clock ran on US Eastern daylight time (UTC-4).
    assert result.ts_offset_hours == 4.0


def test_process_creation_from_sysmon_and_security_agree(con: duckdb.DuckDBPyConnection) -> None:
    """The RTLO-disguised payload is logged by Sysmon 1 (UTC) and Security 4688 (local time)."""
    load_windows_json(con, make_dataset("apt29"), APT29_SAMPLE)
    rows = con.execute(
        """
        SELECT source, event_code, ts, process_name, parent_process_name, user_name,
               user_domain, host_name, event_category, event_action
        FROM events WHERE event_code IN ('1', '4688') AND contains(process_path, ?)
        ORDER BY source
        """,
        [RTLO],
    ).fetchall()
    assert len(rows) == 2
    sysmon, winsec = rows
    assert sysmon[:2] == ("sysmon", "1")
    assert winsec[:2] == ("winsec", "4688")
    assert abs(sysmon[2] - winsec[2]) < timedelta(seconds=1)
    assert sysmon[2] == datetime(2020, 5, 2, 2, 55, 56, 157000)
    for row in rows:
        assert row[3] == f"{RTLO}cod.3aka3.scr"
        assert row[4:] == (
            "explorer.exe",
            "pbeesly",
            "DMEVALS",
            "scranton",
            "process",
            "process-created",
        )


def test_network_logon_fields(con: duckdb.DuckDBPyConnection) -> None:
    load_windows_json(con, make_dataset("apt29"), APT29_SAMPLE)
    row = one(
        con,
        "SELECT ts, ts_source, user_name, user_domain, logon_type, event_outcome, host_fqdn "
        "FROM events WHERE event_code = '4624' AND src_ip = '10.0.0.4'",
    )
    assert row == (
        datetime(2020, 5, 2, 2, 56, 47),
        "local_plus_offset",
        "newyork$",
        "DMEVALS.LOCAL",
        3,
        "success",
        "newyork.dmevals.local",
    )


def test_sysmon_user_comes_from_user_field_not_agent_account(
    con: duckdb.DuckDBPyConnection,
) -> None:
    load_windows_json(con, make_dataset("apt29"), APT29_SAMPLE)
    users = {
        r[0]
        for r in con.execute(
            "SELECT DISTINCT user_name FROM events WHERE source = 'sysmon' AND event_code = '1'"
        ).fetchall()
    }
    assert "pbeesly" in users


def test_network_dns_and_service_fields(con: duckdb.DuckDBPyConnection) -> None:
    load_windows_json(con, make_dataset("apt29"), APT29_SAMPLE)
    assert one(
        con,
        "SELECT count(*) FROM events WHERE event_code = '3' AND source = 'sysmon' "
        "AND dst_ip IS NOT NULL AND dst_port IS NOT NULL AND network_protocol IN ('tcp', 'udp')",
    ) == (12,)
    assert one(con, "SELECT count(*) > 0 FROM events WHERE dns_query = 'ocsp.digicert.com'") == (
        True,
    )
    assert one(con, "SELECT service_path FROM events WHERE service_name = 'PSEXESVC'") == (
        "%SystemRoot%\\PSEXESVC.exe",
    )


def test_fields_are_recovered_from_unparsed_sysmon_messages(
    con: duckdb.DuckDBPyConnection,
) -> None:
    """One APT29 record, the hidden PowerShell stager, arrived with only its Message text."""
    load_windows_json(con, make_dataset("apt29"), APT29_SAMPLE)
    row = one(
        con,
        "SELECT ts, ts_source, process_name, parent_process_name, user_name, process_id, "
        "starts_with(process_command_line, '\"powershell.exe\" -nop -w hidden') "
        "FROM events WHERE json_extract(raw, '$.BeaconFieldsFromMessage')::BOOLEAN",
    )
    assert row == (
        datetime(2020, 5, 2, 3, 21, 29, 362000),
        "utc_field",
        "powershell.exe",
        "powershell.exe",
        "pbeesly",
        8784,
        True,
    )


def test_every_sampled_event_code_is_mapped(con: duckdb.DuckDBPyConnection) -> None:
    load_windows_json(con, make_dataset("apt29"), APT29_SAMPLE)
    assert one(con, "SELECT count(*) FROM events WHERE event_category IS NULL") == (0,)


def test_lsass_sample_offset_and_duplicates(con: duckdb.DuckDBPyConnection) -> None:
    """This file's Security events use a 12-hour clock, which the inferred offset absorbs."""
    result = load_windows_json(con, make_dataset("lsass"), LSASS_SAMPLE)
    assert result.ts_offset_hours == 16.0
    assert result.duplicates_dropped == 9
    assert result.rows_loaded == 175
    spread = one(
        con,
        "SELECT max(ts) - min(ts) FROM events WHERE dataset = 'lsass'",
    )[0]
    assert isinstance(spread, timedelta)
    assert spread < timedelta(minutes=2)


def test_reloading_replaces_rather_than_duplicates(con: duckdb.DuckDBPyConnection) -> None:
    dataset = make_dataset("apt29")
    load_windows_json(con, dataset, APT29_SAMPLE)
    load_windows_json(con, dataset, APT29_SAMPLE)
    assert one(con, "SELECT count(*) FROM events") == (151,)
    assert one(con, "SELECT count(*) FROM data_quality") == (2,)
    assert one(con, "SELECT attack_techniques FROM datasets WHERE name = 'apt29'") == (
        ["T1003.001"],
    )


def test_records_without_timestamp_or_event_id_are_rejected(
    con: duckdb.DuckDBPyConnection, tmp_path: Path
) -> None:
    good = next(
        r for r in map(json.loads, LSASS_SAMPLE.read_text().splitlines()) if r.get("UtcTime")
    )
    no_time = {
        k: v for k, v in good.items() if k not in ("EventTime", "TimeCreated", "UtcTime", "Message")
    }
    no_time["RecordNumber"] = 1
    no_id = {**good, "RecordNumber": 2}
    del no_id["EventID"]
    path = tmp_path / "mixed.json"
    path.write_text("\n".join(json.dumps(r) for r in (good, no_time, no_id)) + "\n")

    result = load_windows_json(con, make_dataset("mixed"), path)
    assert (result.rows_read, result.rows_rejected, result.rows_loaded) == (3, 2, 1)
    quality = one(
        con,
        "SELECT rows_read, rows_rejected, duplicates_dropped, rows_loaded, pct_null_host "
        "FROM data_quality WHERE dataset = 'mixed'",
    )
    assert quality == (3, 2, 0, 1, 0.0)


def test_file_without_local_time_pairs_has_no_offset(
    con: duckdb.DuckDBPyConnection, tmp_path: Path
) -> None:
    record = {"Hostname": "h", "Channel": "Security", "EventID": 4624, "RecordNumber": 1}
    path = tmp_path / "bare.json"
    path.write_text(json.dumps(record) + "\n")
    result = load_windows_json(con, make_dataset("bare"), path)
    assert result.ts_offset_hours is None
    assert result.rows_rejected == 1


def test_offset_falls_back_to_collector_times(
    con: duckdb.DuckDBPyConnection, tmp_path: Path
) -> None:
    record = {
        "Hostname": "h",
        "Channel": "Security",
        "EventID": 4625,
        "RecordNumber": 1,
        "EventTime": "2020-09-21 03:00:00",
        "EventReceivedTime": "2020-09-21 03:00:01",
        "@timestamp": "2020-09-21T07:00:02.000Z",
    }
    path = tmp_path / "winsec.json"
    path.write_text(json.dumps(record) + "\n")
    result = load_windows_json(con, make_dataset("winsec"), path)
    assert result.ts_offset_hours == 4.0
    assert one(con, "SELECT ts, event_outcome FROM events") == (
        datetime(2020, 9, 21, 7, 0, 0),
        "failure",
    )


def test_load_dataset_extracts_and_skips_zeek(
    con: duckdb.DuckDBPyConnection, tmp_path: Path
) -> None:
    raw, interim = tmp_path / "raw", tmp_path / "interim"
    dataset = make_dataset("lsass")
    zip_json(LSASS_SAMPLE, raw / dataset.path)
    result = load_dataset(con, dataset, raw, interim)
    assert result is not None
    assert result.rows_loaded == 175
    assert (interim / "otrf" / "lsass.json").exists()

    zeek = make_dataset("zeek", format="zeek", path="zeek.log")
    assert load_dataset(con, zeek, raw, interim) is None
