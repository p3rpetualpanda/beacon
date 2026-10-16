"""Command-line entry point: `beacon <command>`."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from beacon import __version__, db
from beacon import detect as detect_mod
from beacon import load as load_mod
from beacon.ingest import fetch as fetch_mod

DEFAULT_MANIFEST = Path("data/manifest.yml")
DEFAULT_RAW_DIR = Path("data/raw")
DEFAULT_INTERIM_DIR = Path("data/interim")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="beacon", description=__doc__)
    parser.add_argument("--version", action="version", version=f"beacon {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    data = commands.add_parser("data", help="download and verify public datasets")
    data_commands = data.add_subparsers(dest="data_command", required=True)

    fetch = data_commands.add_parser("fetch", help="download every dataset in the manifest")
    fetch.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    fetch.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    fetch.add_argument("--only", nargs="+", metavar="NAME", help="fetch only these datasets")

    hash_cmd = data_commands.add_parser("hash", help="print the sha256 and size of local files")
    hash_cmd.add_argument("files", nargs="+", type=Path)

    load = commands.add_parser("load", help="normalise downloaded datasets into the database")
    load.add_argument("--db", type=Path, default=db.DEFAULT_DB)
    load.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    load.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    load.add_argument("--interim-dir", type=Path, default=DEFAULT_INTERIM_DIR)
    load.add_argument("--only", nargs="+", metavar="NAME", help="load only these datasets")

    detect = commands.add_parser("detect", help="run the detection rules and record alerts")
    detect.add_argument("--db", type=Path, default=db.DEFAULT_DB)
    detect.add_argument("--rules-dir", type=Path, default=detect_mod.DEFAULT_RULES_DIR)
    detect.add_argument("--only", nargs="+", metavar="ID", help="run only these rules, e.g. R03")

    auth = commands.add_parser("load-auth-log", help="load SSH events from a Linux auth.log")
    auth.add_argument("file", type=Path)
    auth.add_argument("--db", type=Path, default=db.DEFAULT_DB)
    auth.add_argument("--dataset", default="linux_auth", help="dataset name to load under")
    auth.add_argument("--year", type=int, required=True, help="year for syslog timestamps")
    auth.add_argument(
        "--tz", default="UTC", help="time zone of syslog timestamps, e.g. Europe/London"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "load":
        return _load(args.db, args.manifest, args.raw_dir, args.interim_dir, args.only)
    if args.command == "detect":
        return _detect(args.db, args.rules_dir, args.only)
    if args.command == "load-auth-log":
        return _load_auth_log(args.file, args.db, args.dataset, args.year, args.tz)
    if args.data_command == "fetch":
        return _fetch(args.manifest, args.raw_dir, args.only)
    return _hash(args.files)


def _select(datasets: list[fetch_mod.Dataset], only: list[str] | None) -> list[fetch_mod.Dataset]:
    if not only:
        return datasets
    unknown = set(only) - {d.name for d in datasets}
    if unknown:
        raise KeyError(", ".join(sorted(unknown)))
    return [d for d in datasets if d.name in only]


def _fetch(manifest: Path, raw_dir: Path, only: list[str] | None) -> int:
    try:
        datasets = _select(fetch_mod.load_manifest(manifest), only)
    except KeyError as exc:
        print(f"unknown dataset(s): {exc.args[0]}", file=sys.stderr)
        return 2

    failures = 0
    for dataset in datasets:
        try:
            status = fetch_mod.fetch(dataset, raw_dir)
        except (fetch_mod.ChecksumError, OSError) as exc:
            failures += 1
            print(f"FAILED  {dataset.name}: {exc}", file=sys.stderr)
            continue
        print(f"{status:<10}  {dataset.name}  ({dataset.size_bytes / 1e6:.1f} MB)")
    print(f"{len(datasets) - failures} of {len(datasets)} datasets ready in {raw_dir}")
    return 1 if failures else 0


def _hash(files: list[Path]) -> int:
    for path in files:
        print(f"{fetch_mod.sha256_of(path)}  {path.stat().st_size:>12}  {path}")
    return 0


def _load(
    db_path: Path, manifest: Path, raw_dir: Path, interim_dir: Path, only: list[str] | None
) -> int:
    try:
        datasets = _select(fetch_mod.load_manifest(manifest), only)
    except KeyError as exc:
        print(f"unknown dataset(s): {exc.args[0]}", file=sys.stderr)
        return 2

    con = db.connect(db_path)
    try:
        load_mod.load_event_codes(con)
        total = 0
        for dataset in datasets:
            if not (raw_dir / dataset.path).exists():
                print(f"MISSING {dataset.name}: run `beacon data fetch` first", file=sys.stderr)
                return 1
            result = load_mod.load_dataset(con, dataset, raw_dir, interim_dir)
            if result is None:
                print(
                    f"skipped     {dataset.name}  ({dataset.format} is loaded with its own command)"
                )
                continue
            total += result.rows_loaded
            _print_result(result)
        print(f"{total:,} events loaded into {db_path}")
    finally:
        con.close()
    return 0


def _detect(db_path: Path, rules_dir: Path, only: list[str] | None) -> int:
    try:
        rules = detect_mod.load_rules(rules_dir)
    # ValueError covers RuleError and unreadable text; YAMLError a malformed rule.yml.
    except (ValueError, OSError, yaml.YAMLError) as exc:
        print(f"cannot load rules: {exc}", file=sys.stderr)
        return 2
    unknown = set(only or ()) - {r.rule_id for r in rules}
    if unknown:
        print(f"unknown rule(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    con = db.connect(db_path)
    try:
        for rule in rules:
            if not only or rule.rule_id in only:
                detect_mod.run_rule(con, rule)
        rows = con.execute(
            "SELECT rule_id, name, hits, precision FROM rule_performance "
            "WHERE rule_id IN (SELECT unnest($ids))",
            {"ids": [r.rule_id for r in rules if not only or r.rule_id in only]},
        ).fetchall()
    finally:
        con.close()
    for rule_id, name, hits, precision in rows:
        shown = "-" if precision is None else f"{precision:.0%}"
        print(f"{rule_id}  {name:<40} {hits:>5} alerts  precision {shown}")
    return 0


def _load_auth_log(file: Path, db_path: Path, dataset: str, year: int, tz_name: str) -> int:
    try:
        tz: tzinfo = UTC if tz_name.upper() == "UTC" else ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        print(f"unknown time zone: {tz_name}", file=sys.stderr)
        return 2
    con = db.connect(db_path)
    try:
        load_mod.load_event_codes(con)
        _print_result(load_mod.load_auth_log(con, file, dataset=dataset, year=year, tz=tz))
    finally:
        con.close()
    return 0


def _print_result(result: load_mod.LoadResult) -> None:
    offset = "" if result.ts_offset_hours is None else f", local time +{result.ts_offset_hours:g}h"
    print(
        f"loaded      {result.dataset}  {result.rows_loaded:,} events "
        f"({result.duplicates_dropped:,} duplicates, {result.rows_rejected:,} rejected{offset})"
    )
