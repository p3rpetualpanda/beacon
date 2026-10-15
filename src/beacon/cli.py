"""Command-line entry point: `beacon <command>`."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from beacon import __version__
from beacon.ingest import fetch as fetch_mod

DEFAULT_MANIFEST = Path("data/manifest.yml")
DEFAULT_RAW_DIR = Path("data/raw")


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.data_command == "fetch":
        return _fetch(args.manifest, args.raw_dir, args.only)
    return _hash(args.files)


def _fetch(manifest: Path, raw_dir: Path, only: list[str] | None) -> int:
    datasets = fetch_mod.load_manifest(manifest)
    if only:
        unknown = set(only) - {d.name for d in datasets}
        if unknown:
            print(f"unknown dataset(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        datasets = [d for d in datasets if d.name in only]

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
