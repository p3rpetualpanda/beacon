"""DuckDB connection and schema setup."""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path

import duckdb

DEFAULT_DB = Path("data/beacon.duckdb")
MAX_THREADS = 8


def read_sql(name: str) -> str:
    """Read a SQL file shipped inside the beacon.normalise package."""
    return resources.files("beacon.normalise").joinpath(name).read_text(encoding="utf-8")


def connect(path: Path | str = DEFAULT_DB) -> duckdb.DuckDBPyConnection:
    """Open (or create) the Beacon database and make sure every table exists."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(path))
    # One thread per core (32 on a desktop) made the Windows load need over 25 GB; 8 fits easily.
    con.execute(f"SET threads = {min(os.cpu_count() or 1, MAX_THREADS)}")
    con.execute(read_sql("schema.sql"))
    return con
