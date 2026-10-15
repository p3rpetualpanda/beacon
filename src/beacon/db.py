"""DuckDB connection and schema setup."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import duckdb

DEFAULT_DB = Path("data/beacon.duckdb")


def read_sql(name: str) -> str:
    """Read a SQL file shipped inside the beacon.normalise package."""
    return resources.files("beacon.normalise").joinpath(name).read_text(encoding="utf-8")


def connect(path: Path | str = DEFAULT_DB) -> duckdb.DuckDBPyConnection:
    """Open (or create) the Beacon database and make sure every table exists."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(path))
    con.execute(read_sql("schema.sql"))
    return con
