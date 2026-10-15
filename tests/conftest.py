from __future__ import annotations

import zipfile
from collections.abc import Iterator
from pathlib import Path

import duckdb
import pytest

from beacon.db import connect
from beacon.ingest.fetch import Dataset
from beacon.load import load_event_codes

DATA = Path(__file__).parent / "data"
APT29_SAMPLE = DATA / "apt29_day1_sample.json"
LSASS_SAMPLE = DATA / "lsass_dump_comsvcs.json"
AUTH_SAMPLE = DATA / "auth_sample.log"


@pytest.fixture
def con() -> Iterator[duckdb.DuckDBPyConnection]:
    connection = connect(":memory:")
    load_event_codes(connection)
    yield connection
    connection.close()


def make_dataset(name: str = "sample", **overrides: object) -> Dataset:
    fields: dict[str, object] = {
        "name": name,
        "url": "https://example.com/sample.zip",
        "path": f"otrf/{name}.zip",
        "sha256": "0" * 64,
        "size_bytes": 1,
        "licence": "MIT",
        "source": "OTRF Security-Datasets",
        "attack_techniques": ("T1003.001",),
    }
    fields.update(overrides)
    return Dataset(**fields)  # type: ignore[arg-type]


def zip_json(source: Path, archive: Path, member: str = "events.json") -> Path:
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(source, member)
    return archive
