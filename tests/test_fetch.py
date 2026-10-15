from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from beacon.ingest.fetch import (
    ChecksumError,
    Dataset,
    ManifestError,
    fetch,
    load_manifest,
    sha256_of,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def make_dataset(source: Path, **overrides: object) -> Dataset:
    content = source.read_bytes()
    fields: dict[str, object] = {
        "name": "sample",
        "url": source.as_uri(),
        "path": "sample/events.json",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
        "licence": "MIT",
        "source": "test",
    }
    fields.update(overrides)
    return Dataset(**fields)  # type: ignore[arg-type]


@pytest.fixture
def source_file(tmp_path: Path) -> Path:
    path = tmp_path / "source.json"
    path.write_bytes(b'{"EventID": 4625}\n' * 1000)
    return path


def test_fetch_downloads_and_verifies(source_file: Path, tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    dataset = make_dataset(source_file)

    assert fetch(dataset, raw, allowed_schemes=("file",)) == "downloaded"
    assert sha256_of(raw / dataset.path) == dataset.sha256


def test_fetch_skips_file_that_is_already_valid(source_file: Path, tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    dataset = make_dataset(source_file)
    fetch(dataset, raw, allowed_schemes=("file",))

    def no_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("should not download again")

    assert fetch(dataset, raw, allowed_schemes=("file",), opener=no_network) == "cached"  # type: ignore[arg-type]


def test_checksum_mismatch_leaves_no_file(source_file: Path, tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    dataset = make_dataset(source_file, sha256="0" * 64)

    with pytest.raises(ChecksumError, match="does not match"):
        fetch(dataset, raw, allowed_schemes=("file",))
    assert list(raw.rglob("*.*")) == []


def test_oversized_download_is_aborted(source_file: Path, tmp_path: Path) -> None:
    dataset = make_dataset(source_file, size_bytes=10)

    with pytest.raises(ChecksumError, match="larger than"):
        fetch(dataset, tmp_path / "raw", allowed_schemes=("file",))


def test_truncated_download_is_rejected(source_file: Path, tmp_path: Path) -> None:
    dataset = make_dataset(source_file, size_bytes=source_file.stat().st_size + 1)

    with pytest.raises(ChecksumError, match="expected"):
        fetch(dataset, tmp_path / "raw", allowed_schemes=("file",))


def test_non_https_url_is_refused_by_default(source_file: Path, tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="scheme"):
        fetch(make_dataset(source_file), tmp_path / "raw")


def test_path_traversal_is_refused(source_file: Path, tmp_path: Path) -> None:
    dataset = make_dataset(source_file, path="../../escape.json")

    with pytest.raises(ManifestError, match="escapes"):
        fetch(dataset, tmp_path / "raw", allowed_schemes=("file",))


def write_manifest(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "manifest.yml"
    path.write_text(body, encoding="utf-8")
    return path


VALID_ENTRY = """
  - name: one
    url: https://example.com/one.zip
    path: one.zip
    sha256: {sha}
    size_bytes: 10
    licence: MIT
    source: test
"""


def test_load_manifest_reads_entries(tmp_path: Path) -> None:
    manifest = write_manifest(tmp_path, "datasets:" + VALID_ENTRY.format(sha="a" * 64))

    [dataset] = load_manifest(manifest)
    assert dataset.name == "one"
    assert dataset.size_bytes == 10


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("nothing: here", "datasets"),
        ("datasets:" + VALID_ENTRY.format(sha="XYZ"), "sha256"),
        ("datasets:" + VALID_ENTRY.format(sha="a" * 64) * 2, "duplicate"),
        ("datasets:" + VALID_ENTRY.format(sha="a" * 64).replace("one.zip\n", "/etc/x\n"), "path"),
        ("datasets:\n  - name: only-a-name\n", "entry 0"),
    ],
)
def test_load_manifest_rejects_bad_entries(tmp_path: Path, body: str, message: str) -> None:
    with pytest.raises(ManifestError, match=message):
        load_manifest(write_manifest(tmp_path, body))


def test_project_manifest_is_valid_and_pinned() -> None:
    datasets = load_manifest(REPO_ROOT / "data" / "manifest.yml")

    assert datasets
    for dataset in datasets:
        assert dataset.url.startswith("https://")
        # Pinned to a 40-character commit SHA, never a moving branch like "master".
        assert re.search(r"/[0-9a-f]{40}/", dataset.url), dataset.name
