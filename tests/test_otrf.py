from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path

import pytest

from beacon.ingest.otrf import ArchiveError, extract_json
from tests.conftest import LSASS_SAMPLE, zip_json


def test_extracts_the_json_member(tmp_path: Path) -> None:
    archive = zip_json(LSASS_SAMPLE, tmp_path / "a.zip")
    dest = extract_json(archive, tmp_path / "out" / "a.json")
    assert dest.read_bytes() == LSASS_SAMPLE.read_bytes()


def test_reuses_an_up_to_date_extract(tmp_path: Path) -> None:
    archive = zip_json(LSASS_SAMPLE, tmp_path / "a.zip")
    dest = tmp_path / "a.json"
    dest.write_text("already here")
    os.utime(dest, (archive.stat().st_mtime + 10,) * 2)
    assert extract_json(archive, dest).read_text() == "already here"


def test_ignores_macos_resource_forks(tmp_path: Path) -> None:
    archive = zip_json(LSASS_SAMPLE, tmp_path / "a.zip")
    with zipfile.ZipFile(archive, "a") as zf:
        zf.writestr("__MACOSX/._events.json", b"junk")
    assert extract_json(archive, tmp_path / "a.json").stat().st_size == LSASS_SAMPLE.stat().st_size


@pytest.mark.parametrize("names", [[], ["one.json", "two.json"]])
def test_rejects_archives_without_exactly_one_json(tmp_path: Path, names: list[str]) -> None:
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("readme.txt", b"hi")
        for name in names:
            zf.writestr(name, b"{}")
    with pytest.raises(ArchiveError, match="expected one JSON file"):
        extract_json(archive, tmp_path / "a.json")


@pytest.mark.parametrize("name", ["../evil.json", "/abs/evil.json", "dir\\evil.json"])
def test_rejects_unsafe_member_names(tmp_path: Path, name: str) -> None:
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(name, b"{}")
    with pytest.raises(ArchiveError, match="unsafe member name"):
        extract_json(archive, tmp_path / "a.json")


def test_rejects_symlinks(tmp_path: Path) -> None:
    archive = tmp_path / "a.zip"
    info = zipfile.ZipInfo("link.json")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(ArchiveError, match="symbolic link"):
        extract_json(archive, tmp_path / "a.json")


def test_rejects_zip_bombs(tmp_path: Path) -> None:
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.json", b"0" * 5_000_000)
    with pytest.raises(ArchiveError, match="suspicious ratio"):
        extract_json(archive, tmp_path / "a.json")
    assert not (tmp_path / "a.json").exists()
