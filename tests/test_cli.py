from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from beacon import __version__, cli
from beacon.ingest import fetch as fetch_mod

MANIFEST = """datasets:
  - name: alpha
    url: https://example.com/alpha.zip
    path: alpha.zip
    sha256: {sha}
    size_bytes: 1000000
    licence: MIT
    source: test
  - name: beta
    url: https://example.com/beta.zip
    path: beta.zip
    sha256: {sha}
    size_bytes: 2000000
    licence: MIT
    source: test
""".format(sha="a" * 64)


@pytest.fixture
def manifest(tmp_path: Path) -> Path:
    path = tmp_path / "manifest.yml"
    path.write_text(MANIFEST, encoding="utf-8")
    return path


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert __version__ in capsys.readouterr().out


def test_hash_prints_sha256_and_size(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "f.bin"
    path.write_bytes(b"beacon")

    assert cli.main(["data", "hash", str(path)]) == 0
    out = capsys.readouterr().out
    assert hashlib.sha256(b"beacon").hexdigest() in out
    assert " 6 " in out


def test_fetch_reports_each_dataset(
    manifest: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []

    def fake_fetch(dataset: fetch_mod.Dataset, raw_dir: Path) -> str:
        calls.append(dataset.name)
        return "downloaded"

    monkeypatch.setattr(fetch_mod, "fetch", fake_fetch)

    code = cli.main(["data", "fetch", "--manifest", str(manifest), "--raw-dir", str(tmp_path)])
    assert code == 0
    assert calls == ["alpha", "beta"]
    assert "2 of 2 datasets ready" in capsys.readouterr().out


def test_fetch_only_filters_and_rejects_unknown_names(
    manifest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def fake_fetch(dataset: fetch_mod.Dataset, raw_dir: Path) -> str:
        calls.append(dataset.name)
        return "cached"

    monkeypatch.setattr(fetch_mod, "fetch", fake_fetch)

    base = ["data", "fetch", "--manifest", str(manifest), "--raw-dir", str(tmp_path)]
    assert cli.main([*base, "--only", "beta"]) == 0
    assert calls == ["beta"]
    assert cli.main([*base, "--only", "gamma"]) == 2


def test_fetch_returns_failure_on_checksum_error(
    manifest: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def failing_fetch(dataset: fetch_mod.Dataset, raw_dir: Path) -> str:
        raise fetch_mod.ChecksumError("bad hash")

    monkeypatch.setattr(fetch_mod, "fetch", failing_fetch)

    code = cli.main(["data", "fetch", "--manifest", str(manifest), "--raw-dir", str(tmp_path)])
    assert code == 1
    assert "FAILED" in capsys.readouterr().err
