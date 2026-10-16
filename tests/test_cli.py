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


LOAD_MANIFEST = """datasets:
  - name: lsass
    url: https://example.com/lsass.zip
    path: otrf/lsass.zip
    sha256: {sha}
    size_bytes: 1
    licence: MIT
    source: test
    attack_techniques: [T1003.001]
  - name: zeek
    url: https://example.com/zeek.log
    path: otrf/zeek.log
    sha256: {sha}
    size_bytes: 1
    licence: MIT
    source: test
    format: zeek
""".format(sha="a" * 64)


@pytest.fixture
def load_env(tmp_path: Path) -> dict[str, Path]:
    from tests.conftest import LSASS_SAMPLE, ZEEK_SAMPLE, zip_json

    manifest = tmp_path / "manifest.yml"
    manifest.write_text(LOAD_MANIFEST, encoding="utf-8")
    raw = tmp_path / "raw"
    zip_json(LSASS_SAMPLE, raw / "otrf" / "lsass.zip")
    (raw / "otrf" / "zeek.log").write_bytes(ZEEK_SAMPLE.read_bytes())
    return {"manifest": manifest, "raw": raw, "db": tmp_path / "beacon.duckdb", "tmp": tmp_path}


def _load_args(env: dict[str, Path], *extra: str) -> list[str]:
    return [
        "load",
        "--db",
        str(env["db"]),
        "--manifest",
        str(env["manifest"]),
        "--raw-dir",
        str(env["raw"]),
        "--interim-dir",
        str(env["tmp"] / "interim"),
        *extra,
    ]


def test_load_command(load_env: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(_load_args(load_env)) == 0
    out = capsys.readouterr().out
    assert "lsass  175 events (9 duplicates, 0 rejected, local time +16h)" in out
    assert "zeek  15 events (1 duplicates, 1 rejected)" in out
    assert "190 events loaded" in out


def test_load_unknown_dataset(
    load_env: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(_load_args(load_env, "--only", "nope")) == 2
    assert "unknown dataset(s): nope" in capsys.readouterr().err


def test_load_missing_download(
    load_env: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    (load_env["raw"] / "otrf" / "lsass.zip").unlink()
    assert cli.main(_load_args(load_env, "--only", "lsass")) == 1
    assert "beacon data fetch" in capsys.readouterr().err


def test_load_auth_log_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from tests.conftest import AUTH_SAMPLE

    db_path = str(tmp_path / "b.duckdb")
    args = ["load-auth-log", str(AUTH_SAMPLE), "--db", db_path, "--year", "2025"]
    assert cli.main([*args, "--tz", "Europe/London"]) == 0
    assert "linux_auth  5 events (1 duplicates" in capsys.readouterr().out
    assert cli.main([*args, "--tz", "Mars/Olympus"]) == 2
    assert "unknown time zone" in capsys.readouterr().err
