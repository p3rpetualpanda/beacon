"""Download the public datasets listed in the manifest and verify their checksums.

Every dataset is pinned by URL and SHA-256, so a changed or tampered file is rejected
instead of silently feeding different data into detections and models.
"""

from __future__ import annotations

import hashlib
import re
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, Literal

import yaml

CHUNK_SIZE = 1 << 20
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
FORMATS = ("otrf_windows", "zeek", "linux_auth")

Opener = Callable[..., IO[bytes]]
FetchStatus = Literal["downloaded", "cached"]


class ManifestError(ValueError):
    """The manifest file is missing fields or contains unsafe values."""


class ChecksumError(RuntimeError):
    """A downloaded file does not match the size or SHA-256 recorded in the manifest."""


@dataclass(frozen=True)
class Dataset:
    name: str
    url: str
    path: str
    sha256: str
    size_bytes: int
    licence: str
    source: str
    description: str = ""
    format: str = "otrf_windows"  # otrf_windows | zeek | linux_auth
    attack_techniques: tuple[str, ...] = ()
    # Syslog lines carry no year; linux_auth datasets say which year their log starts in.
    syslog_year: int | None = None


def load_manifest(manifest_path: Path) -> list[Dataset]:
    """Read and validate the dataset manifest."""
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("datasets"), list):
        raise ManifestError(f"{manifest_path}: expected a top-level 'datasets' list")

    datasets: list[Dataset] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw["datasets"]):
        if not isinstance(entry, dict):
            raise ManifestError(f"entry {index}: expected a mapping")
        if isinstance(entry.get("attack_techniques"), list):
            entry = {**entry, "attack_techniques": tuple(entry["attack_techniques"])}
        try:
            dataset = Dataset(**entry)
        except TypeError as exc:
            raise ManifestError(f"entry {index}: {exc}") from exc
        _validate(dataset, seen)
        seen.add(dataset.name)
        datasets.append(dataset)
    return datasets


def _validate(dataset: Dataset, seen: set[str]) -> None:
    where = f"dataset {dataset.name!r}"
    if dataset.name in seen:
        raise ManifestError(f"{where}: duplicate name")
    if not SHA256_RE.fullmatch(dataset.sha256):
        raise ManifestError(f"{where}: sha256 must be 64 lowercase hex characters")
    if not isinstance(dataset.size_bytes, int) or dataset.size_bytes <= 0:
        raise ManifestError(f"{where}: size_bytes must be a positive integer")
    if dataset.format not in FORMATS:
        raise ManifestError(f"{where}: format must be one of {', '.join(FORMATS)}")
    year = dataset.syslog_year
    if dataset.format == "linux_auth" and not (type(year) is int and 1990 <= year <= 2100):
        raise ManifestError(
            f"{where}: linux_auth datasets need a syslog_year between 1990 and 2100"
        )
    if not all(TECHNIQUE_RE.fullmatch(t) for t in dataset.attack_techniques):
        raise ManifestError(f"{where}: attack_techniques must look like T1234 or T1234.001")
    # Manifest paths are POSIX-style; a backslash or drive letter (C:) could escape on Windows.
    relative = PurePosixPath(dataset.path)
    if relative.is_absolute() or ".." in relative.parts or any(c in dataset.path for c in "\\:"):
        raise ManifestError(f"{where}: path must be relative and stay inside the data directory")


def sha256_of(path: Path) -> str:
    """Return the SHA-256 of a file, read in chunks so large files stay out of memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(
    dataset: Dataset,
    raw_dir: Path,
    *,
    allowed_schemes: tuple[str, ...] = ("https",),
    opener: Opener = urllib.request.urlopen,
) -> FetchStatus:
    """Download one dataset into raw_dir, verifying size and checksum.

    A file that is already present with the right checksum is not downloaded again.
    The download goes to a temporary file first, so a failed or tampered download
    never leaves a partial or wrong file at the destination.
    """
    dest = (raw_dir / dataset.path).resolve()
    if not dest.is_relative_to(raw_dir.resolve()):
        raise ManifestError(f"dataset {dataset.name!r}: path escapes {raw_dir}")
    if dest.exists() and sha256_of(dest) == dataset.sha256:
        return "cached"

    scheme = urllib.parse.urlparse(dataset.url).scheme
    if scheme not in allowed_schemes:
        raise ManifestError(f"dataset {dataset.name!r}: URL scheme {scheme!r} is not allowed")

    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=dest.parent, suffix=".part", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        digest = _download(dataset, tmp_path, opener)
        if digest != dataset.sha256:
            raise ChecksumError(
                f"dataset {dataset.name!r}: sha256 {digest} does not match the manifest"
            )
        tmp_path.replace(dest)
    finally:
        tmp_path.unlink(missing_ok=True)
    return "downloaded"


def _download(dataset: Dataset, target: Path, opener: Opener) -> str:
    digest = hashlib.sha256()
    received = 0
    # The URL scheme is checked against an allow-list in fetch() before this runs.
    with opener(dataset.url, timeout=60) as response, target.open("wb") as out:  # nosec B310
        while chunk := response.read(CHUNK_SIZE):
            received += len(chunk)
            if received > dataset.size_bytes:
                raise ChecksumError(
                    f"dataset {dataset.name!r}: download is larger than the expected "
                    f"{dataset.size_bytes} bytes"
                )
            digest.update(chunk)
            out.write(chunk)
    if received != dataset.size_bytes:
        raise ChecksumError(
            f"dataset {dataset.name!r}: received {received} bytes, expected {dataset.size_bytes}"
        )
    return digest.hexdigest()
