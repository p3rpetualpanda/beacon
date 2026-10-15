"""Unpack OTRF Security-Datasets archives.

Each OTRF zip holds one JSON-lines file of Windows events exported by NXLog. Archives are
untrusted input, so extraction refuses absolute or `..` member names, links, and members
whose uncompressed size is far larger than a log export should be (a zip bomb guard).
"""

from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath
from typing import IO

MAX_UNCOMPRESSED_BYTES = 4 * 1024**3
MAX_COMPRESSION_RATIO = 200


class ArchiveError(ValueError):
    """The archive does not look like a single-file OTRF dataset, or is unsafe to extract."""


def extract_json(archive: Path, dest: Path) -> Path:
    """Extract the single JSON member of an OTRF zip to dest and return dest.

    An existing dest that is newer than the archive is reused.
    """
    if dest.exists() and dest.stat().st_mtime >= archive.stat().st_mtime:
        return dest

    with zipfile.ZipFile(archive) as zf:
        members = [m for m in zf.infolist() if not m.is_dir() and _is_data_member(m.filename)]
        if len(members) != 1:
            names = ", ".join(m.filename for m in members) or "none"
            raise ArchiveError(f"{archive}: expected one JSON file, found {names}")
        member = members[0]
        _check_member(archive, member)

        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        try:
            with zf.open(member) as src, tmp.open("wb") as out:
                copied = _copy_limited(src, out, member.file_size)
            if copied != member.file_size:
                raise ArchiveError(f"{archive}: {member.filename} is truncated")
            tmp.replace(dest)
        finally:
            tmp.unlink(missing_ok=True)
    return dest


def _is_data_member(name: str) -> bool:
    path = PurePosixPath(name)
    # macOS adds __MACOSX/ resource forks to some archives; they are not data.
    return "__MACOSX" not in path.parts and path.suffix.lower() == ".json"


def _check_member(archive: Path, member: zipfile.ZipInfo) -> None:
    path = PurePosixPath(member.filename)
    if path.is_absolute() or ".." in path.parts or "\\" in member.filename:
        raise ArchiveError(f"{archive}: unsafe member name {member.filename!r}")
    is_symlink = (member.external_attr >> 16) & 0o170000 == 0o120000
    if is_symlink:
        raise ArchiveError(f"{archive}: member {member.filename!r} is a symbolic link")
    if member.file_size > MAX_UNCOMPRESSED_BYTES:
        raise ArchiveError(f"{archive}: member {member.filename!r} is too large")
    if member.compress_size and member.file_size / member.compress_size > MAX_COMPRESSION_RATIO:
        raise ArchiveError(f"{archive}: member {member.filename!r} has a suspicious ratio")


def _copy_limited(src: IO[bytes], out: IO[bytes], limit: int) -> int:
    """Copy at most limit bytes, failing if the stream holds more than it declared."""
    copied = 0
    while chunk := src.read(1 << 20):
        copied += len(chunk)
        if copied > limit:
            raise ArchiveError("archive member is larger than its declared size")
        out.write(chunk)
    return copied
