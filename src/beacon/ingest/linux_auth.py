"""Parse SSH authentication events from a Linux auth.log.

Handles both the classic syslog prefix (`Oct 15 14:02:11 host sshd[812]: ...`), which has
no year or time zone, and the RFC 3339 prefix newer rsyslog and journald exports write
(`2026-10-15T14:02:11.123456+01:00 host sshd[812]: ...`). Every timestamp is converted to UTC.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo

SYSLOG_PREFIX = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: "
    r"(?P<msg>.*)$"
)
RFC3339_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})) "
    r"(?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<msg>.*)$"
)
IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
PORT = r"(?: port (?P<port>\d+))?"
MESSAGES: list[tuple[str, re.Pattern[str]]] = [
    (
        "ssh_login_failure",
        re.compile(rf"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*?) from {IP}{PORT}"),
    ),
    (
        "ssh_login_success",
        re.compile(rf"^Accepted (?P<method>\S+) for (?P<user>.*?) from {IP}{PORT}"),
    ),
    ("ssh_invalid_user", re.compile(rf"^Invalid user (?P<user>.*?) from {IP}{PORT}")),
]


@dataclass(frozen=True)
class AuthEvent:
    event_id: str
    ts: datetime  # naive, UTC
    event_code: str
    host_name: str
    process_id: int
    user_name: str
    src_ip: str
    src_port: int | None
    auth_method: str | None
    raw: str


def parse_lines(lines: Iterable[str], *, year: int, tz: tzinfo = UTC) -> Iterator[AuthEvent]:
    """Yield the SSH events in lines; other lines are skipped.

    year and tz apply only to syslog-prefixed lines, which carry neither. When a syslog
    timestamp jumps backwards by more than six months (December to January) the year rolls on.
    """
    current_year = year
    previous: datetime | None = None
    for line in lines:
        line = line.rstrip("\r\n")
        prefix = RFC3339_PREFIX.match(line)
        if prefix:
            ts = datetime.fromisoformat(prefix["ts"].replace("Z", "+00:00"))
        else:
            prefix = SYSLOG_PREFIX.match(line)
            if not prefix:
                continue
            local = _syslog_time(prefix["ts"], current_year)
            if previous is not None and (previous - local).days > 183:
                current_year += 1
                local = _syslog_time(prefix["ts"], current_year)
            previous = local
            ts = local.replace(tzinfo=tz)
        event = _parse_message(prefix["msg"])
        if event is None:
            continue
        code, fields = event
        ts_utc = ts.astimezone(UTC).replace(tzinfo=None)
        host = prefix["host"].lower()
        yield AuthEvent(
            event_id=hashlib.md5(
                f"{host}|{ts_utc.isoformat()}|{prefix['pid']}|{prefix['msg']}".encode(),
                usedforsecurity=False,
            ).hexdigest(),
            ts=ts_utc,
            event_code=code,
            host_name=host,
            process_id=int(prefix["pid"]),
            user_name=fields["user"].lower(),
            src_ip=fields["ip"],
            src_port=int(fields["port"]) if fields.get("port") else None,
            auth_method=fields.get("method"),
            raw=line,
        )


def _syslog_time(text: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")


def _parse_message(message: str) -> tuple[str, dict[str, str]] | None:
    for code, pattern in MESSAGES:
        match = pattern.match(message)
        if match:
            return code, {k: v for k, v in match.groupdict().items() if v is not None}
    return None
