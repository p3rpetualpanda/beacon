# Decisions log

Short records of design choices and why they were made, newest first.

## 2026-10-15: Infer each dataset's clock offset from the data

NXLog wrote `EventTime` in the lab's local time with no time zone. Sysmon records also carry
`UtcTime`, so the loader takes the median gap between the two in each file, rounds it to 15
minutes, and adds it to every record that has only local time. Files with no Sysmon fall back
to NXLog's own UTC `@timestamp` against its local `EventReceivedTime`.

This gives +4 hours (US Eastern daylight time) for every file except the LSASS dump, whose
Security events use `TimeCreated` on a 12-hour clock with no AM or PM. There the inferred
offset is +16 hours, which lines those events up with the file's Sysmon events. A quality
check confirms that, on every host, Security and Sysmon events start within ten minutes of
each other.

**Why:** a hard-coded time zone would silently misplace any dataset recorded somewhere else,
and detections that join events across sources (a logon followed by a process) depend on
the clocks agreeing.

## 2026-10-15: De-duplicate on host, channel and record number

`event_id` is a hash of the host, the lower-cased channel and the Windows `RecordNumber`,
which Windows assigns once per event. The APT29 day 2 export contains 1,631 records that the
collector shipped twice and the LSASS file 9; they are dropped and counted in `data_quality`.
Channel names are lower-cased because the same log appears as both "Security" and "security".

**Why:** duplicated events would inflate alert counts and skew the anomaly baselines.
Reloading a dataset deletes and replaces its rows, so the table is the same however often it
is rebuilt.

## 2026-10-15: Repair known collector errors instead of dropping records

- Three Sysmon records reached NXLog unparsed, with their fields only in the `Message`
  text. One is the APT29 hidden PowerShell stager. The loader recovers the fields from the
  message and flags the record with `BeaconFieldsFromMessage`.
- The APT29 export decoded some UTF-8 as Windows-1252, turning the right-to-left override
  character (U+202E) used to disguise `cod.3aka3.scr` into "â€®". The loader restores U+202E
  so a detection can look for it.
- Sysmon's `AccountName` is always the Sysmon service (SYSTEM), so the user comes from
  Sysmon's `User` field instead.

**Why:** each of these would hide exactly the attacker activity Beacon exists to find.

## 2026-10-15: Pin datasets by commit and SHA-256

Datasets are downloaded from their original sources, never committed. Each manifest entry
pins a URL to a specific commit and records the file's SHA-256 and size. The downloader
writes to a temporary file and only moves it into place once the checksum matches.

**Why:** reproducible results (the data cannot change underneath a detection or model), no
licence questions from redistributing data, and protection against a tampered or truncated
download being analysed as if it were real.

## 2026-10-15: DuckDB as the storage and query engine

**Why:** real SQL over millions of rows on a laptop with no server, and it reads JSON and
Parquet directly. The SQL stays close to standard, so moving to Postgres or a cloud warehouse
later is mostly a connection change.

## 2026-10-15: Normalise every source to an ECS-style `events` table

All log sources (Sysmon, Windows Security, Zeek, Linux auth) are mapped to one table with
field names based on the Elastic Common Schema.

**Why:** detections are written once and work across sources, and the schema follows an
industry standard rather than an invented one.

## 2026-10-15: OTRF Security-Datasets as the primary data source

**Why:** real attack activity recorded in a lab, already in JSON lines, labelled with MITRE
ATT&CK techniques, MIT-licensed, and small (about 66 MB for everything Beacon uses). The
APT29 evaluation set includes both Windows host logs and Zeek network logs for the same
intrusion.
