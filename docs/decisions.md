# Decisions log

Short records of design choices and why they were made, newest first.

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
