# Decisions log

Short records of design choices and why they were made, newest first.

## 2026-10-16: Load the APT29 Zeek logs as their own records

OTRF ships every Zeek log type for a day in one JSON file. Each record becomes one `events` row
with source `zeek` and the log type (`conn`, `dns`, `http`, ...) as `event_code`; IPs, ports,
protocol and DNS query go in the usual columns and everything else stays in `raw`. Zeek's own
housekeeping logs (`loaded_scripts`, `stats`, `capture_loss`, `packet_filter`, `reporter`)
describe the sensor, not the network, and are counted as rejected.

The Zeek captures do not overlap the host logs in time: day 1's network log covers
2020-04-30 00:06-00:45 UTC and day 2's 2020-05-01 07:02-07:34, while the
host logs are from 2020-05-02 02:55-08:29. They look like a separate run of the same emulation,
so network and host events can't be joined into one timeline; network rules use them alone.

**Why:** network rules (DNS tunnelling, beaconing, port scans) need real traffic, and keeping
one row per Zeek record means a rule can always point at its exact evidence.

## 2026-10-16: Detection rules as folders of SQL, KQL and test events

Each rule is a folder under `detections/` holding `rule.yml` (ID, ATT&CK technique, severity),
`rule.sql` (a SELECT over `events`), `rule.kql` (the same logic for Microsoft Sentinel) and two
small JSON-lines files of events: one the rule must fire on and one it must stay quiet on.
`beacon detect` writes hits to `alerts`, keyed by a hash of the rule and its evidence, so
re-running a rule keeps each alert's triage status. An alert the rule no longer produces is
removed only while it is still `new`; a triaged one is kept, even if a reload changed its
evidence and the rule now raises a fresh alert beside it.

Threshold rules (R02, R16, R20) alert when a sliding-window count first reaches the threshold.
A long attack whose rate dips below it and recovers raises a second alert; that is accepted
for now rather than adding session logic.

Process rules count a launch once: when Sysmon 1 and Security 4688 both record the same command
line on the same host within 5 seconds, only the Sysmon record alerts.

Precision in `rule_performance` counts a hit as a true positive when its dataset is documented
to contain the rule's technique (or its parent or a sub-technique). The datasets have no
per-event attack labels, so this is an approximation: it can't tell a real attack from noise
inside an attack dataset, and it depends on the manifest's technique lists being complete.

**Why:** one folder per rule keeps the logic, the Sentinel version and the proof together,
and tests run every rule against known-good and known-bad events on every push. The KQL is
written by hand and not run, because Beacon has no Sentinel workspace.

## 2026-10-16: Drop datasets that Windows Defender quarantines

Defender flags `dcsync_empire`, `net_localgroup_admins` and `schtasks_empire` as malware,
because they are real attack logs carrying Empire's encoded PowerShell payloads. Each dataset
was loaded once on Windows with Defender on; the four that raised no detection are kept.
Seven more OTRF atomic datasets that don't use Empire (PurpleSharp, Covenant, Dumpert, Task
Manager, sc.exe and remote schtasks) were downloaded and loaded the same way, one at a time,
and all seven stayed clean.
Beacon no longer downloads the three flagged ones; rules they would have exercised are covered
by test events and the APT29 data instead.

**Why:** the project must run on a normal Windows PC without weakening its antivirus.

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

Some later OTRF exports write `TimeCreated` as ISO text ending in `Z` even though it is
local time: their Sysmon `UtcTime` is 5 hours later (remote schtasks) or 16 hours later (the
fax service). The loader parses that form too and lets the Sysmon gap set the offset, rather
than trusting the `Z`.

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
