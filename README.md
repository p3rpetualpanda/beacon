# Beacon

A small, open-source security analytics pipeline (a mini-SIEM). Beacon ingests
real attack logs from public datasets, detects attacker behaviour with SQL rules
mapped to [MITRE ATT&CK](https://attack.mitre.org/), scores unusual activity with
machine learning, and reports the results on a SOC dashboard.

> **Status:** Phase 2 done; Phase 3 next. Beacon loads 1,058,365 Windows, network and SSH events
> into one normalised table, runs 12 ATT&CK-mapped detection rules over them, and shows the
> alerts on a SOC dashboard (see the roadmap).

## Quick start

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```bash
make install   # create the virtual environment and install dependencies
make check     # lint, type-check, security scan and tests
make data      # download the pinned public datasets into data/raw/ and verify checksums
make load      # normalise them into data/beacon.duckdb (a few minutes)
make quality   # data-quality checks on the full database
make detect    # run the detection rules; prints alerts and precision per rule
make dashboard # SOC dashboard at http://localhost:8501 (overview and alert queue)
```

SSH logins from a Linux server can be loaded too:

```bash
uv run beacon load-auth-log /var/log/auth.log --year 2026 --tz Europe/London
```

## The `events` table

Every source is mapped to one table, `events`, with field names based on the
[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html): `ts` (always
UTC), `host_name`, `user_name`, `process_name`, `process_command_line`, `src_ip`, `dst_ip`,
`event_category`, `event_outcome` and so on, plus the original record in `raw`. The full
definition is in [`schema.sql`](src/beacon/normalise/schema.sql).

Each load also writes a row to `data_quality` saying how many records were read, rejected and
de-duplicated, the time range, and how much of each key field is empty:

| Dataset | Events | Duplicates dropped | Local clock |
| --- | ---: | ---: | --- |
| APT29 day 1 | 196,081 | 0 | UTC−4 |
| APT29 day 2 | 585,655 | 1,631 | UTC−4 |
| Four Empire atomic attack datasets | 51,475 | 9 | UTC−4 |
| Seven other OTRF atomic datasets (PurpleSharp, Covenant, built-in tools) | 44,498 | 91 | inferred per file |
| APT29 Zeek network logs (days 1 and 2) | 4,828 | 0 | UTC |
| Loghub OpenSSH server log (real SSH brute-force attempts) | 175,828 | 0 | assumed UTC |
| **Total** | **1,058,365** | **1,731** | |

Known gaps in the data (measured 2026-11-01): `user_name` is empty on most rows, because many event types carry no account (Sysmon file, registry and network events, Zeek, system services). Rules that need a user filter on it being set. Windows account names are lower-cased with any `DOMAIN\` prefix or `@domain` suffix removed. `data_quality` keeps one row per load; use the `data_quality_latest` view for the current state.

## Detections

Each rule lives in [`detections/`](detections/) as SQL over `events`, a hand-written Microsoft
Sentinel KQL version, and two sets of test events: one it must fire on, one it must stay quiet
on. CI runs every rule against both. `make detect` writes hits to `alerts` and prints, per rule:

| Rule | ATT&CK | Alerts on the full data | Precision | Analyst verdicts |
| --- | --- | ---: | ---: | ---: |
| R01 Brute force then success | T1110.001 | 0 | – | 0 |
| R02 Password spraying | T1110.003 | 0 | – | 0 |
| R03 LSASS memory access | T1003.001 | 12 | 100% | 0 |
| R05 Encoded PowerShell | T1059.001 | 9 | 100% | 3 |
| R06 Office app spawns a shell | T1204.002 | 0 | – | 0 |
| R07 Scheduled task created | T1053.005 | 2 | 100% | 0 |
| R08 New service from a user-writable path | T1543.003 | 0 | – | 0 |
| R09 Run key persistence | T1547.001 | 2 | 100% | 1 |
| R12 Security log cleared | T1070.001 | 3 | 0% | 3 |
| R13 New local admin | T1136.001 | 0 | – | 0 |
| R16 Discovery burst | T1087.002 | 1 | 0% | 1 |
| R20 SSH brute force (Linux) | T1110.001 | 515 | 100% | 0 |

Precision uses an analyst's verdict where there is one, and otherwise counts a hit as true when
its dataset is documented to contain the rule's technique (the data has no per-event attack
labels). Verdicts are reviewed by hand and kept in
[`detections/verdicts.csv`](detections/verdicts.csv), each with its reason, so `make detect` on
a freshly built database gives the same numbers. `beacon export-verdicts` copies verdicts saved
in the dashboard into that file. On an existing database a verdict already saved wins over the
file, and `make detect` lists any that differ. R12's three alerts are the lab clearing its logs in the first second
of each recording, and R16's is a Windows diagnostics collector, so both score 0% on this data.
Rules at zero have no matching behaviour in the data yet; their test events show they work.
See [docs/decisions.md](docs/decisions.md).

## Dashboard

`make dashboard` starts a Streamlit app on your machine only (localhost:8501). It installs the
optional `dashboard` dependency group on first run, so CI and `make check` stay light.

- **Overview:** alert and event totals, alerts by severity and status, the noisiest rules with
  their precision, and the events loaded per dataset.
- **Alert queue:** alerts newest first, filtered by status and rule. Selecting one shows its
  evidence events and lets an analyst record a verdict (new, triaged, true positive, false
  positive or closed).

The dashboard opens the database read-only, so `make quality` and other readers work while it
runs. It is meant for one analyst at a time. Saving a verdict briefly needs the database to itself, so it fails with a message while
another program has it open. Stop the dashboard before `make load` or `make detect`, which
need to write.

## Exporting findings

`make export` (or `beacon export-alerts [--out PATH] [--only R01 R05]`) writes every alert as an
[OCSF](https://schema.ocsf.io) Detection Finding, one JSON object per line, to
`exports/findings.jsonl`. The format is defined by
[contracts/detection-finding-v1.schema.json](contracts/detection-finding-v1.schema.json), and the
tests check every rule's alerts against it. The file is byte-identical when the database has not
changed. On the full database it holds 544 findings (2.4 MB), all valid, with at most 10 evidence
events each. ThreatLens ingests this file.

## Roadmap

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Repo, tooling, CI, dataset downloader | Done |
| 1 | Parsers and a normalised `events` table in DuckDB | Done |
| 2 | 12 ATT&CK-mapped SQL detections with KQL equivalents; dashboard v1 | Done |
| 3 | Zeek network logs, 8 more detections, investigation pages | Zeek logs loaded; rules and pages to do |
| 4 | Anomaly detection (robust z-score, Isolation Forest, LOF) and risk scoring | Planned |
| 5 | Power BI report, incident report, Docker, demo | Planned |

### Still to do

- **Phase 3:** rules R04, R10, R11, R14, R15, R17, R18 and R19 (the network rules can use the
  Zeek logs, which don't overlap the host logs in time), plus investigation and ATT&CK
  coverage pages.
- **Phases 4 and 5:** as in the table above.

## Data

Beacon does not redistribute any dataset. `make data` downloads them from their
original sources at a pinned commit or archive record and checks each file's SHA-256. See
[data/README.md](data/README.md) for sources and licences.

## Licence

MIT. Datasets keep their own licences.
