# Beacon

A small, open-source security analytics pipeline (a mini-SIEM). Beacon ingests
real attack logs from public datasets, detects attacker behaviour with SQL rules
mapped to [MITRE ATT&CK](https://attack.mitre.org/), scores unusual activity with
machine learning, and reports the results on a SOC dashboard.

> **Status:** early development. Beacon downloads the datasets and loads 882,537 Windows
> and network events into one normalised table; detections and dashboards follow (see the roadmap).

## Quick start

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```bash
make install   # create the virtual environment and install dependencies
make check     # lint, type-check, security scan and tests
make data      # download the pinned public datasets into data/raw/ and verify checksums
make load      # normalise them into data/beacon.duckdb (about 3 minutes)
make quality   # data-quality checks on the full database
make detect    # run the detection rules; prints alerts and precision per rule
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
| **Total** | **882,537** | **1,731** | |

## Roadmap

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Repo, tooling, CI, dataset downloader | Done |
| 1 | Parsers and a normalised `events` table in DuckDB | Done |
| 2 | 12 ATT&CK-mapped SQL detections with KQL equivalents; dashboard v1 | In progress |
| 3 | Zeek network logs, 8 more detections, investigation pages | Planned |
| 4 | Anomaly detection (robust z-score, Isolation Forest, LOF) and risk scoring | Planned |
| 5 | Power BI report, incident report, Docker, demo | Planned |

## Data

Beacon does not redistribute any dataset. `make data` downloads them from their
original sources at a pinned commit and checks each file's SHA-256. See
[data/README.md](data/README.md) for sources and licences.

## Licence

MIT. Datasets keep their own licences.
