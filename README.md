# Beacon

A small, open-source security analytics pipeline (a mini-SIEM). Beacon ingests
real attack logs from public datasets, detects attacker behaviour with SQL rules
mapped to [MITRE ATT&CK](https://attack.mitre.org/), scores unusual activity with
machine learning, and reports the results on a SOC dashboard.

> **Status:** early development. The project skeleton and dataset downloader are in
> place; ingestion, detections and dashboards follow in later phases (see the roadmap).

## Quick start

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```bash
make install   # create the virtual environment and install dependencies
make check     # lint, type-check, security scan and tests
make data      # download the pinned public datasets into data/raw/ and verify checksums
```

## Roadmap

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Repo, tooling, CI, dataset downloader | In progress |
| 1 | Parsers and a normalised `events` table in DuckDB | Planned |
| 2 | 12 ATT&CK-mapped SQL detections with KQL equivalents; dashboard v1 | Planned |
| 3 | Zeek network logs, 8 more detections, investigation pages | Planned |
| 4 | Anomaly detection (robust z-score, Isolation Forest, LOF) and risk scoring | Planned |
| 5 | Power BI report, incident report, Docker, demo | Planned |

## Data

Beacon does not redistribute any dataset. `make data` downloads them from their
original sources at a pinned commit and checks each file's SHA-256. See
[data/README.md](data/README.md) for sources and licences.

## Licence

MIT. Datasets keep their own licences.
