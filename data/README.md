# Data

Beacon never commits the datasets it analyses. `make data` downloads each file listed in
[`manifest.yml`](manifest.yml) into `data/raw/` and refuses any file whose SHA-256 does not
match the manifest. The only data in the repository is a few hundred sample records in
[`tests/data/`](../tests/data/README.md), so CI can test the parsers.

## Sources

| Source | What it contains | Licence | Used for |
| --- | --- | --- | --- |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (pinned to commit `d9d40ef`) | Attack techniques replayed in a Windows lab, recorded as JSON-lines event logs, each mapped to MITRE ATT&CK | MIT ([LICENSE](https://github.com/OTRF/Security-Datasets/blob/master/LICENSE)) | Rule fixtures, end-to-end testing, model evaluation |
| [APT29 ATT&CK evaluation](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29) (part of OTRF) | A two-day simulated APT29 intrusion: Windows host logs and Zeek network logs | MIT | End-to-end scenario and the incident report |

The OTRF README mentions GPL-3.0 in one place, but the repository's LICENSE file is MIT.
Beacon follows the LICENSE file.

Total download is about 66 MB compressed.

## Adding a dataset

1. Add an entry to `manifest.yml` with a URL pinned to a commit or release, never a branch.
2. Run `beacon data hash <file>` on a trusted copy to get its SHA-256 and size.
3. Record the licence. Do not add datasets whose licence forbids this use.
