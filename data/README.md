# Data

Beacon never commits the datasets it analyses. `make data` downloads each file listed in
[`manifest.yml`](manifest.yml) into `data/raw/` and refuses any file whose SHA-256 does not
match the manifest. The only data in the repository is a few hundred sample records in
[`tests/data/`](../tests/data/README.md), so CI can test the parsers.

## Sources

| Source | What it contains | Licence | Used for |
| --- | --- | --- | --- |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (pinned to commit `d9d40ef`) | Attack techniques replayed in a Windows lab, recorded as JSON-lines event logs, each mapped to MITRE ATT&CK. Beacon uses 11 atomic datasets: 4 Empire and 7 PurpleSharp, Covenant and built-in-tool ones | MIT ([LICENSE](https://github.com/OTRF/Security-Datasets/blob/master/LICENSE)) | Detection testing on real attack activity |
| [APT29 ATT&CK evaluation](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29) (part of OTRF) | A two-day simulated APT29 intrusion: Windows host logs and Zeek network logs | MIT | End-to-end scenario and the incident report |
| [Loghub OpenSSH](https://github.com/logpai/loghub/tree/master/OpenSSH) ([Zenodo record 8196385](https://doi.org/10.5281/zenodo.1144100)) | 28 days of a real internet-facing SSH server's log (655,147 lines), with genuine password-guessing attempts | CC BY 4.0 | SSH brute-force rule (R20) on real attacks |

The OTRF README mentions GPL-3.0 in one place, but the repository's LICENSE file is MIT.
Beacon follows the LICENSE file.

Loghub requires attribution: Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu,
"Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics", IEEE ISSRE
2023. Its syslog lines carry no year or time zone; Beacon assumes the log starts in December
2015 and reads its times as UTC.

Total download is about 70 MB compressed.

## Adding a dataset

1. Add an entry to `manifest.yml` with a URL pinned to a commit or release, never a branch.
2. Run `beacon data hash <file>` on a trusted copy to get its SHA-256 and size.
3. Record the licence. Do not add datasets whose licence forbids this use.
4. On Windows, download and load it on its own and check Defender's history
   (`Get-MpThreatDetection`) after each step. Drop any dataset Defender flags; three Empire
   datasets (`dcsync_empire`, `net_localgroup_admins`, `schtasks_empire`) were dropped this way.
5. Add its expected row count and day to `tests/test_full_load_quality.py`.
