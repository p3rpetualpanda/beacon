# Test samples

Small extracts committed so CI can test the parsers without downloading the full datasets.

| File | Contents | Source |
| --- | --- | --- |
| `apt29_day1_sample.json` | 151 records from APT29 day 1: Sysmon 1, 3, 10, 11, 12, 13, 22, Security 4624, 4672, 4688, 5156, PowerShell and System events, the RTLO-disguised payload, and one record NXLog left unparsed | [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets), commit `d9d40ef` |
| `lsass_dump_comsvcs.json` | The whole LSASS dump dataset (184 records, 9 duplicates, 12-hour `TimeCreated` clock) | OTRF Security-Datasets, commit `d9d40ef` |
| `apt29_zeek_sample.log` | 15 Zeek records from APT29 day 1 (conn, dns, http, ssl, kerberos, weird), plus one exact duplicate, one record with an unusable timestamp and one Zeek `stats` housekeeping record | OTRF Security-Datasets, commit `d9d40ef` |
| `auth_sample.log` | Hand-written sshd lines in syslog and RFC 3339 formats | Written for Beacon |

The OTRF extracts are used under the MIT licence; its full text and copyright notice are in
[`OTRF-LICENSE`](OTRF-LICENSE).
