# Sigma Detection Pack

**Start here:** [Rules](rules/) · [Behaviour tests](tests/test_rules_fire.py) · [Portfolio case study](https://prhoguns.github.io/case-studies/sigma-detection-pack.html)

**What I did:** I wrote eleven Sigma rules and tested their SQL conversions against 6,038 synthetic events, including planted positives and near-misses. The documented run passed twelve tests. SPL and supported KQL are generated outputs; five KQL conversions need Sentinel parser mappings and are not presented as deployable detections.

_Portfolio sprint timeline: January–September 2026. Reported results retain their actual run dates._

Detection-as-code: eleven [Sigma](https://sigmahq.io) rules covering an intrusion chain from
initial access to defense evasion, converted with pySigma to **SQL, Splunk SPL and Sentinel KQL**,
and **tested in CI** against a synthetic event corpus with planted true positives and deliberate
near-misses. Every rule must match exactly its planted events — a miss or a false positive fails the build.

| | |
|---|---|
| Rules | [`rules/`](rules/) — Windows Security, Sysmon and Linux auth/sudo; each with ATT&CK tags, description, documented false positives |
| Catalog | [`out/catalog.md`](out/catalog.md) — every rule with level, tactic, technique and which targets converted |
| Conversions | [`out/sql`](out/sql/) · [`out/splunk`](out/splunk/) · [`out/kql`](out/kql/) |
| Corpus | [`scripts/generate_events.py`](scripts/generate_events.py) — 6,038 events, 25 planted positives, 14 near-misses |
| Tests | [`tests/test_rules_fire.py`](tests/test_rules_fire.py) — converts each rule to SQL, runs it on SQLite, compares to expected ids |

## Why test detections

A rule that never fires is indistinguishable from one that works until the day it matters. The
corpus gives every rule at least one event it must catch and one it must not:

| Rule | Must catch | Must ignore |
|---|---|---|
| PowerShell encoded command | `powershell.exe -enc SQBFAFgA…` | `powershell.exe -Command Get-Encoding`; `cmd.exe /c echo -enc` |
| LSASS access | `procdump.exe` → lsass with `0x1010` | Defender (`MsMpEng.exe`) → lsass; a tool opening lsass with `0x1000` |
| User added to privileged group | 4728 to *Domain Admins* | 4729 (removal); 4728 to *Finance Users* |
| Defender disabled | `DisableAntiSpyware = DWORD (0x00000001)` | the same key set back to `0` by `gpupdate` |
| SSH root from external | `Accepted password for root from 185.220…` | root from `10.10.1.5`; *Failed* password from external |

Run: `docker build -t sigma-pack . && docker run --rm sigma-pack` → `12 passed`.

## How conversion works

```
Sigma YAML ──pySigma──► SQLite backend  ──► SQL  (tests run this)
                    ├─► Splunk backend  ──► SPL  (splunk_windows pipeline)
                    └─► Kusto backend   ──► KQL  (sentinel_asim pipeline; falls back to azure_monitor with an explicit table)
```

Five rules do not convert to KQL and the catalog says so: Sysmon pipe/registry fields and Linux
`Message`/`User` are not columns in Sentinel's `Event` / `Syslog` tables — in a real deployment
they come from a parser (ASIM `imProcessCreate`, a DCR transform, or `parse_xml(EventData)`).
Writing a fake mapping would produce KQL that never matches; leaving it explicit is the honest answer.

## Chain the rules cover

```
Initial access   SSH root from external (T1021.004)
Execution        Encoded PowerShell (T1059.001)
Credential access Mimikatz CLI (T1003.001) · LSASS access (T1003.001)
Persistence      User created by unexpected account (T1136.001) · Scheduled task from user-writable path (T1053.005)
Privilege esc.   Added to privileged group (T1098) · svc-account sudo shell (T1548.003)
Defense evasion  Security log cleared (T1070.001) · Defender disabled via registry (T1562.001)
C2               Cobalt Strike named pipe (T1071)
```

These are the same techniques the planted incidents in
[soc-alert-analytics](https://github.com/prhoguns/soc-alert-analytics) use; that project analyses
the alerts, this one defines the detections that would raise them.

## Add a rule

1. Write `rules/<os>/<name>.yml` (Sigma v2 format; keep `falsepositives` and ATT&CK tags).
2. Add planted positives *and* near-misses in `scripts/generate_events.py`, listing the rule id on the positives.
3. `python scripts/generate_events.py && python scripts/convert.py && pytest`.

## Acknowledgments

AI tools assisted with documentation and repository organization.
