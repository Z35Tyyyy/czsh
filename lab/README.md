# Lab: proving the detections on real telemetry

The offline harness (`make test`) proves the detection *logic*. This guide shows
how to prove the detections **end-to-end on a live host**: generate real attack
telemetry, ship it to a SIEM, and watch the alerts fire. This is the part you
screenshot / GIF for the README.

## Topology

```
┌─────────────────────────────┐         Sysmon + Windows event logs
│  Windows 10/11 VM (victim)  │  ───────────────────────────────────┐
│  - Sysmon (SwiftOnSecurity  │                                      │
│    config)                  │                                      ▼
│  - Atomic Red Team          │                          ┌──────────────────────┐
│  - Wazuh agent              │                          │  Wazuh server VM     │
└─────────────────────────────┘                          │  (Ubuntu) — SIEM +   │
                                                          │  dashboard           │
                                                          └──────────────────────┘
```

**Hardware**: ~8 GB RAM total is enough (Windows VM 4 GB, Wazuh 4 GB). If you're
tight on resources, you can run Wazuh single-node in Docker on the host and keep
only the Windows VM.

## 1. Wazuh (SIEM)

Quickest path is the official single-node Docker deployment:

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node
docker compose up -d
# dashboard: https://localhost:443  (default creds in the repo's docker-compose)
```

Wazuh ingests Sysmon events out of the box and lets you write detection rules in
its own XML format. The Sigma rules in this repo map cleanly onto Sysmon fields
(`Image`, `CommandLine`, `ParentImage`, `TargetObject`, …); use
`make translate` to get a Splunk/Elastic query as a starting point, or port the
logic into a Wazuh rule.

## 2. Windows victim VM

1. **Sysmon** with a good config (telemetry quality is everything):
   ```powershell
   # from an elevated prompt
   Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
   Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon
   Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Sysmon\config.xml
   C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\config.xml
   ```
   Sysmon Event ID 1 = process creation, 13 = registry value set — the two log
   sources these rules use.

2. **Wazuh agent** — install the Windows agent, point it at the Wazuh server IP,
   and enable Sysmon channel collection in `ossec.conf`:
   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```

3. **Atomic Red Team** (the attack generator):
   ```powershell
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
   Install-AtomicRedTeam -getAtomics
   ```
   > Run atomics only inside a disposable VM you own. Snapshot first.

## 3. Fire an attack, watch the detection

Every rule in `detections/` lists the Atomic Red Team test that exercises it (in
its `references:` and in the matching `tests/cases/*.yml`). For example, the LSASS
dump rule:

```powershell
# T1003.001 — matches detections/credential_access/proc_creation_lsass_dump.yml
Invoke-AtomicTest T1003.001 -TestNumbers 1     # ProcDump -ma lsass
```

Then confirm in Wazuh that the corresponding Sysmon Event ID 1 arrived and your
rule (or the translated query) matched. Capture the alert for your write-up.

## Rule → Atomic Red Team map

| Detection | ATT&CK | Atomic test |
|-----------|--------|-------------|
| `proc_creation_powershell_encoded` | T1059.001 | `Invoke-AtomicTest T1059.001` |
| `proc_creation_wmic_process_call_create` | T1047 | `Invoke-AtomicTest T1047` |
| `proc_creation_office_spawns_shell` | T1059 / T1204.002 | macro / `Invoke-AtomicTest T1204.002` |
| `proc_creation_lsass_dump` | T1003.001 | `Invoke-AtomicTest T1003.001` |
| `proc_creation_reg_save_hive` | T1003.002 | `Invoke-AtomicTest T1003.002` |
| `proc_creation_ntdsutil_dump` | T1003.003 | `Invoke-AtomicTest T1003.003` |
| `registry_run_key_suspicious` | T1547.001 | `Invoke-AtomicTest T1547.001` |
| `proc_creation_scheduled_task_create` | T1053.005 | `Invoke-AtomicTest T1053.005` |
| `proc_creation_local_account_manipulation` | T1136.001 | `Invoke-AtomicTest T1136.001` |
| `proc_creation_clear_eventlog` | T1070.001 | `Invoke-AtomicTest T1070.001` |
| `proc_creation_mshta_remote` | T1218.005 | `Invoke-AtomicTest T1218.005` |
| `proc_creation_disable_defender` | T1562.001 | `Invoke-AtomicTest T1562.001` |
| `proc_creation_ad_recon` | T1087.002 / T1482 | `Invoke-AtomicTest T1087.002` |
| `proc_creation_shadowcopy_delete` | T1490 | `Invoke-AtomicTest T1490` |
| `proc_creation_certutil_download` | T1105 | `Invoke-AtomicTest T1105` |

## Turning a live finding back into a test

When you run an atomic and capture the real Sysmon event JSON, drop the relevant
fields into that rule's `tests/cases/*.yml` as a new `true_positive`. Now the
exact event that fired in the lab is pinned as a regression test in CI — the loop
that keeps detection quality from drifting.
