# Windows Log Evasion & Anti-Forensics

*Honest accounting of Windows logging surfaces and the disproportionate cost of tampering. In centrally-collected environments the correct play is to avoid generating evidence, not to delete it - deletion is a louder, higher-fidelity signal than the activity it tries to hide.*

## What & why

The goal of this page is to make an operator stop reaching for `wevtutil cl`, `Clear-Log`, and timestomp utilities as reflexes, and to make the defender understand why those reflexes are gifts. Windows writes operator activity to many channels at once, and in any environment with Windows Event Forwarding (WEF) or an EDR agent shipping ETW in near real time, the local event log is a stale copy - the authoritative record already left the host. Clearing or corrupting that local copy destroys nothing the SIEM cares about and creates its own dedicated event (`1102` for the Security channel, `104` for others) that nearly every detection ruleset alerts on with high confidence and low false-positive rate. The OPSEC rationale is therefore inverted from the naive model: the quiet operator minimizes the events they emit, blends into expected administrative noise, and treats the log subsystem as read-only telemetry to be modeled and avoided, never as an artifact to be scrubbed. Anti-forensics on a monitored host is usually a confession.

## Technique

### Channels that record operator activity

Windows event channels are EVTX files under `C:\Windows\System32\winevt\Logs\` and ETW providers feeding them in real time. The ones an operator must model:

- `Security` (`Security.evtx`) - authentication, privilege use, object access, audit policy. Written by the Local Security Authority (LSASS) via the Security ETW channel. Only `SYSTEM`/auditing subsystem writes here; you cannot append or forge entries.
- `System` (`System.evtx`) - service control manager, driver loads, time changes, log service state.
- `Application` (`Application.evtx`) - app-level and some installer events.
- `Microsoft-Windows-PowerShell/Operational` - script block logging (`4104`), module logging (`4103`), and pipeline execution when enabled by policy.
- `Windows PowerShell` (classic, `Windows PowerShell.evtx`) - engine lifecycle (`400`/`403`/`600`) regardless of the newer policy switches.
- `Microsoft-Windows-Sysmon/Operational` - if Sysmon is installed, a separate, hardened, high-fidelity stream (process create `1`, network `3`, image load `7`, file create `11`, registry `12`/`13`/`14`, raw disk `9`, process access `10`, `CreateRemoteThread` `8`, WMI `19`/`20`/`21`, file delete `23`/`26`).
- `Microsoft-Windows-WMI-Activity/Operational` - WMI provider operations and `Operation_*` events; permanent WMI event subscriptions surface here.
- `Microsoft-Windows-TaskScheduler/Operational` - task registration (`106`), execution (`200`/`201`), and updates (`140`).

See [Windows Event Channels & ETW](01-etw-and-event-channels.md) and [Sysmon Coverage Map](02-sysmon-coverage.md) for the full provider-to-event mapping these sections reference.

### Event IDs an operator generates by default

Trace a single interactive lateral move and count the records it lights up:

| Channel | Event ID | Meaning |
|---|---|---|
| Security | 4624 | Successful logon (note `LogonType`: 3 network, 9 NewCredentials/runas-netonly, 10 RDP) |
| Security | 4625 | Failed logon (spraying, bad creds) |
| Security | 4672 | Special privileges assigned to new logon (admin/SeDebug etc.) |
| Security | 4688 | Process creation (with command line if `ProcessCreationIncludeCmdLine_Enabled` policy is set) |
| Security | 4697 | A service was installed by the system |
| System | 7045 | A new service was installed (SCM view of the same act) |
| Security | 4698 | A scheduled task was created |
| Security | 4699/4700/4702 | Task deleted/enabled/updated |
| Security | 4720 | A user account was created |
| Security | 4732/4728 | Member added to a security-enabled local/global group |
| Security | 1102 | The audit log was cleared |
| System | 104 | A log file (any non-Security channel) was cleared |
| Security | 4719 | System audit policy was changed |
| System | 7036/7040 | Service entered a state / start type changed |
| Security | 4616 | System time was changed (timestomp on the clock, not the file) |

The point: a routine `sc create` plus service start emits at minimum `7045` + `4697` + `4688` (the install binary) + `4624`/`4672` (the context). Each is forwarded independently. You do not get to pick which subset survives.

### The clearing paradox (1102 / 104)

`1102` is the canonical example of an anti-forensic action that is louder than the crime:

- `wevtutil cl Security` (or the EVTX API `EvtClearLog`, or `Clear-EventLog`, or the GUI) triggers the audit subsystem to write event `1102` to the Security channel itself - the last record before the log is emptied is "this log was cleared," including the `SubjectUserName`/`SubjectDomainName` that did it.
- Clearing any other channel writes `104` ("The <Channel> log file was cleared") to the `System` channel via the EventLog service.
- Critically, these events fire *at clear time*. In a WEF/WEC deployment the forwarder has already shipped the pre-clear records as they were generated; clearing only blinds the local responder, not the collector. And the `1102`/`104` themselves are subscribed and forwarded, so you have replaced a diffuse trail with a single high-severity beacon stamped with your account.

```powershell
# DO NOT run on an engagement - shown to identify the IOC it produces.
# Generates Security/1102 stamped with the calling SID, then empties the local copy.
wevtutil cl Security
```

### Selective EVTX manipulation is hard and self-evident

Surgically removing one record (rather than clearing the channel) is the "advanced" alternative and it fails for structural reasons:

- The live channel is held open by the EventLog service (`svchost.exe -k LocalServiceNetworkRestricted` hosting `EventLog`). You cannot get an exclusive write handle to `Security.evtx` while the service runs; you must stop the service or unload/patch the running provider first - and stopping the service is itself logged (see below) and breaks forwarding heartbeats.
- EVTX is a chunked binary format. Each 64 KB chunk carries a CRC32 over the chunk and per-record checksums, and the file header tracks `NumberOfChunks`, `NextRecordIdentifier`, and a header checksum. Deleting a record leaves a gap in the monotonic `EventRecordID` sequence and, unless every dependent checksum and the chunk/file headers are recomputed, the file is flagged corrupt by `wevtutil`, the Event Viewer, and forensic parsers.
- Tools that do recompute checksums (the public EVTX-tampering research utilities) are themselves IOCs: their behavior is loading the running EventLog service's heap or memory-mapping the EVTX and rewriting chunks, which EDR sees as a sensitive process being accessed and an unusual writer to `winevt\Logs`. The monotonic `EventRecordID` gap remains visible to any analyst diffing the forwarded copy against the local one.

The takeaway: a forwarded record cannot be unforwarded. Local surgery does not change what the collector holds, and the surgery is detectable.

### Disabling ETW / the EventLog service

Killing the source rather than the file is equally telling:

- Stopping the EventLog service (`sc stop eventlog`, or patching `ntdll!EtwEventWrite` / `EtwpEventWriteFull` in-process) stops new local writes. But `7036`/`7040` service-state and start-type changes are written to `System` (if EventLog is restarted), and EDR agents consume ETW directly via their own real-time session - in-process patching of `EtwEventWrite` only blinds providers in *your* process, not the kernel ETW sessions an EDR subscribes to.
- WEF runs over WinRM; when a forwarding source stops shipping, the collector sees a heartbeat gap. The subscription's `HeartbeatInterval` (default on the order of minutes) means a silenced host stands out as a dark forwarder within one interval, which is itself an alert in mature SOCs.
- Per-thread ETW patching against AMSI/ScriptBlock providers (`EtwEventWrite` return-1 stubs) is a known evasion but is scoped to the patched process and is detected by EDR via the inline hook on a sensitive `ntdll` export and by the absence of expected `4103`/`4104` from a process that clearly ran scripts.

### Timestomp and what it cannot reach

Timestomping rewrites NTFS timestamps to hide a file's age, but NTFS keeps two timestamp sets and a change journal:

- Every file has `$STANDARD_INFORMATION` (`$SI`) timestamps - the ones shown by Explorer, `dir`, and most tooling - and `$FILE_NAME` (`$FN`) timestamps stored in the parent directory's index entry. The Win32 `SetFileTime` API and tools that call it (and `SetBasicInformationFile` via `NtSetInformationFile`) write `$SI` only. `$FN` is normally only updated by the kernel during create/rename/move and is not writable through `SetFileTime`.
- The classic tell: after a `$SI`-only timestomp, `$SI.CreationTime` precedes `$FN.CreationTime`, or `$SI` shows whole-second/zeroed sub-second precision while `$FN` retains 100ns granularity. Forensic tools (`MFTECmd`, `analyzeMFT`, `fls`/`istat` from Sleuth Kit) read both attributes straight from the `$MFT` and surface the mismatch.
- Even a tool that also rewrites `$FN` (by triggering a rename so the kernel restamps the index entry, or by raw-`$MFT` editing) does not erase the **USN change journal** (`$Extend\$UsnJrnl:$J`), which records `USN_REASON_BASIC_INFO_CHANGE`, `USN_REASON_RENAME_OLD_NAME`/`NEW_NAME`, and creation/close reasons with the time of the operation. The journal entry's own timestamp contradicts the stomped file time.
- The NTFS transaction log (`$LogFile`) records MFT attribute writes for crash recovery and can be carved to reconstruct the original `$SI`/`$FN` values that existed before the stomp.

```text
:: Conceptual MFT view of a $SI-only timestomp (lab artifact, not a command)
:: $SI  Created: 2019-01-01 00:00:00.000   <- attacker-set, sub-second zeroed
:: $FN  Created: 2024-11-03 14:22:07.418   <- kernel truth, full precision
:: => SI < FN and SI sub-second == 0  => timestomp indicator
```

### Execution evidence that survives clearing entirely

Even with every event channel emptied, Windows persists independent execution and presence artifacts that are not part of the event log subsystem and are not cleared by `wevtutil`:

- **Prefetch** (`C:\Windows\Prefetch\<NAME>-<HASH>.pf`) - records executable name, run count, last-eight run times, and referenced file/volume paths. Present on workstations by default; often disabled on servers. Deleting a `.pf` is itself anomalous and leaves a USN entry.
- **Amcache** (`C:\Windows\AppCompat\Programs\Amcache.hve`) - SHA-1 of executed/installed binaries, full path, PE compile time, first-seen. Survives the binary's deletion.
- **Shimcache / AppCompatCache** (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`) - path, `$SI` last-modified, and a flag historically interpreted as execution; flushed to the registry hive at shutdown, so it captures presence even for deleted files.
- **SRUM** (`C:\Windows\System32\sru\SRUDB.dat`) - 60-day rolling per-process network bytes, CPU, and the app/user that ran it; powerful for proving an exfil binary ran and how much it sent.
- **ShellBags, UserAssist, RunMRU, BAM/DAM** (`HKLM\SYSTEM\...\bam\State\UserSettings\<SID>`) - background activity moderator records last-execution time per binary per user SID.

These let a defender reconstruct what ran after the operator cleared the logs, and the gap between "logs are empty" and "Amcache says X.exe ran at T" is itself the finding.

## OPSEC notes

What makes the loud version loud:

- **Clearing logs.** `1102`/`104` are single, named, high-confidence events stamped with your account. They convert a noisy environment (in which your individual `4688`s might be lost in baseline) into a targeted hunt with your SID as the lead.
- **Stopping EventLog / patching ETW.** Produces a forwarder heartbeat gap (WEF) and, for in-proc patches, an EDR-visible inline hook on `ntdll` exports plus the conspicuous absence of `4103`/`4104` from a process that demonstrably executed script.
- **Naive timestomp.** `$SI`-only writes leave `$SI < $FN` and zeroed sub-seconds; the USN journal timestamps the stomp itself.

The quiet variant:

- Model the channels and **emit fewer events**. Prefer logon types and tooling that match the host's baseline (an admin host that RDPs all day makes your `LogonType 10` boring). Use signed, expected binaries; live off the land so `4688`/Sysmon `1` command lines look administrative.
- Treat the event log as **read-only telemetry to avoid**, never as an artifact to scrub. If a record will be damaging, the answer is to not generate it, not to delete it after the collector already has it.
- Accept that on a forwarded host the authoritative log is off-box. Anti-forensics buys nothing against the collector and pays in alert fidelity.

Failure modes and tells: stopping a forwarding source trips heartbeat monitoring; selective EVTX edits leave `EventRecordID` gaps and checksum corruption; `$FN`-aware timestomps still leave USN/`$LogFile` traces; deleting Prefetch/Amcache is anomalous and journaled; SRUM and Shimcache reconstruct execution after the fact.

## Detection & telemetry

The defender's high-value, low-false-positive signals:

### Log clearing

- **Security `1102`** - "The audit log was cleared." Field `SubjectUserSid`/`SubjectUserName` identifies the clearer. Alert always.
- **System `104`** - "The <Channel> log file was cleared." Provider `Microsoft-Windows-Eventlog`. Alert always.

Sigma-style logic:

```yaml
title: Windows Event Log Cleared
logsource:
  product: windows
detection:
  clear_security:
    Channel: Security
    EventID: 1102
  clear_other:
    Channel: System
    EventID: 104
  condition: clear_security or clear_other
level: high
```

KQL (Defender / Sentinel advanced hunting):

```kusto
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account = SubjectUserName, SubjectDomainName
| union (
    Event
    | where EventLog == "System" and EventID == 104
    | project TimeGenerated, Computer, UserName, Channel = tostring(parse_json(EventData).Channel)
  )
```

### ETW / EventLog service tampering

- **System `7036`/`7040`** for the `Windows Event Log` service entering Stopped or having its start type changed.
- **Forwarder gap**: on the WEC, correlate `Microsoft-Windows-Forwarding/Operational` and per-source heartbeat - a source that stops checking in within the subscription `HeartbeatInterval` is a dark host. Hunt for hosts in inventory absent from the forwarded stream.
- **In-process ETW patch**: EDR inline-hook detection on `ntdll!EtwEventWrite`/`EtwEventWriteFull`; behavioral signal is a process with executed scripts but no corresponding `Microsoft-Windows-PowerShell/Operational` `4103`/`4104` or AMSI `1116`. Sysmon `7` (image load) plus `10` (process access to a sensitive process) can corroborate manipulation tooling.

osquery for service state drift:

```sql
SELECT name, status, start_type, path
FROM services
WHERE name IN ('EventLog','Sysmon','Sysmon64')
  AND (status != 'RUNNING' OR start_type NOT IN ('AUTO_START','SYSTEM_START'));
```

### EVTX integrity

- Run `wevtutil` / a parser to detect chunk-CRC or header-checksum corruption indicating in-place edits.
- Diff the **forwarded** copy on the WEC against the host-local EVTX: any monotonic `EventRecordID` gap on the host that is filled on the collector proves local deletion.
- File-write anomaly: Sysmon `11` (FileCreate) or EDR file telemetry for any writer to `C:\Windows\System32\winevt\Logs\*.evtx` that is not the EventLog service.

### Timestomp - MFT $SI vs $FN

The defining artifact is the `$STANDARD_INFORMATION` vs `$FILE_NAME` mismatch in the `$MFT`, plus the change journal:

- Parse `$MFT` with `MFTECmd` (Eric Zimmerman) or `analyzeMFT`; flag records where `$SI.CreationTime < $FN.CreationTime` or where `$SI` sub-second fields are zeroed while `$FN` are not.
- Carve `$Extend\$UsnJrnl:$J` for `USN_REASON_BASIC_INFO_CHANGE` and `RENAME_OLD_NAME`/`RENAME_NEW_NAME` reasons; the journal record's timestamp dates the stomp.
- Parse `$LogFile` to recover pre-stomp `$SI`/`$FN` values.
- Sysmon `2` ("A process changed a file creation time") is emitted on `$SI` creation-time changes and is a direct timestomp signal.

Sysmon config and KQL:

```kusto
DeviceEvents
| where ActionType == "ProcessChangedFileCreationTime"   // Sysmon EventID 2 equivalent
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName
```

```sql
-- osquery: surface files whose change journal and timestamps disagree is non-trivial in SQL;
-- instead enumerate recently-written binaries in sensitive dirs for offline $MFT triage.
SELECT path, btime, mtime, ctime, atime
FROM file
WHERE directory IN ('C:\Windows\Temp','C:\Users\Public')
  AND filename LIKE '%.exe';
```

### Surviving execution evidence to correlate

Pull these regardless of event-log state and correlate against any clearing event - "logs empty + Amcache shows execution" is the finding:

- **Prefetch** `C:\Windows\Prefetch\*.pf` - parse with `PECmd`; run counts and last-eight run times.
- **Amcache** `C:\Windows\AppCompat\Programs\Amcache.hve` - parse with `AmcacheParser`; SHA-1 + path + first-seen.
- **Shimcache** `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` - parse with `AppCompatCacheParser`.
- **SRUM** `C:\Windows\System32\sru\SRUDB.dat` - parse with `SrumECmd`; per-process network bytes for exfil sizing.
- **BAM/DAM** `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` - last-run per binary per user.

Hunt pattern: alert on any `1102`/`104` and, on the same host, automatically pull Prefetch/Amcache/Shimcache/SRUM for the surrounding window. The deletion event becomes the pivot, not the dead end the operator intended.

## MITRE ATT&CK

- T1070 - Indicator Removal
- T1070.001 - Indicator Removal: Clear Windows Event Logs
- T1070.006 - Indicator Removal: Timestomp
- T1562.002 - Impair Defenses: Disable Windows Event Logging
- T1562.006 - Impair Defenses: Indicator Blocking (ETW provider tampering)
- T1562.001 - Impair Defenses: Disable or Modify Tools
- T1489 - Service Stop (stopping EventLog / Sysmon)
- T1112 - Modify Registry (Shimcache/audit-policy registry tampering)
- T1485 - Data Destruction (selective EVTX corruption)

## References

- Microsoft, "wevtutil" command reference - https://learn.microsoft.com/windows-server/administration/windows-commands/wevtutil
- Microsoft, "Windows Event Forwarding (WEF)" - https://learn.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection
- Microsoft, "Audit log cleared (event 1102)" - https://learn.microsoft.com/windows/security/threat-protection/auditing/event-1102
- Microsoft Sysinternals, "Sysmon" event reference - https://learn.microsoft.com/sysinternals/downloads/sysmon
- MITRE ATT&CK, T1070.001 Clear Windows Event Logs - https://attack.mitre.org/techniques/T1070/001/
- MITRE ATT&CK, T1070.006 Timestomp - https://attack.mitre.org/techniques/T1070/006/
- Eric Zimmerman's Tools (MFTECmd, PECmd, AmcacheParser, AppCompatCacheParser, SrumECmd) - https://ericzimmerman.github.io/
- libyal, "Windows XML Event Log (EVTX) format" specification - https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
