# Windows Persistence Stealth

*Quiet Windows persistence mechanisms and the exact event trail each one leaves for a defender to hunt.*

## What & why

The goal is to survive reboot and logon on a Windows host during an authorized engagement while producing the smallest, most ambiguous telemetry footprint possible. Every Windows autostart mechanism is a write to a known, monitored location - a registry value, a file on disk, a scheduled task object, a service control manager record, or a WMI repository class. The OPSEC rationale is simple: persistence is the single most heavily hunted phase of an intrusion because it is durable and centralized. Defenders run Autoruns, osquery's `autoexec` schema, registry FIM, and Sysmon registry/WMI events specifically to enumerate these locations. Loud persistence (a new `Run` value pointing at `C:\Users\Public\evil.exe`, a brand-new service running a renamed binary) is trivially flagged. The quiet play is to blend into a mechanism that already exists and is expected to change, to live under signed-binary execution paths, and to understand precisely which event ID fires the instant you write so you can predict your own detection. This page pairs each technique with that event trail. See also [Living off the Land](./03-lolbins.md) and [Defense Evasion - Log Tampering](./04-log-tampering.md).

## Technique

### Run / RunOnce keys

The classic. Values under these keys execute at logon (per-user `HKCU`) or at boot/any-user logon (`HKLM`).

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run   (32-bit on 64-bit OS)
```

`RunOnce` values are deleted by the OS before the command runs (the value name prefixed with `!` defers deletion until the command succeeds), which is why malware that wants single-shot staging uses it.

```cmd
:: per-user, no admin required
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\Users\labuser\AppData\Local\updater.exe" /f
```

Inline note: writing `HKLM` requires admin and is far louder because it persists for every user and is FIM-watched harder. The value name (`Updater`) and data path are both indexed by Autoruns. Pointing the value at a signed LOLBin with arguments (for example `rundll32.exe`, `regsvr32.exe`) instead of a raw EXE drops the obvious "unsigned binary in a Run key" signal but the registry write event is identical.

The instant that `reg add` (or `RegSetValueExW` under the hood) commits, Sysmon logs **Event ID 13 (RegistryEvent - Value Set)** with `TargetObject` containing the full key path and value name, `Details` containing the data written, and the writing `Image`. There is no native Windows Security event for an arbitrary `Run` value write - this is a Sysmon-only signal unless registry auditing (SACL) is configured on the key, which is rare.

### Scheduled Tasks

Tasks survive reboot, run as `SYSTEM` or any principal, and support rich triggers (logon, boot, idle, time, event). The task definition lives as XML on disk.

```cmd
:: create a task that runs at logon
schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\HealthCheck" /tr "C:\Windows\System32\rundll32.exe C:\ProgramData\health.dll,Run" /sc onlogon /rl highest /f
```

The task object is written to a file and registered in the registry tree:

```text
C:\Windows\System32\Tasks\<TaskFolder>\<TaskName>           (XML definition, no extension)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\...
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}\   (Actions, Triggers as binary)
```

Inline note: naming the task to mimic a legitimate Microsoft task folder (for example nesting under `\Microsoft\Windows\`) and using a signed LOLBin as the action reduces analyst suspicion, but the creation event still fires.

On creation, **Security event 4698 (A scheduled task was created)** fires when the "Object Access -> Audit Other Object Access Events" subcategory is enabled (it is not on by default in many environments - confirm before relying on it). The 4698 event embeds the full task XML in the event data, including the command and arguments. The **Microsoft-Windows-TaskScheduler/Operational** log independently records lifecycle events: **106 (task registered)**, **140 (task updated)**, **141 (task deleted)**, **200 (action started)**, and **201 (action completed)** with the executed image path. The `TaskCache` registry write also generates Sysmon EID 13 on the `Tasks\{GUID}\` values. So a single task touches at minimum: a file write, multiple registry writes, and one to three event log sources.

### Services

A service can run a binary or a `svchost`-hosted DLL as `LocalSystem` at boot. Powerful, but among the loudest mechanisms.

```cmd
:: requires admin
sc create LabSvc binPath= "C:\ProgramData\labsvc.exe" start= auto DisplayName= "Lab Health Service"
```

Inline note: the space after each `=` in `sc.exe` is mandatory syntax. DLL-hosted (`svchost`) services hide the payload behind `services.exe`/`svchost.exe` and require a `Parameters\ServiceDll` value under the service key, which is itself a hunted artifact.

Service install fires **System event 7045 (A new service was installed)** from the Service Control Manager - this event is always logged regardless of audit policy and includes `Service Name`, `Image Path`, `Service Type`, and `Start Type`. With "Audit Security System Extension" enabled you also get **Security event 4697 (A service was installed in the system)**. The service definition lives at:

```text
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\
  ImagePath        (REG_EXPAND_SZ - the binary or svchost line)
  Start            (2 = automatic, 3 = manual)
  Parameters\ServiceDll   (for DLL services)
```

Because 7045 is unconditional and SCM-sourced, service persistence is the easiest of all these to detect. Use it only when SYSTEM-at-boot is genuinely required.

### WMI event subscriptions

The stealthier classic. A permanent WMI subscription pairs three objects in the `root\subscription` namespace: an `__EventFilter` (the trigger condition, a WQL query), a `CommandLineEventConsumer` or `ActiveScriptEventConsumer` (the action), and a `__FilterToConsumerBinding` (the link). It is fileless in the conventional sense - the logic lives in the WMI repository at `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` - and it executes as `SYSTEM` via `WmiPrvSE.exe`, not from a Run key or task.

```powershell
# admin PowerShell - triggers ~60s after boot via Win32_PerfFormattedData polling
$filterArgs = @{
  Name = 'LabFilter'
  EventNamespace = 'root\cimv2'
  QueryLanguage = 'WQL'
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320"
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs

$consumerArgs = @{
  Name = 'LabConsumer'
  CommandLineTemplate = 'C:\Windows\System32\rundll32.exe C:\ProgramData\health.dll,Run'
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
  Filter = $filter
  Consumer = $consumer
}
```

Inline note: WMI subscriptions leave no Run key, no service, no scheduled-task file - which is exactly why they were historically a defender blind spot and why Sysmon added dedicated coverage. They are not invisible anymore.

The three writes generate Sysmon events when WMI logging is enabled in the config:
- **Sysmon Event ID 19 - WmiEvent (WmiEventFilter activity detected)** - the `__EventFilter` create/delete, with `Operation`, `Name`, `EventNamespace`, and the `Query`.
- **Sysmon Event ID 20 - WmiEvent (WmiEventConsumer activity detected)** - the consumer create/delete, with `Type` (CommandLine/ActiveScript), `Name`, and `Destination`/`Command` (the `CommandLineTemplate` or script text).
- **Sysmon Event ID 21 - WmiEvent (WmiEventConsumerToFilter activity detected)** - the binding, linking `Consumer` and `Filter`.

When the subscription fires, the action runs as a child of `WmiPrvSE.exe`, which is itself a strong process-lineage signal (Sysmon EID 1 / Security 4688). Enumerate live subscriptions for cleanup/detection with:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### COM hijacking

Hijack a Component Object Model class so that when a legitimate process instantiates that CLSID, your DLL loads instead. The high-OPSEC variant abuses the per-user hive: `HKCU` is searched before `HKLM` for many lookups, so a non-admin user can shadow a system CLSID by writing `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32`.

```cmd
:: per-user COM hijack - no admin. {GUID} = a CLSID loaded by a frequently-run process
reg add "HKCU\Software\Classes\CLSID\{GUID}\InprocServer32" /ve /t REG_SZ /d "C:\Users\labuser\AppData\Local\health.dll" /f
reg add "HKCU\Software\Classes\CLSID\{GUID}\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both" /f
```

Inline note: target CLSIDs are chosen empirically - typically "abandoned" or `HKCU`-shadowable keys that a host process (Explorer, a scheduled task, Office) resolves at runtime. The persistence triggers without any autostart key of its own, which is the appeal. The tell is process-image-load lineage: a signed host process loading an unsigned/unusual DLL from a user-writable path.

The registry write to `InprocServer32` fires **Sysmon EID 13**. The subsequent DLL load into the host process fires **Sysmon Event ID 7 - Image loaded** (if image-load logging is enabled - it is verbose, so often filtered) with the host `Image`, the loaded DLL path, and signature status. Autoruns has a dedicated "abandoned CLSID" / COM hijack heuristic.

### Startup folder

A shortcut or executable dropped here runs at logon for the user (per-user) or all users (common). Pure file-on-disk persistence, no registry value required.

```text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup            (per-user)
%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup        (all users - needs admin)
```

Dropping a `.lnk` whose target is a LOLBin with arguments is quieter than dropping an EXE, but both are caught by **Sysmon Event ID 11 (FileCreate)** on these paths and by any directory-monitoring control. Autoruns lists Startup-folder entries by default.

### Logon scripts

The legacy `HKCU\Environment\UserInitMprLogonScript` value runs a command at logon via `userinit.exe`. It is a single registry value, requires no admin, and is less commonly enumerated than `Run` keys - but Autoruns and Sysmon still see it.

```cmd
reg add "HKCU\Environment" /v UserInitMprLogonScript /t REG_SZ /d "C:\Users\labuser\AppData\Local\logon.cmd" /f
```

The write fires **Sysmon EID 13** on `HKCU\Environment\UserInitMprLogonScript`. Execution shows `userinit.exe` spawning your interpreter (Sysmon EID 1 / Security 4688), an unusual lineage worth a hunt rule.

### The stealth / persistence trade

Roughly ordered loudest to quietest by native telemetry:

| Mechanism | Native always-on event | Sysmon event | Admin required | Runs as |
| --- | --- | --- | --- | --- |
| Service | System 7045 (always) | EID 13 (Services key) | Yes | SYSTEM |
| Scheduled Task | TaskScheduler/Op 106 (always) | EID 13 (TaskCache) | No (user task) | configurable |
| Run / RunOnce | none (needs SACL) | EID 13 | No (HKCU) | user |
| Startup folder | none | EID 11 (FileCreate) | No (per-user) | user |
| Logon script | none | EID 13 | No | user |
| COM hijack (HKCU) | none | EID 13 + EID 7 | No | host process |
| WMI subscription | none | EID 19/20/21 | Yes | SYSTEM |

The honest takeaway: there is no "silent" mechanism on a host with Sysmon and a sane config. WMI subscriptions and HKCU COM hijacks avoid the always-on native events (7045, 4698, TaskScheduler), but Sysmon EID 19-21 and 13/7 close those gaps. The genuinely quiet play is to blend into an existing legitimate mechanism (hijack a DLL that an already-installed task or service loads), so the autostart artifact predates your access and does not appear as a new write.

## OPSEC notes

What makes the loud version loud:
- A new value in `HKLM\...\Run` or a new `7045` service install is a high-fidelity, low-volume signal that nearly every detection stack alerts on directly.
- Pointing an autostart at an unsigned binary in a user-writable path (`AppData`, `ProgramData`, `Public`, `Temp`) stacks a second signal on top of the autostart write.
- `schtasks.exe`, `sc.exe`, and `reg.exe` invocations with persistence-shaped arguments are themselves command-line-logged (4688 / Sysmon EID 1). Spawning them from a non-interactive parent (an Office app, `wscript`, a web shell host) is glaring lineage.

The quiet variant:
- Prefer HKCU over HKLM where a user-context trigger suffices - no admin, no machine-wide FIM.
- Execute via signed LOLBins (`rundll32`, `regsvr32`, `mshta`) so the on-disk payload is a DLL/script loaded by a trusted host rather than a new EXE image.
- Place payloads alongside legitimate application files in a plausibly-named directory, not in obvious staging dirs.
- Name tasks/services/values to mirror real vendor artifacts and nest task folders under existing Microsoft paths.
- Best of all: modify an artifact that already exists (replace the target of an existing benign `.lnk`, swap a DLL an existing service already loads) so there is no new autostart object to enumerate - only a content change, which requires FIM hashing rather than presence-based hunting to catch.

Failure modes and tells:
- WMI subscription WQL with a polling interval (`WITHIN 60`) plus a `Win32_PerfFormattedData` filter is a well-documented malware pattern; defenders pattern-match it.
- A signed process loading an unsigned DLL from `\Users\` or `\ProgramData\` (COM hijack, DLL sideload) is a strong heuristic even without knowing the CLSID.
- `RunOnce` values that should self-delete but persist (because the command failed) leave a forensic breadcrumb.
- The on-disk task XML and the `TaskCache` registry entries can desynchronize if you tamper with one and not the other - a known anti-forensic tell that detection tooling specifically reconciles.

## Detection & telemetry

This is the section that matters. Map your hunt to the exact artifact each mechanism writes.

### Sysmon registry (EID 12/13/14)

Sysmon **Event ID 13 (RegistryEvent - Value Set)** is the workhorse for Run keys, COM hijacks, logon scripts, and the `TaskCache`/`Services` registry writes. Key fields: `TargetObject` (full path + value name), `Details` (data written), `Image` (writing process), `EventType`. EID 12 covers key create/delete and EID 14 covers value renames. Minimum config coverage to include:

```xml
<RuleGroup name="Persistence-Registry" groupRelation="or">
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
    <TargetObject condition="contains">\CurrentVersion\RunOnce</TargetObject>
    <TargetObject condition="end with">\InprocServer32\(Default)</TargetObject>
    <TargetObject condition="contains">UserInitMprLogonScript</TargetObject>
    <TargetObject condition="contains">\Services\</TargetObject>
  </RegistryEvent>
</RuleGroup>
```

### Sysmon WMI (EID 19/20/21)

The dedicated permanent-subscription coverage. Hunt all three together; a legitimate subscription is rare on workstations.
- **EID 19 WmiEventFilter** - fields `Operation`, `EventNamespace`, `Name`, `Query`. Alert on any `Created` with a `CommandLineEventConsumer` partner.
- **EID 20 WmiEventConsumer** - fields `Type`, `Name`, `Destination`. `Type = CommandLine` or `Type = ActiveScript` pointing at an interpreter or a path in `\Users\`/`\ProgramData\` is high-confidence.
- **EID 21 WmiEventConsumerToFilter** - the binding that confirms an armed subscription.

Sigma-style hunt:

```yaml
title: WMI Permanent Event Subscription - Suspicious Consumer
logsource:
  product: windows
  service: sysmon
detection:
  consumer:
    EventID: 20
  suspicious:
    Destination|contains:
      - 'rundll32'
      - 'regsvr32'
      - 'powershell'
      - 'mshta'
      - 'wscript'
      - 'cscript'
      - '\Users\'
      - '\ProgramData\'
      - '\Temp\'
  condition: consumer and suspicious
level: high
```

### Native Windows event logs

- **System 7045** (Service Control Manager) - always logged, no audit policy needed. Fields: `Service Name`, `Image Path`, `Service Type`, `Service Start Type`, `Account Name`. Baseline expected service installs; alert on the rest.
- **Security 4697** (a service was installed) - requires "Audit Security System Extension". Same intent as 7045, in the Security log, attributed to the installing subject.
- **Security 4698 / 4699 / 4700 / 4701 / 4702** - scheduled task created / deleted / enabled / disabled / updated. Requires "Audit Other Object Access Events". 4698 embeds the full task XML including the action command - parse it.
- **Microsoft-Windows-TaskScheduler/Operational** - 106 (registered), 140 (updated), 141 (deleted), 200/201 (action run start/complete). Always available when the operational channel is enabled; 200 gives you the executed image path even when Security auditing is off.
- **Security 4688 / Sysmon EID 1** - process creation. Catch the *tooling*: `schtasks.exe`, `sc.exe`, `reg.exe`, `wmic.exe` with persistence arguments, and catch the *execution* lineage: payloads spawned by `WmiPrvSE.exe`, `userinit.exe`, `svchost.exe`, or signed LOLBins loading user-path DLLs.

### KQL (Defender / Sentinel) hunts

```kql
// New service installs - SCM 7045 from System log
DeviceEvents
| where ActionType == "ServiceInstalled"
| project Timestamp, DeviceName, InitiatingProcessAccountName, AdditionalFields
| where AdditionalFields has_any ("\\Users\\", "\\ProgramData\\", "\\Temp\\", "rundll32", "regsvr32")
```

```kql
// Run-key writes to user-writable payload paths
DeviceRegistryEvents
| where ActionType in ("RegistryValueSet")
| where RegistryKey has @"\CurrentVersion\Run" or RegistryKey has @"\CurrentVersion\RunOnce"
| where RegistryValueData has_any ("\\Users\\", "\\ProgramData\\", "\\Temp\\", "\\Public\\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

### osquery

osquery aggregates most autostart locations into one virtual table - run it on an interval and diff snapshots.

```sql
-- everything Autoruns-style in one shot
SELECT name, path, source, status, username FROM autoexec;
```

```sql
-- WMI permanent subscriptions
SELECT * FROM wmi_cli_event_consumers;
SELECT * FROM wmi_script_event_consumers;
SELECT * FROM wmi_event_filters;
SELECT consumer, filter FROM wmi_filter_consumer_binding;
```

```sql
-- services with binaries in user-writable paths
SELECT name, display_name, path, start_type, user_account
FROM services
WHERE path LIKE '%\Users\%' OR path LIKE '%\ProgramData\%' OR path LIKE '%\Temp\%';
```

```sql
-- scheduled tasks with their actions
SELECT name, action, path, enabled, hidden FROM scheduled_tasks
WHERE hidden = 1 OR action LIKE '%rundll32%' OR action LIKE '%regsvr32%' OR action LIKE '%powershell%';
```

### Registry FIM and on-disk artifacts

Watch these paths/files with a FIM or registry SACL so content changes (not just new objects) are caught:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\SYSTEM\CurrentControlSet\Services\*
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\*
HKCU\Software\Classes\CLSID\*\InprocServer32
C:\Windows\System32\Tasks\*
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*
%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\*
C:\Windows\System32\wbem\Repository\OBJECTS.DATA   (WMI repository - changes when a subscription is added)
```

Hunt methodology that catches the "blend in" variant: presence-based enumeration (Autoruns, osquery `autoexec`) only finds *new* objects. To catch a modified existing autostart (a swapped `.lnk` target, a replaced DLL loaded by an existing service), you need content hashing - baseline the hashes of every binary referenced by an autostart entry, then alert when a referenced binary's hash changes without a corresponding software-update event. Cross-reference the executed image's signature status (Sysmon EID 7 image-load signature fields) against expected, and treat any signed-host-process loading an unsigned DLL from a user-writable directory as a COM-hijack / sideload candidate.

## MITRE ATT&CK

- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.005** - Scheduled Task/Job: Scheduled Task
- **T1543.003** - Create or Modify System Process: Windows Service
- **T1546.003** - Event Triggered Execution: Windows Management Instrumentation Event Subscription
- **T1546.015** - Event Triggered Execution: Component Object Model Hijacking
- **T1037.001** - Boot or Logon Initialization Scripts: Logon Script (Windows)
- **T1112** - Modify Registry
- **T1574.002** - Hijack Execution Flow: DLL Side-Loading (relevant to COM hijack payload delivery)

## References

- MITRE ATT&CK, Persistence tactic (TA0003) and the technique pages above - https://attack.mitre.org/tactics/TA0003/
- Microsoft, Sysmon documentation (event IDs 1, 7, 11, 12-14, 19-21) - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft, Autoruns for Windows - https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- Microsoft, Audit Other Object Access Events (4698 family) - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698
- Microsoft, Event 7045 and Audit Security System Extension (4697) - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697
- Mandiant / FireEye, "WMI vs. WMI: Monitoring for Malicious Activity" - https://cloud.google.com/blog/topics/threat-intelligence/wmi-vs-wmi-monitoring-malicious-activity/
- osquery schema (autoexec, services, scheduled_tasks, wmi_* tables) - https://osquery.io/schema/
- Microsoft, schtasks.exe and sc.exe command references - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks
