# Windows Process Stealth & Masquerading

_Disguising process lineage, identity, and command line on Windows - and the kernel-backed telemetry that still names the real creator._

## What & why

The goal is to make a process launched by an operator blend into the normal noise of a Windows host: a benign-looking parent, a benign-looking image name and path, and a benign-looking command line, so that a human triaging an alert sees `svchost.exe` under `services.exe` and moves on. The OPSEC rationale is that most analyst triage and many correlation rules key on the visible string fields of a process-create event - parent image, target image name, command line - rather than on the harder-to-forge facts of who actually issued the `NtCreateUserProcess` syscall and what code is mapped into the process. The catch, and the reason this page is mostly a detection page, is that the Windows kernel records the real creating process independently of any attribute the operator sets, EDR sensors hook the same syscall path, and ETW emits the true lineage and image-load chain. Masquerading defeats lazy eyeballing. It does not defeat a sensor that reads the authoritative fields.

## Technique

### Parent PID spoofing (reparenting)

A child normally inherits its parent from the process that calls `CreateProcess`. The Win32 process-creation attribute list lets a caller override the recorded parent by passing a handle to an arbitrary process via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. The high-level flow:

1. `OpenProcess(PROCESS_CREATE_PROCESS, ...)` on the desired fake parent (commonly `explorer.exe` or a `svchost.exe`). This requires a handle with `PROCESS_CREATE_PROCESS` rights - a privilege check that itself is observable.
2. `InitializeProcThreadAttributeList` then `UpdateProcThreadAttribute` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, passing the fake parent handle.
3. `CreateProcess` with `EXTENDED_STARTUPINFO_PRESENT` and the populated `STARTUPINFOEX`.

The new process now shows the spoofed parent in `Parent Process ID` (`PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId`) and in tools that read it (Task Manager, Process Explorer, naive EDR fields). Operationally this is used to make a payload appear to descend from `explorer.exe` (user activity) or from a service host, breaking parent-child heuristics that flag, for example, `winword.exe -> powershell.exe`.

What does NOT change:

- The token. The child still inherits the calling process token unless the operator also passes a duplicated/primary token. A reparented child under `explorer.exe` running with a SYSTEM integrity token is a contradiction a sensor can catch.
- The real creator. The kernel and EDR mini-filter / ETW see the process that actually called the syscall.

### Image masquerading (name, path, and signature tricks)

Several distinct tricks, often combined:

- **Name reuse from a non-standard path.** Drop a binary named `svchost.exe` or `lsass.exe` somewhere writable - `%TEMP%`, `%APPDATA%`, `C:\Users\Public`, a fake `C:\Windows\System32\` lookalike using a trailing space or homoglyph - and run it. The image name matches a trusted system process but the path is wrong. The canonical legitimate paths are `C:\Windows\System32\svchost.exe` and `C:\Windows\System32\lsass.exe`; anything else with those names is suspect by definition.
- **Path masquerading.** Use `C:\Windows \System32\` (note the space before `\System32`) or a directory the loader will still resolve, exploiting that some tools normalize paths and some do not.
- **Signed-binary masquerade / LOLBins.** Rather than a fake binary, abuse a legitimately signed Microsoft binary (`rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `installutil.exe`) to carry execution. The image is genuinely Microsoft-signed, so naive signature checks pass; the tell is the command line and the loaded modules, not the image hash.
- **PE metadata spoofing.** Editing version-info resources (`OriginalFilename`, `CompanyName`) so the binary claims to be a Microsoft product. This forges the strings inside the PE but not the Authenticode signature - a mismatch between claimed publisher and actual signing status is itself a signal.

The durable tell across all of these is the mismatch: a process named like a system component whose **path**, **signing status**, **parent**, **session**, or **integrity level** does not match what the real component always uses. `lsass.exe` should run once, as a SYSTEM-integrity child of `wininit.exe`, from `System32`, signed by Microsoft. Any `lsass.exe` violating one of those invariants is anomalous.

### Command-line spoofing and tampering

Two variants:

- **Argument spoofing.** Create the process suspended with a benign command line, then before the main thread runs, overwrite the in-memory `RTL_USER_PROCESS_PARAMETERS.CommandLine` (and sometimes `ImagePathName`) in the child's PEB so that anything reading the PEB after the fact sees the benign string while the process actually ran with attacker-controlled arguments. This targets sensors that read the command line lazily from the PEB rather than capturing it at creation.
- **Argument confusion.** Use quoting, environment-variable expansion, or trailing-argument tricks so the logged command line differs from what the parser executes.

The decisive countermeasure: process-create command-line capture happens **at creation time in the kernel callback path**, before any user-mode PEB tampering can run. Sysmon Event ID 1 and Security Event ID 4688 (with the "Include command line in process creation events" policy enabled) record the command line as passed to the create call. PEB patching that occurs after the suspended create does not retroactively edit those already-emitted events. So PEB spoofing can fool a later memory read but not the creation-time log.

### Process hollowing and injection (high level)

These move beyond masquerading into running foreign code inside a legitimate process image. Conceptually:

1. `CreateProcess` with `CREATE_SUSPENDED` so the target (often a real signed binary) is mapped but not running.
2. Unmap or overwrite the original image - classic hollowing uses `NtUnmapViewOfSection` (or `ZwUnmapViewOfSection`) on the image base; variants ("process doppelganging", "process ghosting", "transacted hollowing", "module stomping") avoid the unmap to dodge that specific signal.
3. `VirtualAllocEx` / `WriteProcessMemory` to place attacker code, fix relocations, set the thread entry point (`SetThreadContext` to repoint RIP/EIP, or queue an APC), then `ResumeThread`.

Remote thread injection variants use `OpenProcess` -> `VirtualAllocEx` -> `WriteProcessMemory` -> `CreateRemoteThread` (or `NtCreateThreadEx`, `QueueUserAPC`, thread hijacking). The signals these emit are covered below; weaponization detail is deliberately out of scope here.

### Token manipulation (basics)

Used to make a process appear to belong to a different user or to gain privileges while keeping the visible image benign:

- **Token impersonation / theft.** `OpenProcessToken` on a process owning a desirable token, `DuplicateTokenEx`, then `ImpersonateLoggedOnUser` or `CreateProcessWithTokenW` (needs `SeImpersonatePrivilege`) / `CreateProcessAsUserW` (needs `SeAssignPrimaryTokenPrivilege`).
- **Make-and-impersonate.** `LogonUserW` with captured credentials to mint a fresh token.

The mismatch tells: a process whose token user, logon session, or integrity level is inconsistent with its parent and image. A SYSTEM token suddenly appearing under an interactive `explorer.exe` lineage, or a privilege set on a token that the parent did not hold, is the artifact.

## OPSEC notes

What makes the loud version loud:

- Dropping a fake `lsass.exe`/`svchost.exe` to disk in a writable path creates a file-create event, a likely AV scan, and a process whose path fails the System32 invariant instantly. This is the noisiest possible masquerade.
- `CreateRemoteThread` into another process is one of the most heavily instrumented operations on Windows; classic hollowing's `NtUnmapViewOfSection` plus a fresh `WriteProcessMemory` of an entire image into a suspended process is a textbook EDR detection.
- RWX (`PAGE_EXECUTE_READWRITE`) private memory regions and executable memory not backed by any image file on disk are strong, low-false-positive injection signals.
- A reparented child whose token integrity or session ID contradicts the spoofed parent is self-defeating - the contradiction is more anomalous than no spoofing at all.

The quiet variants and their cost:

- Prefer genuinely Microsoft-signed LOLBins from their real System32 paths over dropped fakes, so image name, path, and signature are all internally consistent; the residual signal moves entirely to command line and loaded modules.
- For injection, techniques that avoid `CreateRemoteThread` and avoid `NtUnmapViewOfSection` (thread hijacking, APC, module stomping into already-mapped image memory) reduce the count of high-signal API calls but do not eliminate cross-process memory writes, which the ETW Threat-Intelligence provider surfaces.
- Reparent only to a parent whose token, session, and integrity you can match.

Failure modes and tells, restated bluntly: signed-binary masquerade beats naive AV and tired analysts; it loses to behavioral EDR that correlates the authentic parent, the captured-at-creation command line, image-load (module) telemetry, and memory-region characteristics. The string fields you can forge are exactly the fields a competent sensor does not trust alone.

## Detection & telemetry

This is the section that matters. Masquerading edits strings; the sensors below read authoritative fields and behaviors.

### Sysmon (Microsoft-Windows-Sysmon/Operational)

- **Event ID 1 - Process Create.** Carries `Image`, `OriginalFileName` (from the PE version resource - compare against `Image`), `CommandLine` (captured at creation, defeats PEB spoofing), `CurrentDirectory`, `User`, `IntegrityLevel`, `ParentProcessId`, `ParentImage`, `ParentCommandLine`, and hashes (`MD5`/`SHA256`/`IMPHASH` per config). Key hunts: image name equal to a system binary but `Image` path not under `C:\Windows\System32`; `OriginalFileName` not matching `Image`; `lsass.exe`/`svchost.exe`/`services.exe` with an unexpected `ParentImage`.
  - Note on reparenting: Sysmon's `ParentProcessId`/`ParentImage` reflect the spoofed parent because Sysmon reads the same `PPID` field. The real creator is not in EID 1; you recover it from the kernel/EDR/ETW (see below) or by correlating that the spoofed "parent" never actually created a child at that timestamp.
- **Event ID 7 - Image Loaded.** Module loads with `ImageLoaded`, `Signed`, `Signature`, `SignatureStatus`, and `Hashes`. Use to catch unsigned or unexpected DLLs loaded into a process masquerading as a system component, and to spot `clr.dll`/`amsi.dll`/`mscoree.dll` loading into a process that has no business hosting .NET. See [EDR, AMSI & ETW internals](02-edr-amsi-etw.md) for the AMSI/CLR angle.
- **Event ID 8 - CreateRemoteThread.** `SourceImage`, `TargetImage`, `NewThreadId`, `StartAddress`, `StartModule`, `StartFunction`. A start address that resolves to no module (`StartModule` empty) is a strong injection signal. This is the primary cross-process thread-injection artifact.
- **Event ID 10 - ProcessAccess.** `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`. Tuned to `lsass.exe` as a target, this catches credential-access and injection precursors. High-signal `GrantedAccess` masks include `0x1010`/`0x1410`/`0x1438`/`0x143a` (combinations of `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_QUERY_INFORMATION`); inspect `CallTrace` for frames in `UNKNOWN` regions (unbacked memory).
- **Event ID 25 - Process Tampering.** Sysmon flags image tampering consistent with hollowing/herpaderping/ghosting (`Type` such as `Image is replaced` / `Image is locked for access`). Directly relevant to the hollowing section above.

Minimal Sysmon config intent (illustrative):

```xml
<!-- Sysmon config fragment: name masquerade and lsass access -->
<RuleGroup name="masquerade" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="end with">\svchost.exe</Image>
    <!-- then exclude the legitimate System32 path so only odd-path svchost survives -->
  </ProcessCreate>
</RuleGroup>
<RuleGroup name="lsass-access" groupRelation="or">
  <ProcessAccess onmatch="include">
    <TargetImage condition="image">lsass.exe</TargetImage>
  </ProcessAccess>
</RuleGroup>
```

### Windows Security log (Security.evtx)

- **Event ID 4688 - A new process has been created.** Requires "Audit Process Creation" (Detailed Tracking) to be enabled; the `CommandLine` field requires the additional policy "Include command line in process creation events" (`ProcessCreationIncludeCmdLine_Enabled`). Fields: `NewProcessName`, `ProcessCommandLine`, `CreatorProcessId`, `CreatorProcessName`, `TokenElevationType`, `SubjectUserSid`. Like Sysmon EID 1, the command line is captured at creation and is not retroactively altered by PEB tampering.
  - Reparenting nuance: `CreatorProcessName`/`CreatorProcessId` in 4688 reflect the process that issued the create call as the kernel saw it. In practice this field is populated from the creating process, which is why 4688 is a useful cross-check against a spoofed Sysmon `ParentImage` - a divergence between the 4688 creator and the Sysmon parent on the same new PID is itself the tell that PPID spoofing occurred.
- **Event ID 4689 - process exit**, and **4674 / 4673** (privileged service / sensitive privilege use) help corroborate token-manipulation activity such as use of `SeDebugPrivilege` or `SeImpersonatePrivilege`.
- **Event ID 4624 / 4672** - logon and "special privileges assigned to new logon"; correlate a new SYSTEM-token process against whether a matching privileged logon actually occurred.

Enable the policy:

```cmd
:: Run as admin. Turn on process-create auditing and command-line capture.
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### ETW providers (the authoritative layer)

- **Microsoft-Windows-Threat-Intelligence (ETW-TI).** A protected, EDR-only provider that surfaces sensitive kernel operations: cross-process memory allocation/write/protect changes (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`), remote thread creation, and `NtUnmapViewOfSection`. This is where injection and hollowing that avoided user-mode API hooks still get caught, because the events originate below user mode. Consumption requires an early-launch/anti-malware (ELAM) PPL signature, so it is available to AV/EDR, not arbitrary tooling.
- **Microsoft-Windows-Kernel-Process** (provider GUID `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`). Emits `ProcessStart`/`ProcessStop` with the genuine parent PID and image, independent of any Win32 PPID attribute. This is a primary source for reconstructing true lineage when PPID spoofing is suspected.
- **Microsoft-Windows-Kernel-Memory** and image-load events corroborate executable regions not backed by a file on disk - the defining trait of injected/hollowed code.

### Memory and behavioral artifacts (EDR)

Regardless of which API was used, the residue of injection/hollowing is in memory and is what modern EDR scores on:

- Private (`MEM_PRIVATE`) committed regions with `PAGE_EXECUTE_READWRITE` or executable regions whose backing is not an on-disk image (`MEM_IMAGE` absent) - i.e. "floating" or "unbacked" executable memory.
- A hollowed process whose in-memory image base differs from, or is unmapped relative to, the file on disk (header/entry-point mismatch).
- A primary thread whose start address points into unbacked memory rather than the process's own image - directly observable via Sysmon EID 8 `StartModule` being empty and via EDR thread-creation telemetry.

### Hunt queries

osquery - processes whose path is not the canonical System32 location for a system image name:

```sql
SELECT p.pid, p.name, p.path, p.parent, pp.name AS parent_name
FROM processes p
LEFT JOIN processes pp ON p.parent = pp.pid
WHERE p.name IN ('svchost.exe','lsass.exe','services.exe','smss.exe','csrss.exe')
  AND LOWER(p.path) NOT LIKE 'c:\windows\system32\%'
  AND LOWER(p.path) NOT LIKE 'c:\windows\syswow64\%';
```

osquery - lsass should be a single child of wininit; flag anomalous lineage:

```sql
SELECT p.pid, p.path, p.parent, pp.name AS parent_name
FROM processes p
JOIN processes pp ON p.parent = pp.pid
WHERE p.name = 'lsass.exe'
  AND LOWER(pp.name) <> 'wininit.exe';
```

KQL (Microsoft Defender Advanced Hunting) - system-image masquerade by path:

```kql
DeviceProcessEvents
| where FileName in~ ("svchost.exe","lsass.exe","services.exe","smss.exe","csrss.exe")
| where FolderPath !startswith "C:\\Windows\\System32\\"
  and FolderPath !startswith "C:\\Windows\\SysWOW64\\"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessParentFileName, ProcessCommandLine
```

KQL - reparenting cross-check: a child claiming an explorer.exe parent but running at SYSTEM integrity:

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where ProcessIntegrityLevel in ("System","High")
| project Timestamp, DeviceName, FileName, ProcessIntegrityLevel,
          AccountName, InitiatingProcessAccountName, ProcessCommandLine
```

Splunk (Sysmon) - remote thread with unbacked start address:

```spl
index=sysmon EventCode=8
| search StartModule="" OR StartModule="UNKNOWN"
| stats count by SourceImage, TargetImage, StartAddress, NewThreadId, _time
```

Sigma-style rule sketch - lsass access for memory read by non-system tooling (express in your SIEM's dialect):

```yaml
title: Suspicious lsass.exe Process Access (memory read/write)
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: ['0x1010','0x1410','0x1438','0x143a']
  condition: selection
falsepositives:
  - AV/EDR agents, MSBuild/MMC, legitimate diagnostic tooling
level: high
```

Correlation that catches PPID spoofing directly: join Sysmon EID 1 (which shows the spoofed parent) against the Kernel-Process ETW `ProcessStart` (which shows the genuine parent) or against Security 4688 `CreatorProcessName`, on the new process PID and creation time. A divergence between the two parent values is the spoofing artifact - neither field alone proves it, the disagreement does.

## MITRE ATT&CK

- T1036 - Masquerading
  - T1036.003 - Rename System Utilities
  - T1036.005 - Match Legitimate Name or Location
- T1134 - Access Token Manipulation
  - T1134.002 - Create Process with Token
  - T1134.004 - Parent PID Spoofing
- T1055 - Process Injection
  - T1055.012 - Process Hollowing
  - T1055.002 - Portable Executable Injection
  - T1055.001 - Dynamic-link Library Injection
- T1564 - Hide Artifacts
- T1562.006 - Impair Defenses: Indicator Blocking (relevant when operators target the telemetry above)
- T1003.001 - OS Credential Dumping: LSASS Memory (the typical objective behind lsass-targeted ProcessAccess)

## References

- MITRE ATT&CK, Parent PID Spoofing (T1134.004). https://attack.mitre.org/techniques/T1134/004/
- MITRE ATT&CK, Masquerading: Match Legitimate Name or Location (T1036.005). https://attack.mitre.org/techniques/T1036/005/
- MITRE ATT&CK, Process Injection: Process Hollowing (T1055.012). https://attack.mitre.org/techniques/T1055/012/
- Microsoft Learn, Sysmon (Sysinternals) event reference - Event IDs 1, 7, 8, 10, 25. https://learn.microsoft.com/sysinternals/downloads/sysmon
- Microsoft Learn, Audit Process Creation and "Include command line in process creation events" policy. https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688
- Microsoft Learn, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS and UpdateProcThreadAttribute. https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
- Microsoft Learn, About Event Tracing / Microsoft-Windows-Threat-Intelligence consumption constraints (PPL/ELAM). https://learn.microsoft.com/windows/win32/etw/about-event-tracing
- SwiftOnSecurity sysmon-config, a community baseline for the rules above. https://github.com/SwiftOnSecurity/sysmon-config
