# Windows EDR Evasion: AMSI, ETW & Script-Block Logging

*The script and EDR visibility layer on Windows, treated conceptually from the offense side and authoritatively from the defense side - because on a modern endpoint, every "bypass" of these controls is itself a loud, well-instrumented event.*

## What & why

On modern Windows the runtime-visibility stack - AMSI, ETW, and PowerShell logging - is the primary reason script-based tradecraft gets caught. The operator goal is to understand what each layer actually sees so you can predict your own footprint, not to "defeat" controls that are themselves heavily instrumented. The OPSEC rationale is inverted from the naive view: tampering with AMSI or ETW is not stealth, it is a high-signal action that good EDR detects directly (it watches for the patch). The durable play is staying inside allowed, expected behavior so you never trip the high-confidence "someone disabled my telemetry" alerts. This page is defense-aware: the offensive material is conceptual and the detection material is the deliverable. For the same lesson on Linux (base64/`-e`-encoded payloads do not hide from the shell-history and `execve` audit trail) see [../linux/04-shell-history-and-auditd.md](../linux/04-shell-history-and-auditd.md). For Windows process-creation telemetry that underpins much of this, see [04-process-creation-telemetry.md](04-process-creation-telemetry.md).

## Technique

### AMSI: the in-process scan chokepoint

The Antimalware Scan Interface (AMSI) is a Windows API surface (`amsi.dll`, introduced Windows 10 / Server 2016) that lets a registered antimalware provider scan content *after* it has been decoded and assembled in memory but *before* it executes. It is consumed by:

- PowerShell (both `powershell.exe` and any host loading `System.Management.Automation.dll`)
- the Windows Script Host engines: VBScript and JScript (`vbscript.dll`, `jscript.dll`/`jscript9.dll`)
- Office VBA macros (Office 2016+ with AMSI integration enabled)
- the .NET runtime via `Assembly.Load(byte[])` of dynamically loaded assemblies (Windows 10 1809 / .NET Framework 4.8+), which is what catches in-memory C# tradecraft (`Assembly.Load` of a byte array triggers `AmsiScanBuffer`)
- WMI and other script consumers that opt in

The chokepoint is the call path through `amsi.dll`:

```text
host (PowerShell / WSH / VBA / CLR)
  -> AmsiScanBuffer(amsiContext, buffer, length, contentName, session, *result)
  -> registered provider (e.g. MsMpEng via MpOav.dll for Defender)
  -> AMSI_RESULT  (AMSI_RESULT_CLEAN .. AMSI_RESULT_DETECTED, >= 32768 == block)
```

The critical property for the operator: AMSI scans the *deobfuscated, reconstructed* content. String concatenation, `-EncodedCommand` base64, gzip-in-memory, `IEX (New-Object Net.WebClient).DownloadString(...)`, `Invoke-Expression` of a built-up string - all of these are reassembled into a buffer that is handed to `AmsiScanBuffer` at the moment of evaluation. Obfuscation changes the static bytes on disk and on the wire; it does not change what AMSI sees at the instant of execution. This is the Windows parallel to the Linux base64 lesson: encoding moves the detection point, it does not remove it.

### What "AMSI bypass" actually means (conceptual)

Public AMSI-bypass research falls into a few mechanism classes. Naming them matters only so the defender knows what artifacts each produces:

- **In-process memory patch** of `AmsiScanBuffer` / `AmsiOpenSession` so the function returns `AMSI_RESULT_CLEAN` or an error without scanning. This requires `VirtualProtect` to flip a code page in `amsi.dll` to writable, then writing a few bytes.
- **Context/field corruption** - zeroing or corrupting the `amsiContext` so the provider errors out and the host fails open.
- **Provider de-registration / forced-error** approaches that make the scan return an error the host treats as clean.
- **Load-order / DLL approaches** that influence which `amsi.dll` or provider is loaded.

The key defensive fact: each of these is itself observable. Patching `amsi.dll` flips a normally-execute-only page to RW/RWX in a signed Microsoft module, which is exactly what behavioral EDR and AMSI's own anti-tamper telemetry are built to flag. Microsoft Defender ships specific signatures (for example the `HSTR`/behavioral detections historically reported as `Trojan:Win32/Powessere`, `Behavior:Win32/AmsiTamper`, and similar) that fire on common patch byte patterns and on the act of tampering with the scan interface.

### ETW: the user-mode telemetry backbone

Event Tracing for Windows (ETW) is the high-throughput logging fabric that feeds most EDR sensors in user mode. Relevant providers:

- **Microsoft-Windows-Threat-Intelligence** (`{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`) - a protected, EDR-oriented provider surfacing sensitive kernel-side events (memory allocation, remote thread creation, certain syscall activity). Consumers must run as a Protected Process Light (PPL) antimalware service; ordinary code cannot subscribe.
- **Microsoft-Windows-DotNETRuntime** / **DotNETRuntimeRundown** - CLR events including `AssemblyLoad`, JIT, and method events. This is how .NET in-memory loading (e.g. reflective `Assembly.Load`) becomes visible.
- **Microsoft-Windows-PowerShell** (`{A0C1853B-5C40-4B15-8766-3CF1C58F985A}`) - the ETW side of PowerShell's logging, carrying pipeline and script-block events that also land in the event log.
- **Microsoft-Windows-Kernel-Process**, **Kernel-Audit-API-Calls**, **WMI-Activity**, **DNS-Client**, and others used for correlation.

"ETW patching" or "ETW blinding" in offensive tooling usually means patching `ntdll!EtwEventWrite` (or `EtwEventWriteFull`/`NtTraceEvent`) in the current process so events are never emitted to consumers. There is also the user-mode `EtwEventWrite` no-op patch and, at a broader scope, attempts to stop or reconfigure the trace session.

The defensive reality: patching `EtwEventWrite` only blinds *user-mode* providers *in the patched process*. It does not touch the kernel. Microsoft-Windows-Threat-Intelligence is sourced kernel-side and delivered to a PPL consumer, so a user-mode ETW patch does not suppress it. Good EDR therefore (a) keeps a kernel-side data path that survives user-mode tampering and (b) treats the patch of `ntdll` itself as a detection - a writable `.text` page in `ntdll.dll` is anomalous. Stopping or reconfiguring an autologger/trace session also generates its own audit trail (see Detection).

### PowerShell logging tiers

PowerShell exposes layered logging, configured via Group Policy or registry under `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\` (and the matching `SOFTWARE\Wow6432Node` path):

- **Module logging** (`ModuleLogging`) - records pipeline execution events (EID 4103 in `Microsoft-Windows-PowerShell/Operational`) for configured modules. Captures command invocation and parameter binding.
- **Script Block Logging** (`ScriptBlockLogging`) - the heavy hitter. Logs **EID 4104** in `Microsoft-Windows-PowerShell/Operational`. It records the **decoded, deobfuscated** text of every script block PowerShell compiles. This is the central fact of this page: when you run `powershell -EncodedCommand <base64>`, PowerShell decodes the base64 to UTF-16, compiles the script block, and *that compiled source* is what 4104 records. The base64 never appears as a barrier - the cleartext does. PowerShell additionally has a "suspicious script block" heuristic that can force 4104 logging of certain content even when Script Block Logging is not fully enabled, and warning-level 4104 events flag content matching known-suspicious patterns.
- **Transcription** (`Transcription`) - writes full input/output transcripts to a file (configurable `OutputDirectory`), useful for after-the-fact reconstruction and resilient because it captures rendered output.
- **Constrained Language Mode (CLM)** - `$ExecutionContext.SessionState.LanguageMode`. Under `ConstrainedLanguage`, many .NET type and method calls used by offensive tooling are blocked. When enforced by WDAC/AppLocker policy (not merely set as a session variable), it is a meaningful control; set purely via environment variable it is trivially reset and should not be relied on.

#### Why -EncodedCommand and base64 do not hide from 4104

```powershell
# Loud: a base64 -EncodedCommand still lands in EID 4104 as DECODED text.
$cmd = 'Write-Output "lab-only marker 203.0.113.10"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -EncodedCommand $enc
# Script Block Logging (4104) records:  Write-Output "lab-only marker 203.0.113.10"
# Process creation (4688 / Sysmon EID 1) records the base64 on the command line.
# So you are visible TWICE: once obfuscated (cmdline) and once in cleartext (4104).
```

The same holds for `IEX`, `FromBase64String`, gzip/deflate-in-memory, and string-concatenation obfuscation: the compiler sees the assembled script block and 4104 logs it. Multi-layer obfuscation tends to *increase* signal because each `Invoke-Expression`/`.Invoke()` of a freshly-built string produces another distinct 4104 event, and the heuristic flags the patterns.

### Verifying your own footprint (lab)

```powershell
# Confirm Script Block Logging state (lab box, run elevated).
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue

# Inspect current language mode.
$ExecutionContext.SessionState.LanguageMode

# Read back your own 4104 events to see exactly what the defender sees.
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 20 |
  Where-Object Id -eq 4104 | Select-Object TimeCreated, Id, @{n='Text';e={$_.Message}}
```

## OPSEC notes

- **The loud version** is anything that tampers with the visibility layer: patching `amsi.dll`/`AmsiScanBuffer`, patching `ntdll!EtwEventWrite`, forcing AMSI to fail open, killing or reconfiguring an ETW autologger, or registry-disabling Script Block Logging. Each maps to a specific, high-confidence detection. Memory patches of signed Microsoft modules (`amsi.dll`, `ntdll.dll`) are especially loud because the page-protection change and resulting RWX/RW region in a signed image is exactly what EDR memory-scanners hunt.
- **The quiet variant** is to not generate the alert at all: prefer signed, expected tooling and built-in capability; avoid `Invoke-Expression` of attacker-built strings; avoid in-memory .NET assembly loads on hosts where you expect EDR to be watching CLR ETW; stay in CLM-allowed behavior on locked-down hosts rather than trying to break out. The genuinely quiet move is choosing actions that look like administration, not breaking the cameras.
- **Failure modes and tells:**
  - An AMSI patch that returns the wrong constant or corrupts context can crash the host process - a `powershell.exe` crash with an `amsi.dll` faulting module is its own alert (WER / EID 1000).
  - Patching ETW in user mode gives a false sense of cover: kernel-sourced Threat-Intelligence events still flow to the PPL EDR, so the operator believes they are blind while remaining fully visible.
  - Disabling Script Block Logging via registry is logged (registry-modification telemetry + the Operational channel noticing logging state change), and the *absence* of expected 4104 volume from a host is itself a hunt signal.
  - Many "bypass" snippets are themselves famous strings; AMSI/Defender flag the bypass payload before it runs, so the attempt is detected on the way in.

## Detection & telemetry

This is the section that matters. Map each offensive action to concrete artifacts.

### PowerShell Script Block Logging - EID 4104 (primary)

- **Log source:** `Microsoft-Windows-PowerShell/Operational` (file: `%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`).
- **Event ID 4104** = script block compiled. **Field of interest:** `ScriptBlockText` (the decoded source), plus `ScriptBlockId`, `MessageNumber`/`MessageTotal` (large blocks are split across events - reassemble by `ScriptBlockId`). Level **3 (Warning)** 4104 events are the suspicious-pattern hits.
- **Companion IDs:** **4103** (module/pipeline logging), **4100** (error), **400/403/600** in the legacy `Windows PowerShell` classic log (engine state, provider start - useful for spotting downgrade to v2).
- Because 4104 logs decoded content, hunt the cleartext, not the base64.

Splunk-style hunt for decoded-payload indicators in 4104:

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| eval txt=lower(ScriptBlockText)
| search txt IN ("*frombase64string*","*::loadmodule*","*amsiinitfailed*","*[ref].assembly*",
                 "*system.management.automation.amsiutils*","*invoke-expression*","*downloadstring*",
                 "*-encodedcommand*","*reflection.assembly*","*virtualprotect*","*etweventwrite*")
| table _time host ScriptBlockId MessageNumber MessageTotal ScriptBlockText
```

KQL (Microsoft Defender XDR / Sentinel) equivalent:

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
   or (ActionType == "ScriptContent")
| where AdditionalFields has_any ("AmsiUtils","amsiInitFailed","FromBase64String","VirtualProtect","EtwEventWrite")
| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields
```

Sigma-style logic (pseudo):

```yaml
title: PowerShell 4104 AMSI/ETW Tamper Indicators
logsource: { product: windows, service: powershell }
detection:
  sel:
    EventID: 4104
    ScriptBlockText|contains:
      - 'System.Management.Automation.AmsiUtils'
      - 'amsiInitFailed'
      - 'EtwEventWrite'
      - 'VirtualProtect'
      - '[Ref].Assembly.GetType'
  condition: sel
level: high
```

### Downgrade and host-tampering signals

- **PowerShell v2 downgrade** (`powershell -version 2`) evades v5 Script Block Logging because the v2 engine predates it. Detect via classic `Windows PowerShell` log **EID 400** with `EngineVersion=2.0`, and via process-creation telemetry showing `-version 2` / `-v 2` on the command line. Flag any v2 engine start on a host that has the v2 feature otherwise unused.
- **Logging-policy tampering:** registry writes under `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` (Sysmon **EID 13** registry value set; or `DeviceRegistryEvents` in Defender). Alert on `EnableScriptBlockLogging` being set to `0` or the key being deleted.

### AMSI telemetry and tamper detection

- **AMSI provider events:** with AMSI logging enabled, Defender records the scan verdicts; in Defender XDR these surface as alerts such as "An active 'AMSI' bypass was detected" / `Behavior:Win32/AmsiTamper.*` and `Trojan:Win32/*` signatures on known bypass byte patterns. Microsoft Defender Antivirus events live in `Microsoft-Windows-Windows Defender/Operational` (e.g. **EID 1116** malware detected, **EID 1117** action taken).
- **`amsi.dll` memory patch:** the tell is a private, modified, or RW/RWX region overlapping the on-disk `amsi.dll` image. Hunt with EDR memory scanning and with image/region anomaly detections. The act of `VirtualProtect`-ing an `amsi.dll` code page to writable is the high-signal primitive.
- **Host crash fallout:** an `AmsiScanBuffer` patch gone wrong yields Application Error **EID 1000** in the `Application` log with `amsi.dll` as the faulting module - a cheap, reliable hunt for botched bypasses.

osquery to surface modules and signing state for a process of interest (point-in-time):

```sql
-- Modules loaded by a powershell process; cross-check for unexpected/unsigned amsi providers.
SELECT p.pid, p.name, m.path, s.result AS sig
FROM processes p
JOIN process_memory_map m ON m.pid = p.pid
LEFT JOIN authenticode s ON s.path = m.path
WHERE p.name = 'powershell.exe' AND m.path LIKE '%amsi%';
```

### ETW tamper detection

- **User-mode `EtwEventWrite` patch:** detect via memory-integrity checks on `ntdll.dll` - a modified/writable `.text` page or a private copy of `ntdll` in a process is anomalous. Many EDRs raise a dedicated "ETW tamper"/"telemetry tampering" alert on this primitive.
- **Kernel-side resilience:** Microsoft-Windows-Threat-Intelligence (`{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`) keeps emitting to the PPL EDR consumer even when user-mode ETW is patched. Defenders should ensure their sensor consumes a kernel-sourced path (TI provider, ETW-TI, or a minifilter/callback-based sensor) so a user-mode patch does not blind them.
- **Autologger / session tampering:** stopping or reconfiguring a trace session leaves registry artifacts under `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\` (Sysmon EID 13 / registry telemetry) and `logman`/`wevtutil` process-creation events. Alert on modification of EDR-owned autologger keys.

### .NET in-memory load telemetry

- **CLR `AssemblyLoad` via ETW** (Microsoft-Windows-DotNETRuntime) surfaces dynamically loaded assemblies, including reflective `Assembly.Load(byte[])`. In Defender this appears under load/CLR events; correlate an in-memory assembly load with no corresponding file on disk as a strong indicator of tradecraft.
- **AMSI for .NET:** the same `Assembly.Load(byte[])` triggers `AmsiScanBuffer` on the assembly bytes (Windows 10 1809+/.NET 4.8+), so a malicious in-memory assembly can be caught by AMSI *and* logged by CLR ETW simultaneously.

### Process-creation cross-reference

Always correlate the above with process creation: **Security EID 4688** (with command-line auditing enabled) and **Sysmon EID 1** capture `powershell.exe` command lines including `-EncodedCommand`, `-version 2`, `-w hidden`, and `-nop`. Sysmon **EID 7** (image load) captures `amsi.dll`/`clr.dll` loads; Sysmon **EID 8** (CreateRemoteThread) and **EID 10** (ProcessAccess) catch the injection that often precedes an in-process AMSI/ETW patch. See [04-process-creation-telemetry.md](04-process-creation-telemetry.md) for the full command-line auditing setup.

### Defensive baseline checklist

- Enable Script Block Logging and Module Logging via GPO; ship `Microsoft-Windows-PowerShell/Operational` to the SIEM and retain 4104 at scale.
- Enforce CLM through WDAC/AppLocker, not session variables.
- Enable command-line process auditing (4688) and deploy Sysmon with image-load and registry config.
- Ensure the EDR sensor consumes a kernel-sourced telemetry path (ETW-TI) so user-mode ETW patches do not blind it.
- Alert specifically on: registry disablement of PowerShell logging, PowerShell v2 engine starts, `amsi.dll`/`ntdll.dll` memory modification, and AMSI/Defender tamper signatures.

## MITRE ATT&CK

- **T1562.001** - Impair Defenses: Disable or Modify Tools (AMSI/ETW patching, disabling Defender features)
- **T1562.002** - Impair Defenses: Disable Windows Event Logging
- **T1562.006** - Impair Defenses: Indicator Blocking (ETW blinding / telemetry tampering)
- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1059.005** - Command and Scripting Interpreter: Visual Basic (VBScript/VBA)
- **T1059.007** - Command and Scripting Interpreter: JavaScript (JScript)
- **T1027** - Obfuscated Files or Information (base64 `-EncodedCommand`, in-memory deobfuscation)
- **T1140** - Deobfuscate/Decode Files or Information
- **T1620** - Reflective Code Loading (in-memory .NET assembly load)
- **T1055** - Process Injection (delivery vector for in-process AMSI/ETW patches)

## References

- Microsoft - Antimalware Scan Interface (AMSI) overview and `IAntimalware`/`AmsiScanBuffer` API. https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
- Microsoft - `AmsiScanBuffer` function reference. https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer
- Microsoft - About PowerShell Script Block Logging and logging tiers. https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Microsoft - Event Tracing for Windows (ETW) documentation. https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
- FireEye/Mandiant - "Greater Visibility Through PowerShell Logging" (4103/4104 and decoded script-block behavior). https://cloud.google.com/blog/topics/threat-intelligence/greater-visibility-through-powershell-logging
- MITRE ATT&CK - T1562.001 Impair Defenses: Disable or Modify Tools. https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK - T1059.001 Command and Scripting Interpreter: PowerShell. https://attack.mitre.org/techniques/T1059/001/
- SwiftOnSecurity / Olaf Hartong - Sysmon configuration references for image-load and registry telemetry. https://github.com/olafhartong/sysmon-modular
