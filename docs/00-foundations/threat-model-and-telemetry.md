---
title: "Threat Model & Telemetry"
parent: "0. Foundations"
nav_order: 3
---

# The Defender Threat Model: What Actually Gets Collected

*A survey of modern defensive telemetry so the operator knows their adversary: where data is born, where it is forwarded, where it is stored, and where it is simply never collected.*

## What & why

Every action on a host or network either produces a record or it does not. The operator's job during an authorized engagement is to know, before acting, which of the two is true and where the resulting record lands. This page maps the defensive collection surface across host, network, and cloud so the rest of "Quiet Operator" can be specific about the artifacts each technique generates. The OPSEC rationale is simple: stealth is not the absence of evidence, it is the deliberate routing of activity into the gaps between sensors, the controls that are deployed but unconfigured, and the pipelines that buffer or drop under load. You cannot route around a sensor you do not know exists, and you cannot estimate detection risk without knowing whether a log is local-only, forwarded in near-real-time, or batched hourly. Treat this as the collection map the defender wishes you did not have.

## Technique

This section catalogs the sensors. For each, note three properties the operator must track: what it observes (the data domain), where the record is written (local vs forwarded), and the cost to tamper (privilege required, and whether tampering is itself observed).

### Host EDR sensors

Modern endpoint detection and response (EDR) products do not rely on a single hook. They layer several telemetry sources so that defeating one still leaves others intact.

- Kernel callbacks. On Windows, drivers register notification routines with the kernel: `PsSetCreateProcessNotifyRoutineEx` (process create/exit), `PsSetCreateThreadNotifyRoutine` (thread create, the backbone of remote-thread injection detection), `PsSetLoadImageNotifyRoutine` (DLL/image loads, including reflective loads that touch the image notify path), and `CmRegisterCallbackEx` (registry operations). These fire in kernel context and cannot be unhooked from userland. Image-load callbacks are why manually mapping a PE without calling `LdrLoadDll` still generates an event the moment the section is mapped through the standard path.
- Minifilter drivers. File system activity is captured through the Filter Manager (`fltmgr.sys`) at a registered altitude. EDR minifilters intercept `IRP_MJ_CREATE`, write, and rename operations before they reach the file system. `fltmc instances` enumerates loaded minifilters and their altitudes - useful reconnaissance for an authorized assessor mapping the sensor stack.
- Userland hooks. Many products still patch the first bytes of `ntdll.dll` exports (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) with a `jmp` to a monitoring stub. This layer is the weakest: it lives in the process's own address space and can be inspected, compared against a clean on-disk copy, or bypassed via direct/indirect syscalls. Userland hooking is detailed on the Windows pages; see [windows/userland-hook-evasion.md](../10-windows/userland-hook-evasion.md).
- Command-line and parent/child capture. The single highest-value field EDR collects is the full process command line plus the parent process. This is captured at process-create time (kernel callback augmented by ETW). It is why `powershell -enc <base64>` is loud regardless of what the decoded script does, and why process-hollowing and argument-spoofing exist. See [windows/process-creation-telemetry.md](../10-windows/process-creation-telemetry.md).

The operator's takeaway: EDR is a stack, not a switch. Defeating the userland hooks does nothing about the kernel image-load callback or the command line already shipped to the cloud console.

### Linux: auditd and the audit framework

The Linux kernel audit subsystem is the canonical host audit source. `auditd` is the userland daemon that reads records from the kernel via a netlink socket and writes them to `/var/log/audit/audit.log`.

- Rules are loaded with `auditctl` (runtime) or `/etc/audit/rules.d/*.rules` (persistent, compiled by `augenrules`). A syscall rule names an architecture, a syscall, and a key:

```bash
# Linux / auditd: flag execve and key it for hunting
auditctl -a always,exit -F arch=b64 -S execve -k exec_watch
# Watch a sensitive file for writes and attribute changes
auditctl -w /etc/passwd -p wa -k passwd_watch
# List active rules
auditctl -l
```

- Records carry a type and fields. A single `execve` produces a `SYSCALL` record (with `syscall=59`, `exe=`, `uid=`, `auid=` - the login UID that survives `su`/`sudo` and defeats naive identity laundering), a `EXECVE` record (argv), a `CWD`, and `PATH` records. Parse with `ausearch -k exec_watch` and summarize with `aureport`.
- Key tamper tells for the operator: `auditctl -e 2` locks the configuration until reboot (immutable mode); stopping `auditd` while the kernel still has rules loaded routes records to the kernel printk buffer and then to the configured `disp` or syslog, and the stop itself is a record. Editing `/var/log/audit/audit.log` requires defeating any local integrity and is visible as a gap or sequence-number discontinuity (each record has a monotonically increasing serial within an event boundary).

See [linux/auditd-evasion-and-tells.md](../20-linux/auditd-evasion-and-tells.md) for depth.

### Linux: eBPF-based sensors

eBPF moved Linux host telemetry below the auditd userland race. Programs attach to tracepoints, kprobes, and LSM hooks and stream events through ring buffers, so killing a userland daemon does not stop in-kernel collection the way it can stall auditd dispatch.

- Falco attaches to syscalls (via its kernel module or its modern eBPF probe) and evaluates rules against a stream of syscall events; alerts go to stdout, a Unix socket, or gRPC. Its default ruleset flags shells spawned by web servers, writes below `/etc`, and `ptrace` of non-child processes.
- Tetragon (Cilium) attaches eBPF to kprobes/tracepoints and can both observe and enforce (it can `SIGKILL` in-kernel before a syscall returns). It records process lineage with cgroup and container context, which is why container-escape attempts surface with full ancestry.
- Cilium itself provides L3/L4/L7 network observability via eBPF (Hubble flow logs) on Kubernetes nodes.

Operator note: eBPF sensors observe syscalls, not your intent. They are blind to logic that never crosses the syscall boundary, but a verifier-loaded program reading the same `execve` argv that auditd reads cannot be unhooked from userland and is not defeated by an `ld.so.preload` trick. Loading your own eBPF program requires `CAP_BPF`/`CAP_SYS_ADMIN` and is itself auditable via the `bpf` syscall.

### Linux: journald, syslog, and /var/log

- `systemd-journald` collects structured logs (kernel ring buffer, service stdout/stderr, `_COMM`, `_PID`, `_UID`, `_SYSTEMD_UNIT`, `_AUDIT_SESSION` correlation). Query with `journalctl`. Journals can be volatile (`/run/log/journal`) or persistent (`/var/log/journal`); a missing persistent path means logs die at reboot - a collection gap worth knowing.
- Traditional files under `/var/log`: `auth.log` / `secure` (PAM, sshd, sudo), `syslog` / `messages`, `wtmp`/`btmp`/`lastlog` (binary login records read via `last`, `lastb`, `lastlog`), `cron`, and application logs. Shell history (`~/.bash_history`) is application-level, written at session exit, and trivially defeated by `unset HISTFILE` - which is exactly why its absence, not its content, is the signal.
- AppArmor and SELinux denials. SELinux AVC denials land in the audit log (`type=AVC`) and, if auditd is down, in the kernel buffer (`dmesg`). AppArmor denials appear as `apparmor="DENIED"` lines via the audit/kernel path. A denial is a loud, high-fidelity event because it means a mandatory access control policy was tripped, not merely a discretionary permission. See [linux/mac-policy-and-denials.md](../20-linux/mac-policy-and-denials.md).

### Windows: ETW providers

Event Tracing for Windows (ETW) is the bus that nearly all Windows telemetry rides. Providers emit events; consumers (Sysmon, EDR, the Event Log service) subscribe to sessions.

- Microsoft-Windows-Threat-Intelligence. A kernel-mode, PPL-protected provider that surfaces sensitive memory operations (allocations of executable memory, `NtProtectVirtualMemory` to RX, remote allocations) that userland hooks miss. Only Protected Process Light anti-malware consumers can subscribe, which is why this telemetry is hard to blind without disabling the EDR's PPL service.
- Microsoft-Windows-DotNETRuntime and the CLR ETW providers expose assembly loads, which underpins detection of in-memory .NET execution (the `assembly load` events that catch many Cobalt-Strike-style execute-assembly tradecraft). AMSI (`AmsiScanBuffer`) covers the script/content side; ETW covers the runtime side.
- Microsoft-Windows-PowerShell emits script block logging (Event ID 4104 in the operational log) and module logging. Encoded and obfuscated commands are deobfuscated and logged at the 4104 layer regardless of `-enc`.

Tampering with ETW (patching `EtwEventWrite`, or `EtwpDisableTraceLogging`-style tricks) blinds providers in-process but does not touch kernel-side providers like Threat-Intelligence. See [windows/etw-and-amsi.md](../10-windows/etw-and-amsi.md).

### Windows: Sysmon and the event logs

Sysmon (System Monitor) is a free Sysinternals driver+service that writes high-fidelity events to `Microsoft-Windows-Sysmon/Operational`. The event IDs the operator must respect:

| Event ID | Meaning | Why it matters |
|----------|---------|----------------|
| 1 | Process create | Full command line, hashes, parent, integrity level |
| 3 | Network connection | Process-to-destination attribution |
| 7 | Image loaded | Unsigned/abnormal DLL loads, signing status |
| 8 | CreateRemoteThread | Classic injection primitive |
| 10 | ProcessAccess | `OpenProcess` to LSASS (credential theft) |
| 11 | FileCreate | Drops, including ADS |
| 13 | Registry value set | Persistence and config changes |
| 22 | DNS query | Process-attributed DNS resolution |
| 25 | Process tampering | Hollowing/herpaderping heuristics |

Sysmon's coverage is only as good as its config (the SwiftOnSecurity and Olaf Hartong configs are common baselines). A thin or default config is itself a collection gap. Native Windows logs run in parallel: `Security.evtx` carries 4624/4625 (logon success/failure), 4688 (process creation, with command line if the audit policy and the `ProcessCreationIncludeCmdLine_Enabled` GPO are set), 4672 (special privileges), 4720 (account created), and 4768/4769 (Kerberos TGT/TGS - Kerberoasting hunting). See [windows/sysmon-and-security-log.md](../10-windows/sysmon-and-security-log.md).

### Windows: WEF/WEC forwarding

Local logs are deletable by an Administrator. The defender's countermeasure is Windows Event Forwarding (WEF): hosts push events over WinRM to a Windows Event Collector (WEC), often in near-real-time for high-value channels. Once an event is forwarded, clearing the local log (4104-style script logs, or the 1102 "audit log cleared" event) does not recall the copy already at the collector - and the act of clearing generates Security Event ID 1102 / System Event ID 104, which is itself a high-priority forwarded alert. The operator must assume any forwarded channel is write-once from their perspective.

### Network telemetry

The network sees what the host hides and vice versa. The operator should treat the wire as an independent observer.

- Flow records: NetFlow / IPFIX / sFlow from routers and firewalls record the 5-tuple, byte/packet counts, timestamps, and TCP flags - no payload, but enough for beaconing analysis (regular intervals, consistent byte sizes) and large-egress detection. Jitter and variable sizes are the counter-tradecraft; see [network/beacon-shaping.md](../40-network/beacon-shaping.md).
- Zeek (formerly Bro) produces protocol-aware logs: `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `x509.log`, `notice.log`. `ssl.log` records JA3/JA3S and, in current builds, JA4 fingerprints plus SNI and certificate details even when payload is encrypted. `dns.log` is where DNS tunneling and DGA traffic surface (high NXDOMAIN, long labels, high entropy, high query volume to one zone).
- Suricata / Snort: signature IDS/IPS plus, in Suricata, EVE JSON output with protocol metadata, TLS fingerprints, and file extraction. Signatures catch known C2 patterns, default user-agents, and staging URIs.
- TLS fingerprinting: JA3/JA3S hash the TLS ClientHello/ServerHello field ordering and values; JA4/JA4+ are the newer, more robust suite covering TLS, HTTP, and SSH. A default tooling TLS stack produces a known-bad fingerprint regardless of certificate or domain fronting; matching a common browser fingerprint is the quiet variant.
- DNS query logging: resolver logs, Windows DNS Analytical logs, and passive DNS. DNS is frequently the last egress channel still allowed and therefore the most monitored.
- Proxy and DLP: forward-proxy logs (full URL, user, bytes, category) and Data Loss Prevention engines that inspect content for patterns (credit cards, classified markings, keyword/regex/fingerprint matches) at the proxy, on the endpoint agent, and at the mail gateway. Large or pattern-matching egress trips DLP independent of any host log.

### Cloud control-plane logs

In cloud, the API is the operating system and the audit log is the control-plane log. These are usually outside the operator's reach to delete.

- AWS CloudTrail records management-plane API calls (`eventName`, `eventSource`, `sourceIPAddress`, `userIdentity`, `userAgent`); data events (S3 object-level, Lambda invokes) are opt-in and a common gap. CloudWatch and GuardDuty consume these for detection. Disabling a trail (`StopLogging`, `DeleteTrail`) is itself a logged, classic-finding event.
- Azure Activity Log (control plane) plus Entra ID sign-in/audit logs and Microsoft Defender for Cloud. Microsoft Graph activity logs cover Graph API calls.
- GCP Cloud Audit Logs split into Admin Activity (always on, non-disableable), Data Access (mostly opt-in), System Event, and Policy Denied.

Across all three: assume the control-plane log is forwarded to a tenant the workload identity cannot touch. The realistic gaps are the opt-in data-plane events, not the always-on admin trail. See [cloud/control-plane-logging.md](../50-cloud/control-plane-logging.md).

### SIEM correlation and UEBA

Individual logs are forwarded into a SIEM (Splunk, Microsoft Sentinel, Elastic) where detection actually happens. Two properties matter to the operator:

- Correlation. A single quiet event may be invisible; the sequence is not. A 4769 with weak encryption, then an anomalous process spawning, then egress to a fresh domain is a correlated chain even when each link individually clears thresholds.
- UEBA (User and Entity Behavior Analytics) builds per-identity and per-host baselines and alerts on deviation (first-time admin logon at 03:00, service account running a shell, impossible-travel sign-ins). UEBA is why "blend in with normal" beats "produce no logs": you cannot produce zero logs, but you can produce logs that match the baseline.

## OPSEC notes

The loud version of nearly every technique shares one trait: it crosses a monitored boundary in a default, known-bad shape. `powershell -enc` is loud because 4104 deobfuscates it and 4688/Sysmon-1 ship the command line. A default Meterpreter or framework TLS stack is loud because its JA3/JA4 is cataloged. Stopping `auditd` or clearing an event log is loud because the stop/clear is itself a high-priority event (1102/104 on Windows, the auditd stop record on Linux).

The quiet variant in each case is not silence but mimicry and gap-routing: use signed, expected binaries with expected arguments (so the command-line field looks ordinary), match a common-browser TLS fingerprint, keep egress under DLP thresholds and shaped to look like normal traffic, and prefer actions that land only in opt-in/never-forwarded channels. Identity laundering on Linux fails against `auid` - the audit login UID follows you through `su` and `sudo`, so escalating does not reset who the kernel thinks you are.

Failure modes and tells the operator must internalize:

- Absence as signal. A vanished `~/.bash_history`, a Sysmon service that stopped (Event ID indicating service stop / channel gap), or a sudden quiet period on a normally chatty host all read as tampering to a competent hunter. Gaps are detected by their edges.
- Forwarding latency is not your friend forever. WEF and cloud trails may buffer, but they are write-once from your side once shipped. Plan as if every forwarded event is already at the collector.
- Kernel-side telemetry survives userland tricks. Unhooking `ntdll`, patching `EtwEventWrite`, or `LD_PRELOAD` shims do nothing to kernel callbacks, the Threat-Intelligence ETW provider, eBPF programs, or auditd's kernel-side rule evaluation.
- Sensor reconnaissance is itself observable. `fltmc`, `auditctl -l`, listing services, and reading `/proc` for security agents can trip behavioral rules. Enumerate carefully and prefer passive inference.

## Detection & telemetry

This page's detection section is the collection map itself - for the defender, the value is a checklist of where each domain's evidence lives and how to confirm a sensor is actually collecting rather than merely installed.

Host, Linux:

- auditd. Source `/var/log/audit/audit.log`. Confirm rules are loaded (`auditctl -l`) and that immutable mode is intended (`auditctl -s` shows `enabled 2`). Key fields: `type`, `syscall`, `exe`, `comm`, `uid`, `auid`, `ses`, `key`. Hunt with `ausearch -k <key>` / `aureport`.
- eBPF sensors. Falco alerts via stdout/syslog/gRPC; Tetragon via JSON export. Confirm probes are attached, not just the daemon running.
- journald/syslog. `journalctl -u <unit>`, `/var/log/auth.log`, binary `wtmp`/`btmp` via `last`/`lastb`. Watch for persistent journal absence (`/var/log/journal` missing).
- MAC. SELinux `type=AVC` in the audit log; AppArmor `apparmor="DENIED"` lines. A denial is high fidelity by definition.

Example Linux hunt (auditd rules to deploy, then osquery to confirm coverage):

```bash
# Linux / auditd: high-value baseline rules
auditctl -a always,exit -F arch=b64 -S execve -k exec
auditctl -w /etc/ld.so.preload -p wa -k preload_persist
auditctl -w /etc/cron.d/ -p wa -k cron_persist
auditctl -w /etc/audit/ -p wa -k auditd_tamper
```

```sql
-- osquery: is the audit daemon actually running and is it the one configured?
SELECT name, path, state FROM processes WHERE name = 'auditd';
SELECT * FROM augeas WHERE path = '/etc/audit/auditd.conf';
-- LD_PRELOAD-style persistence
SELECT * FROM file WHERE path = '/etc/ld.so.preload';
```

Host, Windows:

- Sysmon `Microsoft-Windows-Sysmon/Operational`: IDs 1 (process), 3 (network), 7 (image load), 8 (remote thread), 10 (process access - filter for `TargetImage` ending `lsass.exe`), 11 (file create), 13 (registry), 22 (DNS), 25 (tamper).
- Security log `Security.evtx`: 4624/4625, 4688 (+ command line if enabled), 4672, 4720, 4768/4769; 1102 = audit log cleared.
- PowerShell `Microsoft-Windows-PowerShell/Operational`: 4104 (script block), 4103 (module/pipeline).
- ETW: subscribe Threat-Intelligence and DotNETRuntime via an EDR or a research consumer for in-memory and CLR activity that Sysmon alone misses.

Example KQL (Sentinel-style) for LSASS access, a high-value chain link:

```kusto
// LSASS handle access with credential-dump access masks
SysmonEvent
| where EventID == 10
| where TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
| where SourceImage !endswith "MsMpEng.exe"   // tune known-good readers
| project TimeGenerated, Computer, SourceImage, GrantedAccess, CallTrace
```

Example Sigma-style logic (process-creation, encoded PowerShell):

```yaml
detection:
  selection_img:
    Image|endswith: '\powershell.exe'
  selection_enc:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: selection_img and selection_enc
fields: [ParentImage, CommandLine, User]
```

Network:

- Flow (NetFlow/IPFIX): beaconing = regular interval + consistent byte size to one destination; large egress = sustained outbound bytes. No payload, so it is shape-based.
- Zeek: `conn.log` (5-tuple, duration, bytes), `dns.log` (NXDOMAIN ratio, label length/entropy for tunneling/DGA), `ssl.log` (JA3/JA3S/JA4, SNI, cert), `http.log` (URI, user-agent), `x509.log` (cert details), `notice.log`.
- Suricata: EVE JSON with `tls.ja3.hash`, `tls.sni`, `http.user_agent`, `alert.signature`; file extraction for staged payloads.
- DNS: resolver logs and Windows DNS Analytical channel; passive DNS for newly observed domains.
- Proxy/DLP: full-URL proxy logs and content-inspection hits at endpoint, proxy, and mail gateway.

Example Splunk hunt (Zeek SSL, default/known-bad TLS fingerprints):

```spl
index=zeek sourcetype=ssl
| stats count values(server_name) as sni values(id.resp_h) as dest by ja3
| lookup ja3_known_bad ja3 OUTPUT description
| where isnotnull(description)
```

Cloud:

- AWS CloudTrail: `eventName` like `StopLogging`, `DeleteTrail`, `PutBucketPolicy`, `CreateAccessKey`; `userIdentity.type`, `sourceIPAddress`, `userAgent`. GuardDuty for managed detections. Data events (S3/Lambda) only if enabled.
- Azure: Activity Log + Entra sign-in/audit logs + Defender for Cloud + Graph activity logs.
- GCP: Cloud Audit Logs - Admin Activity (always on), Data Access (opt-in), Policy Denied.

Example CloudTrail hunt (defense-evasion on the trail itself):

```spl
index=cloudtrail (eventName=StopLogging OR eventName=DeleteTrail OR eventName=UpdateTrail OR eventName=DeleteFlowLogs)
| table _time userIdentity.arn sourceIPAddress eventName requestParameters.name awsRegion
```

Collection gaps and blind spots (state honestly to the defender, because the operator already knows them):

- CloudTrail/GCP data-access events are off by default; object reads and Lambda invokes can be invisible unless explicitly enabled.
- Sysmon detects only what its config covers; a thin config or no Sysmon at all is a host-wide blind spot.
- 4688 command-line capture requires both the audit subcategory and the dedicated GPO; without them, the most valuable field is empty.
- Flow data has no payload, so encrypted, well-shaped, threshold-respecting egress is shape-invisible.
- Local-only logs (volatile journald, unforwarded Linux files) die at reboot or are mutable by root; only forwarded copies are durable.
- Userland-only EDR deployments (no kernel driver, no PPL) are blind to the same memory and image-load events the kernel providers would catch.
- East-west traffic inside a flat segment may never reach an IDS sensor positioned only at the perimeter.

## MITRE ATT&CK

- T1562 - Impair Defenses
- T1562.001 - Impair Defenses: Disable or Modify Tools
- T1562.002 - Impair Defenses: Disable Windows Event Logging
- T1562.006 - Impair Defenses: Indicator Blocking
- T1562.008 - Impair Defenses: Disable or Modify Cloud Logs
- T1070 - Indicator Removal
- T1070.002 - Indicator Removal: Clear Linux or Mac System Logs
- T1070.003 - Indicator Removal: Clear Command History
- T1070.001 - Indicator Removal: Clear Windows Event Logs
- T1562.012 - Impair Defenses: Disable or Modify Linux Audit System
- T1014 - Rootkit
- T1055 - Process Injection (collection context: image-load and remote-thread callbacks)
- T1071.004 - Application Layer Protocol: DNS (collection context: DNS query logging)

## References

- Microsoft, "Process and thread notification routines" (PsSetCreateProcessNotifyRoutineEx, PsSetLoadImageNotifyRoutine), Windows Driver Kit docs. https://learn.microsoft.com/windows-hardware/drivers/ddi/
- Linux man pages: auditctl(8), ausearch(8), aureport(8), auditd.conf(5), augenrules(8). https://man7.org/linux/man-pages/man8/auditctl.8.html
- Sysmon, Sysinternals documentation (event IDs and configuration schema). https://learn.microsoft.com/sysinternals/downloads/sysmon
- MITRE ATT&CK, Enterprise Matrix (Defense Evasion, Indicator Removal, Impair Defenses). https://attack.mitre.org/
- Zeek documentation, log files reference (conn, dns, ssl, http, x509). https://docs.zeek.org/en/master/logs/index.html
- Suricata documentation, EVE JSON output. https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- John Althouse et al., JA3 and JA4+ TLS/network fingerprinting (FoxIO). https://github.com/FoxIO-LLC/ja4
- AWS, "Logging IAM and AWS STS API calls with AWS CloudTrail" and CloudTrail event reference. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/
- Falco rules and event sources, falco.org documentation. https://falco.org/docs/
- Cilium Tetragon documentation (eBPF process and security observability). https://tetragon.io/docs/
