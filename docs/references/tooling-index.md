---
title: "Tooling Index"
parent: References
nav_order: 1
---

# Tooling Index

*Curated reference of native, open-source, and defensive tools used across this repo, with OPSEC ratings and the telemetry each generates.*

## What & why

Every tool choice is a telemetry decision. A dropped binary stands out on disk and in
process telemetry; a native binary blends into the baseline but its argv is still logged.
This index rates each tool by its default noise level and cross-references the relevant
technique pages.

## OPSEC rating key

| Rating | Meaning |
|---|---|
| **Quiet** | Native/expected binary; low disk artifact; behavioral anomalies only |
| **Moderate** | Native binary but unusual usage; or dropped binary that is widely known |
| **Loud** | Dropped binary with a known hash/name; or produces high-signal behavioral artifacts by default |

---

## Native / built-in - Linux

| Tool | Purpose | OPSEC | Telemetry generated | Repo page |
|---|---|---|---|---|
| `bash /dev/tcp` | File transfer without curl | Quiet | auditd execve (bash), netflow outbound conn | [linux/05](../linux/05-living-off-the-land.md) |
| `ss` | Network socket enumeration | Quiet | auditd execve; does NOT generate netflow | [linux/01](../linux/01-host-triage-and-situational-awareness.md) |
| `find` | File discovery | Quiet | auditd execve with full argv; atime updates if `-atime` not used | [linux/01](../linux/01-host-triage-and-situational-awareness.md) |
| `cat` / `head` / `tail` | File read | Quiet | auditd `open(O_RDONLY)` on watched paths | [linux/01](../linux/01-host-triage-and-situational-awareness.md) |
| `tar` | Archive/compress/stage | Moderate | auditd execve with path args; file-create event for output | [data-transfer/01](../data-transfer/01-exfil-principles-and-staging.md) |
| `curl` | HTTP/HTTPS transfer | Moderate | auditd execve; netflow outbound; proxy log; JA3 fingerprint | [data-transfer/04](../data-transfer/04-https-and-cloud-exfil.md) |
| `wget` | HTTP/HTTPS download | Moderate | Same as curl; different JA3 | [linux/05](../linux/05-living-off-the-land.md) |
| `openssl` | Encryption, TLS client | Moderate | auditd execve; `-pass pass:` leaks passphrase in argv | [data-transfer/02](../data-transfer/02-encoding-compression-encryption.md) |
| `base64` | Encoding/decoding | Loud | auditd execve; full argv; decode-exec chain heavily signatured | [data-transfer/02](../data-transfer/02-encoding-compression-encryption.md) |
| `xxd` | Hex encode/decode | Loud | auditd execve; signatured in decode-exec context | [data-transfer/02](../data-transfer/02-encoding-compression-encryption.md) |
| `ssh` | Remote shell / tunnel | Moderate | auth.log accepted/failed at both ends; netflow | [linux/06](../linux/06-network-stealth-and-tunneling.md) |
| `python3` / `perl` / `awk` | Script execution / shell escape | Moderate | auditd execve; spawning shell from interpreter is signatured | [linux/05](../linux/05-living-off-the-land.md) |
| `crontab` | Persistence via cron | Moderate | cron syslog on each run; `/var/spool/cron` file-write | [linux/03](../linux/03-persistence-stealth.md) |
| `systemctl` | Manage systemd units | Moderate | journald unit-start records; systemd-analyze | [linux/03](../linux/03-persistence-stealth.md) |
| `sudo -l` | Enumerate sudo rights | Loud | `/var/log/auth.log` sudo entry; SIEM alert common | [linux/01](../linux/01-host-triage-and-situational-awareness.md) |
| `id` / `whoami` / `uname` | Situational awareness | Moderate | auditd execve; EDR process event | [linux/01](../linux/01-host-triage-and-situational-awareness.md) |
| `lsmod` / `bpftool` | Enumerate kernel modules/eBPF | Moderate | auditd execve; `bpftool` may itself be watched | [linux/07](../linux/07-edr-and-kernel-telemetry-evasion.md) |
| `split` | Chunk files | Quiet | file-create events per chunk | [data-transfer/01](../data-transfer/01-exfil-principles-and-staging.md) |
| `age` | Modern key-based encryption | Quiet | auditd execve; key not in argv | [data-transfer/02](../data-transfer/02-encoding-compression-encryption.md) |
| `ping` | Connectivity / ICMP probe | Moderate | Firewall/IDS; ICMP size anomaly if large payload | [data-transfer/05](../data-transfer/05-covert-channels.md) |

---

## Native / built-in - Windows

| Tool | Purpose | OPSEC | Telemetry generated | Repo page |
|---|---|---|---|---|
| `powershell.exe` | Script execution | Moderate | Script Block Log EID 4104 (decoded content); EID 4688/Sysmon 1 | [windows/05](../windows/05-edr-evasion-amsi-etw.md) |
| `cmd.exe` | Command execution | Quiet | EID 4688; Sysmon EID 1 with full cmdline | [windows/01](../windows/01-process-stealth.md) |
| `certutil.exe` | Download / base64 decode | Loud | `-urlcache`, `-decode` heavily signatured; Sysmon EID 1; EID 4688 | [windows/04](../windows/04-lolbas-and-execution.md) |
| `mshta.exe` | Script/HTA execution | Loud | LOLBAS; parent-child lineage anomaly; EID 4688 | [windows/04](../windows/04-lolbas-and-execution.md) |
| `rundll32.exe` | DLL/COM execution | Loud | LOLBAS; unusual args signatured; Sysmon EID 7 (image load) | [windows/04](../windows/04-lolbas-and-execution.md) |
| `schtasks.exe` | Create scheduled task | Loud | EID 4698 (task created); Task Scheduler operational log | [windows/02](../windows/02-persistence-stealth.md) |
| `reg.exe` | Registry modification | Moderate | Sysmon EID 13 (registry value set); EID 4657 | [windows/02](../windows/02-persistence-stealth.md) |
| `wmic.exe` | WMI queries / lateral | Loud | WMI-Activity log; EID 4688; process lineage anomaly | [windows/02](../windows/02-persistence-stealth.md) |
| `bitsadmin.exe` | Background file transfer | Loud | LOLBAS; BITS operational log; Sysmon EID 3 (network) | [windows/04](../windows/04-lolbas-and-execution.md) |
| `msbuild.exe` | Inline task execution | Loud | LOLBAS; compiles/runs inline C# - EDR behavioral | [windows/04](../windows/04-lolbas-and-execution.md) |

---

## Open-source offensive tools (commonly encountered)

These are dropped binaries - louder on disk and in hash telemetry. Listed for recognition.

| Tool | Purpose | OPSEC | Notes |
|---|---|---|---|
| `nmap` | Port/service scan | Loud | Distinct TCP fingerprint; scan patterns in NetFlow/IDS |
| `pspy` | Enumerate processes without root | Moderate | Reads `/proc`; dropped binary; hash-checked by AV |
| `linpeas` / `winpeas` | Enumeration scripts | Loud | Well-signatured; auditd shows mass file-read burst |
| `chisel` | HTTP tunnel / SOCKS proxy | Loud | Dropped Go binary; JA3 fingerprint; beaconing |
| `socat` | Network relay / reverse shell | Moderate | Often available natively; listen/connect events |
| `ligolo-ng` | Tunneling proxy | Loud | Dropped binary; TUN interface creation; syslog |
| `mimikatz` (Windows) | Credential dumping | Loud | Sysmon EID 10 (lsass access); AV signature; ETW |

---

## Defensive / telemetry tools (know these are present)

| Tool | Purpose | Detection surface exposed |
|---|---|---|
| `auditd` + `audit.rules` | Linux syscall logging | Execve, file, socket, auth events |
| Falco | eBPF kernel behavioral detection | Process, network, file access rules |
| Tetragon (Cilium) | eBPF policy enforcement + telemetry | Syscall, network, credential access |
| Sysmon (Windows) | Windows process/network/registry telemetry | EIDs 1,3,7,8,10,11,12,13,19-21 |
| osquery | Host-state querying (tables) | On-demand or scheduled queries |
| Zeek | Network metadata (conn, dns, ssl, x509 logs) | Protocol-level metadata |
| Suricata / Snort | Network IDS | Signature + content matches |
| auditbeat / Elastic Agent | Ships auditd/file events to SIEM | Aggregates host telemetry |
| Velociraptor | DFIR + live response | Artifact collection, hunt queries |

---

## OPSEC notes

All tool choices - native or dropped - generate process events with full command-line argv
when auditd `execve` rules are active or an EDR is present. Native/signed binaries defeat
hash-based AV but not behavioral detection. The argv is the tell, not the binary.

## Detection & telemetry

Command-line auditing (`auditd execve` on Linux, `EID 4688` + `Sysmon EID 1` on Windows)
captures every tool invocation with its full argument list. There is no tool in this index
that evades command-line telemetry. The difference between ratings is how much additional
behavioral signal each tool generates beyond the basic process event.

## MITRE ATT&CK

- **T1059** - Command and Scripting Interpreter
- **T1218** - System Binary Proxy Execution (LOLBAS)
- **T1105** - Ingress Tool Transfer

## References

- GTFOBins (Linux LOLBins): https://gtfobins.github.io/
- LOLBAS (Windows LOLBins): https://lolbas-project.github.io/
- MITRE ATT&CK Software catalogue: https://attack.mitre.org/software/
- osquery schema reference: https://osquery.io/schema/current/
- Sysmon event ID reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
