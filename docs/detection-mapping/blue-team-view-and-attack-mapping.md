# Blue-Team View & MITRE ATT&CK Mapping

*The defender's index to "Quiet Operator": every offensive technique page mapped to its ATT&CK IDs, the data sources that record it, and the highest-signal hunt that catches it.*

## What & why

This page inverts the rest of the repo. Where the offensive pages ask "what record does this action produce and how do I route around it," this page asks "given the records I already collect, which technique do they reveal and what query surfaces it first." It is the purple bridge: a single master table that maps each technique area to its MITRE ATT&CK technique IDs, the ATT&CK Data Sources / Data Components that observe it (process creation, command execution, file modification, network traffic, logon session, kernel module load, and so on), the single best telemetry source on a real estate, and a copy-pasteable hunt. The OPSEC rationale for the operator is that this table is also the operator's risk register - if you can read where a defender will look first, you can estimate detection probability per action before you take it. For the SOC, the rationale is coverage accounting: it lets you walk the repo as a threat model, confirm you have the data source for each row, and write or import a detection for every technique an authorized adversary would attempt. Detection is not a list of signatures; it is a mapping from data source to technique, and the gaps in that mapping are exactly where stealth lives - see [00-foundations/threat-model-and-telemetry.md](../00-foundations/threat-model-and-telemetry.md).

## Technique

### How to read the master table

Each row names a technique area, the page that covers the offense, the relevant ATT&CK technique IDs, the best single telemetry source to detect it on a typical enterprise estate, and an example hunt expressed in whatever query language is most natural (auditd `ausearch`, osquery SQL, Sysmon/Security EventID filters, Sigma-style logsource conditions, Splunk SPL, or Elastic/KQL). Where an ATT&CK Data Source ID is meaningful it is noted in the telemetry column (DS IDs are ATT&CK's enterprise data source identifiers, for example DS0009 Process, DS0017 Command, DS0022 File, DS0029 Network Traffic).

The example hunts are intentionally broad-to-medium fidelity. They are starting points for a hunt, not tuned production alerts - expect to add environment allowlists (known admin hosts, backup service accounts, patch windows) before promoting any of them to an alert, or alert fatigue will bury the real signal. See the detection-priorities narrative below for the order in which to deploy them.

### Master mapping table

| Technique area | ATT&CK ID(s) | Best telemetry source | Example detection / hunt |
| --- | --- | --- | --- |
| Host triage / situational awareness ([linux/01](../linux/01-host-triage-and-situational-awareness.md)) | T1082 System Information Discovery, T1083 File and Directory Discovery, T1057 Process Discovery, T1033 System Owner/User Discovery, T1518 Software Discovery | auditd `execve` (DS0017 Command Execution); EDR process telemetry | auditd: `ausearch -m EXECVE` and grep for clustered discovery binaries (`whoami`, `id`, `uname -a`, `hostname`, `cat /etc/os-release`, `ps aux`) from one PID/session within a short window. Discovery is rarely one command; the tell is the burst. |
| Process stealth / masquerading ([linux/02](../linux/02-process-stealth-and-masquerading.md)) | T1036.004 Masquerade Task or Service, T1036.005 Match Legitimate Name or Location, T1564.001 Hidden Files and Directories, T1574 Hijack Execution Flow | auditd `execve` argv vs `/proc/<pid>/exe`; Sysmon for Linux EventID 1 | osquery: join `processes.path` against `processes.cmdline` and flag where `name` looks like a kernel thread (`[kworker/...]`) but `path` is non-empty, or where `path` is in `/tmp`, `/dev/shm`, `/var/tmp`. A real `[kworker]` has an empty `path`. |
| Persistence ([linux/03](../linux/03-persistence-stealth.md)) | T1053.003 Cron, T1543.002 Systemd Service, T1546.004 Unix Shell Config Mod, T1547 Boot/Logon Autostart, T1037 Boot/Logon Init Scripts | auditd file watches (DS0022 File Modification); osquery scheduled diffs | osquery: snapshot and diff `crontab`, `systemd_units`, `startup_items`, and writes to `~/.bashrc`, `~/.profile`, `/etc/cron.*`, `/etc/systemd/system`. auditd watch: `-w /etc/systemd/system -p wa -k systemd_persist`. Alert on any new unit file outside change windows. |
| Log tampering / anti-forensics ([linux/04](../linux/04-log-and-anti-forensics.md)) | T1070.002 Clear Linux or Mac System Logs, T1070.004 File Deletion, T1070.006 Timestomp, T1562.001 Disable or Modify Tools, T1564.008 Email Hiding / log evasion | auditd config-change + journald, forwarded off-host | auditd: `type=CONFIG_CHANGE` records for audit rule edits; `type=SERVICE_STOP` for `auditd`/`rsyslog`. journald: gaps in monotonic cursor, or `journalctl --verify` failure. Highest fidelity is the absence detected centrally: SIEM alert on heartbeat loss from a host that is still pingable. |
| Living off the land ([linux/05](../linux/05-living-off-the-land.md)) | T1059.004 Unix Shell, T1059.006 Python, T1105 Ingress Tool Transfer, T1218 System Binary Proxy Execution (LOLBins) | auditd `execve` + command line; EDR script-content telemetry | Sigma-style: interpreter (`bash`/`python`/`perl`) spawned by a network service or with a command line containing `curl|sh`, `wget -O- ... | bash`, base64 decode piped to a shell. Hunt parent lineage, not just the binary - `nginx` to `bash` to `curl` is the chain. |
| Network stealth / tunneling ([linux/06](../linux/06-network-stealth-and-tunneling.md)) | T1071.001 Web Protocols, T1071.004 DNS, T1572 Protocol Tunneling, T1090 Proxy, T1095 Non-Application Layer Protocol | Network sensor / Zeek / firewall flow logs (DS0029 Network Traffic) | Zeek/Splunk: long-lived connections with low jitter (beaconing), high DNS TXT volume per second-level domain, or constant-size periodic flows. KQL: aggregate `DeviceNetworkEvents` by `RemoteIP`, flag connection counts with regular inter-arrival times and small variance. |
| Credential access / lateral movement ([linux/08](../linux/08-credential-access-and-lateral-movement.md)) | T1003.008 /etc/passwd and /etc/shadow, T1552.001 Credentials in Files, T1021.004 SSH, T1110 Brute Force, T1098.004 SSH Authorized Keys | auditd file reads + `auth.log`/journald authentication; osquery `authorized_keys` | auditd: `-w /etc/shadow -p r -k shadow_read` then `ausearch -k shadow_read` for any reader that is not a known auth/backup process. osquery: monitor `authorized_keys` table for new key additions; alert on writes to `~/.ssh/authorized_keys` outside provisioning. |
| EDR / kernel telemetry evasion ([linux/07](../linux/07-edr-and-kernel-telemetry-evasion.md)) | T1562.001 Disable or Modify Tools, T1014 Rootkit, T1547.006 Kernel Modules and Extensions, T1620 Reflective Code Loading | Kernel module load events; auditd `init_module`/`finit_module`; eBPF audit | auditd: rule on `-S init_module -S finit_module -S delete_module -k kmod`. Hunt: any `finit_module` from a non-package-managed path, `kill -0` probing of the EDR PID, or `ptrace` against the agent. Compare loaded `lsmod` against the package-owned baseline. |
| Data encoding / staging ([data-transfer/02](../data-transfer/02-encoding-compression-encryption.md)) | T1560 Archive Collected Data, T1132 Data Encoding, T1027 Obfuscated Files or Information, T1074 Data Staged | auditd `execve` of archive/crypto tools; file-create telemetry in staging dirs | osquery/auditd: execution of `tar`, `zip`, `gzip`, `openssl enc`, `gpg`, `xz` with output redirected to `/tmp`, `/dev/shm`, or a web root. Flag large new compressed/encrypted files (`file` magic + size) appearing in staging locations before an outbound transfer. |
| HTTPS / cloud exfiltration ([data-transfer/04](../data-transfer/04-https-and-cloud-exfil.md)) | T1567.002 Exfil to Cloud Storage, T1048 Exfil Over Alternative Protocol, T1041 Exfil Over C2 Channel, T1071.001 Web Protocols | Proxy / TLS metadata / DNS logs; netflow byte counts | Splunk/proxy: outbound bytes-sent to a destination the host has never contacted, especially to cloud-storage FQDNs (`*.s3.amazonaws.com`, `storage.googleapis.com`, paste sites). Alert on upload/download byte ratio inversion (egress >> ingress) from a server that normally only serves. |
| Windows process stealth ([windows/01](../windows/01-process-stealth.md)) | T1055 Process Injection, T1134 Access Token Manipulation, T1036 Masquerading, T1620 Reflective Code Loading, T1059.001 PowerShell | Sysmon + Security.evtx + PowerShell ScriptBlock logging | Sysmon EventID 1 (process create) parent/child anomalies, EventID 8 (CreateRemoteThread), EventID 10 (ProcessAccess to `lsass.exe`). Security 4688 with command line. PowerShell 4104 (ScriptBlock) for decoded `-enc` payloads. KQL: `DeviceProcessEvents | where InitiatingProcessFileName == "winword.exe" and FileName in~ ("powershell.exe","cmd.exe","wscript.exe")`. |
| C2 infrastructure / beaconing (c2-infrastructure) | T1071 Application Layer Protocol, T1568.002 Domain Generation Algorithms, T1573 Encrypted Channel, T1090.004 Domain Fronting, T1102 Web Service | Network sensor + DNS + TLS JA3/JA4 fingerprinting | Zeek/Suricata: rare JA3/JA4 client hashes, mismatched SNI vs HTTP Host (domain fronting), newly registered or algorithmically generated domains, periodic same-size POSTs. Beaconing detection on connection-interval regularity beats any single-packet signature. |

### Worked hunt examples

These expand a few rows above into runnable form. Replace doc IPs and lab hostnames with your estate's allowlists.

#### auditd: sensitive-file read by an unexpected process (T1003.008 / T1552.001)

```bash
# Linux / auditd: arm a read watch on the credential stores
auditctl -w /etc/shadow -p r -k shadow_read
auditctl -w /etc/passwd -p r -k passwd_read

# Hunt: every reader of /etc/shadow, then eyeball for non-auth processes.
# Known-good readers: unix_chkpwd, sshd, sudo, login, the backup agent.
ausearch -k shadow_read --format text | grep -vE 'unix_chkpwd|sshd|sudo|login'
```

The login UID (`auid`) field is the high-value pivot: it survives `su` and `sudo`, so a `shadow_read` whose `auid` maps to an interactive user who then escalated is far more interesting than one from a system service. See the auditd identity discussion in [00-foundations/threat-model-and-telemetry.md](../00-foundations/threat-model-and-telemetry.md).

#### osquery: new persistence across cron, systemd, and shell rc (T1053.003 / T1543.002 / T1546.004)

```sql
-- osquery: anything scheduled, plus the units and the rc files most abused.
-- Schedule this and diff results; the new rows are the leads.
SELECT 'crontab' AS source, command AS detail, path FROM crontab
UNION ALL
SELECT 'systemd' AS source, id AS detail, fragment_path AS path
  FROM systemd_units WHERE fragment_path NOT LIKE '/usr/lib/systemd/%'
UNION ALL
SELECT 'startup' AS source, name AS detail, path FROM startup_items;
```

Pair this with an auditd write-watch on the same paths so you catch the modification event in near-real-time rather than only at the next osquery interval:

```bash
# Linux / auditd: catch the write the moment it lands
auditctl -w /etc/systemd/system -p wa -k systemd_persist
auditctl -w /etc/cron.d -p wa -k cron_persist
```

#### Sysmon / KQL: office-to-shell lineage and lsass access (T1059.001 / T1003.001 / T1055)

```kql
// Microsoft Defender / KQL: classic initial-access lineage
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

```
# Sysmon (Security/Sysmon Operational): credential theft signal
# EventID 10 ProcessAccess where TargetImage ends with lsass.exe and
# GrantedAccess includes 0x1010 / 0x1410 (read memory). Exclude known AV/EDR.
```

#### Network: beacon-interval regularity (T1071 / T1573)

```
# Splunk SPL: find low-variance, repeating outbound connections (beaconing).
# Regular inter-arrival time with small stdev is the tell, not the payload.
index=network sourcetype=zeek_conn
| eventstats avg(duration) stdev(duration) by src_ip dest_ip dest_port
| streamstats current=f window=1 last(_time) AS prev_time by src_ip dest_ip
| eval interval=_time-prev_time
| stats count avg(interval) AS mean_iat stdev(interval) AS sd_iat by src_ip dest_ip
| where count > 20 AND sd_iat < (0.1 * mean_iat)
```

## OPSEC notes

What makes a detection-mapping useful to a defender is the same property that makes it dangerous to the operator: it is honest about which rows are high-signal and which are noisy. The loud techniques in this repo light up the top of the table - command-line discovery bursts, office-to-shell lineage, lsass access, `init_module` from a non-package path, a brand-new systemd unit, an `auditd` stop event. These produce a single discrete record on a data source that virtually every mature estate collects, and the record is hard to suppress without producing a second, louder record (you cannot quietly turn off the thing that logs you turning it off). The quiet variants live in the table's gaps: discovery spread thin across a long session so no burst forms; persistence placed in a mechanism the SOC does not snapshot; exfil shaped to look like the host's normal egress so the byte-ratio and beacon-interval heuristics never trip.

The failure modes are symmetric. For the operator, the tell is usually not the action but its context - the right binary from the wrong parent, the right file read by the wrong `auid`, the right protocol to a destination the host has never spoken to. For the defender, the failure mode is alert fatigue: every hunt in the table will fire on legitimate admin activity until it is fenced with allowlists (patch windows, backup accounts, jump hosts, known automation). Deploy them as hunts first, characterize the benign baseline, then promote to alerts. A mapping that is never tuned is a mapping that is never read.

## Detection & telemetry

This section names the concrete artifact behind each table row so a defender knows exactly where to point a collector.

### Linux host (auditd, journald, eBPF)

- Log source: `/var/log/audit/audit.log` via the kernel audit subsystem; `auditd` daemon.
- Record types to collect: `SYSCALL` (with `syscall=` number, `exe=`, `uid=`, `auid=`, `key=`), `EXECVE` (argv), `PATH`, `CWD`, `CONFIG_CHANGE` (audit rule edits), `SERVICE_STOP`/`SERVICE_START`.
- High-value syscalls to rule on: `execve` (59 on x86-64), `init_module`/`finit_module`/`delete_module` (kernel module load/unload), `ptrace` (injection/anti-debug), `open`/`openat` on credential files.
- journald: structured fields `_SYSTEMD_UNIT`, `_PID`, `_COMM`, `_AUDIT_LOGINUID`; use `journalctl --verify` and monotonic cursor continuity to detect tampering.
- eBPF: modern agents (Falco, Tetragon, Elastic Defend) attach to tracepoints and LSM hooks. Falco rules express the same intent as the auditd rules above but with richer process lineage; map every auditd `-k` key to an equivalent Falco rule so the two cross-validate.
- Forwarding: ship audit and journald off-host in near-real-time. The single most valuable Linux detection is central heartbeat loss - a host that stops forwarding but still answers ping is the log-clear / agent-kill signal that local tampering tries to hide.

### Windows host (Sysmon, Security.evtx, ETW, PowerShell logs)

- Sysmon (Microsoft-Windows-Sysmon/Operational): EventID 1 process create (full command line, hashes, parent), 3 network connect, 7 image load, 8 CreateRemoteThread, 10 ProcessAccess (lsass), 11 file create, 13 registry value set, 22 DNS query, 25 process tampering.
- Security.evtx: 4688 process creation (enable command-line auditing via the `Include command line in process creation events` policy), 4624/4625 logon, 4672 special privileges, 4720/4732 account and group changes, 1102 audit log cleared.
- PowerShell: Module logging (EventID 4103) and ScriptBlock logging (EventID 4104) in Microsoft-Windows-PowerShell/Operational - 4104 reconstructs the decoded payload behind `-EncodedCommand`.
- ETW providers: Microsoft-Windows-Threat-Intelligence (kernel-mode telemetry consumed by EDR), Microsoft-Windows-DNS-Client, Microsoft-Windows-WMI-Activity for T1047.
- Data Source mapping: these line up to ATT&CK DS0009 Process, DS0017 Command, DS0011 Module, DS0022 File, DS0024 Windows Registry, DS0029 Network Traffic.

### Network and C2

- Flow / connection logs: Zeek `conn.log`, NetFlow/IPFIX, firewall logs. Key fields: bytes-sent vs bytes-received ratio, connection duration, inter-arrival time, destination rarity (first-seen-for-host).
- DNS: Zeek `dns.log`, Microsoft DNS analytical logs, resolver query logs. Hunt high TXT/NULL record volume per registered domain (DNS tunneling, T1071.004) and algorithmically generated domain entropy (T1568.002).
- TLS: Zeek `ssl.log` and JA3/JA4 client/server fingerprints. Mismatched SNI vs HTTP Host header is the domain-fronting tell (T1090.004); rare JA3 hashes flag non-browser clients.
- Proxy logs: URL, method, user-agent, content-length. Byte-ratio inversion (a server uploading more than it serves) is the cloud-exfil signal (T1567.002).

### Detection priorities - what a hunter watches first

Order matters because attention is finite. A practical hunt cadence, highest leverage first:

1. Command-line auditing. The full process command line plus parent is the single highest-value field on any platform (Security 4688, Sysmon 1, auditd `EXECVE`). Most LOLBin, encoded-payload, and discovery activity is visible here and nowhere cheaper.
2. Process lineage. The right binary from the wrong parent (office-to-shell, web-service-to-shell, `services.exe` spawning an interpreter) catches injection and initial access that a binary allowlist misses.
3. New outbound and beaconing. First-seen-for-host destinations plus low-variance connection intervals. This catches C2 regardless of payload encryption.
4. Sensitive-file reads. `/etc/shadow`, `lsass` memory, SSH keys, `authorized_keys`, cloud credential files - read by anything that is not a known reader.
5. Log-clear and agent-tamper events. Security 1102, auditd `CONFIG_CHANGE`/`SERVICE_STOP`, and centrally observed heartbeat loss. The act of hiding is itself a detection.
6. New persistence. New systemd units, cron entries, run keys, scheduled tasks, and `authorized_keys` additions outside change windows.

### Rule ecosystems to import rather than reinvent

- Sigma (SigmaHQ): vendor-neutral detection rules that compile to Splunk, Elastic, Sentinel, and others. Most table rows above have an existing Sigma rule; map each to your SIEM's backend.
- Falco / Falco Rules: eBPF and kernel-audit runtime rules for Linux and containers; the natural home for the auditd-equivalent detections.
- osquery / osquery-packs and Fleet: scheduled queries for persistence, kernel modules, `authorized_keys`, and process anomalies - ideal for the diff-based persistence hunts.
- Elastic detection-rules and Microsoft Sentinel/Defender hunting repos: maintained KQL and EQL rules mapped directly to ATT&CK IDs, so coverage gaps are visible against the same matrix this page uses.

## MITRE ATT&CK

This page indexes techniques covered across the repo; the most load-bearing IDs:

- T1059 Command and Scripting Interpreter (.001 PowerShell, .004 Unix Shell, .006 Python)
- T1082 System Information Discovery; T1057 Process Discovery; T1083 File and Directory Discovery
- T1036 Masquerading (.004, .005); T1564 Hide Artifacts (.001 Hidden Files)
- T1053.003 Scheduled Task/Job: Cron; T1543.002 Systemd Service; T1546.004 Unix Shell Config Mod
- T1070 Indicator Removal (.002 Clear Linux Logs, .004 File Deletion, .006 Timestomp); T1562.001 Disable or Modify Tools
- T1218 System Binary Proxy Execution; T1105 Ingress Tool Transfer
- T1071 Application Layer Protocol (.001 Web, .004 DNS); T1572 Protocol Tunneling; T1090 Proxy (.004 Domain Fronting)
- T1003 OS Credential Dumping (.001 LSASS, .008 /etc/passwd and /etc/shadow); T1552.001 Credentials In Files; T1021.004 Remote Services: SSH
- T1055 Process Injection; T1134 Access Token Manipulation; T1620 Reflective Code Loading
- T1014 Rootkit; T1547.006 Kernel Modules and Extensions
- T1560 Archive Collected Data; T1132 Data Encoding; T1027 Obfuscated Files or Information; T1074 Data Staged
- T1567.002 Exfiltration to Cloud Storage; T1048 Exfil Over Alternative Protocol; T1041 Exfil Over C2 Channel
- T1568.002 Dynamic Resolution: DGA; T1573 Encrypted Channel; T1102 Web Service

## References

- MITRE ATT&CK Enterprise Matrix - https://attack.mitre.org/matrices/enterprise/
- MITRE ATT&CK Data Sources - https://attack.mitre.org/datasources/
- SigmaHQ detection rules - https://github.com/SigmaHQ/sigma
- Falco runtime security rules - https://falco.org/docs/rules/
- osquery schema and tables - https://osquery.io/schema/
- Sysmon documentation (Sysinternals) - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- auditd / auditctl man pages - https://man7.org/linux/man-pages/man8/auditctl.8.html
- Zeek network monitor documentation - https://docs.zeek.org/
- Elastic detection-rules repository - https://github.com/elastic/detection-rules
