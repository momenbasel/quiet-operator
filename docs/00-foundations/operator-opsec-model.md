# The Operator OPSEC Model

*Stealth is not invisibility. It is telemetry management and artifact budgeting under the assumption that a human hunter is reading the logs.*

## What & why

Every action an operator takes on a target leaves an artifact: a disk write, a process spawn, a network connection, a log line, an authentication event, a kernel audit record. Stealth is the discipline of choosing actions whose artifact cost is lower than the defender's ability or willingness to investigate. This page is the philosophical anchor for the rest of "Quiet Operator": it frames operations not as "did I get caught" but as "what telemetry did I generate, who collects it, and was the objective worth the trace." The default posture for every page in this repo is pessimistic - assume an EDR agent on the endpoint, a central SIEM ingesting Windows Security and Sysmon and Linux auditd, and at least one competent human threat hunter who will pivot on anything anomalous. Under that posture, the operator's job is to minimize, blend, and account for artifacts, not to believe any single action is free. This is for AUTHORIZED red team and purple team engagements only.

## Technique

The model is a discipline, not a tool. It has four parts: a cost model for actions, a minimize-touch principle, a default threat posture, and a per-action decision framework. Apply it before you run anything.

### The artifact cost model

Treat each primitive you have access to as a transaction that debits an artifact budget. The budget is finite because each artifact raises the probability that a hunter's query returns your activity. The five primary artifact classes:

- **Disk write** - a file created, modified, or deleted on a monitored filesystem. Generates filesystem telemetry, EDR file-write events, and potentially MFT/USN-journal or inode changes. The most durable artifact: it survives reboots and is available to forensic timelining even after you leave.
- **Process spawn** - any new process. Generates Sysmon Event ID 1 (process creation), Windows Security 4688, Linux auditd `execve` records, and an EDR process tree node with full command line, parent, hashes, and signer. Command lines are logged in full on modern stacks; this is where most operators die.
- **Network connection** - an outbound or lateral socket. Generates Sysmon Event ID 3, EDR netflow, firewall/proxy logs, NetFlow/IPFIX at the network layer, and DNS query logs. Beaconing patterns (regular interval, fixed jitter, consistent byte sizes) are themselves an artifact even when the payload is encrypted.
- **Authentication event** - any credential use. Generates Windows Security 4624/4625/4768/4769/4776, Linux PAM and `sshd` records in journald, and identity-provider logs. Logon type, source host, and the account-to-host pairing are the fields hunters pivot on.
- **Log/config mutation** - any change to a security control, log source, or service. Clearing a log (Security 1102), stopping a service, disabling AMSI, or loading a driver is high-signal precisely because it is rare and security-relevant.

### Minimize-touch principle

For a given objective, prefer the primitive that debits the fewest and least durable artifact classes. The hierarchy, cheapest to most expensive in artifact terms:

1. Read-only use of data you already have access to (no new process, no new connection).
2. In-memory execution within an already-running, expected process.
3. Use of a built-in, signed, expected binary (living-off-the-land) over a dropped tool.
4. A network call to expected infrastructure on an expected port over a novel destination.
5. A disk write to a path that already sees churn over a write to a pristine system directory.
6. A new process from an unexpected parent (last resort; loudest of the common primitives).

The principle in one sentence: do not spawn when you can call in-process, do not write to disk when you can stay in memory, do not bring a binary when one exists, and do not delete anything you did not have to create.

### Staging vs in-memory

Staging (writing a payload, tool, or output to disk) trades stealth for reliability and reusability. In-memory execution trades reliability for a smaller, non-persistent footprint. The trade is not free in either direction:

- **On-disk staging** produces a file-write event, a hash that can be looked up against threat intel, a signer mismatch if unsigned, and a forensic artifact that outlives the session. It also enables EDR static scanning and quarantine. The mitigating advantage is that disk-backed payloads survive reboots and crashes.
- **In-memory execution** avoids the file-write artifact but is not invisible. Reflective loading, manual mapping, and `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` injection chains generate their own EDR telemetry: RWX private memory regions, unbacked executable memory (no associated module on disk), and on Windows the kernel ETW `Microsoft-Windows-Threat-Intelligence` provider surfaces remote-thread and memory-protection-change events that bypass userland hooks. Linux equivalents - `memfd_create` + `execveat`, or `ptrace`-based injection - are visible to auditd and eBPF sensors.

The correct framing: in-memory removes one artifact class (durable disk) and adds another (anomalous memory + injection telemetry). Choose based on what the specific defender collects. If they have a tuned ETW-TI or eBPF memory sensor, on-disk in a noisy directory may actually be quieter than injection. See [the staging vs in-memory deep dive](../linux/in-memory-execution.md) for the Linux primitives and [Windows injection telemetry](../windows/process-injection-telemetry.md) for the ETW-TI fields.

### The cost of cleanup

Deletion is itself an artifact, and often a louder one than the thing it removes. This is the most commonly violated principle in the model.

- Deleting a file generates its own filesystem event and leaves a USN-journal `FILE_DELETE` record and MFT residue on Windows, or an auditd `unlink`/`unlinkat` record on Linux. A forensic timeline shows the create-then-delete pair, which is more suspicious than a single benign-looking file.
- Clearing an event log is one of the highest-signal actions possible: Windows Security Event ID **1102** ("The audit log was cleared") and System Event ID **104** are specifically what hunters alert on. On Linux, truncating or removing `/var/log/auth.log`, `/var/log/secure`, or wtmp/btmp, or running `journalctl --rotate --vacuum-time`, breaks the log continuity that a SIEM forwarder will notice as a gap.
- Selectively removing individual records (for example `utmpdump`/edit/`utmpdump -r` against wtmp) is quieter than wholesale clearing but requires precise knowledge of what was written, and any forwarded copy already in the SIEM cannot be unsent.

The takeaway: the only artifact you can reliably "clean" is one you never created. Cleanup is damage control, not erasure, and in a forwarded-logging environment it is frequently a net increase in signal. Plan operations so cleanup is unnecessary.

### Deconfliction in purple exercises

In a purple-team engagement the model has a sixth artifact class the blue team cares about: ambiguity. An alert the SOC cannot attribute to the red team consumes real incident-response cycles and can trigger a genuine containment action mid-test. Deconfliction removes that ambiguity without removing the test value:

- Maintain a shared, timestamped activity log: action, source IP/host, target, technique ID, and expected telemetry. Many teams keep this in a tool such as Vectr or a shared sheet keyed to ATT&CK technique IDs.
- Use a pre-shared deconfliction marker the blue team can query: a known source-IP allowlist, a fixed user-agent or JA3 on red infrastructure, or a canary string in command lines, so the SOC can confirm "is this us" in seconds.
- Agree on a "real-world intrusion" abort signal in advance, so that if the blue team sees activity that is NOT on the red team's log, the exercise pauses to investigate a possible genuine compromise.

Deconfliction is an OPSEC obligation, not a courtesy: it is what separates a measured purple exercise from a denial-of-service against your own client's SOC.

### The kill chain as a telemetry sequence

Read the kill chain not as phases of access but as a sequence of telemetry-generating steps, each with a different loudest artifact. Knowing where each step is loudest tells you where to spend your stealth budget.

| Kill-chain step | Loudest artifact | Primary telemetry source |
| --- | --- | --- |
| Initial access (phish/exploit) | Anomalous child process from Office/browser; new inbound | Sysmon 1, EDR parent-child, email/proxy logs |
| Execution | Full command line of a new process | Sysmon 1, Security 4688, auditd `execve` |
| Persistence | New autostart artifact (Run key, service, cron, unit) | Sysmon 12/13 registry, Security 4697/7045, auditd on cron/systemd paths |
| Privilege escalation | Token manipulation, new high-integrity process, SUID exec | Security 4672/4673, ETW-TI, auditd `setuid`/`setgid` |
| Defense evasion | Log clear, security-service stop, AMSI/ETW patch | Security 1102/104, Sysmon 5/255, ETW provider gaps |
| Credential access | LSASS handle/read; SAM/SECURITY hive access; `/etc/shadow` read | Sysmon 10 (LSASS), Security 4656/4663, auditd file watch |
| Lateral movement | New auth event from an unusual source-host pair | Security 4624 type 3, 4648, 4768/4769, netflow |
| Collection/exfil | Large or off-hours outbound; archive creation | Proxy/NetFlow byte counts, Sysmon 11 (file create), DLP |

Persistence and credential access are usually the loudest steps because they touch rare, security-relevant objects (autostart locations, LSASS, the SAM hive). Spend your quietest primitives there. Initial command-line execution is loud because of full command-line logging; favor in-process execution to avoid it.

### The decision framework

Before any action, answer four questions. If you cannot answer them, you do not yet understand the action's cost and should not run it.

1. **What artifacts does this create?** Enumerate by class: disk, process, network, auth, log/config. Name the specific event IDs or syscalls you expect (see the kill-chain table and the [detection-mapping index](../detection-mapping/index.md)).
2. **Who collects them?** Local-only (cleanable, lower risk), forwarded to SIEM (permanent, higher risk), or EDR-cloud (permanent plus behavioral correlation). Forwarded and cloud artifacts cannot be cleaned.
3. **Is there a quieter primitive?** Walk the minimize-touch hierarchy. Can this be done in-process, with a signed built-in, against expected infrastructure, in a noisy directory?
4. **Is the value worth the trace?** A loud action that achieves the objective can be correct; a loud action for reconnaissance you could have inferred is never correct. Spend artifacts only where they buy objective progress.

## OPSEC notes

**What makes the loud version loud.** The loud operator treats primitives as free. They drop a tool to `C:\Windows\Temp` or `/tmp`, spawn `powershell.exe -enc <base64>` or `bash -i` from an unexpected parent, beacon every 60 seconds with zero jitter to a fresh VPS, dump LSASS with a tool named `procdump`, and then clear the Security log to "cover tracks." Each of those is a textbook detection. The full command line is logged before the process even runs anything; the log clear is itself Event ID 1102; the new file's hash hits threat intel; the fixed-interval beacon is a trivial NetFlow histogram. The loud version is loud because it generates rare, high-signal, security-relevant artifacts and then generates more trying to remove them.

**The quiet variant.** The quiet operator stays in-process where possible, uses signed built-ins (LOLBins/GTFOBins) so the binary and signer are expected, blends C2 into expected destinations with realistic jitter and traffic profiles (see [malleable profiles](../c2-infrastructure/malleable-profiles.md)), writes only to directories that already see churn when disk is unavoidable, accesses sensitive objects with the lowest-privilege handle that works, and - critically - designs the operation so no cleanup is required. They account for every artifact in advance and accept the small, blended ones rather than generating large ones and trying to delete them.

**Failure modes and tells.** The model fails when the operator's mental cost map is wrong: assuming a directory is noisy when it is monitored, assuming a binary is expected on a host where it has never run (first-seen-binary detections), assuming "encrypted means invisible" while ignoring the metadata (timing, volume, JA3/JA4, SNI), or assuming local-only logging when a forwarder is running. The largest tell is behavioral inconsistency: a service account that suddenly runs interactive tools, a workstation that initiates SMB to twenty hosts, a process whose parent makes no sense (`winword.exe` spawning `cmd.exe`). EDR and SIEM hunters key on these relationships, not on signatures. Stealth fails at the relationship layer long before it fails at the payload layer.

## Detection & telemetry

This is the inverse of the rest of the page: how a hunter reconstructs an operator who ignored the model. Because that operator treated artifacts as free, the reconstruction is a timeline-join across the exact artifact classes above. Use it to validate that your own activity would or would not be caught.

### Reconstructing the operator: the join

A hunter rebuilds the session by joining artifacts on host, process GUID/PID, and time. The pivots, by source:

- **Sysmon (Windows)** - Event ID 1 (process create: full command line, parent image, hashes, signer), 3 (network connect: destination, port, process), 7 (image load: unsigned/anomalous DLLs), 8 (CreateRemoteThread), 10 (process access, especially handles to `lsass.exe`), 11 (file create), 12/13/14 (registry autostart), 22 (DNS query). The process-tree join from a single anomalous Event ID 1 to its children and network connections is the backbone of reconstruction.
- **Windows Security (Security.evtx)** - 4688 (process creation with command line if audited), 4624/4625 (logon success/failure, with Logon Type), 4648 (explicit-credential logon), 4672 (special privileges assigned), 4697 (service installed), 4768/4769/4776 (Kerberos TGT/TGS and NTLM auth), 4656/4663 (handle requested / object access for SACL-audited objects), **1102** (audit log cleared). Event ID **7045** in the System log marks a new service.
- **Linux auditd** - `SYSCALL` records for `execve`/`execveat` (process exec with full argv if `-a exit,always -S execve`), `connect`, `unlink`/`unlinkat`, `setuid`/`setgid`, `ptrace`, and `memfd_create`; `PATH` records for file access; watched-path rules (`-w /etc/shadow -p r`, `-w /etc/cron.d -p wa`). Auditd ties each to `auid`/`ses`, which survive `su`/`sudo` and defeat naive identity laundering.
- **journald / syslog** - `sshd` and PAM authentication, `sudo` invocations, systemd unit start/stop, and the continuity gap left by any log rotation or truncation.
- **EDR** - the behavioral overlay: parent-child anomaly scoring, first-seen-binary, RWX/unbacked-memory alerts, LSASS-access alerts, and beacon-detection on netflow. This is where the relationship-layer tells surface even when each individual artifact looks benign.

### Hunt queries

Sigma-style logic for the loudest tells. Adapt field names to your pipeline.

```yaml
# Sigma-style: event log cleared (defense-evasion reconstruction anchor)
title: Security Event Log Cleared
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 1102   # Security log cleared
  selection_sys:
    EventID:
      - 104    # System/application log cleared
  condition: selection or selection_sys
level: high
```

```sql
-- osquery: first-seen / non-standard-path executables that ran recently
-- Pivot on processes whose binary lives in a world-writable or temp path.
SELECT p.pid, p.name, p.path, p.cmdline, p.parent, f.sha256
FROM processes p
LEFT JOIN hash f ON p.path = f.path
WHERE p.path LIKE '/tmp/%'
   OR p.path LIKE '/dev/shm/%'
   OR p.path LIKE '/var/tmp/%'
   OR p.path LIKE 'C:\Windows\Temp\%'
   OR p.path LIKE 'C:\Users\%\AppData\Local\Temp\%';
```

```
# Splunk: anomalous parent-child (Office/browser spawning a shell or LOLBin)
index=sysmon EventCode=1
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe"
   OR ParentImage="*\\outlook.exe" OR ParentImage="*\\chrome.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe"
   OR Image="*\\wscript.exe" OR Image="*\\mshta.exe"
   OR Image="*\\rundll32.exe")
| stats count by host, ParentImage, Image, CommandLine, User
```

```
# KQL (Microsoft Defender / Sentinel): handle/read access to LSASS
DeviceEvents
| where ActionType == "ProcessAccessLsass"
   or (FileName =~ "lsass.exe" and ActionType has "OpenProcess")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
```

```bash
# auditd rules: watch the objects credential-access and persistence touch (Linux)
# /etc/audit/rules.d/opsec-model.rules  -> augenrules --load
-a always,exit -F arch=b64 -S execve,execveat -k exec_full
-w /etc/shadow -p r  -k shadow_read
-w /etc/cron.d -p wa -k cron_persist
-w /etc/systemd/system -p wa -k unit_persist
-a always,exit -F arch=b64 -S ptrace -k injection
-a always,exit -F arch=b64 -S memfd_create -k fileless
```

```
# Splunk: fixed-interval beacon detection (network artifact even when encrypted)
index=netflow
| streamstats current=f last(_time) as prev by src_ip, dest_ip, dest_port
| eval delta = _time - prev
| stats count, dc(delta) as distinct_intervals, avg(delta) as avg_s,
        stdev(delta) as jitter_s by src_ip, dest_ip, dest_port
| where count > 20 and jitter_s < 5   /* low jitter = beacon */
```

### How the reconstruction concludes

The hunter does not need every artifact. One anchor (a 1102 log clear, an LSASS handle, a first-seen binary, a low-jitter beacon) seeds a time-windowed join across the other sources, and the operator's whole session unspools from there: the parent that spawned the loud process, the network destination it talked to, the files it wrote, the credentials it used, the host it moved to next. The operator who applied the artifact-budget model leaves no anchor for that join to start from. The operator who treated primitives as free leaves several, and any one is enough. For the full source-to-event mapping per technique, see the [detection-mapping index](../detection-mapping/index.md).

## MITRE ATT&CK

- T1070.001 - Indicator Removal: Clear Windows Event Logs (Security 1102 / System 104)
- T1070.002 - Indicator Removal: Clear Linux or Mac System Logs
- T1070.004 - Indicator Removal: File Deletion (the cost-of-cleanup artifact)
- T1562.001 - Impair Defenses: Disable or Modify Tools (AMSI/ETW/EDR tampering)
- T1562.002 - Impair Defenses: Disable Windows Event Logging
- T1562.006 - Impair Defenses: Indicator Blocking (suppressing telemetry at the source)
- T1055 - Process Injection (the in-memory artifact class)
- T1620 - Reflective Code Loading (fileless execution telemetry)
- T1003.001 - OS Credential Dumping: LSASS Memory (the loudest credential-access step)
- T1218 - System Binary Proxy Execution (living-off-the-land, signed-binary blending)
- T1071 - Application Layer Protocol (C2 blending into expected traffic)
- T1029 - Scheduled Transfer (off-hours exfil to reduce volume anomalies)

## References

- MITRE ATT&CK, Indicator Removal (T1070) and sub-techniques. https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK, Impair Defenses (T1562). https://attack.mitre.org/techniques/T1562/
- Microsoft, Sysmon (System Monitor) event reference, Sysinternals documentation. https://learn.microsoft.com/sysinternals/downloads/sysmon
- Microsoft, Windows Security audit events and Event ID reference (4624, 4688, 1102, 4697, 4769, 4656). https://learn.microsoft.com/windows/security/threat-protection/auditing/
- Linux audit framework: auditctl(8) and audit.rules(7) man pages. https://man7.org/linux/man-pages/man8/auditctl.8.html
- man7.org, execve(2), memfd_create(2), ptrace(2), unlink(2) syscall references. https://man7.org/linux/man-pages/man2/execve.2.html
- SigmaHQ, Sigma detection rule format and rule repository. https://github.com/SigmaHQ/sigma
- Osquery schema and tables reference, Fleet/osquery documentation. https://osquery.io/schema/
- The Unified Kill Chain (Paul Pols), telemetry-oriented phase model. https://www.unifiedkillchain.com/
