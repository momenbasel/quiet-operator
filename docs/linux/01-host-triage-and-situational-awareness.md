# Linux Host Triage & Quiet Situational Awareness

_Reading a freshly-accessed Linux host without generating the recon burst that fires the first alert._

The first sixty seconds on a new host decide whether the rest of the engagement is quiet. The reflex move is to dump a wall of `id; uname -a; ps aux; netstat; find / -perm -4000` into the shell. That reflex is exactly what behavioral detections are tuned for: a dense cluster of `execve` events from one session in a short window. This page covers how to characterize the host using reads instead of execs, how to find the logging and EDR that would record you, and what each enumeration action actually emits so you can decide what is safe before you run it. Pair this with [../00-foundations/threat-model-and-opsec-baseline.md](../00-foundations/threat-model-and-opsec-baseline.md) and the sink map in [../detection-mapping/auditd-execve-coverage.md](../detection-mapping/auditd-execve-coverage.md).

## What & why

The goal is full situational awareness - privilege, network position, what monitoring exists, whether your own keystrokes are recorded - while emitting the minimum number of auditable events. The OPSEC rationale is ordering: you must learn what is logging you _before_ you do anything loud, because some of the most useful enumeration commands (`sudo -l`, spawning interpreters, `find` walking the tree) are themselves high-signal and in some cases impossible to take back. A read of `/proc/self/status` costs nothing on most hosts; a `sudo -l` writes a syslog line to a box you may not control. Build the picture from cheap reads first, identify the recorders, then spend expensive commands only where the value justifies the trace.

## Technique

### Order of operations

1. Determine whether your shell is interactive and whether history/command logging is on (do this before anything else).
2. Read identity and privilege from `/proc` and files, not from helper binaries where avoidable.
3. Find EDR, auditd, eBPF tracers, and log shippers.
4. Only then decide whether `sudo -l`, `find`, or interpreter-based enumeration is worth its trace.

### Identity and privilege without execs

Most identity facts are files. Reading a file under `/proc` or `/etc` generates no `execve` and, by default, no `auditd` record unless a watch is set on the path.

```bash
# bash - reads only, no child processes spawned
printf '%s\n' "$0" "$-"        # shell name and flags ('i' = interactive)
echo "$UID:$EUID"             # real vs effective uid from shell builtins
cat /proc/self/status         # Uid, Gid, Groups, CapEff, CapBnd, Seccomp, NoNewPrivs
cat /proc/self/loginuid       # the audit loginuid - ties later events to a login
cat /proc/self/sessionid
cat /etc/passwd               # accounts, shells, home dirs
cat /etc/group                # group membership
```

Key fields in `/proc/self/status`:

- `CapEff` / `CapBnd` - effective and bounding capability sets as hex masks. Decode against `/usr/include/linux/capability.h`. A non-root shell with `CapEff` containing `CAP_SYS_ADMIN`, `CAP_DAC_READ_SEARCH`, or `CAP_SYS_PTRACE` is a privilege story worth more than uid 0 in a container.
- `Seccomp` - `0` none, `2` filtered. Tells you if syscall filtering will block later tradecraft.
- `NoNewPrivs` - `1` means setuid binaries will not elevate; plan accordingly.

`id` is a single clean `execve` and is widely expected on shared hosts, so it is low-signal in isolation. The tell is `id` immediately followed by ten more recon binaries. Prefer the `/proc` reads when you want zero process trace.

### Host, kernel, distro

```bash
# bash - all reads
cat /proc/version            # kernel + build/compiler string, same data as uname -a
cat /etc/os-release          # distro id and version
cat /proc/cmdline            # boot args - look for container/hypervisor hints
hostname                     # one execve; or: cat /proc/sys/kernel/hostname
```

`uname` is an `execve`; `cat /proc/version` and `cat /proc/sys/kernel/osrelease` give the same data as pure reads.

### Network position without `netstat`/`ss`

`ss` and `netstat` are single execs but are classic recon signatures when chained. The kernel exposes the same socket tables as readable files:

```bash
# bash - parse /proc directly, no socket-tool execve
cat /proc/net/tcp /proc/net/tcp6     # local/remote addr:port in hex, state, inode, uid
cat /proc/net/udp /proc/net/udp6
cat /proc/net/unix                   # unix domain sockets - finds local IPC/agents
cat /proc/net/fib_trie               # routing/interfaces without `ip route`
cat /etc/resolv.conf /etc/hosts      # resolver and static mappings
```

`/proc/net/tcp` columns are hex and little-endian per 32-bit word. `0100007F:0050` is `127.0.0.1:80`. State `0A` is `LISTEN`, `01` is `ESTABLISHED`. The `uid` column attributes the socket to an account - useful for spotting a root-owned listener you can target. This read also shows _who is connected_, which can reveal an admin SSH session you do not want to surprise.

`ip`, `ss`, `arp` each cost one `execve`. If the environment expects them (most do) they are tolerable singly; the risk is volume.

### Who else is here

```bash
# bash
cat /proc/loadavg                    # quick liveness without `uptime` execve
ls -la /dev/pts/                     # active ptys = interactive sessions, no exec needed
cat /var/run/utmp 2>/dev/null | strings   # current logins (utmp is binary)
```

`w`, `who`, `last`, and `lastlog` are execs that read `utmp`/`wtmp`/`lastlog`. They do not modify those files (login/logout does), so they are read-only as far as login records go, but each is an `execve` an EDR will see. `ls /dev/pts/` and reading `/proc/*/stat` for tty fields gives you concurrent-session awareness without those binaries.

### Mounts, environment, secrets at rest

```bash
# bash
cat /proc/mounts /proc/self/mountinfo   # mounts incl. overlay/container layers
cat /proc/self/environ | tr '\0' '\n'   # YOUR env: tokens, proxies, KRB5CCNAME
cat /proc/1/cgroup                       # cgroup path reveals docker/k8s/lxc
ls -la /run/secrets /var/run/secrets 2>/dev/null   # k8s/docker mounted secrets
```

`/proc/<pid>/environ` of _other_ processes is readable only if you own them or are root, and reading another user's `environ` is a meaningful escalation signal if ptrace/yama is monitored. Reading your own is free.

## Detecting the monitoring stack

This is the part that decides everything after it. None of the reads below trigger `execve` if you `cat` the files; the moment you call `lsmod`, `auditctl`, `bpftool`, or `ps` you are running a binary that an EDR may flag - so read files first, run tools only when a file read is insufficient.

### auditd presence and what it is watching

```bash
# bash - file reads first
cat /proc/self/loginuid                 # if set to a real uid, auditd is wired into login
ls -la /etc/audit/ /etc/audit/rules.d/  # ruleset on disk
cat /etc/audit/audit.rules 2>/dev/null
cat /etc/audit/rules.d/*.rules 2>/dev/null
ls -la /var/log/audit/                  # log dir; can you even read it?
```

```bash
# bash - these are execs (loud-ish), use only if files were unreadable
auditctl -s        # status: enabled, pid, backlog, lost, rate limit
auditctl -l        # the LIVE ruleset (may differ from files on disk)
```

`auditctl -l` is the ground truth - rules can be loaded that are not in `rules.d`. The fields that matter for you: any `-a always,exit -F arch=b64 -S execve` rule means every command you run is recorded with full argv (Linux audit type `EXECVE`, record `SYSCALL` with `syscall=59`). Any `-w` watch on a path you intend to read (for example `-w /etc/passwd -p r`) means even your `cat` will generate a `PATH`/`SYSCALL` record. Check `rules.d` for watches before reading sensitive files.

### EDR / sensor processes

```bash
# bash - prefer reading /proc over `ps` where you can
ls -la /proc/*/exe 2>/dev/null | grep -Ei 'falco|auditd|osqueryd|sysmon|sentinel|crowdstrike|falcon|carbonblack|cbagent|wazuh|elastic|filebeat|auditbeat|fluentd|fluent-bit|rsyslog|td-agent'
# kernel-side sensors
cat /proc/modules | grep -Ei 'falco|sysmon|ebpf|cb|crowdstrike|aegis'
ls -la /sys/module/ | grep -Ei 'falco|cb|crwd|aegis'
```

Known sensor footprints:

- `falco` userspace + a kernel module `falco` OR (modern) an eBPF/`modern_bpf` probe - check `/proc/modules` and for an eBPF program (below).
- CrowdStrike Falcon - process `falcon-sensor`, kernel module `falcon_lsm_serviceable`/`falcon_kal`, files under `/opt/CrowdStrike/`.
- Microsoft Defender for Endpoint (MDE) on Linux - `mdatp` daemon, `/opt/microsoft/mdatp/`, uses eBPF or `auditd` as its event source; if it consumes `auditd`, your `audit.rules` will contain rules it inserted.
- SentinelOne - `/opt/sentinelone/`, `sentinelagent`/`sentineld`.
- osquery - `osqueryd`, config `/etc/osquery/osquery.conf`, scheduled `process_events`/`socket_events` tables that snapshot exactly the recon you are doing.
- Wazuh/OSSEC - `wazuh-agentd`, `/var/ossec/`, often tails `auth.log` and audit.

`ps -ef` / `ps aux` are themselves execs an EDR logs. Walking `/proc/*/comm` and `/proc/*/cmdline` with shell reads gives the same data without an `execve`:

```bash
# bash - process listing with zero execve beyond the shell builtins
for p in /proc/[0-9]*; do printf '%s\t%s\n' "${p#/proc/}" "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"; done
```

### eBPF tracers and kernel tracing

Modern EDR and Falco increasingly run eBPF rather than kernel modules, so `lsmod` shows nothing while you are fully instrumented. Look for loaded BPF programs and active tracepoints:

```bash
# bash - bpftool is an exec and usually root-only; try file reads first
ls -la /sys/fs/bpf/                              # pinned BPF objects
cat /sys/kernel/debug/tracing/kprobe_events 2>/dev/null    # active kprobes (needs debugfs mounted + perms)
cat /sys/kernel/tracing/kprobe_events 2>/dev/null
ls -la /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/  # is execve traced?
```

```bash
# bash - if you have root and bpftool exists (this is itself observable)
bpftool prog show          # loaded BPF programs, types (tracepoint, kprobe, lsm)
bpftool perf show          # which PIDs attached BPF to which probes
```

A `BPF_PROG_TYPE_TRACEPOINT` or `kprobe` program attached to `sys_enter_execve` or `tcp_connect` is a sensor watching process and network events. A `BPF_PROG_TYPE_LSM` program is an enforcement/audit hook. Note: reading `/sys/kernel/debug/tracing` requires debugfs mounted and usually root; failing to read it is itself informative (locked down host).

### Virtualization, container, honeypot/canary

```bash
# bash
cat /proc/1/cgroup /proc/self/cgroup     # 'docker'/'kubepods'/'lxc' in path = container
cat /proc/cpuinfo | grep -i hypervisor   # 'hypervisor' flag = VM
ls -la /sys/class/dmi/id/                 # product_name/sys_vendor: VMware/VirtualBox/QEMU/KVM/Xen
cat /sys/class/dmi/id/product_name 2>/dev/null
cat /sys/class/dmi/id/sys_vendor 2>/dev/null
```

Honeypot/canary tells: a host that is too clean (no shell history, no real users, empty `cron`), a single account with an obviously baited name, files like `*.canary` or AWS-keys-in-a-readme, or thinkst-style canarytokens in config files. Canary _files_ and _tokens_ frequently phone home only on read/access - so on a suspected deception host, avoid touching baited artifacts; reading a canarytoken file can fire an alert the same way `sudo -l` does. Cross-reference [../00-foundations/deception-and-canary-awareness.md](../00-foundations/deception-and-canary-awareness.md).

### Are your own commands being recorded - check before going loud

You must answer this _before_ the first expensive command.

```bash
# bash - shell history config (in-memory and on disk)
echo "HISTFILE=$HISTFILE HISTSIZE=$HISTSIZE HISTCONTROL=$HISTCONTROL"
echo "PROMPT_COMMAND=$PROMPT_COMMAND"     # may pipe every command to syslog/logger
shopt 2>/dev/null | grep -i hist          # histappend etc (bash)
cat /etc/profile /etc/bash.bashrc 2>/dev/null | grep -Ei 'history|PROMPT_COMMAND|logger|HISTTIMEFORMAT|readonly'
cat ~/.bashrc ~/.bash_profile 2>/dev/null | grep -Ei 'history|PROMPT_COMMAND|logger'
```

Three independent command-logging mechanisms can be live at once, and disabling one does not touch the others:

1. Shell history file (`~/.bash_history`) - in-process, written on exit. Can be neutralized for the session with `unset HISTFILE` or `export HISTFILE=/dev/null`, but if `HISTFILE` is marked `readonly` in `/etc/profile` you cannot, and the attempt is itself recorded by the other two mechanisms.
2. `PROMPT_COMMAND` shipping to `logger`/syslog - a hardened host pipes each command to `auth.log` or a SIEM on every prompt. This is independent of `HISTFILE`. Inspect it before assuming your shell is private.
3. `auditd execve` - kernel-level, captures full argv regardless of any shell setting. If `auditctl -l` showed an `execve` rule, _nothing you unset in the shell hides your commands_. This is the decisive check.

Decision rule: if `auditd` has an `execve` rule OR `PROMPT_COMMAND` ships to a remote sink, treat every `execve` as recorded and minimize them - lean on `/proc` reads. If only `HISTFILE` exists and is not readonly, you have shell-level cover but still leave `wtmp`/`auth.log` login traces.

### Log shippers and their destinations

Know where the telemetry goes so you can reason about what is offloaded beyond your reach.

```bash
# bash - configs reveal remote SIEM/collector endpoints
cat /etc/rsyslog.conf; ls -la /etc/rsyslog.d/; cat /etc/rsyslog.d/*.conf 2>/dev/null
cat /etc/filebeat/filebeat.yml /etc/auditbeat/auditbeat.yml 2>/dev/null   # output.logstash/elasticsearch hosts
ls -la /etc/fluentd /etc/fluent /etc/td-agent 2>/dev/null; cat /etc/td-agent/td-agent.conf 2>/dev/null
cat /etc/systemd/journald.conf 2>/dev/null | grep -Ei 'ForwardToSyslog|Storage|Seal'
cat /proc/net/tcp | awk '{print $3}'     # outbound connections (hex) corroborate shipper destinations
```

`rsyslog` lines beginning `*.* @host` (UDP) or `@@host` (TCP) name a remote collector. `filebeat`/`auditbeat` `output.elasticsearch`/`output.logstash` name the SIEM. If `journald` has `Seal=yes` (Forward Secure Sealing), tampering with journal files is detectable. Once logs leave the box, local cleanup is cosmetic - plan exfil/cleanup ([../detection-mapping/log-tamper-tells.md](../detection-mapping/log-tamper-tells.md)) accordingly.

## OPSEC notes

What makes the loud version loud:

- Volume and burst. A dozen recon execs in one session within a few seconds is the signature, not any single command. `sudo -l; id; uname -a; ps aux; netstat -tulpn; find / -perm -4000 2>/dev/null; cat /etc/shadow` is the canonical "I just landed" pattern and is trivially alerted on by sequence rules.
- `sudo -l` is logged. Every `sudo` invocation, including `sudo -l`, writes to `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL) and to the journal under `_COMM=sudo`, with a `COMMAND=` field. A failed or unexpected `sudo -l` from a service account is a high-fidelity alert. There is no quiet variant of `sudo -l`; if you run it, you have accepted the log line. Reading `/etc/sudoers` and `/etc/sudoers.d/*` instead reveals the same rights without the auth.log entry (it does require read access, often root, but on misconfigured hosts it is group-readable).
- Spawning interpreters. `python -c`, `perl -e`, launching `sh`/`bash` subshells, `nc`, `socket` modules - each is an `execve` of a known-suspicious binary and many EDRs score interpreter-spawning-from-a-shell heavily. Prefer shell builtins and `/proc` reads over `python -c 'import os'`.
- Commands that write. `find` updates directory access times (atime) unless the filesystem is `noatime`/`relatime` (relatime is now the default, which masks most of this). Worse, `find / ...` is a giant `openat`/`getdents` storm that auditd path-watches and EDR I/O monitors will see, and it hammers load. `updatedb`/`locate` touch a database. `tee`, `>>`, editing dotfiles all leave mtime changes. Reads of `/proc` and `/etc` do not change mtime/ctime of those targets.

The quiet variant: read files, do not exec; when you must exec, use expected binaries (`id`, `ls`, `cat`, `hostname`) that blend into normal admin activity, run them spaced out rather than in a burst, and never spawn a new interpreter or networking tool during triage.

Failure modes and tells:

- Unsetting `HISTFILE` while `auditd execve` is live - you think you are quiet, but `unset HISTFILE` itself was captured by audit, and now the analyst sees deliberate evasion (higher severity than the recon itself).
- Reading a file under an `-w` audit watch (for example `/etc/shadow`, `/etc/sudoers`) - the read generates a `PATH` record naming you. Check `auditctl -l` before touching watched paths.
- Touching a canary file or canarytoken - immediate out-of-band alert you cannot see locally.
- Reading another user's `/proc/<pid>/environ` or `cmdline` when Yama/ptrace_scope is monitored - cross-process reads from a non-owner stand out.

## Detection & telemetry

Defender-side, this is what host triage produces and where to hunt it.

### auditd (the primary execve source)

Process executions appear as paired records: a `SYSCALL` record (`syscall=59` execve on x86_64, with `auid`, `uid`, `pid`, `ppid`, `exe`, `success`) and an `EXECVE` record carrying `argc` and `a0..aN` argv fields. Recon bursts show as many `EXECVE` records with the same `pid` lineage and `auid` in a short interval.

Useful watch rules to surface triage activity:

```bash
# /etc/audit/rules.d/recon.rules
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k exec_recon
-w /etc/passwd -p r -k cred_read
-w /etc/shadow -p r -k cred_read
-w /etc/sudoers -p r -k cred_read
-w /etc/sudoers.d/ -p r -k cred_read
-w /usr/bin/sudo -p x -k sudo_exec
-w /usr/bin/whoami -p x -k recon_tool
-w /sbin/ss -p x -k recon_tool
```

Hunt for a recon burst (many distinct recon binaries from one auid in a 60s window):

```bash
# bash - ausearch over the recon key, then cluster by pid/time
ausearch -k exec_recon -ts recent --format csv \
  | awk -F, '{print $0}' \
  | sort
```

Splunk-style query over forwarded auditd:

```spl
index=linux sourcetype=auditd type=EXECVE
| eval cmd=coalesce(a0,"")
| search cmd IN ("id","whoami","uname","ps","netstat","ss","ip","w","who","last","find","lsmod","sudo","mount")
| bin _time span=60s
| stats dc(cmd) AS distinct_recon values(cmd) AS cmds by _time, pid, auid, host
| where distinct_recon >= 5
```

Sigma-style logic (process_creation on Linux): a single parent shell that spawns 5+ of {`id`,`whoami`,`uname`,`hostname`,`ps`,`ss`,`netstat`,`ip`,`w`,`last`,`lsmod`,`mount`,`sudo`} within 60 seconds, fired by count/correlation. This maps to the same burst the offensive side is trying to avoid.

### sudo logging

`sudo -l` and every `sudo` execution land in:

- `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS), lines `sudo: <user> : ... COMMAND=...`.
- journald: `journalctl _COMM=sudo` or `SYSLOG_IDENTIFIER=sudo`; fields `USER`, `COMMAND`, `PWD`, `TTY`.
- auditd if a watch on `/usr/bin/sudo -p x` exists (key `sudo_exec`).

KQL (e.g. Sentinel `Syslog` table) for `sudo -l` from non-admin accounts:

```kql
Syslog
| where ProcessName == "sudo"
| where SyslogMessage has "COMMAND=" 
| where SyslogMessage has "list" or SyslogMessage has "-l"
| project TimeGenerated, Computer, SyslogMessage
```

### login/session records

`w`/`who`/`last`/`lastlog` only _read_ `utmp`/`wtmp`/`btmp`/`lastlog`, but the act of running them is an `execve` visible to auditd and EDR. Actual session creation (your SSH login) is logged by PAM/sshd to `auth.log`/`secure` and updates `/var/run/utmp` and `/var/log/wtmp`. Hunt for the login event itself, not the enumeration tools, for ground truth of access.

### EDR / sensor process events

osquery `process_events` and `socket_events` (BPF-backed) capture exactly the triage commands and the `/proc/net` socket reads if configured. Falco rules such as the bundled "system information discovery" / "find suspicious recon" detect clusters of `uname`/`whoami`/`hostname`/`id` and reads of `/etc/shadow`. CrowdStrike/SentinelOne/MDE emit process-creation telemetry for each enumeration binary and behavioral detections for recon-burst sequences. Reading `/proc` files generates `openat` syscalls but no process-creation event - which is precisely why the quiet variant favors reads, and precisely why a defender should also watch sensitive-file reads via auditd `-w` watches, not only process creation.

### journald and shippers

`journalctl _COMM=sudo`, `journalctl -k` (kernel: module loads, BPF), and `journalctl _TRANSPORT=audit` surface the same events when audit is forwarded to the journal. If `Seal=yes` is set in `journald.conf`, verify integrity with `journalctl --verify`. Where `rsyslog`/`filebeat`/`auditbeat` forward off-box, the authoritative copy is in the SIEM regardless of local file state - hunt there for the burst pattern even if local logs were truncated.

### Quick defender checklist

- auditd: `EXECVE` burst by `auid`/`pid` within 60s; `PATH` records on `/etc/shadow`,`/etc/sudoers`.
- sudo: `auth.log`/`secure` `COMMAND=` lines, especially `sudo -l` from service accounts.
- Sensors: Falco recon rules, osquery `process_events`/`socket_events`, EDR process-creation + behavioral recon detections.
- File reads: `-w` watches on credential files catch the quiet `cat` path the offensive side prefers.
- Module/BPF: `journalctl -k` and `auditd` `KERN_MODULE`/`init_module` for new sensors; `bpftool prog show` baselines.

## MITRE ATT&CK

- T1082 - System Information Discovery
- T1057 - Process Discovery
- T1033 - System Owner/User Discovery
- T1016 - System Network Configuration Discovery
- T1049 - System Network Connections Discovery
- T1518.001 - Software Discovery: Security Software Discovery
- T1083 - File and Directory Discovery
- T1497 - Virtualization/Sandbox Evasion
- T1622 - Debugger Evasion (anti-tracing / eBPF-tracer awareness)
- T1562.003 - Impair Defenses: Impair Command History Logging (HISTFILE/HISTCONTROL)
- T1070.003 - Indicator Removal: Clear Command History

## References

- Linux man-pages: proc(5) - /proc filesystem fields including status, net/tcp, modules. https://man7.org/linux/man-pages/man5/proc.5.html
- Linux man-pages: capabilities(7). https://man7.org/linux/man-pages/man7/capabilities.7.html
- Linux Audit documentation: auditctl(8) and audit.rules(7). https://man7.org/linux/man-pages/man8/auditctl.8.html
- sudo manual: sudoers(5) and sudo logging behavior. https://www.sudo.ws/docs/man/sudoers.man/
- MITRE ATT&CK: Discovery tactic (TA0007) and Security Software Discovery T1518.001. https://attack.mitre.org/tactics/TA0007/
- Falco default ruleset (system information / recon detections). https://github.com/falcosecurity/rules
- osquery schema: process_events and socket_events tables. https://osquery.io/schema/
- systemd-journald.conf(5) - Storage, Seal/Forward Secure Sealing, ForwardToSyslog. https://man7.org/linux/man-pages/man5/journald.conf.5.html
