# Linux EDR & Kernel Telemetry Evasion

*What Linux sensors actually observe at the syscall boundary, the narrow surface where userland tricks still buy you something, and why fully blinding a kernel sensor is a loud, kernel-level event the defender catches.*

## What & why

The goal is to operate on an instrumented Linux host while understanding - honestly - what the deployed sensors can and cannot see, so you neither burn the engagement with a noisy "disable the agent" move nor waste time on userland tricks that a kernel sensor ignores by design. The OPSEC rationale is grounded in where the telemetry is generated. Signature antivirus reads files on disk; userland hooks read libc; auditd and eBPF sensors (Falco, Tetragon, Cilium) read syscalls inside the kernel. The deeper the observation point, the harder it is to evade without escalating privilege to the kernel itself, and kernel-level tampering (LKM unload, BPF program detach, auditd stop) produces its own high-signal event. The realistic quiet path is therefore not "blind the sensor" but "stay inside the behavior the sensor already expects from this host." This page maps the sensor stack, shows how to enumerate it as an attacker, and - the part that matters most for the purple-team reader - tells the defender exactly which artifacts a tamper attempt leaves behind. See also [Auditd & Journald Tradecraft](./05-auditd-and-journald.md) and [Log Tampering and Anti-Forensics](./06-log-tampering.md).

## Technique

### Map the sensor stack before you touch anything

Enumeration is read-only and low-risk; acting blind is what burns engagements. Establish what is watching before deciding whether evasion is even possible.

```bash
# linux/bash - is auditd present and running?
systemctl is-active auditd 2>/dev/null
ps -e -o pid,comm | grep -E 'auditd|audisp|laurel'
# auditd writes to /var/log/audit/audit.log by default; the kernel side is auditctl
auditctl -s 2>/dev/null     # status: enabled, pid, backlog, lost, rate
```

`auditctl -s` returns the kernel audit subsystem status. `enabled 2` means the configuration is locked (immutable) until reboot - rules cannot be added or removed, and `auditctl -e 2` is the flag an administrator sets to achieve that. `enabled 1` is the normal mutable state. The `pid` field is the userland `auditd` PID receiving records; `pid 0` means no daemon is draining the kernel buffer.

### Enumerate the active audit rules

You only know which syscalls are watched by reading the live ruleset. Loaded rules are authoritative; `/etc/audit/rules.d/*.rules` and `/etc/audit/audit.rules` are only the on-disk source that `augenrules` compiles at boot, and may differ from what is actually loaded.

```bash
# linux/bash - dump the CURRENTLY LOADED kernel rules (this is what matters)
auditctl -l
# example output you might see on a hardened host:
#   -a always,exit -F arch=b64 -S execve,execveat -k exec
#   -a always,exit -F arch=b64 -S connect -F a2=16 -k network
#   -w /etc/passwd -p wa -k identity
#   -w /etc/ld.so.preload -p wa -k preload
```

Read the rules precisely - the syntax tells you the evasion surface:

- `-a always,exit -F arch=b64 -S execve,execveat -k exec` watches process creation on 64-bit. Note that it lists both `execve` and `execveat`. If a rule only named `execve`, calling `execveat(2)` directly would slip past it - but mature rulesets (the upstream `audit` and CIS-derived sets) include both, plus the `arch=b32` companion line. Always check for the 32-bit twin; a rule that only specifies `arch=b64` can be evaded by a 32-bit process issuing the 32-bit syscall number.
- `-w /path -p wa -k key` is a watch: a permission filter on a path. `-p wa` triggers on write and attribute change. `-p x` would trigger on execute. A watch on `/etc/passwd` does not cover a hardlink created elsewhere to the same inode under some configurations, but it does cover the path.
- The `-k` key is the hunt tag the defender greps for. It tells you exactly what they are correlating on.

### Why narrow rules are the only place syscall choice helps

The recurring myth is "use `openat` instead of `open` to evade auditd." This is only true if the rule is narrow. A rule written as `-a always,exit -F arch=b64 -S open -k file_access` watches solely `open(2)`. Modern glibc and modern code paths call `openat(2)` (the `*at` family takes a directory file descriptor), so on many systems the legacy `open` rule already misses ordinary activity, and an attacker calling `openat` adds nothing. Conversely, if the rule names `open,openat,openat2`, every variant is covered and there is no syscall to swap to. The lesson: enumerate first, and only consider a syscall swap when `auditctl -l` proves the watched set is incomplete. Do not assume.

```bash
# linux/bash - find which file-related syscalls are actually watched
auditctl -l | grep -E -- '-S (open|openat|openat2|creat|truncate)'
# if this returns only 'open', openat/openat2 are unwatched on this host
```

### You cannot quietly disable auditd

There is no silent kill. Every path to stopping or weakening auditd is itself an audited or logged event:

- `systemctl stop auditd` / `service auditd stop` generates a `SERVICE_STOP` record and a systemd journal entry, and the kernel emits a `DAEMON_END` audit record when the daemon detaches.
- `auditctl -D` (delete all rules) produces a `CONFIG_CHANGE` record before the rules are gone - the deletion itself is logged.
- `auditctl -e 0` (disable) produces a `CONFIG_CHANGE` record with `audit_enabled` transition.
- Killing the daemon with `SIGKILL` leaves the kernel still generating records with no userland consumer; `auditctl -s` then shows `pid 0` and a climbing `lost` counter - a glaring gap.
- If the ruleset is immutable (`enabled 2`), none of the above rule manipulations work at all until reboot, and a reboot is itself an event.

The honest conclusion: on a host with centralized audit forwarding (audisp-remote, Laurel to a SIEM, journald to a log pipeline), tampering with auditd trades one quiet day for one screaming alert. Living within allowed behavior beats it every time.

### eBPF sensors observe the same syscalls and ignore your userland tricks

Falco, Cilium Tetragon, and Cilium itself attach eBPF programs to kernel hook points - tracepoints (`sys_enter_execve`), kprobes, LSM hooks, and raw syscall tracepoints. Because the observation happens in kernel space at the syscall boundary, the techniques that defeat userland visibility do not touch them:

- `LD_PRELOAD` shimming libc - the eBPF probe sits below libc, on the kernel entry, so the real `execve`/`connect` is still recorded with the real arguments.
- `ps`/`/proc` hiding rootkit-style tricks - the sensor never asked `/proc`; it got the event from the kernel directly.
- Renaming your binary, hollowing argv[0], or memory-only execution - the syscall arguments (the resolved path, the `argv`, the socket address) are read by the probe from kernel memory at the moment of the call.

To enumerate eBPF sensors as an attacker (requires root or `CAP_BPF`/`CAP_SYS_ADMIN` to see much):

```bash
# linux/bash - list loaded BPF programs and their attach types
bpftool prog show          # IDs, types (tracepoint, kprobe, lsm, raw_tracepoint)
bpftool perf show          # which perf/probe events have BPF attached
ls -la /sys/fs/bpf/        # pinned BPF objects (maps/progs persisted by sensors)
# tracepoint/kprobe attachments are also visible here:
cat /sys/kernel/debug/tracing/kprobe_events 2>/dev/null
cat /sys/kernel/debug/tracing/uprobe_events 2>/dev/null
# sensor processes themselves:
ps -e -o pid,comm | grep -E 'falco|tetragon|cilium|sysmon'
```

A `prog` of type `lsm` is especially relevant: LSM-BPF programs can enforce, not just observe - they can deny a syscall outright. You cannot "swap a syscall" around an LSM hook because the hook is on the security operation, not a single syscall number.

Detaching or unloading these programs requires `CAP_BPF`/`CAP_SYS_ADMIN`, leaves the pinned objects gone from `/sys/fs/bpf`, and - for a well-built sensor - trips the sensor's own watchdog because its programs vanish. That is the same loud trade as killing auditd.

### AV versus EDR - different observation models

Treat them separately because the evasion that works on one is irrelevant to the other.

- **AV (signature, file-scan):** ClamAV, and the on-access scanners built on the kernel `fanotify` API. These read file content and match signatures/hashes, primarily on file open/exec. Defeated by content changes: packing, encryption, polymorphism, or never writing to disk. A pure in-memory `memfd_create(2)` + `execveat` payload bypasses a disk file scanner because there is no file on disk to read. But note - `fanotify` with `FAN_OPEN_EXEC_PERM` operates at the kernel and can still observe the exec event even if it cannot scan a meaningful file, and an eBPF sensor sees the `memfd` exec plainly.
- **EDR (behavioral, syscall):** observes the sequence of actions - process lineage, network connects, file writes to sensitive paths, privilege transitions - via auditd, eBPF, or both. Changing your file content does nothing here. The only evasion is changing your behavior, or operating so it resembles sanctioned activity.

The cross-link: a `memfd`-resident payload is detailed in [Memory-Only Execution](./08-memfd-and-fileless.md), with the caveat that fileless defeats the file scanner, not the syscall sensor.

### ptrace anti-debug and anti-instrument, and its limits

`ptrace(2)` is the userland debugging/instrumentation primitive. A process can call `ptrace(PTRACE_TRACEME, 0, 0, 0)` to detect or refuse a userland debugger attaching, because a process can have only one tracer - a second `PTRACE_ATTACH` then fails with `EPERM`. Some payloads use this as anti-analysis.

```c
// linux/c - classic anti-debug self-check
#include <sys/ptrace.h>
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    // already being traced - a debugger/instrumenter is attached
}
```

The hard limit: this only frustrates `ptrace`-based userland tooling (gdb, strace, ltrace, frida-style attach). It does nothing against a kernel sensor. auditd and eBPF do not use `ptrace`; they read the syscall stream from inside the kernel. An anti-debug payload that thinks it is "clean" because no debugger attached is still fully visible to Falco/Tetragon/auditd. Anti-ptrace is anti-analyst, not anti-telemetry.

Operationally, ptrace itself is watchable: a rule `-a always,exit -F arch=b64 -S ptrace -k tracing` records every ptrace call, so an injector using `PTRACE_POKETEXT`/`PTRACE_ATTACH` for code injection lights up. Modern hosts also set `kernel.yama.ptrace_scope=1` (or higher), restricting non-child attaches, which both limits your injection options and is visible in `/proc/sys/kernel/yama/ptrace_scope`.

### Living within allowed behavior - the actual quiet path

Since you cannot blind the kernel without kernel access, and kernel access is loud, the real tradecraft is blending:

- Use binaries already present and sanctioned (the LOLBins set - `python3`, `curl`, `ssh`, package managers, the host's own admin tooling) so process-lineage telemetry shows expected parents.
- Reuse existing network egress paths and ports already in the host's baseline rather than novel sockets that stand out in `connect` telemetry.
- Schedule activity within normal admin windows; an exec at 03:14 from a service account that never runs interactive shells is its own anomaly regardless of syscall choice.
- Avoid touching watched paths (`/etc/passwd`, `/etc/ld.so.preload`, `/etc/sudoers`, SSH `authorized_keys`) which carry `-w ... -p wa` watches on virtually every hardened host.

This is covered in depth in [Living off the Land](./09-lolbins-and-blending.md).

## OPSEC notes

The **loud** version is any direct assault on the sensor: stopping auditd, deleting rules, `rmmod` of a sensor LKM, detaching BPF programs, killing the EDR agent process. Each produces a discrete, high-fidelity event and, worse, a telemetry *gap* that a SIEM heartbeat monitor flags within minutes. Tamper-protected agents (those running with a kernel component or under systemd `Restart=always` plus a watchdog) respawn and emit a tamper alert. A gap is louder than activity: defenders alert on "sensor X stopped reporting" precisely because attackers try to silence sensors.

The **quiet** variant is to never touch the sensor. Enumerate it, understand its blind spots through the loaded ruleset, and route activity through behavior it already tolerates. Where a genuine gap exists (a narrow `open`-only rule, an unmonitored syscall variant, an `arch=b64`-only rule reachable from a 32-bit process), use it *passively* - choose the unwatched path rather than disabling the watch.

**Failure modes and tells:**

- Assuming on-disk `audit.rules` equals loaded rules. They diverge after manual `auditctl` changes. Trust `auditctl -l` only.
- Assuming `LD_PRELOAD` or `/proc` hiding evades eBPF. It does not; the kernel probe already has the truth.
- Disabling auditd and forgetting the kernel keeps generating records into a buffer that now overflows - the `lost` counter in `auditctl -s` and the `backlog` climb are evidence even after the daemon is dead.
- ptrace-based injection on a host with a `ptrace` audit rule or `yama.ptrace_scope >= 1`.
- `memfd`/fileless execution assumed to be invisible - it defeats the file scanner only; exec telemetry still fires.
- Immutable audit config (`enabled 2`): your rule-tamper commands silently fail, you believe you succeeded, and every action is still fully logged.

## Detection & telemetry

This is the section that matters. Below are the exact artifacts each tamper or evasion attempt produces and where to hunt them.

### auditd tamper and stop

| Action | Artifact | Where |
| --- | --- | --- |
| Daemon stopped | `type=DAEMON_END` audit record; `type=SERVICE_STOP` for the systemd unit | `/var/log/audit/audit.log`, journald |
| Rules deleted/disabled | `type=CONFIG_CHANGE` with `op=` / `audit_enabled` transition | `/var/log/audit/audit.log` |
| Daemon killed (SIGKILL) | No clean `DAEMON_END`; kernel `lost` counter climbs, `pid 0` in status | `auditctl -s`, SIEM gap |
| Config file edited | `-w /etc/audit/ -p wa` watch fires `type=CONFIG_CHANGE`/`type=PATH` | `/var/log/audit/audit.log` |

Hunt for the absence as much as the presence - alert when an agent that normally emits N records/min drops to zero.

```splunk
index=linux sourcetype=linux_audit ( type=DAEMON_END OR type=CONFIG_CHANGE OR ( type=SERVICE_STOP unit=auditd.service ) )
| table _time host type op auid exe key
```

```sql
-- osquery: confirm auditd is alive and the kernel side is enabled
SELECT name, path, state FROM systemd_units WHERE id = 'auditd.service';
-- osquery process table: is the daemon present?
SELECT pid, name, path FROM processes WHERE name = 'auditd';
```

A Sigma-style logsource note: map to `category: process_creation` / Linux auditd and key on `DAEMON_END` and `CONFIG_CHANGE`. Falco ships an analogous managed rule for audit/sensor tampering.

### SIEM heartbeat / sensor gap

The highest-value detection requires no host artifact at all. Every sensor (auditd forwarder, Falco, Tetragon, EDR agent) reports on a cadence. Build a watchdog that fires when a known host stops reporting.

```splunk
| tstats latest(_time) as last_seen where index=edr by host
| eval gap_min = round((now() - last_seen)/60, 1)
| where gap_min > 10
| sort - gap_min
```

```kql
// KQL - Linux endpoints silent beyond expected heartbeat interval
Heartbeat
| where OSType == "Linux"
| summarize LastBeat = max(TimeGenerated) by Computer
| extend GapMinutes = datetime_diff('minute', now(), LastBeat)
| where GapMinutes > 10
```

### eBPF program load/unload

BPF program loading goes through the `bpf(2)` syscall (`BPF_PROG_LOAD`). Module/sensor loads of an LKM go through `init_module`/`finit_module`. Watch both - a sudden BPF load that is not from your sanctioned sensor, or an unload that removes a sensor's pinned program, is the signal.

```bash
# linux/bash - audit rules to record bpf() and kernel module operations
auditctl -a always,exit -F arch=b64 -S bpf -k bpf_activity
auditctl -a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kmod
# (persist these in /etc/audit/rules.d/ on the defender's hosts)
```

```sql
-- osquery: inventory loaded kernel modules and watch for unexpected additions/removals
SELECT name, size, used_by, status, address FROM kernel_modules ORDER BY name;
```

```bash
# linux/bash - defender baseline of attached BPF programs; diff against this
bpftool prog show --json | jq -r '.[] | "\(.id)\t\(.type)\t\(.name)"' | sort
ls -1 /sys/fs/bpf/ 2>/dev/null
```

A vanished entry from the BPF baseline or a `delete_module` for a sensor's LKM is a tamper indicator. The sensor's own watchdog log (Falco/Tetragon emitting "rules reloaded" or "program detached") corroborates it.

### Agent tamper-detection (EDR)

Mature EDR agents self-protect. The detections live in the EDR console, not on the host: agent service stop, agent binary modification (file-integrity on the agent path), driver/kernel-module unload, and watchdog-respawn events. Hunt for agent-uninstall command lines and service-control events targeting the agent unit name. On systemd hosts the agent typically runs `Restart=always`; a stop followed by an immediate respawn plus a tamper event is the expected self-protection trace.

### Evasion-specific tells

- **memfd / fileless exec:** `execveat` against an fd whose `/proc/<pid>/exe` or `/proc/<pid>/maps` references `memfd:` or a deleted file. Hunt `type=EXECVE`/`type=PROC_TITLE` records where the resolved exe path contains `memfd:` or ends in `(deleted)`.
- **ptrace injection:** `type=SYSCALL` records with `syscall=ptrace` and a request of `PTRACE_ATTACH`/`PTRACE_POKETEXT`, especially across process boundaries; also check `yama.ptrace_scope`.
- **LD_PRELOAD persistence:** `-w /etc/ld.so.preload -p wa` watch fires `CONFIG_CHANGE`/`PATH`; also hunt `execve` records carrying an `LD_PRELOAD=` entry in the environment if env capture is enabled.
- **32-bit syscall slip:** `execve`/`connect` from a `b32` process on an otherwise 64-bit host - add the `arch=b32` companion rule so this is not a blind spot in the first place.

```splunk
index=linux sourcetype=linux_audit type=SYSCALL syscall=ptrace
| search a0=PTRACE_ATTACH OR a0=PTRACE_POKETEXT OR a0=PTRACE_POKEDATA
| table _time host auid pid ppid exe a0 key
```

### Defender hardening checklist (closes the blind spots above)

- Set audit config immutable at boot (`-e 2` as the final rule) so attacker rule-tamper fails and is logged.
- Include both `arch=b64` and `arch=b32` on every syscall rule; name all variants (`open,openat,openat2`; `execve,execveat`).
- Forward audit off-host (audisp-remote / Laurel -> SIEM) so local deletion does not erase evidence.
- Deploy a kernel-side sensor (Falco/Tetragon) alongside auditd so userland tricks have no effect.
- Run a heartbeat monitor that alerts on sensor silence within minutes.

## MITRE ATT&CK

- T1562.001 - Impair Defenses: Disable or Modify Tools (stopping auditd, killing the EDR agent, detaching BPF)
- T1562.012 - Impair Defenses: Disable or Modify Linux Audit System (`auditctl -D`/`-e 0`, daemon stop)
- T1562.006 - Impair Defenses: Indicator Blocking (cutting off telemetry forwarding to the SIEM)
- T1070 - Indicator Removal (broader cleanup of tracks)
- T1014 - Rootkit (LKM-level blinding of kernel telemetry)
- T1620 - Reflective Code Loading (memory-only / `memfd` execution to dodge file scanning)
- T1055.008 - Process Injection: Ptrace System Calls
- T1622 - Debugger Evasion (ptrace anti-debug self-checks)
- T1574.006 - Hijack Execution Flow: Dynamic Linker Hijacking (`LD_PRELOAD`, `/etc/ld.so.preload`)
- T1480 - Execution Guardrails (living within allowed behavior / environment-keyed execution)

## References

- Linux man-pages project - auditctl(8), audit.rules(7), auditd(8), ptrace(2), bpf(2), execveat(2), openat(2), memfd_create(2). https://man7.org/linux/man-pages/
- MITRE ATT&CK - Impair Defenses (T1562) and sub-techniques, Process Injection (T1055). https://attack.mitre.org/techniques/T1562/
- Falco documentation - rules, eBPF probe, and tamper/drift detection. https://falco.org/docs/
- Cilium Tetragon documentation - eBPF-based process and syscall observability. https://tetragon.io/docs/
- Linux kernel documentation - BPF and BPF LSM. https://docs.kernel.org/bpf/
- Linux Audit project (linux-audit) - audisp/Laurel forwarding and rule design. https://github.com/linux-audit
- Kernel documentation - Yama LSM and ptrace_scope. https://docs.kernel.org/admin-guide/LSM/Yama.html
- bpftool documentation - inspecting loaded BPF programs, maps, and pinned objects. https://docs.kernel.org/bpf/bpftool/
