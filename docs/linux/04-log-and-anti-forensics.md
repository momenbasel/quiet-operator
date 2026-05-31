---
title: "Log & Anti-Forensics"
parent: "1. Linux"
nav_order: 4
---

# Linux Log Evasion & Anti-Forensics

*An honest accounting of Linux log artifacts, why local tampering is itself a loud, high-signal IOC, and why the only quiet play is to never generate the log in the first place.*

## What & why

The goal here is not to teach operators how to "clean up" after themselves - it is to make explicit that on any modern, centrally-logged Linux estate, deleting or editing local logs is near-useless and actively harmful to OPSEC. Logs are mirrored to a syslog collector, a journald remote, an EDR sensor, or a SIEM forwarder within seconds of being written. Once a line is off-box, scrubbing the local copy only creates a divergence between what the host holds and what the collector already has - and that divergence is one of the cleanest detections a defender owns. Tampering also generates its own second-order evidence: auditd config-change events, journald rotation records, `ctime` anomalies, and gaps in append-only accounting files. The mature tradecraft is to reason about which subsystem records a given action and to avoid triggering it, not to race a forwarder you cannot win against. This page documents the artifacts so a defender knows exactly where to look, and so an authorized red team understands the true cost of every "cleanup" action.

See also: [03 - Persistence](03-persistence.md) for log sources that persistence touches, and [05 - Exfiltration](05-exfiltration.md) for network-side telemetry that local log work does nothing to suppress.

## Technique

### The log sources you are actually fighting

Before touching anything, enumerate what records the action in question. These are distinct subsystems with distinct storage, distinct rotation, and distinct forwarding:

- **`/var/log/auth.log`** (Debian/Ubuntu) or **`/var/log/secure`** (RHEL/CentOS/Fedora) - PAM, sshd, sudo, su, cron auth. Plaintext, written by the syslog daemon (rsyslog/syslog-ng) or by journald's syslog bridge.
- **`/var/log/syslog`** / **`/var/log/messages`** - general facility logging. Plaintext.
- **journald binary journals** - `/var/log/journal/<machine-id>/*.journal` (persistent) or `/run/log/journal/...` (volatile, lost on reboot). Indexed, optionally sealed with Forward Secure Sealing (FSS). Not editable with a text editor.
- **`/var/log/audit/audit.log`** - the Linux Audit subsystem (`auditd`). Kernel-sourced syscall and watch records. The single richest host telemetry source on Linux.
- **Accounting databases** (fixed-width binary, `struct utmp` records):
  - **`/var/run/utmp`** - who is logged in *right now*. Read by `w` and `who`.
  - **`/var/log/wtmp`** - append-only history of logins/logouts and boots. Read by `last`.
  - **`/var/log/btmp`** - failed login attempts. Read by `lastb` (root only).
  - **`/var/log/lastlog`** - sparse file, one record per UID, the most recent login per user. Read by `lastlog`.

A single SSH login writes to all of: auth.log/secure, the journal, audit.log (if rules are loaded), utmp, wtmp, and lastlog. There is no single file to clean.

### Shell history controls and why each is itself suspicious

Every one of these prevents a command from reaching `~/.bash_history`. None of them is invisible - each leaves a different tell, and several are themselves recorded by other subsystems.

```bash
# Linux / bash
# Per-command: a leading space suppresses history IF HISTCONTROL includes ignorespace.
export HISTCONTROL=ignorespace        # or ignoreboth (ignorespace + ignoredups)
 sensitive --command --here           # leading space -> not stored
```

```bash
# Linux / bash - blunter approaches, each with a tell
unset HISTFILE                        # history not flushed to disk on exit
export HISTSIZE=0                     # in-memory list disabled
export HISTFILESIZE=0                 # truncates the file to 0 on next write
set +o history                        # disable history recording for this shell
ln -sf /dev/null ~/.bash_history      # all writes discarded
kill -9 $$                            # SIGKILL the shell -> no atexit flush of history
```

Why each is a tell:

- **`HISTCONTROL=ignorespace`** is the quietest of the set, but the *setting itself* is the artifact. If it is exported in `~/.bashrc`, `~/.bash_profile`, or `/etc/profile.d/`, it is on disk with a fresh `mtime`, and `auditd` file watches on those paths will have logged the modification. The commands you hid are gone, but the mechanism that hid them is sitting in a config file.
- **`unset HISTFILE`** / **`set +o history`** - the gap is the signal. A real interactive session writes history continuously; a session with zero `~/.bash_history` growth despite live commands (observable via process accounting, `pty` activity, or EDR command-line capture) is anomalous.
- **`ln -sf /dev/null ~/.bash_history`** - the symlink is permanent and obvious. `ls -l ~/.bash_history` showing a link to `/dev/null` is a textbook IOC; any hunt that stats home-directory history files finds it instantly.
- **`kill -9 $$`** - bash flushes history on a clean exit (or per-command if `PROMPT_COMMAND='history -a'` / `shopt -s histappend` with `histappend` semantics). SIGKILL skips the flush, but the absence of a logout/exit and an abnormal child-process termination is itself recorded by process accounting and by EDR.
- **The hard truth**: none of this touches `auditd` `execve` records. If audit `execve` auditing is enabled, every command you "hid" from bash history is in `/var/log/audit/audit.log` with full `argv`, and already forwarded. Bash history is a convenience file, not the authoritative command log.

### Accounting files: selective edit vs truncation

`utmp`/`wtmp`/`btmp` are arrays of fixed-size binary records. `utmpdump` does a lossless round-trip to and from a text representation, which is how the "selective edit" is performed versus a blunt truncate.

```bash
# Linux - round-trip a wtmp record set to text and back
utmpdump /var/log/wtmp > /tmp/wtmp.txt    # binary -> human-readable text
# edit /tmp/wtmp.txt to remove specific session lines
utmpdump -r /tmp/wtmp.txt > /var/log/wtmp # text -> binary, written back
```

```bash
# Linux - the blunt version (do not do this; included to show the tell)
: > /var/log/wtmp        # truncate to zero -> 'last' shows almost nothing
```

Why selective edit is preferred over truncation, and why both still fail:

- **Truncation** zeroes the file. `last` then reports a suspiciously short history that does not reach back to the documented system install or last reboot. The mismatch between `wtmp` history depth and the kernel's `btime`/uptime (`/proc/stat` `btime`, `uptime -s`) is trivially detected.
- **Selective edit via `utmpdump`** removes one session but leaves a hole: `last` shows sessions out of strict chronological order or with gaps, the file size is no longer a clean multiple consistent with surrounding records' timing, and `wtmp` no longer corroborates `lastlog` (which records the *last* login per UID separately). A defender cross-references `wtmp` against `lastlog`, against `auth.log`/`secure`, and against the SIEM's copy of the auth events. All four must agree; the edit breaks the agreement.
- **`btmp`** edits to hide brute-force noise similarly desynchronize from `auth.log`'s "Failed password" lines and from the SIEM's failed-auth counters.
- The act of writing back to these files updates their `mtime`/`ctime`. An accounting file whose `mtime` does not line up with the last real login event is anomalous by itself.

### Timestomp and the `ctime` problem

`touch` can move `atime` and `mtime`. It **cannot** set `ctime` (inode change time). This is the single most important forensic fact on this page.

```bash
# Linux - copy timestamps from a reference file (blends with neighbors)
touch -r /etc/hostname ./implant            # set atime+mtime to match reference
# Linux - set an explicit time
touch -d '2026-01-15 09:14:02' ./implant    # mtime+atime to a chosen value
touch -a -d '2026-01-15 09:14:02' ./implant # atime only
touch -m -d '2026-01-15 09:14:02' ./implant # mtime only
```

The catch:

- `mtime` = last content modification. `atime` = last access. **`ctime` = last inode metadata change** (permissions, ownership, link count - and `mtime` itself). Any `touch` that changes `mtime` *sets `ctime` to now* as a side effect. There is no `touch` flag to set `ctime`.
- Therefore the classic forensic tell is **`ctime` more recent than `mtime`** (and often more recent than `atime`). A file claiming to be from 2026-01-15 but with a `ctime` of "today" was timestomped. `stat` shows all three:

```bash
# Linux
stat ./implant
#   Access: 2026-01-15 09:14:02   <- atime  (set by touch)
#   Modify: 2026-01-15 09:14:02   <- mtime  (set by touch)
#   Change: 2026-05-31 22:41:10   <- ctime  (NOW - the tell)
```

Setting `ctime` to an arbitrary value requires one of two heavy, loud actions:

1. **Move the system clock** backward, perform the metadata change, then move it forward (`date -s`, `hwclock`). This is extremely noisy: clock steps are logged by chrony/ntpd, by the journal, and frequently by EDR; downstream `mtime`s on every other file written during the skew are now wrong; TLS and Kerberos may break.
2. **Edit the inode directly with `debugfs`** on an ext2/3/4 filesystem - `debugfs -w -R "set_inode_field <inode> ctime <value>" /dev/sdaN`. This requires the filesystem unmounted or accepts the risk of writing to a live device, requires root, and `debugfs` invocation against a block device is itself a high-fidelity audit/EDR event. ext4 also stores `crtime` (creation/birth time) in the inode, which `debugfs` reports and which a naive timestomp leaves untouched - another tell.

Either path is dramatically louder than the artifact it tries to hide.

### journald: vacuuming and rotation are themselves logged

The systemd journal is not a flat file you can sed. You manage it through `journalctl`, and every management action is recorded.

```bash
# Linux / systemd
journalctl --rotate                       # force rotation of the active journal
journalctl --vacuum-time=1s               # drop everything older than 1 second
journalctl --vacuum-size=1M               # shrink to a size cap
journalctl --vacuum-files=1               # keep only the newest archived file
```

The problems:

- `journalctl --vacuum-*` and `--rotate` **write journal records describing the rotation/vacuum** (systemd-journald logs its own housekeeping). You cannot vacuum your way to silence; the act leaves a fingerprint in the very journal you are trimming, and that record may already be on a remote sink.
- If **`systemd-journal-remote` / `systemd-journal-upload`** or an rsyslog `omfwd`/`omrelp` forwarder is configured, **the lines are already gone from your control** before you ever touch the box's storage. Vacuuming local journals changes nothing the collector holds.
- If **Forward Secure Sealing (FSS)** is enabled (`journalctl --setup-keys`), the journal is cryptographically sealed in epochs. Editing or truncating the binary file breaks the seal verification (`journalctl --verify` returns FAIL with the offset), proving tampering even without a remote copy.
- Stopping the daemon (`systemctl stop systemd-journald`) to freeze logging triggers a service-state-change record and leaves a coverage gap that brackets exactly the window you operated in - a gap-based detection's dream.

### auditd: you cannot quietly turn off the thing that watches you

`auditd` is the highest-value target for an evader and the best-defended. The kernel audit subsystem emits records for changes to its own configuration and state.

```bash
# Linux - the loud actions, shown to map them to their events
auditctl -e 0                 # set audit enabled=0  -> emits a CONFIG_CHANGE record
auditctl -D                   # delete all rules     -> emits CONFIG_CHANGE records
service auditd stop            # stop the daemon      -> SERVICE_STOP / DAEMON_END
auditctl -e 2                  # lock config until reboot (defenders set this)
```

If defenders set `-e 2` (immutable until reboot) in `/etc/audit/rules.d/`, rules cannot be removed without a reboot - and a reboot is itself one of the loudest events on the host. Even with `-e 1`, disabling audit emits a `CONFIG_CHANGE` (type 1305) record *before* logging stops, and that record is typically already forwarded.

## OPSEC notes

**What makes the loud version loud:**

- Any *deletion or truncation* of a forwarded log is a divergence the collector detects by simple comparison. The host says "I have no record"; the SIEM says "here is the record, and here is the gap that appeared right after." The cleanup is the alert.
- Symlinking history to `/dev/null`, zeroing `wtmp`, stopping `auditd`/`journald`, and stepping the clock are all **categorical IOCs** - their mere presence, independent of what they were hiding, is alertable.
- Timestomping that only moves `mtime` is detected by the `ctime > mtime` inequality with no extra tooling beyond `stat`.

**The quiet variant is not a quieter delete - it is not generating the event:**

- Prefer techniques that never reach an audited sink: operate within a single process that produces no new `execve` records (use built-ins instead of spawning binaries where audit watches `execve`), avoid touching files under `auditd` watch paths, and avoid actions that mint auth events.
- If a config file must be read, read it in a way that does not change `atime` (e.g. mount-time `noatime` is common anyway, but do not rely on it) and never change `mtime`/`ctime`.
- Use memory-resident workflows so there is no on-disk artifact whose timestamps need stomping in the first place. The best anti-forensic file is the one that was never written.
- Assume forwarding. Treat every local log as a cache of something already off-box. Plan the operation as if local logs do not exist as a deletion target, because for OPSEC purposes they do not.

**Failure modes and tells (summary):**

- `ctime > mtime` -> timestomp.
- `~/.bash_history` is a symlink, missing, or zero-length on an active account -> history suppression.
- `wtmp` shorter than uptime, out of order, or disagreeing with `lastlog`/auth.log -> accounting edit.
- journal rotation/vacuum records, `journalctl --verify` FAIL, or a daemon-stop gap -> journald tampering.
- `CONFIG_CHANGE`/`DAEMON_END` audit records, or audit silence bracketed by activity on neighboring sources -> audit tampering.
- Forwarder/SIEM holds events the host no longer has -> deletion, full stop.

## Detection & telemetry

This is the operative section. Hunt these directly.

### File timestamp anomalies (`ctime > mtime`)

Stat every file in suspect directories and flag inode-change-time newer than modify-time. With osquery:

```sql
-- osquery: timestomp candidates in common drop locations
SELECT path, mode, mtime, ctime, atime, btime
FROM file
WHERE (path LIKE '/tmp/%' OR path LIKE '/dev/shm/%' OR path LIKE '/var/tmp/%'
       OR path LIKE '/home/%/.%')
  AND ctime > mtime + 86400;   -- ctime at least a day after claimed mtime
```

On ext4, also compare `btime` (creation) against `mtime`; a birth time later than the modify time is impossible for an honest file. `debugfs -R 'stat <inode>' /dev/sdaN` reveals `crtime` even when `touch` left it untouched.

### Accounting-file integrity

```bash
# Linux - read the binaries with their native tools, then corroborate
last  -f /var/log/wtmp        # login history
lastb -f /var/log/btmp        # failed logins (root)
lastlog                       # last login per UID
who   -a                      # current sessions from utmp
```

Corroboration checks a defender runs:

- Depth of `last` output vs `uptime -s` and `/proc/stat` `btime`. A `wtmp` that does not reach back to the last boot is edited or truncated.
- `lastlog` per-UID times that have no matching session in `wtmp` -> selective `wtmp` edit.
- `wtmp` login events with no corresponding `auth.log`/`secure` "Accepted password/publickey" line (or vice versa) -> one of the two was tampered.
- File size of `wtmp`/`btmp` not consistent with record count and timing continuity.
- Compare host `wtmp` against the SIEM-side copy of auth events; any auth event in the SIEM with no local `wtmp`/auth.log peer is a deletion tell.

### journald rotation, vacuum, seal, and gaps

```bash
# Linux / systemd - verify cryptographic sealing (FSS)
journalctl --verify
#   PASS  -> intact;  FAIL: <offset>  -> tampered/truncated journal
```

Hunt for journald's own housekeeping and state-change records and for coverage gaps:

```
# Sigma-style (pseudo) - journald/journalctl tampering on a host
title: journald rotation, vacuum, or daemon stop
logsource: { product: linux }
detection:
  audit_execve:
    type: 'EXECVE'
    a0|contains: 'journalctl'
    a*|contains: ['--vacuum-time','--vacuum-size','--vacuum-files','--rotate']
  service_stop:
    SYSCALL|contains: 'systemd-journald'
    event: 'service stopped/killed'
  condition: audit_execve or service_stop
```

- A time window with zero journal entries flanked by normal-volume activity (compare adjacent boots/hours) indicates a stop-start or vacuum that excised the window.
- If `systemd-journal-upload`/`-remote` is in use, diff the remote sink's record count for the window against local - the remote should always be >= local.

### auditd configuration-change and daemon events

The audit subsystem self-reports. Look for these record types in `/var/log/audit/audit.log` (and on the audit forwarder):

- **type=`CONFIG_CHANGE` (1305)** - rule add/delete, `-e` enable/disable, `auditctl -D`. Fields include `op=`, `audit_enabled=`, `auid=`, `ses=`, the originating `exe=` and `comm=`.
- **type=`SERVICE_STOP` / `DAEMON_END` / `DAEMON_ABORT`** - the daemon shutting down or being killed. A `DAEMON_END` with no clean reboot/maintenance context is suspicious.
- **type=`SYSTEM_BOOT` / `SYSTEM_SHUTDOWN`** - reboots, which `-e 2` forces an attacker into.

Search:

```bash
# Linux - surface audit tampering directly
ausearch -m CONFIG_CHANGE,DAEMON_END,DAEMON_ABORT -ts recent -i
auditctl -s    # show current status: enabled, pid, lost, backlog
```

Recommended baseline watches so the *attempt* is recorded before silence falls. Place in `/etc/audit/rules.d/` and keep the config immutable:

```
## auditd rules (rules.d) - watch the evasion surface itself
-w /var/log/wtmp   -p wa -k accounting_tamper
-w /var/log/btmp   -p wa -k accounting_tamper
-w /var/run/utmp   -p wa -k accounting_tamper
-w /var/log/lastlog -p wa -k accounting_tamper
-w /var/log/audit/ -p wa -k audit_tamper
-w /etc/audit/    -p wa -k audit_config
-w /etc/profile.d/ -p wa -k profile_change
-a always,exit -F arch=b64 -S execve -k exec   ## full argv capture for command-level truth
-e 2                                            ## lock the config until reboot
```

### Shell history suppression

```sql
-- osquery: history files that are symlinks, missing, or empty on active accounts
SELECT u.username, u.directory,
       f.path, f.size, f.type
FROM users u
LEFT JOIN file f ON f.path = u.directory || '/.bash_history'
WHERE u.directory LIKE '/home/%'
  AND (f.path IS NULL OR f.size = 0 OR f.type = 'symbolic');
```

- A history file symlinked to `/dev/null` (`f.type = 'symbolic'` pointing at `/dev/null`) is a definitive IOC.
- Cross-reference: `auditd` `execve` records for a session whose `ses=`/`auid=` produced commands, against a `~/.bash_history` that did not grow -> deliberate suppression. The `execve` records are authoritative; bash history is not.
- A fresh `mtime` on `~/.bashrc`/`~/.bash_profile`/`/etc/profile.d/*` containing `HISTCONTROL=ignorespace`, `unset HISTFILE`, or `set +o history`, caught by the `-w` watches above.

### SIEM-side divergence (the strongest signal)

The detection that defeats all local cleanup: **the forwarder/collector holds records the host no longer has.** Concretely:

```
# Splunk-style: host claims fewer events than the indexer holds for a window
index=linux host=lab-web-01 sourcetype=linux_secure earliest=-24h
| stats count AS indexed_events
| append
  [ search index=host_inventory host=lab-web-01 metric=local_secure_linecount
    | stats latest(value) AS local_events ]
| stats values(indexed_events) values(local_events)
```

Any host where `local_events < indexed_events` for a forwarded source is, by definition, missing local logs that were already collected - the canonical "they deleted logs" finding. The same logic applies to `journald` remote, `auditd` `audispd`/`audisp-remote` forwarding, and EDR cloud telemetry: the cloud copy is immutable from the host's perspective, so every on-box cleanup only widens the gap the detection measures.

## MITRE ATT&CK

- **T1070** - Indicator Removal
- **T1070.002** - Indicator Removal: Clear Linux or Mac System Logs
- **T1070.003** - Indicator Removal: Clear Command History
- **T1070.006** - Indicator Removal: Timestomp
- **T1070.008** - Indicator Removal: Clear Mailbox Data (where mail logs apply)
- **T1562** - Impair Defenses
- **T1562.001** - Impair Defenses: Disable or Modify Tools (auditd/journald)
- **T1562.006** - Impair Defenses: Indicator Blocking (stop forwarding/logging)
- **T1564** - Hide Artifacts
- **T1222.002** - File and Directory Permissions Modification: Linux and Mac (metadata changes that move ctime)

## References

- MITRE ATT&CK, T1070 Indicator Removal and sub-techniques. https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK, T1070.006 Timestomp. https://attack.mitre.org/techniques/T1070/006/
- MITRE ATT&CK, T1562 Impair Defenses. https://attack.mitre.org/techniques/T1562/
- The Linux Audit project and `auditctl(8)` / `ausearch(8)` / `audit.rules(7)` man pages. https://man7.org/linux/man-pages/man8/auditctl.8.html
- `utmp(5)`, `wtmp(5)`, `lastlog(8)`, `last(1)`, `utmpdump(1)` man pages. https://man7.org/linux/man-pages/man5/utmp.5.html
- `systemd-journald.service(8)` and `journalctl(1)`, including Forward Secure Sealing (`--setup-keys`, `--verify`). https://www.freedesktop.org/software/systemd/man/journalctl.html
- `touch(1)`, `stat(1)`, `debugfs(8)` man pages (timestamp semantics and inode fields). https://man7.org/linux/man-pages/man1/stat.1.html
- osquery schema: `file`, `users`, and process tables for host hunting. https://osquery.io/schema/
