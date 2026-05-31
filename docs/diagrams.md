# Diagrams

_Visual companions to the Quiet Operator thesis: stealth is telemetry management. Every diagram below pairs an offensive decision with the defensive signal it generates. GitHub renders the fenced `mermaid` blocks inline. Use only lab/RFC-5737 examples in any derived work._

These charts are referenced throughout the repo. For the written models behind them see
[`00-foundations/operator-opsec-model.md`](00-foundations/operator-opsec-model.md),
[`00-foundations/threat-model-and-telemetry.md`](00-foundations/threat-model-and-telemetry.md),
and the blue-team index
[`detection-mapping/blue-team-view-and-attack-mapping.md`](detection-mapping/blue-team-view-and-attack-mapping.md).

---

## 1. Operator decision loop

Run this loop before every action. The point is to spend artifacts deliberately, not by accident. Full reasoning in [`00-foundations/operator-opsec-model.md`](00-foundations/operator-opsec-model.md).

```mermaid
flowchart TD
    A[Action under consideration] --> B{What artifacts does it produce?}
    B --> C[Enumerate: disk write, new process, outbound conn, auth event, log line]
    C --> D{Who collects each artifact?}
    D --> E[Host EDR / auditd / eBPF]
    D --> F[Network: NetFlow / Zeek / IDS / proxy]
    D --> G[Identity / SIEM / UEBA / cloud audit]
    E --> H{Is there a quieter primitive?}
    F --> H
    G --> H
    H -->|Yes| I[Switch to the cheaper-in-artifacts path]
    I --> J{Does the quieter path still meet the objective?}
    J -->|No| K[Reconsider objective or accept the louder path knowingly]
    J -->|Yes| L{Worth the trace it still leaves?}
    H -->|No| L
    K --> L
    L -->|No| M[Do not act. Find another route]
    L -->|Yes| N[Act. Log expected artifacts for deconfliction]
    N --> O[Record what you generated for the purple-team report]
    M --> A
```

---

## 2. Exfil channel selection decision tree

Pick the channel that blends with the environment baseline, not the one that is technically cleverest. See [`data-transfer/04-https-and-cloud-exfil.md`](data-transfer/04-https-and-cloud-exfil.md) and the data-transfer index.

```mermaid
flowchart TD
    A[Need to move data out] --> B{Does the host already make outbound HTTPS to SaaS or cloud?}
    B -->|Yes| C{Is TLS interception or DLP in path?}
    C -->|No| D[HTTPS to an expected SaaS or object-storage endpoint]
    C -->|Yes| E{Can payload look like normal app content?}
    E -->|Yes| F[Blend into the inspected channel, shape size and timing]
    E -->|No| G[Treat as covert-channel or out-of-band candidate]
    B -->|No| H{Is outbound DNS allowed and recursive?}
    H -->|Yes| I{Is volume small and latency tolerable?}
    I -->|Yes| J[Low-and-slow DNS tunneling]
    I -->|No| G
    H -->|No| K{Any other egress at all?}
    K -->|ICMP or timing tolerated| L[Covert channel: ICMP / timing]
    K -->|None| M[Out-of-band: alternate media or staged off-host]
    G --> L
    G --> M
    D --> N[Throttle, jitter, off-hours, chunk to baseline sizes]
    F --> N
    J --> N
    L --> N
    M --> N
    N --> O[Log destination, volume, timing for deconfliction]
```

---

## 3. Base64 decode-and-execute data flow with telemetry taps

The repo's worked example: encoding raises signal, it does not lower it. Each stage below is a place a defender already watches. Deep dive in [`detection-mapping/base64-and-encoding-telemetry.md`](detection-mapping/base64-and-encoding-telemetry.md).

```mermaid
flowchart LR
    A[Operator types curl pipe base64 -d pipe sh] --> B[Shell history file]
    A --> C[Kernel execve syscall]
    C --> D[auditd execve and proctitle records]
    C --> E[eBPF and EDR process tree]
    A --> F[Outbound HTTPS fetch of payload]
    F --> G[NetFlow and conntrack record]
    F --> H[IDS content match on the wire]
    F --> I[Proxy and DLP charset and entropy check]
    E --> J[Lineage tell: bash spawns curl base64 sh]
    D --> K[Full argv captured: base64 -d visible verbatim]
    H --> L[Regex on A-Za-z0-9+/ run with padding]
    I --> L
    B --> M[DFIR collection of plaintext one-liner]
    J --> N[SIEM correlation and alert]
    K --> N
    L --> N
    G --> N
    M --> N
    N --> O[Decode-and-execute behavior flagged]
```

---

## 4. Noise versus value quadrant

Representative techniques plotted by how loud they are against how much they advance the objective. Prefer the high-value, low-noise quadrant. Mapping discussion in [`00-foundations/operator-opsec-model.md`](00-foundations/operator-opsec-model.md).

```mermaid
quadrantChart
    title Technique noise vs value
    x-axis Quiet --> Loud
    y-axis Low value --> High value
    quadrant-1 Use deliberately
    quadrant-2 Prefer these
    quadrant-3 Skip
    quadrant-4 Avoid
    Read config files: [0.15, 0.55]
    SSH agent reuse: [0.25, 0.78]
    LOLBin recon: [0.35, 0.5]
    base64 decode to shell: [0.85, 0.45]
    Clear a log: [0.9, 0.2]
    DNS tunneling exfil: [0.6, 0.7]
    HTTPS blend exfil: [0.4, 0.82]
    New persistence service: [0.7, 0.65]
    Mass port scan: [0.95, 0.35]
```

---

## 5. Defender telemetry stack

The collection surface an operator is moving through. If you do not know which branch sees you, you are not stealthy. See [`00-foundations/threat-model-and-telemetry.md`](00-foundations/threat-model-and-telemetry.md).

```mermaid
mindmap
  root((Defender telemetry stack))
    Host
      EDR process and file events
      auditd execve and watches
      eBPF sensors Falco Tetragon
    Windows
      ETW providers
      Sysmon EID 1 3 11
      Security evtx 4688 4624 1102
      PowerShell 4103 4104
    Network
      NetFlow and IPFIX
      Zeek conn and http and dns logs
      IDS Suricata and Snort
      JA3 and JA3S fingerprints
    DNS
      Resolver query logs
      QNAME length and entropy
      Record type anomalies
    Proxy and DLP
      Web access logs
      Content and charset rules
      TLS interception and CASB
    Cloud audit
      CloudTrail and Activity logs
      Control plane API calls
      Identity and access events
    Analytics
      SIEM correlation
      UEBA baselining
      Command line ML classifiers
```

---

## 6. Kill chain as telemetry-generating stages

Each stage emits a loudest signal. Knowing it tells you where to be quietest. Cross-mapped in [`detection-mapping/blue-team-view-and-attack-mapping.md`](detection-mapping/blue-team-view-and-attack-mapping.md).

```mermaid
flowchart LR
    A[Recon] --> B[Execution]
    B --> C[Persistence]
    C --> D[Credential access]
    D --> E[Lateral movement]
    E --> F[Collection]
    F --> G[Exfiltration]
    A -.loudest.-> A1[Port and service scans in NetFlow and IDS]
    B -.loudest.-> B1[execve with full argv in auditd and EDR]
    C -.loudest.-> C1[New service task or run key file create and FIM]
    D -.loudest.-> D1[Key and credential file reads and failed auth in logs]
    E -.loudest.-> E1[New auth events and east-west connections]
    F -.loudest.-> F1[Staging archive writes and high entropy files]
    G -.loudest.-> G1[Outbound volume anomaly and DLP content match]
```

---

## Reading these in context

Read each diagram against the page it links to. The charts are deliberately lossy summaries; the prose pages carry the exact event IDs, syscalls, field names, and hunt queries. For the canonical technique-to-detection table that underpins diagrams 5 and 6, start at
[`detection-mapping/blue-team-view-and-attack-mapping.md`](detection-mapping/blue-team-view-and-attack-mapping.md).
