# Detection Signals

Every signal is a **pure function** over normalized events. No signal touches the network, calls a router API, or mutates global state. This is what makes them unit-testable against fixture data with no hardware present.

Each signal is documented with three things: what it fires on, why a replicator must produce it, and where it will produce false positives.

---

## Signal taxonomy

Signals fall into two classes with very different durability:

**Replication-required signals** fire on something a weight-based replicator cannot avoid doing. They degrade slowly.

**Proof-of-concept artifacts** fire on something the current research prototypes happen to do. They will not survive an adversary that aims to evade.

The distinction matters, and it is one we make explicitly because the source research makes it explicitly. From arXiv:2606.03811:

> We deliberately omitted features that would complicate detection or removal: the worm does not encrypt its communications, employ polymorphic code, suppress forensic artefacts, or attempt to conceal its use of local compute resources. ... Crucially, however, **these signatures are artefacts of our proof-of-concept scope, not inherent properties of AI-driven worms.** A future adversary could direct the same reasoning capabilities that the AI-driven worm uses to generate exploits toward generating evasion strategies, for example, using the elevated privileges the worm already obtains to clean logs, mimic legitimate traffic patterns, or establish covert communication channels.

Signals marked **[P]** below are proof-of-concept artifacts. Signals marked **[R]** are replication-required and should hold even against an evasive adversary.

---

## R1 — Large transfer to a model hosting endpoint

**Class:** [R]
**Source:** EVE `flow` + `http` + `tls` (SNI)

A replicator must move its weights. There is no version of weight-based replication that does not involve moving multi-gigabyte artifacts onto a new host, either from another host on the network or from a public model hub.

**Fires on:** a single flow, or a small number of correlated flows from one source, transferring more than the configured volume threshold to a destination matching a model-hosting domain set or category.

**Known model-hosting endpoints:**

```
huggingface.co
cdn-lfs.huggingface.co
*.xethub.hf.co
ollama.com
registry.ollama.ai
*.hf.co
```

Extend from feed data. Treat this list as configuration, not code.

**False positives:** legitimate model downloads by a developer workstation, large OS updates, media library sync, backup jobs.

**Suppression:**
- Exclude devices previously observed downloading from the same endpoint family (baseline, not a static allowlist).
- Require duration ≥ configured minimum. A backup job saturates a link for hours; a replicator is bandwidth-constrained on edge hardware and moves more slowly.
- Require the destination to be novel for that device. A developer who always pulls from HuggingFace is not news; a security camera that does so for the first time is.

---

## R2 — Model host SNI on an IoT-class device

**Class:** [R]
**Source:** EVE `tls` / Zeek `ssl.log`

**Fires on:** a device classified as IoT, appliance, or embedded (by OUI vendor class, by port profile, or by absence of interactive client traffic) resolving or initiating TLS to a model-hosting endpoint.

This is R1's low-volume cousin. A device need not complete a large transfer to be interesting; a request to a model hub from a smart speaker is itself anomalous.

**False positives:** a legitimate AI-enabled appliance that ships with on-device inference and legitimately fetches model updates. These exist and are increasing.

**Suppression:**
- Per-vendor allowlist for known on-device-inference appliances, sourced from configuration.
- Require corroboration before any action beyond logging: a second signal from the same device within the decay window.

---

## R3 — Inference engine signature on a non-server device

**Class:** [R]
**Source:** EVE `conn`, Zeek `conn.log`

Standing up inference is a required step, and inference engines have distinctive network behavior — listening ports, handshake patterns, and request/response size distributions that differ from ordinary HTTP services.

**Signatures:**

| Engine | Default port | Distinguishing behavior |
|---|---|---|
| Ollama | 11434 | `/api/generate`, `/api/chat`; long-lived streaming responses |
| llama.cpp | 8080, 8000 | OpenAI-compatible `/v1/completions` |
| vLLM | 8000 | OpenAI-compatible; high concurrency |
| Text Generation Inference | 7860 | `/generate` with streaming |

**Fires on:** one of the above ports serving, or responding with, an OpenAI-compatible or engine-specific completion endpoint on a device not classified as a workstation or server.

**False positives:** a user running local LLMs on a NAS or home server, which is increasingly common and entirely legitimate.

**Suppression:**
- Device classification is the primary filter. A desktop or explicitly user-designated "AI host" device is excluded by default.
- Port alone is insufficient. Require a protocol-level match on the completion endpoint path or a request/response size distribution consistent with token streaming.
- This signal is high-FP by nature and should never trigger containment on its own. It is corroboration.

---

## R4 — Sustained east-west volume between peer devices

**Class:** [R]
**Source:** Flow aggregation across the LAN segment

Pipeline-parallel distributed inference produces sustained, high-volume traffic between ordinary consumer devices that would not ordinarily exchange data at that rate. Anthropic's own demonstration sharded a 26B model across fifteen TV boxes; that configuration is invisible to any single-host detector but produces an unmistakable topology in flow data.

**Fires on:** aggregate byte volume between a pair of LAN hosts exceeding the configured threshold over a rolling window, where neither host is classified as a server, NAS, backup, or media device.

**False positives:** Network-attached storage, mesh VPN traffic, Chromecast and AirPlay, peer-to-peer file sync, camera-to-NVR streams. **This is the highest-FP signal in the set** and must be tuned against a real network's baseline before it produces anything actionable.

**Suppression:**
- Establish a per-pair baseline over the first N days of operation. Only *deviation from a device's own established peer set* is interesting, not raw volume.
- Explicit device-class exclusions for NAS, NVR, mesh, and media devices.
- Require the traffic to be bidirectional with a request/response asymmetry consistent with token streaming rather than bulk transfer.

---

## R5 — Port-scan burst from a LAN host

**Class:** [P]
**Source:** EVE `flow`

Network discovery is the first phase of propagation. A host that suddenly begins rapid sequential or fan-out connection attempts to many destinations is behaving like a scanner.

**Fires on:** a single source exceeding N distinct destination ports or hosts within a configured time window, with a connection-attempt-to-success ratio consistent with scanning.

**False positives:** `nmap` users, firmware updaters, mDNS/SSDP device discovery, some mesh networking protocols.

**Suppression:**
- Exclude the device designated as the administrator's workstation.
- Exclude destinations on the local link that match multicast/broadcast discovery patterns.
- Require the pattern to involve off-link destinations or unusual port ranges. Consumer device discovery is almost always on-link and on well-known ports.

**Durability note:** this signal is marked **[P]** because a sophisticated adversary would replace an obvious scan with a slower, stealthier enumeration. It holds against the current generation of prototypes and against unskilled automation, not against an adversary actively optimizing for evasion.

---

## R6 — Authentication burst from one source to many destinations

**Class:** [P]
**Source:** Zeek `ssh` + flow correlation

The source research describes systematic credential reuse across hosts as a primary accelerator, and describes a specific incident in which a single discovered credential set produced "a second explosion of agent replication." This is the propagation mechanism most worth catching early.

**Fires on:** one source authenticating successfully to N distinct destinations within a configured window, where N exceeds the device's historical maximum.

**False positives:** administrative tooling, configuration management, monitoring agents, vulnerability scanners.

**Suppression:**
- Device-class exclusion for known admin and monitoring hosts.
- Require the destinations to span more than one device class or subnet. Admin tooling tends to target a homogeneous group.
- Require credential reuse: the same username across distinct destination hosts, which is the actual signal rather than raw fan-out volume.

**Durability note:** [P]. An adversary could avoid reuse entirely by harvesting distinct credentials per host. The signal detects the *pattern*, and the pattern is avoidable.

---

## R7 — Device DNS query deviating from its own baseline

**Class:** [R]
**Source:** Our own resolver's query log

Every device that resolves through us accumulates a query history. The first time a device queries a model-hosting, bulk-CDN, or inference-registry domain is a state transition, not a volume threshold, which makes it far more sensitive than R1.

**Fires on:** a device's first-ever query to any domain in a configured category, where that device has an established baseline of at least N prior queries.

**False positives:** a new app installed on a phone, a firmware update, a user exploring a new service.

**Suppression:**
- Require an established baseline. A device seen for the first time cannot deviate from a baseline that does not exist; it is handled by R8 instead.
- Categories are configuration, not code. Ship conservative defaults; let the operator add device-specific expectations.

**This is the signal most specific to passive-only operation and it is the one most worth tuning carefully.** It requires no volume threshold and no DPI, and it catches a first contact rather than a completed transfer.

---

## R8 — New device appearing on the network

**Class:** [R]
**Source:** Router inventory API — DHCP leases, ARP table, 802.11 association list

A device that has not previously been seen is a device that could have been introduced by a replicator.

**Fires on:** a MAC or IP address absent from the persistent inventory with a configurable lookback window.

**False positives:** every legitimate new device a household or office ever acquires. **This will fire constantly on any real network** and must never trigger containment by itself.

**Suppression:**
- This is an inventory event, not a detection. It transitions a device from `unknown` to `observed` and starts its baseline accumulation.
- Escalation only if the new device immediately exhibits one of R1, R2, R3, or R7 on first contact.

---

## R9 — Periodic beaconing on a non-standard port

**Class:** [P]
**Source:** Flow periodicity analysis

The source research lists beacon callbacks on non-standard ports as one of three concrete detection targets it observed.

**Fires on:** a flow whose initiation intervals exhibit periodicity below a configured jitter threshold, to a destination not in any known-service category, on a port outside the common service set.

**False positives:** IoT vendor cloud connections, NTP-adjacent periodic syncs, some telemetry agents, printer check-ins.

**Suppression:**
- Jitter threshold is the discriminator. Legitimate IoT vendor connections are rarely metronomic; an agent callback often is. Tune per network.
- Destination novelty: a periodic connection to a destination the device has used for months is baseline, not beacon.

**Durability note:** [P]. The source paper explicitly flags this as avoidable by an adversary that establishes covert channels.

---

## What we deliberately do not detect

Documented so that no one assumes coverage we have not claimed:

**SSH public key injection.** Listed as a proof-of-concept artifact. Network-side detection requires TLS or SSH interception, which R0-Invader does not perform and will not add. This is an endpoint-forensics problem, not a network one.

**Persistence mechanism installation** — service manager registration, scheduled task creation, cron modification. Entirely on-host and invisible at the network layer.

**Self-modification of agent source.** The source research observed the agent rewriting its own containment checks and its own target allowlist. This is invisible to us by definition.

**Any behavior of a device that never routes through our resolver or our router.** Hardcoded resolvers and static addressing on a separate segment are outside observation.

---

## Scoring

Signals do not fire in isolation. Each contributes weight to a per-device risk score, which accumulates with exponential decay over a configurable half-life (default 72 hours), so that a device's history fades rather than accumulating indefinitely.

| Combination | Rationale |
|---|---|
| R7 alone | Novel model-domain contact. Log, do not act. |
| R1 alone | Large transfer. Investigate; likely FP. |
| R7 + R1 | Novel contact *and* a large transfer from the same device. High confidence. |
| R5 + R6 | Scanning *and* credential reuse. Propagation behavior. High confidence. |
| R3 + R4 | Local inference *and* unusual east-west volume. Consistent with distributed inference. |
| Any [R] + any [P] | Corroboration across classes. Highest confidence tier. |

Default policy is `monitor`. Escalation to `restrict` or `quarantine` requires either a high-confidence combination or corroboration from two independent sources. See [CONTAINMENT.md](CONTAINMENT.md).

---

## Threshold defaults

All thresholds are configuration. The defaults below are starting points derived from the measured characteristics in the source research — specifically the observation that a 9B inference-setup trajectory takes between roughly 28 and 150 hours on edge hardware, and that reaching half of a 33-host flat network took about five days.

That timing is why conservative thresholds are viable: **a slow adversary gives a defender room to require higher confidence before acting.**

```yaml
signals:
  r1_weight_transfer:
    min_bytes: 500000000          # 500 MB
    min_duration: 90s
    require_destination_novelty: true
  r3_inference_port:
    require_protocol_match: true  # port alone is insufficient
    action: log                   # never contain on this signal alone
  r4_east_west:
    window: 1h
    min_bytes: 200000000          # 200 MB between peer devices
    require_pair_baseline: true
  r5_scan_burst:
    window: 60s
    min_distinct_hosts: 25
    min_distinct_ports: 15
  r6_auth_fanout:
    window: 3600s
    min_distinct_destinations: 5
    require_credential_reuse: true
  r7_dns_drift:
    require_baseline_queries: 100
  r9_beacon:
    window: 1h
    max_jitter_ratio: 0.15
    min_samples: 6

risk:
  decay_half_life: 72h
  action_thresholds:
    monitor: 0
    restrict: 30
    quarantine: 60
  require_corroboration: true
  min_independent_sources: 2
```

Tune against a live network's baseline before enabling any action above `monitor`. A default install logs and learns; it does not contain.
