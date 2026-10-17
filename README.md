<div align="center">

# R₀-Invader

**An AI worm must move its own weights to every new host.**
**That makes it loud, slow, and killable.**

*Break the loop. Cut the reproduction number below 1 so the outbreak dies out on your network.*

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-red)](docs/ROADMAP.md)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8?logo=go&logoColor=white)](go.mod)

</div>

---

## Why this exists

On 12 October 2026 the Anthropic Frontier Red Team published evidence that small open-weight models may be months away from autonomously copying themselves onto commercial IoT devices — smart ovens, off-brand Android TV boxes, security cameras — with no datacenter required. Independently, a University of Toronto / Vector Institute / Cambridge / ServiceNow team demonstrated an AI-driven computer worm that propagated across a heterogeneous network of Linux, Windows, and IoT devices, exploiting 23 hosts out of 33 and replicating across 7 generations in fully autonomous operation ([arXiv:2606.03811](https://arxiv.org/abs/2606.03811)).

There is no central server to shut down. Vendor-side safety controls are, as the paper puts it, *structurally irrelevant*.

That sounds hopeless. It isn't, for three reasons the research itself supplies.

### 1. The entry vector is boring

The worm does not get into "any" device. It gets into the ones you already know are broken: default manufacturer passwords, unpatched CISA KEV CVEs, exposed Docker APIs, hardcoded camera API keys, unauthenticated Jupyter notebooks. The paper is explicit: *"the majority of real-world cyberattacks rely less on discovering new zero-days than on exploiting disclosed vulnerabilities, unpatched systems, misconfigurations."* This is a solvable problem.

### 2. The AI is its weakness, not its strength

| | Traditional worm | AI weight-based replicator |
|---|---|---|
| Propagation speed | Minutes | **~5 days to reach half a network** |
| Payload size | ~60 KB (Mirai) | **Multi-gigabyte model weights** |
| Cross-device chatter | Minimal | **Sustained device-to-device inference traffic** |
| Stop by patching? | Yes | No — it adapts |

A Mirai payload is 60 KB and silent. An AI worm must copy its *own reasoning capacity* onto each new host and stand up an inference engine there. That is enormously loud.

### 3. Cutting R₀ below 1 kills any outbreak

The epidemiological framing is the whole design. If each infected device infects fewer than one other device, the outbreak dies regardless of how clever the agent is. Anthropic cites the strongest empirical result in this space: restricting an infected subscriber's network to a short egress whitelist cleared **92% of Mirai infections in 14 days, versus 74% with notification alone.**

R₀-Invader does both: it detects the artifacts replication produces, and it cuts reachability so the outbreak terminates even when detection misses.

---

## What it does

```
  ┌─ SENSE ──────────────────────────────────────────────────────────┐
  │  Authoritative DNS  ── every resolution = device identity + intent│
  │  Suricata (subproc) ── EVE: flow, http, dns, tls, files, ssh      │
  │  Router API         ── DHCP leases, ARP table, 802.11 assoc list  │
  └────────────────────────────┬─────────────────────────────────────┘
                               ▼
  ┌─ NORMALIZE ───────┐    ┌─ DETECT ──────────────────────────────┐
  │ ThreatFox  (conf%) │──▶ │ weight transfer  · inference ports   │
  │ URLhaus    (C2)    │    │ scan bursts      · auth fan-out      │
  │ CISA KEV   (CVEs)  │    │ east-west swarm  · DNS drift         │
  │ SSLBL      (JA3)   │    └──────────────┬───────────────────────┘
  └────────────────────┘                   ▼
                               ┌─ RISK ────────────────────────────┐
                               │ per-device EWMA + decay + reasons  │
                               └──────────────┬────────────────────┘
                                              ▼
  ┌─ ACT ────────────────────────────┐  ┌─ PORTAL ─────────────────┐
  │ Quarantine · Release             │  │ device-specific          │
  │ BlockNet · BlockDomain           │  │ remediation +            │
  │ OpenWrt · VyOS · OPNsense        │  │ approve / release        │
  └──────────────────────────────────┘  └──────────────────────────┘
```

1. **Authoritative DNS** is the primary sensor and the primary identity source. Every device that resolves through us is enumerated and profiled by its query history. Containment and identity share one mechanism.
2. **Feed ingest** pulls ThreatFox, URLhaus, CISA KEV, and SSLBL, then normalizes them with confidence, TTL, and IoT-specific tagging — something no consumer tool currently does.
3. **Detection** runs nine pure-function signal matchers over normalized telemetry, each with a documented false-positive profile.
4. **Risk scoring** accumulates signal weight per device with exponential decay, so a single weak signal never triggers an action.
5. **Containment** moves a device to a quarantine zone: peer traffic blocked (this is what drives R₀ below 1), internet restricted to a walled garden of vendor patch servers.
6. **Portal** explains *why* a device was contained and gives device-specific remediation steps.

---

## What it does not do

Stated plainly, because the failure mode of security tools is overpromising:

- **It never probes your network.** No scanning, no fingerprinting by active request, no exploitation. It is passive by architecture, not by configuration. See [SAFETY.md](SAFETY.md).
- **It does not run on endpoints.** No agents on your devices, no firmware modification. Network layer and DNS only.
- **It does not see upstream.** A worm reaching a neighbor through your ISP's network is outside our observation boundary. We reduce *your* contribution to R₀, not the global rate.
- **It does not detect SSH key injection.** That is invisible without interception, which we do not perform. We say so rather than implying otherwise.
- **Artifact detection is generation-specific.** A replicator that encrypts or compresses its weight traffic will defeat the detectors. The containment core is what must hold — and it works regardless of detection, because it acts on reachability rather than on identification.

---

## Detection signals

Every signal is a pure function over normalized events, independently unit-testable, each with a suppression mechanism.

| Signal | What it means | False-positive profile |
|---|---|---|
| Multi-hundred-MB flow to model host | Weight transfer — the payload | Backups, OS updates, media sync |
| Known model-host SNI | `huggingface.co`, `cdn-lfs.*`, `ollama.com`, `registry.ollama.ai` | A developer machine on the LAN |
| Inference-server signature | llama.cpp, vLLM, Ollama, TGI on a non-server | Legit local inference |
| East-west sustained bytes | Distributed inference swarms | NAS, mesh VPN, casting, P2P |
| SYN scan burst from LAN host | Propagation phase 1 | nmap, updaters, device discovery |
| Auth burst, one source to many targets | Credential reuse fan-out (T1021.004/.006) | Admin tooling, monitoring |
| Deviation from device DNS baseline | First contact with a model/CDN domain | A new app on a phone |
| New-device baseline violation | Replication onto an unseen host | A legitimate new device |
| Periodic non-standard-port beacon | C2 callback | IoT vendor clouds |

Full detail including thresholds and suppression rules in [docs/DETECTION.md](docs/DETECTION.md).

---

## Status

**Pre-alpha.** The containment core is in progress; nothing here is ready to put in front of a production network.

| Version | Scope | Status |
|---|---|---|
| **v0.1** | Containment core: DNS + walled garden, feed ingest, inventory, risk scoring, quarantine/release, remediation portal | In progress |
| **v0.2** | Artifact detectors with fixtures and suppression | Planned |
| **v0.3** | Honeypot feedback loop (Cowrie/Dionaea → local IoCs) | Planned |
| **v0.4** | Whole-network baseline drift | Planned |

See [docs/ROADMAP.md](docs/ROADMAP.md).

### Proving it works

We are not going to ask you to take containment efficacy on faith. The lab in `tests/lab/` stands up a containerized multi-segment network and measures R₀ with and without containment enabled. The number it produces is the metric this project is judged on.

---

## Target platforms

One adapter interface, three backends:

| Platform | Mechanism | Best for |
|---|---|---|
| **OpenWrt** | `firewall4` nftables sets + `uci`; inventory via `ubus` | Consumer routers — the largest install base |
| **VyOS** | `/configure` with `ipset` groups | Best bulk-IoC primitive; members change without firewall reloads |
| **OPNsense** | REST API | Cleanest documented automation; `POST /api/firewall/filter/apply` |

Runs on a Raspberry Pi 5, a mini-PC, or alongside an existing router appliance. Suricata requires tuning on Pi-class hardware — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Quickstart

The detection half runs today. `analyze` reads a Suricata EVE file, attributes events to devices, runs the detectors, and scores each device with exponential decay — reporting the containment tier it would recommend. It reads and reports only; it never contacts a router or a device.

```bash
git clone https://github.com/lanceh17/Ro-invader.git
cd Ro-invader
go build ./agent/cmd/r0-guard

# Score the bundled sample network
./r0-guard analyze \
  -eve tests/fixtures/eve/sample.json \
  -inventory tests/fixtures/inventory.json
```

Sample output:

```
events: 6 normalized
inventory: 3 devices
signals: 4 from 1 detectors

aa:bb:cc:dd:ee:01  score=51.7   tier=monitor uncorroborated(1 kinds)
    - device contacted a model-hosting endpoint (cdn-lfs.huggingface.co) (score 17.2)
    vendor: Hikvision  class: camera
```

Note the last line: the camera scores above the `restrict` threshold (30) but is held at `monitor` because only one signal kind fired. Corroboration is required by default, so a single finding — however large — never contains a device. That is the project's central safety property, and it is the first thing to verify after any change to the risk engine.

The inventory file maps IPs to MACs and device classes; without it, events cannot be attributed and no signal can name a device. See [docs/ROADMAP.md](docs/ROADMAP.md) for what ships next.

Read [THREAT_MODEL.md](THREAT_MODEL.md) to check whether this tool addresses the threat you actually face. If your concern is the existing Mirai-class botnets, the containment core is directly useful today. If your concern is the AI replicator specifically, the honest answer is that the detectors are forward-looking and the containment is the part that does real work.

---

## Contributing

Read [SAFETY.md](SAFETY.md) first. Three hard requirements for any contribution:

1. **No active probing.** Not a config option. Contributions that introduce scanning will be rejected.
2. **No remote command execution.** Anywhere, on anything, for any reason.
3. **GPL stays out of the binary.** Suricata and similar tools are consumed as subprocesses, never linked. See the dependency table in SAFETY.md for why.

Detection fixtures must remain telemetry that *represents* a behavior, never a program that *performs* one.

---

## References

- Anthropic Frontier Red Team, [*AI models may be capable of self-replicating without access to a datacenter*](https://www.anthropic.com/research/self-replicating-ai), 12 Oct 2026.
- Guan, Blanchard, Foerster, Jia, Huang, Papernot, [*AI Agents Enable Adaptive Computer Worms*](https://arxiv.org/abs/2606.03811), arXiv:2606.03811, Jun 2026.
- Antonakakis et al., [*Understanding the Mirai Botnet*](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/antonakakis), USENIX Security 2017.
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- OWASP Agentic AI Top 10 — FORGE-07, Insecure Data And Artifact Handling.

---

<div align="center">

Licensed under [Apache-2.0](LICENSE).

</div>
