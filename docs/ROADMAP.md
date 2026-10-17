# Roadmap

Sequencing is driven by one principle: **ship the part that works against threats that exist today, before shipping the part aimed at a capability that is projected for the future.**

The containment core is justified by Mirai-class botnets, which still infect millions of devices using exactly the default-credential and KEV entry vectors a replicator would use. The artifact detectors are forward-looking and valuable, but they detect a capability that Anthropic's own evaluation found only one model achieving, and only under deliberately simplified conditions. Building detection first would mean validating against a threat model rather than a threat.

---

## v0.1 — Containment core

The shippable product. Everything needed to observe a network, score devices, and contain them, with no AI-specific detection at all.

- [x] `core` types: `Device`, `NormalizedEvent`, `Signal`, `Policy`, `ContainmentState`
- [x] DNS resolver (with query logging, per-device policy decisions, and walled-garden sinkholes — `serve`)
- [x] Feed pullers: ThreatFox, URLhaus, CISA KEV (SSLBL struck — its botnet C2 IP blacklist was deprecated by abuse.ch on 2025-01-03)
- [x] Normalization with confidence, TTL, and provenance tagging
- [ ] Inventory ingest from all three router backends
- [ ] IEEE OUI vendor lookup
- [x] Per-device risk scoring with exponential decay
- [x] Policy tier selection with corroboration requirement
- [x] Actuator interface + OpenWrt adapter
- [ ] Actuator adapter + VyOS adapter
- [ ] Actuator adapter + OPNsense adapter
- [x] Remediation portal with per-device reason codes and release action
- [ ] Action audit log
- [ ] Docker Compose deployment
- [ ] R0 measurement lab in `tests/lab/`

**Exit criteria:** the lab demonstrates measured R0 below 1 with containment enabled, against a control run above 1. That number is the v0.1 release gate, not a passing test suite.

---

## v0.2 — Artifact detectors

The nine signals in [DETECTION.md](DETECTION.md), each as a pure function with fixtures and a suppression mechanism.

- [ ] R1 large transfer to model host
- [x] R2 model-host SNI on IoT-class device
- [ ] R3 inference engine signature on non-server device
- [ ] R4 sustained east-west peer volume
- [ ] R5 port-scan burst from LAN host
- [ ] R6 authentication fan-out with credential reuse
- [x] R7 device DNS baseline deviation
- [ ] R8 new device appearance (inventory transition)
- [ ] R9 periodic beaconing on non-standard port
- [x] Per-device baseline accumulation and drift
- [ ] Per-vendor suppression allowlists
- [ ] Detection fixture corpus from published signatures

**Exit criteria:** every detector has a fixture demonstrating both a true positive and a documented false-positive profile, and no detector can produce a containment action without corroboration.

---

## v0.3 — Honeypot feedback loop

Nobody currently closes the loop between a LAN-adjacent honeypot and a local blocklist.

- [ ] Cowrie sidecar (SSH/Telnet, captures credentials and command-line IoT malware)
- [ ] Dionaea sidecar (TFTP/HTTP payload staging — the protocols a worm uses to stage weights)
- [ ] Parse `cowrie.session.file_download` and Dionaea captures into normalized IoCs
- [ ] Feed honeypot-derived IoCs into the normalize layer with a distinct provenance tag
- [ ] Optional: deploy decoy device profiles that look like vulnerable IoT to attract interest

Both tools are GPL; they run as containers and we consume their JSON output. Same subprocess boundary as Suricata.

---

## v0.4 — Whole-network baseline drift

Anthropic's measurement that inference-setup success rose from 45% to between 61% and 84% across six generations of inherited notes suggests that a replicator's traffic signature changes as it adapts. Baseline the entire network rather than individual devices, so that drift is visible.

- [ ] Network-wide traffic profile with seasonal decomposition
- [ ] Drift scoring across the fleet, not just per-device
- [ ] Alerting on topology change (new device pairs exchanging volume that never did before)
- [ ] Periodic baseline recomputation with human review of drift

---

## Later, undecided

Ideas that have been considered and not scheduled. Each has a reason it is not yet a commitment.

- **eBPF sensor as an alternative to Suricata.** Lower overhead on Pi-class hardware and permissive licensing, but a multi-year engine project to match Suricata's coverage. Worth evaluating only if Suricata proves unworkable on the target hardware.
- **nDPI for L7 classification.** LGPL-3.0 and 450+ protocols. Considered as a replacement for OpenAppFilter, which is GPL-2.0-only and would be incompatible with Apache-2.0. Deferred until L7 classification is actually needed; flow and DNS data cover most signals.
- **Home Assistant integration.** The closest thing to a maintained home device inventory UI. A read-only bridge would give users a familiar surface for the inventory we build.
- **Commercial Spamhaus BCL access.** Arguably the closest thing to a purpose-built botnet-C2 feed. The free tier is home-use-only, so this is gated on whether R0-Invader is ever packaged for sale.
- **Manufacturer-facing output.** A per-vendor report of what an OEM's devices look like on a network when compromised. Useful for advocacy, orthogonal to the product.

---

## Explicitly not planned

- **Active scanning.** Hard architectural commitment, not a roadmap item. See [SAFETY.md](../SAFETY.md).
- **Endpoint agents.** Out of scope permanently.
- **Remote command execution.** Out of scope permanently.
- **Detection of SSH key injection.** Requires TLS/SSH interception, which we will not add.
- **Detection of zero-day exploitation.** Containment bounds the damage instead.
