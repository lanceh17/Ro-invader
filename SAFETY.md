# Safety and Dual-Use Posture

R0-Invader is a defensive tool. This document records the commitments that make that true in a way that can be checked against the code, not merely asserted in a README.

**Last updated:** 2026-10-18

---

## 1. Passive-only is an architectural commitment

**R0-Invader never sends a packet to a host it does not own or administer.** It does not scan, probe, fingerprint by active request, fuzz, or exploit. This is not a configuration flag that can be turned off; it is a property of the design, and it is the single most important line in this document.

Why it is structural rather than configurable:

- The actuator interface exposes no operation that reaches a target host. Its verbs are `Authoritative`, `Quarantine`, `Release`, `BlockNet`, `BlockDomain`, and `Health`. None of them transmit to a managed device.
- The sensing path is entirely reactive: DNS queries arriving at our resolver, flow records emitted by the router, and inventory state pushed by the router's own API.
- The only outbound requests the control plane makes go to the router you administer — reading its inventory state, and pushing rules — or to the threat-intel feeds named in section 4, or to the IEEE OUI registry when `-oui` enables vendor lookup. The feed and OUI traffic are the only exceptions to the rule above: they carry nothing derived from a managed host and run only when explicitly enabled, so they are website requests like any browser's, never a packet aimed at anything on the managed network.
- There is no code path that generates a network request on behalf of a scanned host.

A tool that actively scans creates ambiguity under laws such as the U.S. Computer Fraud and Abuse Act, even when the scanned network is your own, because the scanner's behavior is indistinguishable from an attacker's once it leaves your machine. Passive-only eliminates that question rather than arguing it. It also removes the failure mode of a scanner breaking a fragile embedded device, which is a real and common operational hazard on networks with IoT hardware.

**If a future contribution introduces active probing, it must be justified in this document and reviewed as a change to the project's legal posture, not as an ordinary feature.**

---

## 2. Containment is reversible and human-overridable

The most consequential action R0-Invader can take is to restrict a device's network access. That action is bounded:

- **Reversible by a human, always.** Quarantine can be released from the portal. There is no state from which a device cannot be recovered.
- **Default posture is observe, not act.** A fresh installation runs in `monitor` mode and logs without restricting. Escalation requires either a high-confidence signal or corroboration from two independent sources.
- **No automatic remediation on endpoints.** R0-Invader does not patch, does not modify, does not execute, and does not install anything on a managed device. Its worst action is "this device cannot reach its peers until a person clicks release."
- **No remote command execution, anywhere.** The project does not contain a mechanism for running commands on a target system, by design.

---

## 3. Detection test data derives from published signatures

The test corpus in `tests/fixtures/` is synthetic network telemetry constructed from behaviors documented in the public sources cited in [THREAT_MODEL.md](THREAT_MODEL.md): large transfers to known model-hosting endpoints, port-scan bursts, authentication fan-out, and periodic beaconing on non-standard ports.

It is **not** a replicator, does not perform replication, contains no model weights, and contains no exploit code. It exists to verify that the detectors recognize documented defensive signatures.

If you are contributing detection fixtures, keep them at this level of abstraction: telemetry records that *represent* a behavior, never a program that *performs* one.

---

## 4. Dependency and licensing posture

R0-Invader is Apache-2.0. It consumes several GPL-licensed tools, and the boundary is deliberate and enforced:

| Component | License | How we use it | Why the boundary matters |
|---|---|---|---|
| **Suricata** | GPL-2.0 | **Subprocess only.** Consume EVE JSON over a pipe or socket. Never linked. | Linking creates a derivative work. Subprocess isolation is also the correct architecture: crash isolation, independent upgrades. |
| **OpenAppFilter (`kmod-oaf`)** | GPL-2.0-*only* | **Not shipped. Not linked.** | GPL-2.0-only is incompatible with Apache-2.0 in the same binary. It also conflicts with hardware flow offloading, which destroys throughput. If L7 classification is needed, use nDPI (LGPL-3.0) in a separate process. |
| **openNDS** | GPL | **Clean-roomed architecture only.** The walled-garden design pattern is reimplemented against nftables. No code is copied. | Same reason. The idea is not copyrighted; the code is. |
| **nDPI** | LGPL-3.0 | Optional, separate process. | LGPL permits dynamic linking with relinkable object files, but process isolation keeps the option open. |
| **IEEE OUI database** | Published data | Used directly. | This is published data, not arp-scan's GPL code. Using the data file does not create a derivative of the tool that distributes it. |
| **OPNsense / VyOS / OpenWrt** | BSD-2 / GPLv3 / GPL-2.0 | Driven over their APIs. Never linked. | We are a client of their API, which creates no derivative. |

**Known traps, documented so they are not rediscovered the hard way:**

- `hagezi/dns-blocklists` and `AdGuardSDNSFilter` are GPL-3.0. Prefer raw upstream feeds over GPL-licensed aggregators, since the legal status of blocklist *data* under copyright is unsettled but a careful reviewer will argue the point.
- **Spamhaus free-tier DBL is restricted to home and non-commercial use.** Commercial redistribution requires a DQS subscription. If you are packaging R0-Invader for sale, this feed is not available to you on free terms.
- **abuse.ch's Feodo Tracker is empty** as of Operation Endgame. Do not build on it.
- **abuse.ch's SSLBL Botnet C2 IP blacklist was deprecated on 2025-01-03** (the feed itself says so). Do not build on it; SSLBL's live products are certificate and JA3 feeds, which are not DNS-addressable indicators.
- abuse.ch now requires an API key for both ThreatFox and URLhaus. Read it from the `R0_ABUSECH_KEY` environment variable (falling back to `R0_THREATFOX_KEY`, which this document previously named); never hardcode it.

---

## 5. What R0-Invader is not

To keep the dual-use question answered in advance rather than deferred:

- **Not a penetration testing tool.** It contains no exploitation logic and no scanner.
- **Not a botnet.** It has no command-and-control channel, no peer-to-peer coordination, and no mechanism for self-propagation. It is a single control-plane process that reads telemetry and pushes firewall rules to a router you control.
- **Not an offensive framework.** It has no payload generation, no shell, no session management, and no credential harvesting.
- **Not a model.** It contains no weights, no inference engine, and no agentic loop. It is a rules-and-correlation system.

---

## 6. Reporting a safety concern

If you believe a change to this repository would make it capable of active probing, remote command execution, payload delivery, or self-propagation, that is a safety regression. Please open an issue with the `safety` label and describe the capability in question. We treat these as priority defects rather than feature requests.
