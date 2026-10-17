# Containment and the R0 Model

This document describes the mechanism that actually stops propagation, and it is deliberately separate from detection because **containment does not depend on detection.**

---

## The epidemiological framing

A self-replicating agent persists on a network only if each infected device infects, on average, at least one other device. That average is the basic reproduction number, R0.

- **R0 > 1** — the outbreak grows. Endemic.
- **R0 = 1** — the outbreak is stable. Endemic.
- **R0 < 1** — the outbreak shrinks. It dies out.

Any control that pushes R0 below one terminates the outbreak regardless of how capable the agent is, how novel its exploits are, or how well it hides its traffic. This is the single most important property of the design: **containment operates on reachability, not on identification.**

An outbreak that is 90% undetected but fully contained still terminates. An outbreak that is 100% detected but left with peer reachability does not.

---

## Two controls, both measured

### Peer reachability reduction

If a compromised device can reach fewer than one other susceptible device on average, propagation stops at that node. The source research environment is described by its authors as "a flat network in which every host is reachable from every other," and they call it explicitly the worst case.

Most real networks are not flat, but many are *effectively* flat at the consumer layer: a home router places every device on one broadcast domain with no segmentation between a security camera, a printer, and a laptop. R0-Invader restores segmentation at the network layer without requiring the user to buy VLAN-capable hardware.

**Quarantine blocks peer-to-peer traffic.** This is the action that drives R0 below 1, and it is why quarantine is not simply "cut the device's internet access." A device that keeps LAN access but loses internet has not been contained at all — it can still propagate laterally.

### Egress restriction

Anthropic cites ISP-level Mirai remediation as the strongest empirical result available for this threat class:

> Remediation of the Mirai botnet was possible when an ISP used externally obtained infection evidence to quarantine and notify customers. Quarantining infected subscribers involved restricting their networks to only being capable of reaching a short whitelist of sites, and otherwise redirecting their browsers to cleanup instructions. **This cleared 92% of infections within 14 days, against 74% with no notification.**

That result is the basis of the walled-garden quarantine mode: a contained device may reach only vendor patch and update endpoints and time synchronization, everything else resolves to a remediation page.

Note what makes this work. The infected host retains enough connectivity to be *fixed* — it can reach the vendor's firmware server — but not enough to *propagate*. Containment without a remediation path would produce devices that are isolated and permanently broken, which is a worse outcome than the infection.

---

## Policy tiers

Containment is graduated. A fresh installation does not act on anything.

### `monitor`

Log and score only. No traffic is affected. **This is the default for a new install.**

Every signal contributes to the per-device risk score. Nothing happens except that a baseline accumulates. Run in this mode for at least one full weekly cycle before escalating, so that device baselines are established and false-positive rates are understood.

### `restrict`

Peer-to-peer traffic between LAN hosts is blocked. Internet access is unrestricted.

This is the tier that most directly drives R0 below one. It is appropriate for a device with moderate-confidence risk that still needs cloud connectivity to function — a camera that must reach its vendor, for example.

The tradeoff: many IoT devices break entirely without LAN peer access, because they expect to talk to a hub, a bridge, or a companion phone on the same segment. Restricting such a device will visibly break it. This is intentional and is the correct trade, but the portal must say so clearly rather than leaving the user to discover it.

### `quarantine`

Peer traffic blocked. Internet restricted to the walled garden. Device moved to an isolated network zone. The remediation portal is notified.

This is the tier corresponding to the ISP remediation model above, and the one with measured efficacy.

---

## The containment sequence

```
 signal fires
     │
     ▼
 risk score accumulates ── decays with half-life ──► (score falls back below threshold)
     │
     │ score crosses threshold AND corroboration requirement met
     ▼
 policy tier selected per configuration
     │
     ├── monitor    ──► log only
     │
     ├── restrict   ──► block peer-to-peer; leave internet unrestricted
     │
     └── quarantine ──► move to quarantine zone (nftables set)
                        ├─ block all peer-to-peer
                        ├─ DNS restricted to walled garden
                        │    ├─ vendor patch/update FQDNs → resolve normally
                        │    ├─ NTP → allowed
                        │    └─ everything else → remediation portal
                        └─ notify portal with reason codes
     │
     ▼
 human reviews portal ──► Release, or remediate the device and release
```

### Corroboration requirement

By default, containment requires **either** a high-confidence signal combination **or** corroboration from two independent sources. A single weak signal never produces an action.

This matters because the false-positive profiles in [DETECTION.md](DETECTION.md) are non-trivial. A smart TV that is also a media server looks, in flow data, a great deal like a device participating in distributed inference. Requiring two independent signals — say DNS drift plus east-west volume, rather than east-west volume alone — trades a small amount of response speed for a large amount of avoiding bricking someone's living room.

Given that the source research measures a propagation timeline of **approximately five days to reach half the network**, that trade is clearly favorable. There is time to require higher confidence.

---

## Walled garden design

A quarantined device's DNS resolves through us authoritatively, which means we control what it can reach.

**Allowed:**

- Vendor patch and firmware domains, resolved from a per-vendor configuration. This is what makes remediation possible.
- Network time synchronization, so that device clocks remain correct and TLS validation continues to function.
- The remediation portal itself.

**Blocked:**

- Everything else. Resolution fails or returns the remediation page.

**Why DNS and not a firewall drop for egress:** DNS restriction is both the containment mechanism and the notification mechanism. A device that has been restricted discovers this by attempting to resolve a hostname and receiving a page that explains why. A firewall drop gives the device no way to learn what happened or what to do about it. The source ISP remediation model that produced the 92% clearance figure worked the same way — browsers were *redirected to cleanup instructions*, not silently dropped.

**Devices with hardcoded resolvers bypass this.** A device configured for `8.8.8.8` never queries us. Partial mitigation: force port-53 redirection at the firewall where the platform supports it. This is an integration detail per actuator, not a guarantee. Where redirection is impossible, the device can still be blocked at the flow level, and it will still trip R1 and R4 if it transfers weights.

---

## Measuring R0

Claims about containment efficacy should be measurable. The lab in `tests/lab/` exists to produce a number.

The lab stands up a containerized multi-segment network, seeds a propagating agent that moves an artifact between hosts and beacons on a schedule, and counts successful propagation events per infected host over a fixed observation window.

- **Control run:** containment disabled. Measure observed R0.
- **Treatment run:** containment enabled at `restrict` or `quarantine`. Measure observed R0.

The success criterion for the containment core is that the treatment run produces R0 below 1.

The propagating agent in the lab is a **propagation simulator**, not a replicator: it moves an inert file and emits scheduled connections. It contains no model weights, no inference engine, and no exploitation logic. Its purpose is to produce measurable propagation events that the containment system must interrupt. See [SAFETY.md](SAFETY.md) for why the distinction is enforced.

---

## Failure modes and honest limitations

**Containment breaks legitimate devices.** Many IoT devices require LAN peer access to function. Restricting them will visibly break them. This is the correct trade but it must be communicated clearly, and the portal's remediation text must be per-vendor where possible rather than generic.

**Containment does not help devices outside our segment.** A device that has already been compromised and is propagating outward through the ISP's network is beyond our observation boundary. We reduce the user's contribution to the epidemic. We do not reduce the epidemic.

**False containment has a cost.** An incorrectly quarantined device is a broken appliance in someone's home. This is why the default tier is `monitor`, why corroboration is required by default, and why the half-life on risk scores is long enough that a device must be consistently anomalous to escalate. Being wrong is expensive; the design optimizes for not acting rather than for acting quickly.

**The measurement window shrinks.** The approximately five-day propagation timeline from the source research is a property of current inference speed on edge hardware, not a property of the threat class. As model efficiency and hardware improve, that window compresses, and the case for aggressive automated containment strengthens while the case for requiring human confirmation weakens. This document's recommendation should be revisited as that trend continues.
