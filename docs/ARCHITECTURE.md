# Architecture

The control plane is a single Go process. It reads telemetry, scores devices, and pushes rules to a router. It is not a botnet, not a scanner, and not an agentic loop.

---

## Design principles

**1. Passive-only is structural, not configurable.**
No code path sends a packet to a managed device. The actuator interface has no verb that does so. See [SAFETY.md](../SAFETY.md).

**2. Enforcement lives above the workload.**
The source research's governing axiom is that "containment enforcement must reside in a privilege domain the agent cannot reach," because they repeatedly observed the worm rewriting its own containment checks. Applied here: our enforcement is in the router's nftables rules, pushed from a control plane the compromised device cannot address or modify. A compromised IoT device cannot reach our API.

**3. Detectors are pure functions.**
Every detector is `func(NormalizedEvent) []Signal`. No I/O, no clock reads, no network access. This is what makes the test suite runnable with no hardware and no Suricata.

**4. Consume GPL tools as subprocesses. Never link.**
Suricata runs as a separate process; we read its EVE JSON output. This is a licensing requirement and also the correct architecture — crash isolation and independent upgrade cycles fall out of it for free.

**5. The DNS resolver is load-bearing.**
In passive-only mode there is no other guaranteed identity source. Every device that resolves through us is enumerated. Containment and identity share one mechanism: a quarantined device resolves only walled-garden domains through us, which is simultaneously its restriction and its notification.

---

## Data flow

```
            ┌──────────────────────────────────────────────────────┐
            │                    CONTROL PLANE                      │
            │                        (Go)                            │
┌───────────┴───────┐                                              │
│  Suricata         │  EVE JSON      ┌──────────┐                  │
│  (subprocess)     │───────────────▶│          │                  │
└───────────────────┘  unix socket   │          │   Normalized     │
                                     │  ingest  │─── Event ───┐    │
┌───────────┐  queries  ┌──────────┐ │          │            │    │
│ Resolver  │──────────▶│          │ │          │            ▼    │
│ (ours)    │◀──────────│  dns     │ └──────────┘     ┌──────────┐│
└─────┬─────┘  answers  └──────────┘                  │  detect  ││
      │                                                │ (pure)   ││
      │                                                └────┬─────┘│
┌─────┴──────┐  leases, ARP         ┌──────────┐           │      │
│  Router    │─────────────────────▶│  router  │           ▼      │
│  (ours)    │◀─────────────────────│  ingest  │     ┌──────────┐│
└────────────┘   nft rule push      └──────────┘     │   risk   ││
                                                    │ (EWMA)   ││
┌───────────┐                                     └────┬─────┘│
│  Feeds    │  ThreatFox, URLhaus, KEV, SSLBL          │      │
│ (puller)  │──────────────▶ ┌──────────┐              ▼      │
└───────────┘                │normalize │        ┌──────────┐│
                             │(TTL/conf)│───────▶│  policy  ││
                             └──────────┘        └────┬─────┘│
                                                      │      │
                                                      ▼      │
                                                ┌──────────┐│
                                                │ actuator ││
                                                │ (adapter)││
                                                └────┬─────┘│
                                                     │      │
                              ┌──────────────────────┴──┐   │
                              │  Router nftables / dns  │◀──┘
                              └─────────────────────────┘
```

---

## Package layout

```
agent/
├── cmd/r0-guard/              main; wiring, config load, signal handling
└── internal/
    ├── core/                  shared types: Device, NormalizedEvent, Signal, Policy
    ├── ingest/
    │   ├── suricata/          EVE JSON reader (file or unix socket tail)
    │   ├── dns/               resolver query log
    │   ├── router/            DHCP leases + ARP over each vendor's HTTP API (802.11 assoc struck — not implemented)
    │   └── oui/               IEEE OUI vendor lookup
    ├── normalize/             feeds → normalized IoCs with TTL + confidence
    ├── detect/                pure-function signal matchers
    ├── risk/                  per-device EWMA scoring with decay
    ├── policy/                tier selection, corroboration, action scheduling
    ├── act/                   Actuator interface + adapters
    │   ├── opnsense/          REST: /api/firewall/filter/apply
    │   ├── vyos/              /configure with ipset groups
    │   └── openwrt/           firewall4 nftables sets + uci + ubus
    ├── feeds/                 feed pullers (ThreatFox, URLhaus, KEV)
    └── portal/                remediation UI + release endpoint
```

`internal/` rather than a public API surface: nothing here is a library yet. Exposing a stable API is a decision to make once the types stop moving.

---

## Core types

```go
// core.Device is the persistent identity of a host on the managed network.
type Device struct {
    MAC            net.HardwareAddr
    IPs            []netip.Addr
    Vendor         string        // from IEEE OUI
    Class          DeviceClass   // IoT, Appliance, Workstation, Server, Camera, Unknown
    FirstSeen      time.Time
    LastSeen       time.Time
    RiskScore      float64
    Containment    ContainmentState // Monitor, Restricted, Quarantined
    Notes          []string
}

// core.NormalizedEvent is the single shape every ingest path produces.
// Detectors accept only this type, which is what keeps them pure and
// hardware-independent.
type NormalizedEvent struct {
    Time       time.Time
    Kind       EventKind  // Flow, DNSQuery, DNSAnswer, TLS, SSHAuth, Inventory
    Src        Endpoint   // may be zero for egress-only events
    Dst        Endpoint
    Bytes      int64
    Duration   time.Duration
    SNI        string     // TLS server name, if observed
    QueryName  string     // DNS, if this is a DNS event
    AuthUser   string     // SSH auth, if observed
    DeviceMAC  net.HardwareAddr // the LAN-side device, when attributable
    Raw        map[string]any   // original EVE fields, for debugging
}

// core.Signal is a detector's finding.
type Signal struct {
    Kind       SignalKind // R1..R9
    Class      SignalClass // ReplicationRequired or PoCArtifact
    DeviceMAC  net.HardwareAddr
    Weight     float64
    Confidence float64
    Reason     string     // human-readable, rendered into the portal
    Evidence   map[string]any
}
```

### Why `NormalizedEvent` rather than detectors consuming EVE directly

Suricata's EVE schema is large, versioned, and will change. Decoupling at a normalized shape means:

- A detector can be unit-tested with a hand-written event and no Suricata present.
- A second telemetry source (Zeek, a future eBPF sensor) can be added without touching any detector.
- A Suricata upgrade that reorganizes EVE fields costs one adapter change, not nine.

The cost is that fields outside the normalized shape are only reachable through `Raw`, which is a `map[string]any` and therefore not type-safe. That is the deliberate trade: type safety in exchange for requiring a normalization pass.

---

## Actuator interface

```go
// act.Actuator is the only interface through which the system affects
// network state. Note what is absent: there is no verb that transmits
// to a managed device. This is enforced by the interface shape, not by
// convention.
type Actuator interface {
    Name() string
    Authoritative(ctx context.Context, d core.Device) error
    Quarantine(ctx context.Context, d core.Device, p core.Policy) error
    Release(ctx context.Context, d core.Device) error
    BlockNet(ctx context.Context, n netip.Prefix, until time.Time) error
    BlockDomain(ctx context.Context, d string, until time.Time) error
    Health(ctx context.Context) error
}
```

Three backends, one contract.

| Backend | Quarantine mechanism | Inventory source | Notes |
|---|---|---|---|
| **OpenWrt** | `firewall4` nftables sets via `uci` | `ubus` over HTTP: `file read` of `/tmp/dhcp.leases`, plus `dhcp ipv6leases` | Largest install base. `ubus` is awkward for service accounts; evaluate `openwrt-iac/uapi` (MIT) as an optional layer. |
| **VyOS** | `ipset` group membership via `/configure` | DHCP + ARP | Best bulk-IoC primitive — members change without touching rules, so no firewall reload and no traffic gap. |
| **OPNsense** | REST `POST /api/firewall/filter/apply` | REST lease and ARP endpoints | Cleanest documented API. **Constraint:** its automation filter only surfaces rules created within it, so our tool must own every rule it manages. |

---

## Storage

SQLite, single file, WAL mode. Appropriate for a home or SMB network where the device count is hundreds, not millions.

Tables: `devices`, `events` (rolling window, pruned), `signals`, `ioc` (normalized with expiry), `baselines` (per-device peer sets and query categories), `actions` (audit log of every containment decision, with reason codes).

**The action audit log is not optional.** Every containment decision records which signals fired, what the score was, which corroboration rule was satisfied, and who released it if released. A security tool that silently contains a device and cannot explain why is worse than no tool.

---

## Deployment shapes

**1. Container (primary).** `docker-compose` with the control plane, a DNS resolver, and optionally a honeypot sidecar. The router is external and reached over its API. This is the fastest path to v0.1 and the recommended starting point.

**2. Appliance (Raspberry Pi 5).** Control plane plus resolver on the Pi, with the Pi acting as the network's DNS server via DHCP option 6. The router can remain a separate device.

**3. Router-integrated.** Package as `.ipk` for OpenWrt or as an OPNsense plugin. Highest reach, most integration work, and the platform-specific adapters do most of the work here.

### Hardware constraint on Pi 5

Suricata with a full Emerging Threats rule set needs multiple gigabytes of RAM. On a Pi, use XDP/eBPF to pre-drop known-safe traffic in-kernel so Suricata only sees what matters, and curate the rule set aggressively. Home networks do not need 30,000 rules; they need roughly two dozen that match this project's specific signals.

---

## What is deliberately absent

- **No outbound telemetry.** Nothing phones home. Outbound traffic goes to the public abuse.ch and CISA endpoints and to the router you administer, and nowhere else.
- **No model weights, no inference engine, no agentic loop.** This is a rules-and-correlation system.
- **No remote command execution.** Anywhere.
- **No active scanning.** Not even as an option.

These absences are the product's safety argument, and they are worth stating as architectural commitments rather than as roadmap items that might later be reconsidered.
