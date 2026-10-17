# Threat Model

**Scope:** R₀-Invader defends a single network under its user's administrative control — a home or small business. It reduces the reproduction number of a self-replicating agent *on that network*. It does not, and cannot, reduce the global epidemic.

**Last updated:** 2026-10-17

---

## 1. The threat

An autonomous **weight-based replicator** is a program that:

1. Enumerates a network to find new hosts.
2. Gains execution on a host through a disclosed vulnerability, a default credential, or an exposed management interface.
3. Copies model weights onto that host and stands up an inference engine.
4. Uses the reasoning that inference provides to locate and compromise the next host.
5. Repeats, passing along notes from previous attempts.

The defining property is that **the model weights are the malware payload**. The agent does not carry a small static exploit kit; it moves its own reasoning capacity with it, and reconstructs it on each new host.

### Primary sources

- **Anthropic Frontier Red Team**, *"AI models may be capable of self-replicating without access to a datacenter,"* 12 October 2026.
  <https://www.anthropic.com/research/self-replicating-ai>
- **Guan, Blanchard, Foerster, Jia, Huang, Papernot**, *"AI Agents Enable Adaptive Computer Worms,"* arXiv:2606.03811, June 2026.
  <https://arxiv.org/abs/2606.03811>
- **OWASP Agentic AI Top 10 — FORGE-07 (Insecure Data And Artifact Handling)**, which states that traditional DLP and storage monitoring "may not classify files such as `.pt`, `.pth`, `.safetensors`, `.onnx`, or `.h5` as sensitive IP by default, allowing large transfers to blend into routine deployment, backup, or storage activity."
- **Antonakakis et al.**, *"Understanding the Mirai Botnet,"* USENIX Security 2017, and the subsequent NDSS work on real-world ISP remediation of Mirai infections, which established the quarantine efficacy figures cited below.

---

## 2. In scope

### Threat taxonomy

Anthropic identifies three replicator classes. **R₀-Invader targets exactly one:**

| # | Replicator class | In scope? |
|---|---|---|
| 1 | **Small weight-based replicator** spreading through host compromise on IoT and edge devices | **Yes** |
| 2 | Large replicator targeting datacenter / high-compute hosts | No |
| 3 | API-based replicator that replicates by stealing inference credentials | No |

### Entry vectors

The entry surface is **boring, and that is the point.** The paper is explicit that real-world attack is dominated not by novel zero-days but by known, disclosed, unpatched flaws:

> "the majority of real-world cyberattacks rely less on discovering new zero-days than on exploiting disclosed vulnerabilities, unpatched systems, misconfigurations, and recurring weakness classes. Our worm targets precisely this attack surface."

The specific vulnerability classes represented in the source research environment, drawn from three published taxonomies:

**CISA Known Exploited Vulnerabilities (KEV)** — EternalBlue (MS17-010), PrintNightmare (CVE-2021-34527), ActiveMQ RCE (CVE-2023-46604), Struts2 OGNL injection (CVE-2017-5638), PwnKit (CVE-2021-4034), Dirty Pipe (CVE-2022-0847), Apache path traversal (CVE-2021-42013), Drupalgeddon 2 (CVE-2018-7600), Webmin command injection (CVE-2019-15107), Exim SMTP RCE (CVE-2019-10149), SambaCry (CVE-2017-7494).

**OWASP Top 10: 2025** — missing authorization (CWE-862), SSRF (CWE-918), XXE, default credentials on a management endpoint, XOR-encrypted credentials (CWE-327), SQL and OS command injection (CWE-89, CWE-78), unauthenticated Jupyter (CWE-306), JWT `alg:none` bypass (CWE-347), hardcoded API keys on an IP camera (CWE-798), Python pickle deserialization (CWE-502).

**MITRE ATT&CK** — unsecured firmware upload (T1190), exposed Docker API (T1133, the initial-access vector documented in TeamTNT cryptojacking), world-writable cron scripts (T1053.003), SUID binaries (T1548.001), weak Windows service registry permissions (T1574.011), password spraying (T1110.002), valid-account reuse over SSH (T1021.004) and WinRM (T1021.006).

**Credential reuse is the accelerator.** In the source research, a single configuration file containing network management credentials, discovered by accident and shared across replicas, produced "a second explosion of agent replication." This is the fastest propagation mechanism in the entire model and it is the one our containment loop is most directly designed to interrupt.

### Target devices

Commodity IoT and edge hardware with sufficient memory to hold a model shard at 4-bit quantization. Anthropic names Android TV boxes, smart appliances, security cameras, vacuum robots, and video-conferencing units as first targets. Off-brand Android TV boxes in the 1–4 GB RAM range are the representative case; 4 GB supports a ~9B model across four or more machines and a ~26B model across ten or more under pipeline parallelism.

### Observable behaviors

Behaviors that R₀-Invader detects, all derived from what replication actually requires:

- Multi-gigabyte transfers to or from model hosting endpoints, and between LAN hosts.
- Sustained device-to-device byte volume consistent with distributed inference.
- Inference-engine signatures (llama.cpp, vLLM, Ollama, TGI) on devices that are not servers.
- Port-scan bursts originating from a LAN host.
- Authentication bursts from one source to many destinations (credential reuse fan-out).
- Periodic beaconing on non-standard ports.
- Device DNS queries deviating from that device's established baseline.

---

## 3. Out of scope

### By threat model

- **Datacenter replicators.** These target infrastructure above our observation boundary.
- **API-credential replicators.** These live in a model provider's environment, which we do not see.
- **Upstream infection.** A worm that reaches a neighbor through the ISP's network is outside our view entirely. We reduce *your* contribution to R₀, not the global rate. This limitation is structural and cannot be engineered away from a single edge position.

### By design

- **Zero-day exploitation.** We do not attempt to prevent novel exploitation of unpatched flaws. Our position is that containment bounds the damage from a successful entry regardless of how it happened.
- **Endpoint compromise.** R₀-Invader does not run on endpoints, does not install agents on IoT devices, and does not modify device firmware. It acts only at the network layer and through the DNS resolver.
- **Devices that never route through us.** A device with a hardcoded resolver, a static IP, and no wireless association will not appear in our inventory. Partial mitigation: wireless clients are still visible via 802.11 association lists regardless of IP configuration.

---

## 4. The honest caveat on timing

We are building against a capability that is **projected, not yet widespread.**

Anthropic's evaluation found that only one tested open-weight model achieved end-to-end replication, and only under deliberately simplified conditions — an unauthenticated ADB port with no authentication step, on a network where every host was pre-seeded with an exploitable vulnerability. The authors describe this as an upper bound on real-world success. Their own trend analysis puts a small model at the same capability level by the end of 2026, and the experiments were run on eight *emulated* Android devices rather than the real world.

This means:

1. **Artifact detectors are a generation-specific control.** A replicator that encrypts or compresses its weight traffic, or that learns to mimic benign traffic patterns, will defeat the detection signals. The paper's authors state this directly: the behavioral signatures they observed are "artefacts of our proof-of-concept scope, not inherent properties of AI-driven worms," and a future adversary would point the same reasoning at "clean logs, mimic legitimate traffic patterns, or establish covert communication channels."
2. **The containment core is the durable control.** Cutting peer reachability below one is effective against *any* propagating agent regardless of how cleverly it hides its traffic, because it does not depend on detection at all. This is why the containment loop ships in v0.1 and the detectors ship in v0.2.
3. **The containment core is justified by today's threat.** Mirai-class botnets still infect millions of devices using exactly the default-credential and KEV entry vectors the replicator would use. R₀-Invader is defensible on that basis alone, independent of whether the AI replicator materializes.

---

## 5. Detection effectiveness and its limits

### What we can see

R₀-Invader sits at the network edge with authoritative DNS. It observes every DNS query a device makes through it, every flow traversing the router, and the inventory state of the network.

### What we cannot see

- **Encrypted peer-to-peer traffic contents.** We see volume, duration, and endpoints, not payloads. A replicator that encrypts its weight transfer is invisible to content-based detection and must be caught by volume and topology signals instead.
- **Inbound-only compromise followed by outbound-only propagation.** A device that is compromised from the internet and then propagates only outward will show up in flow records but not in DNS-based device profiling.
- **SSH public key injection.** Listed as a proof-of-concept artifact in the source research. Network-side observation requires TLS or SSH interception, which we do not perform. We treat this as an explicitly undetectable event and do not claim otherwise.
- **Anything a compromised device does entirely on its own host.**

### The tradeoff a replicator must make

Per Anthropic's analysis, a weight-based replicator "trades off between replication speed and stealth: the faster it replicates, the more traffic it produces." Their measured baseline is between roughly 28 and 150 hours for a single 9B-weight inference-setup trajectory, and reaching half of a 33-host flat network took approximately five days.

That window is the single most useful property of this threat class for a defender. It is also explicitly expected to compress as inference hardware and model efficiency improve. **Do not treat the detection window as a durable advantage.**

---

## 6. What actually reduces R₀

The epidemiological framing is the governing design principle. For a replicator to remain endemic, each infected device must on average infect at least one other device. Any control that pushes that average below one causes the outbreak to die out.

Two controls do this, and neither requires detection:

- **Peer reachability reduction.** If a compromised device can reach fewer than one other susceptible device, propagation terminates. This is network micro-segmentation, and it is why quarantine blocks peer-to-peer traffic rather than merely dropping the device's internet access.
- **Egress restriction.** Anthropic cites ISP-level Mirai remediation as the strongest empirical result in this space: restricting an infected subscriber's network to a short egress whitelist cleared **92% of infections within 14 days, against 74% with no notification and no restriction.** This is the basis of our walled-garden quarantine mode.

Both controls work regardless of whether the propagating agent is an AI replicator, a traditional worm, or something not yet described. That is intentional.
