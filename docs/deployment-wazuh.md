# HoneyGas — two-site cloud deployment with Wazuh

This guide deploys **two independent HoneyGas instances** — a gas-transport
station (gaseoducto) and a biomethane plant — on separate cloud VMs, and
ingests their telemetry into a **Wazuh** instance on a separate, private
network.

> Deploy only on infrastructure and network segments you own or are explicitly
> authorized to operate. See the "Legal & ethical use" section of the main
> README.

---

## 1. Why two VMs

Each profile emulates a different ICS environment — different protocols,
points, device banners, and S7/IEC-104/DNP3 identities. Running both behind a
**single IP** is an obvious tell: no real site is simultaneously a gas-transport
station and a biomethane plant. So each instance gets its **own VM and its own
public IP**, and should look like an independent operator:

- Put the two VMs in **different address ranges / ASNs** (ideally different
  subnets or regions) — not consecutive IPs in the same `/28`.
- Give each coherent (or absent) **reverse DNS**; don't let a shared PTR tie
  them to one organisation.
- **No shared fingerprints**: distinct SSH host keys, TLS certificates and base
  images per VM (two clones of one image share a host key → trivial to
  correlate). Stagger their boot times.
- The per-profile banners already differ (OmniFlow / OmniRTU-3000 and an
  S7-300 vs BioGridTech / BGT-500 and an S7-1500), which helps.

Separate VMs also contain the blast radius: compromising one never touches the
other, and each can be rebuilt independently.

---

## 2. Network topology

```
Attackers / internet
        │  ICS ports (502,102,2404,20000,8080[,10001])
        ▼
┌─────────────────────────────┐        ┌──────────────────────────────┐
│  DMZ subnet (sacrificial)   │        │  Management subnet (private)  │
│                             │ 1514/t │                               │
│  VM-A  gaseoducto  ─────────┼───────▶│  Wazuh manager + indexer +    │
│        (transport)          │  only  │  dashboard                    │
│  VM-B  biometano   ─────────┼──────▶ │                               │
│        (biomethane)         │ allowed│  (no inbound from internet)   │
└─────────────────────────────┘        └──────────────────────────────┘
                                             ▲  443, via bastion/VPN only
                                             │
                                           Admin
```

The separation is enforced by firewall rules that make the telemetry path
effectively one-way:

| Source → destination            | Port(s)                          | Action                 |
|---------------------------------|----------------------------------|------------------------|
| Internet → honeypot VMs         | 502, 102, 2404, 20000, 8080, 10001 | allow (the bait)     |
| Honeypot VMs → Wazuh manager    | 1514/tcp (+1515/tcp to enrol once) | **allow — the only egress** |
| Honeypot VMs → anything else    | —                                | **deny** (no C2, no pivot) |
| Wazuh → honeypot VMs            | —                                | **deny** (SIEM never initiates to the sacrificial box) |
| Admin → Wazuh dashboard         | 443                              | allow from bastion/VPN only |
| Internet → Wazuh                | —                                | **deny**               |

Note: the honeypot **container** itself has no egress at all (the compose
`honeynet` is `internal`). The one allowed egress belongs to the **host Wazuh
agent**, which is a separate, minimal shipper — see §4.

---

## 3. Deploy each honeypot VM

On each VM (one per profile), install Docker, create the data dir owned by the
container user, and bring up that VM's compose:

```bash
sudo install -d -o 10001 -g 10001 /opt/honeygas/data/audit /opt/honeygas/data/quarantine

# VM-A (gaseoducto):
sudo docker compose -f docker/compose.transport.yml up --build -d
# VM-B (biometano):
sudo docker compose -f docker/compose.biomethane.yml up --build -d
```

Harden each VM as a sacrificial box: no public SSH (bastion/SSM only), disk
encryption, and a golden image you can recreate from (see §5). The container is
already non-root, read-only-root, `cap_drop: ALL`, `no-new-privileges`, CPU/mem
capped, and egress-locked.

---

## 4. Ingest into Wazuh

Stand up a Wazuh single-node stack in the management subnet (the official
`wazuh/wazuh-docker` single-node compose is the easiest start). Then drop in the
files from `wazuh/`:

1. **Rules** — copy `wazuh/local_rules.xml` to
   `/var/ossec/etc/rules/local_rules.xml` on the manager and restart it.
2. **Agent (primary telemetry)** — install the Wazuh agent on **each honeypot
   VM host** (not in the container) and merge `wazuh/agent-ossec.conf`. It tails
   the bind-mounted `/opt/honeygas/data` and ships:
   - the complete JSON audit trail (`honeygas-audit.jsonl`), decoded natively so
     every field is queryable;
   - the quarantine inventory (hashes/type only — never the samples);
   - host file-integrity (syscheck) + rootcheck, to catch a breakout.
   Register each agent and assign it to a group named for its site:
   ```bash
   agent-auth -m 10.20.0.10
   /var/ossec/bin/agent_groups -a -i <AGENT_ID> -g gaseoducto   # or biometano
   ```
3. **CEF syslog (optional)** — only if you also want HoneyGas's built-in
   real-time CEF push. It requires setting `alerts.enabled: true` in the instance
   config AND relaxing the egress firewall to allow exactly honeypot→Wazuh:514.
   Then add `wazuh/manager-syslog.xml`. By default this is **off** — the host
   agent already delivers the full trail in near-real-time, and keeping the
   container egress-locked is the stronger posture.

Because a honeypot has no legitimate users, treat **every** event as suspicious.
The rules escalate by HoneyGas's own `severity` field and raise a high-level
alert when **one source hits both sites** within an hour — that is targeted
reconnaissance against your operator, not internet background noise. The `site`
field (`EDR-GAS-NODE-07` vs `BIO-PLANT-01`) and the agent groups keep the two
plants distinguishable in one dashboard. Wire the Wazuh **VirusTotal
integration** to auto-enrich the `sha256` of each `capture.*` event.

---

## 5. Resetting after compromise

There are two very different notions of "compromise" here, with two different
responses.

### 5a. The simulated plant — nothing to reset

In normal operation an attacker *thinks* they have written registers, operated
a valve or uploaded firmware. This is the intended behaviour and needs **no
reset**:

- Writes/commands/set-points land in that attacker's **per-session overlay**
  (keyed by source IP), never in the shared baseline — one attacker never sees
  another's tampering, and the simulated process keeps running untouched.
- Nothing the attacker sends is ever executed; payloads are hashed, typed and
  quarantined (`.quarantine`, `0o400`), never run.
- Session overlays **auto-expire** after `session_idle_timeout_seconds` (30 min),
  so the environment self-heals between attackers with no intervention.

So routine attacker activity never contaminates the honeypot. You do not rebuild
to "clean up" after an ordinary engagement — and you generally **don't rebuild
mid-engagement** either: the attacker can do no real harm, so letting them keep
interacting yields more intelligence.

### 5b. The VM/host — rebuild, don't clean

You rebuild when the concern is the **box itself** (an unknown RCE in the
service, or a container breakout), i.e. persistence you can't see. Treat the VM
as cattle: recreate it from a known-good golden image rather than trying to
disinfect it.

**When (triggers):**

- **Scheduled** — rebuild from the golden image on a cadence (e.g. daily or
  weekly) regardless of events, to destroy any persistence.
- **Event-triggered** — rebuild immediately on a high-fidelity host-compromise
  signal from Wazuh:
  - the agent goes silent unexpectedly (built-in rules 503/505/506) — the box
    may have been killed or isolated;
  - file-integrity / rootcheck flags a change to a system path (the container FS
    is read-only, so **any** write outside `/opt/honeygas/data` is a breakout
    signal — syscheck rules 550/554);
  - the egress-deny firewall logs a **denied outbound** from a honeypot VM (feed
    that log to Wazuh) — a strong "it's trying to call home" signal;
  - an actual working exploit is captured against the honeypot service itself.
- **Analyst-triggered** — after you've collected what you need from a session.

**Why it's lossless:** the audit trail and quarantine inventory are shipped to
Wazuh in near-real-time over the one-way path, so the evidence is already in the
management subnet (which the attacker cannot reach) before any wipe. The malware
samples themselves stay on the sacrificial box — snapshot the data volume to
cold storage first if you want them for deeper forensics.

**How:**

- **Container-level** (fast, same VM): `docker/rebuild.sh` snapshots the data
  dir to cold storage, tears the instance down, wipes the data dir, and brings a
  fresh instance up with empty state. Schedule it with cron/systemd timer for
  the hygiene rebuild:
  ```bash
  sudo docker/rebuild.sh docker/compose.transport.yml     # or compose.biomethane.yml
  ```
- **VM-level** (stronger, for suspected host compromise): terminate the VM and
  recreate it from the golden image (Terraform/cloud-init, an autoscaling group
  of size 1, or your CI). The new VM comes up clean in minutes. Wire the
  event-triggers above to invoke this (e.g. a Wazuh active-response or a cloud
  function that calls the rebuild pipeline).

Pair this with Wazuh alerting on **agent disconnect**: if an attacker takes the
box down, the silence is itself the alert.

---

## 6. File map

| Path | Role |
|------|------|
| `config/honeygas.transport.yaml`  | gaseoducto instance config (transport profile) |
| `config/honeygas.biomethane.yaml` | biometano instance config (biomethane profile) |
| `docker/compose.transport.yml`    | VM-A stack (standard ports, own volume, hardened) |
| `docker/compose.biomethane.yml`   | VM-B stack (no ATG) |
| `docker/rebuild.sh`               | container-level reset/clean |
| `wazuh/local_rules.xml`           | detection + cross-site correlation rules |
| `wazuh/agent-ossec.conf`          | host agent: JSON ingest + host FIM |
| `wazuh/manager-syslog.xml`        | optional CEF receiver |
