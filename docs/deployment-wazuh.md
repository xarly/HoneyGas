# HoneyGas — two-site cloud deployment with Wazuh

This guide deploys **two independent HoneyGas instances** — a gas-transport
station (gaseoducto) and a biomethane plant — on low-cost VMs at **two different
providers**, and ingests their telemetry into a **Wazuh** hub at a third
provider. A **WireGuard management overlay** links them and replaces the
private management subnet that a single-provider deployment would use. The
overlay is plain WireGuard (`10.99.0.0/24`) by default, or **Tailscale** (§8).
The single-provider variant is in §9.

The cheapest layout runs the hub on a cloud free tier, so you only pay for the
two smallest VPS plans (§2).

> Deploy only on infrastructure and network segments you own or are explicitly
> authorized to operate. See the "Legal & ethical use" section of the main
> README.

---

## 1. Why two VMs, at different providers

Each profile emulates a different ICS environment — different protocols,
points, device banners, and S7/IEC-104/DNP3 identities. Running both behind a
**single IP** is an obvious tell: no real site is simultaneously a gas-transport
station and a biomethane plant. So each instance gets its **own VM and its own
public IP**, and should look like an independent operator:

- Put the two VMs in **different address ranges / ASNs**. Using two providers
  gives you this for free, plus different base images and network fingerprints.
- Give each coherent (or absent) **reverse DNS**; don't let a shared PTR tie
  them to one organisation.
- **No shared fingerprints**: distinct SSH host keys, TLS certificates,
  WireGuard keys and base images per VM (two clones of one image share a host
  key → trivial to correlate). Stagger their boot times.
- The per-profile banners already differ (OmniFlow / OmniRTU-3000 and an
  S7-300 vs BioGridTech / BGT-500 and an S7-1500), which helps.

Separate VMs also contain the blast radius: compromising one never touches the
other, and each can be rebuilt independently.

---

## 2. Where to run it: sizing and cost

| Role | Needs | Runs on |
|------|-------|---------|
| Wazuh hub (manager + indexer + dashboard) | official minimum 4 vCPU / 8 GB / 50 GB; with 2 agents, 2 cores / 8 GB+ is enough | **provider 3**: a free-tier VM with enough RAM (often ARM), ~100 GB disk |
| VM-A gaseoducto | 1 vCPU / 1 GB (container capped at 1 CPU / 256 MB) | **provider 1**: smallest VPS plan |
| VM-B biometano | same | **provider 2**: smallest VPS plan |

Why this split:

- **Wazuh is the expensive piece** (the indexer alone wants several GB of RAM),
  so it goes on the free tier. Free tiers commonly reclaim VMs they consider
  *idle* (low CPU, network and memory use over several days). The indexer's
  resident memory keeps the hub busy.
- **The honeypots do NOT go on a free tier**: they idle most of the time and
  would look reclaimable. They need almost nothing, so the smallest paid plan
  of any provider will do.

Caveats — check each before you sign up:

- **Free tiers change**: allowances get cut and accounts can be stopped when
  that happens. ARM capacity is often scarce; retry later. Check the current
  limits, and keep the hub's evidence backed up. Some free tiers fix the home
  region at sign-up, so **choose an EU region when you create the account**.
- **ARM**: Wazuh's 5.0 documentation covers the all-in-one install on
  AARCH64/ARM64. For a 4.x release, check its compatibility matrix first.
- **Acceptable-use policies**: providers' terms rarely say anything explicit
  about honeypots, and HoneyGas stores attacker payloads in quarantine (some
  providers restrict malware research without consent). **Ask each provider's
  support in writing** before deploying.
- **Data protection**: attacker IPs are personal data under the GDPR. Keep all
  three VMs in EU regions.

Fallback: if no free tier gives you enough RAM, run the hub on any paid 8 GB
VPS. The rest of this guide is unchanged.

---

## 3. Network topology

```
                 Attackers / internet
         ICS ports │                    │ ICS ports
                   ▼                    ▼
  ┌──────────────────────┐   ┌──────────────────────┐
  │ VM-A  gaseoducto     │   │ VM-B  biometano      │
  │ provider 1, VPS      │   │ provider 2, VPS      │
  │ overlay 10.99.0.11   │   │ overlay 10.99.0.12   │
  └──────────┬───────────┘   └──────────┬───────────┘
             │  WireGuard, dialled OUT  │
             │  udp/51820 = only egress │
             └────────────┬─────────────┘
                          ▼
           ┌───────────────────────────────┐
           │ Wazuh hub — provider 3        │
           │ (free-tier VM)                │
           │ overlay 10.99.0.1             │
           │ manager + indexer + dashboard │
           │ public: udp/51820 only        │
           └───────────────▲───────────────┘
                           │ WireGuard
                     Admin (10.99.0.100)
```

This section and §4–§5 describe plain WireGuard; §8 lists what changes with
Tailscale (the same flows, enforced by a tailnet policy as well, and no public
port on the hub at all).

The hub is the only WireGuard peer with a listening port. WireGuard does not
answer unauthenticated packets, so scanners see **no open port** on the hub.
The honeypots never listen for WireGuard at all; they dial the hub. All
telemetry and administration runs inside the overlay, so nothing management-
related is exposed on the honeypots' public IPs.

The firewall rules keep the telemetry path effectively one-way:

| Source → destination | Port(s) | Enforced by | Action |
|----------------------|---------|-------------|--------|
| Internet → honeypot VMs | 502, 102, 2404, 20000, 8080, 10001; ICMP echo | Docker publish + honeypot nftables | allow (the bait) |
| Internet → honeypot VMs | everything else, **including SSH** | honeypot nftables | deny |
| Honeypot VM → hub public IP | udp/51820 (WireGuard) | honeypot nftables | **allow — the only internet egress** |
| Honeypot → hub, inside the tunnel | 1514/tcp, 1515/tcp (agent), 123/udp (NTP) | honeypot nftables + hub iptables | allow |
| Honeypot → anything else | — | honeypot nftables | **deny + count → rule 100260** |
| Honeypot ↔ honeypot, honeypot → admin | — | hub FORWARD | **deny** (no pivot) |
| Hub → honeypots, new connections | — | hub OUTPUT | **deny** (the SIEM never initiates to the sacrificial box) |
| Admin → hub, inside the tunnel | 443 (dashboard), 22 | hub iptables | allow |
| Admin → honeypots, inside the tunnel | 22 (routed by the hub) | hub FORWARD + honeypot nftables | allow |
| Internet → hub | anything but udp/51820 | provider cloud firewall + hub iptables | **deny** |

Note: the honeypot **container** itself has no egress at all (the compose
`honeynet` is `internal`). The one allowed egress belongs to the **host**: the
WireGuard tunnel carrying the Wazuh agent, a separate, minimal shipper (§6).

Overlay addressing:

| Address | Peer |
|---------|------|
| `10.99.0.1`   | Wazuh hub |
| `10.99.0.11`  | VM-A gaseoducto |
| `10.99.0.12`  | VM-B biometano |
| `10.99.0.100` | admin workstation |

---

## 4. Build the Wazuh hub

### 4.1 Instance

- 2+ cores / 8–12 GB RAM, Ubuntu 24.04 (aarch64 or x86_64), ~100 GB disk.
- **Provider cloud firewall (security group / security list), ingress:**
  `udp/51820` from `0.0.0.0/0`. Keep `tcp/22` only until the overlay works
  (§4.3), then **remove it**. For break-glass access, use the provider's web or
  serial console.
- Egress stays open: the hub needs it for updates and the VirusTotal
  integration. It is never reachable *from* the honeypots except through the
  rules below.

### 4.2 Wazuh all-in-one

Download `wazuh-install.sh` for the current release, as the official quickstart
shows, and run the all-in-one install:

```bash
sudo bash wazuh-install.sh -a
```

Then size it for this box:

- **Indexer heap**: set `-Xms` / `-Xmx` in `/etc/wazuh-indexer/jvm.options`
  to about a third of RAM (`4g` on a 12 GB box), leaving room for the manager
  and dashboard, then restart `wazuh-indexer`.
- **Retention**: add an Index State Management policy that deletes
  `wazuh-alerts-*` indices after e.g. 90 days, so the disk never fills.
- **Rules**: copy `wazuh/local_rules.xml` to
  `/var/ossec/etc/rules/local_rules.xml` and restart `wazuh-manager`.

### 4.3 WireGuard hub

```bash
sudo apt install -y wireguard
sudo sh -c 'cd /etc/wireguard && umask 077 && wg genkey | tee privatekey | wg pubkey > publickey'
sudo install -m 0600 deploy/wg-hub.conf.example /etc/wireguard/wg0.conf   # then fill in the keys
sudo systemctl enable --now wg-quick@wg0
```

Add the admin workstation from `deploy/wg-admin.conf.example`. Check that
`ssh <user>@10.99.0.1` works through the tunnel before going on.

### 4.4 Host firewall

```bash
sudo apt install -y iptables-persistent
sudo deploy/wazuh-hub-firewall.sh
```

It defaults to `OVERLAY=wireguard` and the overlay addresses of §3. It puts
its own chains at the top of INPUT/FORWARD/OUTPUT and persists them with
`netfilter-persistent`. On the public side it allows only replies, DHCP and
`udp/51820`, so it **closes public SSH**: run it only after SSH over the
overlay works. Your current session survives. It leaves the image's existing
rules alone; don't flush them, because some cloud images need them to reach
their metadata, DNS and NTP services. The script is idempotent; re-run it
after changing the peer list. Then remove `tcp/22` from the provider's cloud
firewall too.

### 4.5 NTP for the honeypots

The honeypots take their time from the hub, so they need no internet NTP. Add
this line to `/etc/chrony/chrony.conf` on the hub, then restart `chrony`:

```
allow 10.99.0.0/24
```

The hub itself keeps syncing from its provider's NTP service.

---

## 5. Build each honeypot VM

Do steps 5.1–5.4 while the VM still has normal egress (this is the
"golden image" build), then lock it down (5.5–5.7). Use Debian 12 or
Ubuntu 24.04 (x86), the provider's own image, the smallest plan.

### 5.1 Base packages and HoneyGas

Install Docker, `wireguard-tools`, `nftables` and the Wazuh agent
(`WAZUH_MANAGER=10.99.0.1` at install time). Then create the data dir owned by
the container user and bring up that VM's compose:

```bash
sudo install -d -o 10001 -g 10001 /opt/honeygas/data/audit /opt/honeygas/data/quarantine

# VM-A (gaseoducto):
sudo docker compose -f docker/compose.transport.yml up --build -d
# VM-B (biometano):
sudo docker compose -f docker/compose.biomethane.yml up --build -d
```

The image is built **now**, while the VM has egress. After lockdown the VM
cannot reach Docker Hub or PyPI, and `docker/rebuild.sh` reuses this local
image (it builds only with `HONEYGAS_BUILD=1`).

The container is already non-root, read-only-root, `cap_drop: ALL`,
`no-new-privileges`, CPU/mem capped, and egress-locked.

### 5.2 WireGuard client

```bash
sudo sh -c 'cd /etc/wireguard && umask 077 && wg genkey | tee privatekey | wg pubkey > publickey'
sudo install -m 0600 deploy/wg-honeypot.conf.example /etc/wireguard/wg0.conf  # .11 or .12, keys, hub IP
sudo systemctl enable --now wg-quick@wg0
ping -c3 10.99.0.1
```

Add this VM's public key as a `[Peer]` on the hub (`deploy/wg-hub.conf.example`)
and reload it there without dropping the other peers:

```bash
sudo bash -c 'wg syncconf wg0 <(wg-quick strip wg0)'
```

### 5.3 Wazuh agent

Merge `wazuh/agent-ossec.conf` into `/var/ossec/etc/ossec.conf` (manager
`10.99.0.1`), then enrol it and assign it to its site group:

```bash
sudo /var/ossec/bin/agent-auth -m 10.99.0.1
# on the hub:
sudo /var/ossec/bin/agent_groups -a -i <AGENT_ID> -g gaseoducto   # or biometano
```

### 5.4 Quiet the host

Once locked, any outbound packet other than the tunnel trips the egress
tripwire (§6). Remove the usual sources of background traffic first, or they
will cause false alarms:

- package timers: `apt-daily*.timer`, `unattended-upgrades`, `snapd`,
  `motd-news`, Ubuntu Pro / landscape, `popularity-contest`;
- `cloud-init` after first boot (`sudo touch /etc/cloud/cloud-init.disabled`),
  since it re-queries the metadata service on every boot;
- time: point `systemd-timesyncd` (`NTP=10.99.0.1`, empty `FallbackNTP=`) or
  chrony (`server 10.99.0.1 iburst` only) at the hub;
- IPv6: `net.ipv6.conf.all.disable_ipv6 = 1` in `/etc/sysctl.d/`;
- any monitoring agent the provider's image ships.

Updates from now on come from **rebuilding** the VM (§7b), never from
re-opening egress on a live honeypot.

### 5.5 Lock egress

Edit the `define` lines at the top of `deploy/nftables-honeypot.nft` (overlay
interface and addresses; with WireGuard, also the hub's public IP and port),
then apply it with a dead-man switch, so that a mistake rolls back by itself
after 3 minutes:

```bash
sudo nft -c -f deploy/nftables-honeypot.nft                 # syntax check only
sudo install -m 0644 deploy/nftables-honeypot.nft /etc/nftables.conf
sudo nft -f /etc/nftables.conf && \
  sudo systemd-run --on-active=180 --unit=hg-fw-rollback nft delete table inet honeygas_host
```

Your current SSH session survives (established connections stay allowed), but
public SSH is now closed. From the admin workstation, open a **new** session
over the overlay (`ssh <user>@10.99.0.11`). If it works, cancel the rollback
and make the firewall persistent:

```bash
sudo systemctl stop hg-fw-rollback.timer
sudo systemctl enable nftables
```

The file replaces Debian/Ubuntu's stock `/etc/nftables.conf`, which starts
with `flush ruleset`. Never put that line back: it wipes Docker's NAT rules
and takes the bait ports offline.

### 5.6 Burn-in (24 h)

Leave the VM running for a day and check that the tripwire stays at zero:

```bash
sudo nft list counter inet honeygas_host egress_denied     # packets 0 bytes 0
sudo journalctl -k -g HONEYGAS-EGRESS-DENY                 # what tried to get out, if anything
```

Silence whatever shows up (§5.4). Then test the tripwire once, on purpose:

```bash
curl -m 3 http://1.1.1.1/     # must time out: the packet is dropped and counted
```

Within about a minute, rule **100260** must appear in the dashboard for that
agent. Only after a clean burn-in and a working test, wire rule 100260 to
automatic rebuilds (§7b).

### 5.7 Record the bootstrap

Keep steps 5.1–5.5 as a script or cloud-init file in your private repo. That
file is your "golden image": a VM-level rebuild means reinstalling the OS and
running it again.

---

## 6. Ingest into Wazuh

The files in `wazuh/` are already in place from §4.2 and §5.3:

1. **Rules** — `wazuh/local_rules.xml` on the hub.
2. **Agent (primary telemetry)** — runs on **each honeypot VM host** (not in
   the container) and talks only to `10.99.0.1` through the tunnel. It ships:
   - the complete JSON audit trail (`honeygas-audit.jsonl`), decoded natively so
     every field is queryable;
   - the quarantine inventory (hashes/type only — never the samples);
   - host file-integrity (syscheck) + rootcheck, to catch a breakout;
   - the **egress tripwire**: every 60 s it reads the host firewall's
     `egress_denied` counter. Rule **100260** fires (level 14) when the counter
     changes, i.e. when the box tried to reach anything other than the hub. It
     also fires if the firewall table was removed or altered.
3. **CEF syslog (optional, keep it off here)** — HoneyGas's built-in real-time
   CEF push needs the *container* to reach the hub (`udp/514`). In this
   topology that would mean giving the container a non-internal network and
   writing a forward-chain allowlist for it. The host agent already delivers
   the full trail in near-real-time, and keeping the container egress-locked is
   the stronger posture. If you still want it: `alerts.enabled: true` in the
   instance config, `wazuh/manager-syslog.xml` on the hub, and `udp/514` from
   the honeypot peers in `deploy/wazuh-hub-firewall.sh`.

Because a honeypot has no legitimate users, treat **every** event as suspicious.
The rules escalate by HoneyGas's own `severity` field and raise a high-level
alert when **one source hits both sites** within an hour — that is targeted
reconnaissance against your operator, not internet background noise. The `site`
field (`EDR-GAS-NODE-07` vs `BIO-PLANT-01`) and the agent groups keep the two
plants distinguishable in one dashboard. Wire the Wazuh **VirusTotal
integration** to auto-enrich the `sha256` of each `capture.*` event.

The dashboard is at `https://10.99.0.1`, reachable only from the admin peer.

---

## 7. Resetting after compromise

There are two very different notions of "compromise" here, with two different
responses.

### 7a. The simulated plant — nothing to reset

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

### 7b. The VM/host — rebuild, don't clean

You rebuild when the concern is the **box itself** (an unknown RCE in the
service, or a container breakout), i.e. persistence you can't see. Treat the VM
as cattle: reinstall it from your bootstrap (§5.7) rather than trying to
disinfect it.

**When (triggers):**

- **Scheduled** — rebuild on a cadence (e.g. weekly) regardless of events, to
  destroy any persistence and pick up OS updates.
- **Event-triggered** — rebuild immediately on a high-fidelity host-compromise
  signal from Wazuh:
  - **rule 100260** — the egress tripwire moved: the box tried to call out, or
    its firewall was tampered with;
  - the agent goes silent unexpectedly (built-in rules 503/505/506) — the box
    may have been killed or isolated;
  - file-integrity / rootcheck flags a change to a system path (the container FS
    is read-only, so **any** write outside `/opt/honeygas/data` is a breakout
    signal — syscheck rules 550/554);
  - an actual working exploit is captured against the honeypot service itself.
- **Analyst-triggered** — after you've collected what you need from a session.

**Why it's lossless:** the audit trail and quarantine inventory are shipped to
the hub in near-real-time through the tunnel, so the evidence is off-box (where
the attacker cannot reach) before any wipe. The malware samples themselves stay
on the sacrificial box. If you want them for deeper forensics, pull the
snapshots over the overlay first:
`scp -r <user>@10.99.0.11:/opt/honeygas/snapshots ./evidence/`.

**How:**

- **Container-level** (fast, same VM): `docker/rebuild.sh` snapshots the data
  dir, tears the instance down, wipes the data dir, and brings a fresh
  container up from the **local** image with empty state. It checks that the
  image is present before tearing anything down, because the locked VM cannot
  pull or build it. Schedule it with a cron job or systemd timer for the
  hygiene rebuild:
  ```bash
  sudo docker/rebuild.sh docker/compose.transport.yml     # or compose.biomethane.yml
  ```
- **VM-level** (stronger, for suspected host compromise): reinstall the OS from
  the provider's panel or API and re-run your bootstrap (§5.7). These VPS have
  no autoscaling groups; to automate it, have the hub call the provider's
  reinstall API from a Wazuh integration or active response. After every
  VM-level rebuild:
  - generate **new WireGuard keys** and replace the VM's `[Peer]` on the hub —
    the old private key may have been copied (with Tailscale, see §8.5);
  - remove the old agent on the hub (`/var/ossec/bin/manage_agents -r <ID>`)
    and enrol the new one;
  - expect new SSH host keys on the admin side.

Pair this with Wazuh alerting on **agent disconnect**: if an attacker takes the
box down, the silence is itself the alert.

---

## 8. Overlay option: Tailscale instead of plain WireGuard

Tailscale builds the same kind of WireGuard overlay, but hands out keys and
addresses for you, applies access rules centrally and traverses NAT. As a
result, **the hub needs no public port at all**. The flows of §3 stay exactly
the same.

| | Plain WireGuard (default) | Tailscale |
|---|---|---|
| Hub exposure | `udp/51820` (silent to scanners) | none |
| Access rules | host firewalls | tailnet policy (central) **and** host firewalls |
| Honeypot egress | one destination: hub IP, `udp/51820` | one **process**: the `tailscaled` service, to any destination (control plane, relays, peers). Every other process stays locked and counted |
| Keys and revocation | by hand, per peer | auth keys; remove the device in the admin console |
| Third party | none | the coordination service sees node metadata (names, public IPs, connection times), not the traffic. New connections need it to be up |
| Admin access | one WireGuard peer | any of the admin's devices |

The weaker point is the honeypot egress: it goes from "one destination" to
"one process". A non-root breakout still cannot get out, and the tripwire still
counts it. An attacker with root can abuse `tailscaled`, but root already
defeats any host firewall, and FIM and agent-disconnect cover that case. If you
want the convenience without the third-party control plane, a self-hosted
control server (e.g. Headscale) works the same way, but must be reachable over
HTTPS.

### 8.1 Tailnet policy and auth keys

- Load `deploy/tailscale-policy.hujson` in the admin console's access-control
  editor. It defines `tag:siem` (hub) and `tag:sensor` (honeypots) and allows
  only the §3 flows; everything else, including hub → honeypots and honeypot ↔
  honeypot, is denied.
- **Use a dedicated tailnet.** If you reuse one, merge the entries and remove
  the default allow-all rule, which would let the honeypots reach every device
  in it.
- Create one **pre-approved, tagged, single-use** auth key per node (`tag:siem`
  for the hub, `tag:sensor` for each honeypot).

### 8.2 Settings on every node (hub and honeypots)

```bash
# /etc/default/tailscaled — no log upload to the vendor:
FLAGS="--no-logs-no-support"

sudo tailscale up --auth-key=<key> --advertise-tags=tag:sensor \
     --hostname=<neutral-name> --accept-dns=false --netfilter-mode=off
sudo tailscale set --auto-update=false
tailscale ip -4      # note each node's 100.x address
```

- `--advertise-tags=tag:siem` on the hub.
- `--accept-dns=false`: otherwise every process's DNS is answered by
  `tailscaled` and forwarded from its own (allowed) traffic, which would be a
  DNS exfiltration channel.
- `--netfilter-mode=off`: otherwise `tailscaled` inserts iptables rules that
  accept everything arriving on `tailscale0` ahead of ours. The host firewalls
  stay in charge; `tailscaled` enforces the tailnet policy anyway.
- Auto-update off: updates come from rebuilding (§7b).
- Neutral hostnames (the site ids, not "honeypot").
- Addresses: you can pin each node's 100.x address in the admin console, so
  the configs below survive a rebuild.

### 8.3 Hub (replaces §4.3–4.5)

- No WireGuard. The provider's cloud firewall can drop **all** inbound
  traffic.
- Host firewall, with the 100.x addresses from §8.2 (`ADMIN` can list several
  admin devices):
  ```bash
  sudo OVERLAY=tailscale HONEYPOTS="<hp-A> <hp-B>" ADMIN="<admin-1> <admin-2>" \
       deploy/wazuh-hub-firewall.sh
  ```
  In this mode it opens no public port and routes nothing: admins reach the
  honeypots directly over the tailnet.
- NTP: in `/etc/chrony/chrony.conf`, add an `allow <hp-address>` line for each
  honeypot.
- The dashboard is at `https://<hub-100.x>`.

### 8.4 Honeypots (replaces §5.2, changes §5.3–5.5)

1. **Egress for `tailscaled` only.** Install the systemd drop-in, which refills
   the firewall's `tailscaled_egress` chain with the cgroup of the starting
   service, just before it runs:
   ```bash
   sudo install -D -m 0644 deploy/tailscaled-egress.conf \
        /etc/systemd/system/tailscaled.service.d/10-honeygas-egress.conf
   sudo systemctl daemon-reload
   ```
2. **DNS.** `tailscaled` resolves its control plane itself. On Ubuntu, disable
   `systemd-resolved` and point `/etc/resolv.conf` straight at the provider's
   resolvers. Otherwise `resolved` makes those lookups from its own cgroup,
   which the firewall blocks and counts. Everything else that tries to resolve
   names is still blocked, as intended.
3. **Firewall values.** In `deploy/nftables-honeypot.nft` set
   `OVERLAY_IF = "tailscale0"`, `HUB_OVERLAY` to the hub's 100.x address and
   `ADMIN_OVERLAY` to your admin devices' addresses. `HUB_PUBLIC` and `WG_PORT`
   are unused.
4. **Agent.** Use the hub's 100.x address wherever §5.1, §5.3 and §5.4 say
   `10.99.0.1` (`WAZUH_MANAGER`, `agent-ossec.conf`, `agent-auth -m`, NTP).
5. **Lock egress** as in §5.5, but restart `tailscaled` right after loading the
   ruleset, because loading it recreates the chain empty:
   ```bash
   sudo nft -f /etc/nftables.conf && sudo systemctl restart tailscaled && \
     sudo systemd-run --on-active=180 --unit=hg-fw-rollback nft delete table inet honeygas_host
   ```
   Then test SSH over the tailnet (`ssh <user>@<hp-100.x>`) and cancel the
   rollback as in §5.5. **Every time you reload the firewall, restart
   `tailscaled`**; otherwise its traffic is blocked and the tripwire fires.

The burn-in and the deliberate tripwire test (§5.6) are unchanged.

### 8.5 After a VM-level rebuild

- Remove the old device in the admin console: that revokes its key, which
  the attacker may have copied.
- Enrol the new VM with a fresh single-use auth key.
- If its 100.x address changed, update `HONEYPOTS` on the hub (re-run the
  firewall script) and the hub's `chrony.conf`.
- Then continue as in §7b (old Wazuh agent, SSH host keys).

---

## 9. Variant: single provider with a private network

If you prefer one bill and one console, and the provider offers private
networks and cloud firewalls (often free), you can drop WireGuard:

- put the hub on the private network only, and use its private IP wherever
  this guide says `10.99.0.1` (agent config, `agent-auth`, NTP);
- express the §3 table in the provider's firewall;
- run `deploy/wazuh-hub-firewall.sh` with `OVERLAY_IF` set to the hub's
  private interface and `HONEYPOTS` / `ADMIN` set to private addresses;
- keep `deploy/nftables-honeypot.nft` on the honeypots, replacing its two
  WireGuard rules with "private interface → hub private IP, tcp 1514/1515 and
  udp 123".

The trade-off: both honeypots share the provider's ASN. Place them in
different locations and subnets to limit the correlation.

---

## 10. File map

| Path | Role |
|------|------|
| `config/honeygas.transport.yaml`  | gaseoducto instance config (transport profile) |
| `config/honeygas.biomethane.yaml` | biometano instance config (biomethane profile) |
| `docker/compose.transport.yml`    | VM-A stack (standard ports, own volume, hardened) |
| `docker/compose.biomethane.yml`   | VM-B stack (no ATG) |
| `docker/rebuild.sh`               | container-level reset/clean (reuses the local image) |
| `deploy/nftables-honeypot.nft`    | honeypot host firewall: bait in, tunnel-only egress, egress tripwire |
| `deploy/wazuh-hub-firewall.sh`    | hub host firewall (iptables): public side closed, overlay rules (WireGuard or Tailscale) |
| `deploy/wg-hub.conf.example`      | WireGuard config, hub |
| `deploy/wg-honeypot.conf.example` | WireGuard config, each honeypot |
| `deploy/wg-admin.conf.example`    | WireGuard config, admin workstation |
| `deploy/tailscale-policy.hujson`  | Tailscale option: tailnet policy (tags + the §3 flows) |
| `deploy/tailscaled-egress.conf`   | Tailscale option: systemd drop-in that lets only `tailscaled` out |
| `wazuh/local_rules.xml`           | detection + cross-site correlation + egress tripwire rules |
| `wazuh/agent-ossec.conf`          | host agent: JSON ingest, host FIM, egress tripwire |
| `wazuh/manager-syslog.xml`        | optional CEF receiver |
