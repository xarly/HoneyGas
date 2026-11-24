# HoneyGas

**HoneyGas** is a defensive ICS/OT **honeypot** for natural-gas and biomethane
infrastructure. It emulates industrial automation and control devices and
services, generates realistic process traffic, exposes deliberately
vulnerable-looking services, and **captures, inventories, and audits** whatever
an attacker injects — with each attacker isolated from the others.

It is designed for research, threat intelligence, early-warning detection, and
training. It is **not** an attack tool and contains no real exploits.

> ⚠️ **Deploy only on an isolated, monitored network segment that you are
> authorized to operate.** A honeypot is a sensor meant to be attacked; treat
> everything it collects as hostile and keep it away from production assets.

---

## Contents

- [Operating modes](#operating-modes)
- [Emulated services (listeners)](#emulated-services-listeners)
- [The four requirements, mapped to the code](#the-four-requirements-mapped-to-the-code)
- [Safety contract](#safety-contract--captured-payloads-are-never-executed)
- [Architecture](#architecture)
  - [Repository layout](#repository-layout)
  - [Runtime flow](#runtime-flow)
  - [Core modules](#core-modules-honeygascore)
  - [Simulation layer](#simulation-layer-honeygassim)
  - [Protocol services](#protocol-services-honeygasprotocols)
  - [Per-attacker isolation model](#per-attacker-isolation-model)
  - [S7comm emulation detail](#s7comm-emulation-detail)
  - [IEC-104 emulation detail](#iec-104-emulation-detail)
  - [DNP3 emulation detail](#dnp3-emulation-detail)
  - [Audit event taxonomy](#audit-event-taxonomy)
  - [Out-of-band alerting](#out-of-band-alerting)
  - [Data model (profile schema)](#data-model-profile-schema)
- [Quick start (local)](#quick-start-local)
- [Deployment (Docker)](#deployment-docker-recommended)
- [Data outputs](#data-outputs)
- [Extending](#extending)
- [Legal & ethical use](#legal--ethical-use)

---

## Operating modes

Selected with `mode:` in `config/honeygas.yaml` (or `--mode` on the CLI):

| Mode         | Emulated installation | Highlighted assets |
|--------------|-----------------------|--------------------|
| `transport`  | Gas transport & distribution station | Station RTU / flow computer, custody-transfer metering, pressure regulation, odorant injection, Veeder-Root ATG |
| `biomethane` | Biomethane upgrading & grid-injection plant | Anaerobic digester, gas upgrading (membrane/PSA), compressor, CH₄/CO₂/H₂S/Wobbe analyzer, grid injection |

Each mode is a data-only **profile** (`config/profile_<mode>.yaml`): process
tags, Modbus register maps, HMI points, device/vendor banner, default
credentials, Siemens S7 PLC identity, and tank data. Add or edit a profile
without touching code.

## Emulated services (listeners)

| Service      | Default port | Backing class | What it does |
|--------------|--------------|---------------|--------------|
| Modbus/TCP   | 502   | `ModbusService` | FC1–6, 15, 16 reads/writes against live register values; FC43 device-id banner |
| HMI (HTTP)   | 8080  | `HttpHmiService` | Operator web UI with default creds, **firmware upload**, and a **diagnostics** command-injection surface |
| Veeder-Root ATG | 10001 | `AtgVeederService` | `I201xx` in-tank inventory + related reports (station / odorant tanks) |
| S7comm       | 102   | `S7CommService` | Full emulation: COTP connect, Setup Comm, **Read SZL** PLC fingerprint (order no./firmware/serial), Read/Write Var, PLC STOP/START |
| IEC 60870-5-104 | 2404 | `Iec104Service` | Full emulation: STARTDT/STOPDT/TESTFR, **General Interrogation** (live points), clock sync, spontaneous data, and audited **control commands** |
| DNP3         | 20000 | `Dnp3Service` | Full emulation: link layer (framing + DNP3 CRC), Request Link Status, **Class 0 integrity read** (live analog/binary/counter points), restart-bit handling, and audited **SELECT/OPERATE** controls (CROB + analog) |

Disable or re-port any of them in `config/honeygas.yaml`.

## The four requirements, mapped to the code

1. **Simulate ICS devices & services** — `honeygas/protocols/*` expose the
   protocols above; `honeygas/sim/profiles.py` describes the emulated devices.
2. **Simulate realistic installation traffic** — `honeygas/sim/process.py` is a
   lightweight digital-twin that advances pressures, flows, gas quality, etc.
   over time, so polled values look live and plausible, not static.
3. **Deliberately vulnerable versions** — dated firmware banners (Modbus FC43,
   HTTP `Server`/`/api/status`, S7 Read SZL), default/weak credentials, an
   unauthenticated-style firmware-flash endpoint, a command-injection
   diagnostics field, an unauthenticated S7 PLC STOP/START, and unauthenticated
   IEC-104 control commands (no RFC 2385 / TLS, as in the field).
4. **Inject + exploit, while inventorying and auditing, isolated per attacker**:
   - *Inject malware* → `POST /firmware/upload`, S7 Write Var, and raw payloads
     on the capture ports are captured by `honeygas/core/quarantine.py`.
   - *Exploit the vuln* → the `/diagnostics` injection, unknown ATG commands,
     S7 PLC control and IEC-104 control commands/set-points are inventoried as
     **calls** (evidence), with canned success returned so the attacker stays
     engaged.
   - *Inventory the binary/call* → hashed (MD5/SHA1/SHA256), type-tagged (magic
     bytes), stored under `data/quarantine/`, and appended to `inventory.jsonl`.
   - *Audit the event* → every interaction is one JSON line in
     `data/audit/honeygas-audit.jsonl` (`honeygas/core/audit.py`).
   - *Isolated between attackers* → `honeygas/core/sessions.py` gives each
     source IP its own copy-on-write overlay, so one attacker's writes never
     appear in another's reads, while `honeygas/core/limits.py` bounds what one
     source may consume (connections, rate, session memory) so it cannot starve
     the rest. Docker adds host/network isolation. See
     [Per-attacker isolation model](#per-attacker-isolation-model).

### Safety contract — captured payloads are never executed

HoneyGas **captures and inventories** attacker payloads; it **does not run
them**. Stored files get a neutralizing `.quarantine` extension and read-only
(`0o400`) permissions, and the service only *simulates* a successful exploit to
keep the attacker engaged — the simulated plant keeps running unchanged. If you
ever want real sample detonation, do it out-of-band in a dedicated, air-gapped
malware sandbox you operate separately — that is intentionally outside this
project's scope.

---

## Architecture

HoneyGas is a single-process **asyncio** application (Python 3.12+, standard
library only; PyYAML for config, optional `yara-python` for tagging). One
orchestrator builds a shared runtime **context** and starts each enabled
protocol listener plus two background loops (process tick + idle-session purge).
Protocol services are thin I/O front-ends; all state, logging, capture and
isolation live in the shared core.

```
                         ┌──────────────────────────────┐
   attacker TCP ───────► │  protocol service (asyncio)   │
                         │  Modbus / HTTP / ATG / S7 /…  │
                         └───────────────┬──────────────┘
                                         │ uses
             ┌───────────────────────────┼───────────────────────────┐
             ▼                           ▼                           ▼
    ┌─────────────────┐        ┌──────────────────┐        ┌──────────────────┐
    │ SessionManager  │        │ ProcessSimulator │        │   Quarantine     │
    │ per-IP overlay  │        │  live tag values │        │ hash+store+index │
    └─────────────────┘        └──────────────────┘        └────────┬─────────┘
             │                           │                          │
             └───────────────┬───────────┴──────────────────────────┘
                             ▼
                     ┌────────────────┐
                     │  AuditLogger   │  → data/audit/honeygas-audit.jsonl (JSONL)
                     └────────────────┘
```

### Repository layout

```
HoneyGas/
├── config/
│   ├── honeygas.yaml            # main config: mode, listeners, logging, quarantine, isolation
│   ├── honeygas.transport.yaml  # deployment: gaseoducto instance (own VM)
│   ├── honeygas.biomethane.yaml # deployment: biometano instance (own VM)
│   ├── profile_transport.yaml   # transport/distribution station profile (data only)
│   └── profile_biomethane.yaml  # biomethane upgrading plant profile (data only)
├── honeygas/
│   ├── __main__.py              # `python -m honeygas` entrypoint
│   ├── main.py                  # orchestrator: build context, start services, run loops
│   ├── core/
│   │   ├── config.py            # YAML → Config/Listener dataclasses
│   │   ├── context.py           # Context: the shared runtime bundle
│   │   ├── audit.py             # AuditLogger: structured JSONL events
│   │   ├── sessions.py          # SessionManager + per-attacker Session overlays (bounded, LRU-capped)
│   │   ├── limits.py            # ResourceGovernor: per-attacker connection quotas (cgroup equivalent)
│   │   ├── alerts.py            # AlertDispatcher: out-of-band push (syslog/CEF + webhook)
│   │   └── quarantine.py        # Quarantine: capture/hash/type/inventory (never executes)
│   ├── sim/
│   │   ├── profiles.py          # typed profile model + loader
│   │   └── process.py           # ProcessSimulator digital-twin
│   └── protocols/
│       ├── base.py              # Service base class (lifecycle + ctx accessors)
│       ├── modbus.py            # Modbus/TCP emulation
│       ├── http_hmi.py          # HTTP HMI/SCADA web UI
│       ├── atg.py               # Veeder-Root ATG serial-over-TCP
│       ├── s7comm.py            # Siemens S7comm (TPKT/COTP/S7) full emulation
│       ├── iec104.py            # IEC 60870-5-104 telecontrol full emulation
│       ├── dnp3.py              # DNP3 outstation (link/transport/application) full emulation
│       └── tcp_capture.py       # generic capture fallback (no listener wired by default)
├── docker/
│   ├── Dockerfile               # non-root, slim runtime image
│   ├── docker-compose.yml       # hardened single-instance stack
│   ├── compose.transport.yml    # two-site deploy: gaseoducto VM
│   ├── compose.biomethane.yml   # two-site deploy: biometano VM
│   └── rebuild.sh               # container-level reset/clean after compromise
├── wazuh/                       # Wazuh drop-ins: rules, host-agent config, CEF receiver
├── docs/
│   └── deployment-wazuh.md      # two-site cloud deployment + Wazuh ingestion guide
├── data/
│   ├── audit/                   # audit JSONL output (git-ignored)
│   └── quarantine/              # captured artifacts + inventory.jsonl (git-ignored)
├── requirements.txt
└── README.md
```

### Runtime flow

1. **`honeygas/main.py:main()`** parses `--config` / `--mode` and calls
   `build_context()`.
2. **`build_context()`** loads the main config (`load_config`) and the selected
   mode profile (`load_profile_dict` → `load_profile`), then constructs the
   `AuditLogger`, `Quarantine`, `SessionManager` and `ProcessSimulator` and
   bundles them into a `Context`.
3. **`build_services()`** walks `config.listeners`, maps each `type` through the
   `SERVICE_TYPES` registry to a `Service` subclass, and instantiates the
   enabled ones.
4. **`run()`** installs signal handlers (with a Windows fallback), starts every
   service's `asyncio` server, and launches two background tasks:
   - `_sim_loop` — calls `sim.tick()` every `tick_seconds` so tag values evolve;
   - `_purge_loop` — drops idle sessions every 60 s.
5. Each inbound TCP connection is handled by its service's coroutine, which pulls
   a per-IP `Session`, reads/writes live simulator values, captures anything the
   attacker injects, and emits audit events — all against the shared `Context`.

### Core modules (`honeygas/core`)

| Module | Key types / functions | Responsibility |
|--------|-----------------------|----------------|
| `config.py` | `Config`, `Listener`, `load_config()`, `load_profile_dict()` | Parse the main YAML into dataclasses; resolve paths against the project root (`<root>/config/..` → `<root>`). |
| `context.py` | `Context` | Immutable bundle (`config`, `audit`, `sessions`, `quarantine`, `sim`, `profile`, `governor`, `alerts`) handed to every service. |
| `audit.py` | `AuditLogger.log()`, `SEVERITIES` | Append one JSON object per event to the audit file; optional severity-filtered stdout echo, and hand each event to the optional alert sink. Severities: `debug < info < notice < warning < high < critical`. |
| `alerts.py` | `AlertConfig`, `AlertDispatcher`, `to_cef()` | Out-of-band push of high-signal events to the operator's monitoring — syslog/CEF and/or webhook — on a background thread. Off by default; see [Out-of-band alerting](#out-of-band-alerting). |
| `sessions.py` | `Session`, `BoundedDict`, `SessionManager.get()` / `purge_idle()` | One `Session` per `(src_ip, service)`, each with a **bounded** copy-on-write `overlay`, free-form `store`, and list of `captured` ids; a global session cap with least-recently-seen reclaim. |
| `limits.py` | `ResourceLimits`, `ResourceGovernor` | Per-attacker resource quotas (concurrent connections per-IP / total, new-connection rate) — the in-process cgroup equivalent, enforced in `Service._serve`. |
| `quarantine.py` | `Quarantine.capture_binary()` / `capture_call()`, `CaptureRecord` | Hash (MD5/SHA1/SHA256), magic-byte type detection, de-duplicated storage as `<sha256>.quarantine` (`0o400`), append to `inventory.jsonl`, optional YARA matching. **Never executes.** |

### Simulation layer (`honeygas/sim`)

- **`profiles.py`** — the typed device/process model (`Profile`, `TagSpec`,
  `RegEntry`, `ModbusMap`, `HmiSpec`/`HmiValue`, `Credential`, `AtgSpec`/`AtgTank`,
  `Vendor`, `S7Spec`) and `load_profile(dict)` that builds it from a profile YAML.
- **`process.py`** — `ProcessSimulator` holds one value per tag and advances it on
  every `tick()`:
  - `sine` — `base + amp·sin(2π·t/period) + gauss(0, noise)` (pressures, flows,
    gas quality that oscillate around a setpoint);
  - `counter` — monotonic accumulation at `rate`/s with optional wrap at `max`
    (totalized/custody volumes);
  - `setpoint` — slow random walk around the current value.
  Every value is clamped to `[min, max]`. Modbus registers and HMI points read
  through this simulator, so polled data always looks live.

### Protocol services (`honeygas/protocols`)

All services subclass **`base.Service`**, which provides the `start()`/`stop()`
lifecycle, convenience accessors (`audit`, `sessions`, `sim`, `quarantine`,
`profile`) and `peer(writer)` for the source IP/port.

- **`modbus.py` — `ModbusService`** — parses the MBAP header + PDU and implements
  FC1 (read coils), FC2 (discrete inputs), FC3/FC4 (holding/input registers),
  FC5/FC6 (write single coil/register), FC15/FC16 (write multiple), and FC43/14
  (read device identification → vendor banner). Reads resolve against the session
  overlay first, then the profile register map (static value or `tag × scale`
  from the simulator). Writes land in the overlay and raise a `modbus.write`
  (`high`) event. Unsupported functions return a Modbus exception and log
  `modbus.unsupported`.
- **`http_hmi.py` — `HttpHmiService`** — a minimal async HTTP/1.1 server exposing
  an operator-console facade: `/` + `/login` (accepts the profile's default
  creds, logs `http.login_attempt` at `high`), `/dashboard` (live tag values),
  `POST /firmware/upload` (captures the multipart body via
  `quarantine.capture_binary`, returns a fake flash-success), `/diagnostics`
  (command-injection surface: the submitted host/command is inventoried via
  `capture_call`, with canned `ping` output returned), and `/api/status` (JSON
  banner). Probes to unknown paths log `http.probe`.
- **`atg.py` — `AtgVeederService`** — emulates a Veeder-Root TLS-350 Automated
  Tank Gauge over TCP. Answers `I201xx`/`I202xx`/`I203xx`/`I205xx` with an
  in-tank inventory report built from the profile's `atg` tanks; any unrecognized
  command is inventoried as a `call` and acknowledged.
- **`s7comm.py` — `S7CommService`** — full Siemens S7 emulation (see below).
- **`iec104.py` — `Iec104Service`** — full IEC 60870-5-104 emulation (see below).
- **`dnp3.py` — `Dnp3Service`** — full DNP3 outstation emulation (see below).
- **`tcp_capture.py` — `TcpCaptureService`** — a generic capture front-end. All
  six shipped listeners now use dedicated full-emulation services, so nothing in
  the default config uses this; it remains the fallback for any new port you
  point at it (`type: tcp_capture`) before promoting it to its own module. It
  performs a minimal protocol-plausible handshake to keep scanners talking, logs
  `tcp.connect` / `tcp.data` / `tcp.close`, and captures payloads over a size
  threshold.

### Per-attacker isolation model

Isolation is defence in depth across three layers, so one attacker can neither
**see** nor **starve** another:

**1. Logical state isolation (always on).** Every `(src_ip, service)` pair gets
its own `Session` (`honeygas/core/sessions.py`). Writes — Modbus coils/registers,
S7 DB words, IEC-104 set-points/commands — land in that session's copy-on-write
`overlay` (or free-form `store`), never in the shared read-only baseline, so
attacker A's tampering is invisible to attacker B. Reads resolve against the
session overlay first, then the live simulator.

**2. In-process resource isolation (the cgroup equivalent).** One asyncio
process serves every attacker and never executes their payloads, so there is no
code-execution surface to sandbox per attacker. The *resource* dimension still
matters: one source must not exhaust connections, CPU or memory and so degrade
observation of the others. `honeygas/core/limits.py` (`ResourceGovernor`)
enforces, uniformly for every protocol in `Service._serve`:

| Quota | Default | Bounds |
|-------|---------|--------|
| `max_connections_per_ip` | 32 | concurrent connections from one source |
| `max_total_connections` | 512 | concurrent connections across all sources |
| `connection_rate_per_minute` | 240 | new-connection flood from one source (sliding 60 s window) |
| `max_sessions` | 8192 | live sessions before least-recently-seen reclaim |
| `max_overlay_entries` / `max_store_entries` | 4096 / 256 | writable points / scratch keys per session (`BoundedDict`) |

A connection refused by a quota is closed **before** its handler (and session)
ever run, and audited as `isolation.connection_rejected`; a session reclaimed at
the cap is audited as `isolation.session_evicted`. Defaults are generous — a
real honeypot wants to keep engaging attackers and the bursty scanners that
precede them, so ordinary reconnaissance is never tripped — and are tunable
under `isolation.limits` in `config/honeygas.yaml` (`0` disables a quota).

**3. Host / network isolation (deployment).** The compose stack in `docker/`
runs the whole honeypot non-root, read-only-root, `cap_drop: ALL`,
`no-new-privileges`, on an `internal` bridge with no egress, under a CPU/memory
cap — so even though captures are never executed, a payload has nowhere to call
home from.

#### Hard per-source isolation (optional)

For kernel-level isolation *between sources* — e.g. a research deployment that
wants each attacker in its own network namespace — front HoneyGas with a
per-source dispatcher rather than building it into the process. Two recipes:

- **Per-source connection limiting at the host edge with nftables**, which
  complements the in-process governor:

  ```nft
  table inet honeygas {
    chain input {
      type filter hook input priority 0; policy accept;
      define ics_ports = { 102, 502, 2404, 8080, 10001, 20000 }
      # cap concurrent connections per source IP
      tcp dport $ics_ports ct state new ct count over 64 reject with tcp reset
      # cap new-connection rate per source IP
      tcp dport $ics_ports ct state new \
        meter flood { ip saddr limit rate over 10/second } reject with tcp reset
    }
  }
  ```

- **Per-source network namespaces** — run one hardened HoneyGas container per
  source class (e.g. one per `/24`, or one per allowlisted researcher), each on
  its own `internal` compose network, and steer traffic to the right instance
  with the host firewall or a small TCP proxy. Device state is already per-IP
  inside each instance, so this adds a kernel boundary with **no code change**.

### S7comm emulation detail

`s7comm.py` implements the full Siemens stack over TCP/102 — **TPKT (RFC 1006) →
COTP (ISO 8073) → S7comm** — the layer scanners and engineering tools actually
speak:

- **COTP connect** — answers the Connection Request with a well-formed
  Connection Confirm (reflects references, swaps the client TSAPs) → `s7.cotp_connect`.
- **Setup Communication** — negotiates the PDU size (`min(request, profile
  pdu_size)`, default 480) and replies with `Ack_Data` → `s7.setup`.
- **Read SZL (System Status List)** — the fingerprint path used by nmap
  `s7-info`, PLCScan, snap7 and Metasploit:
  - **SZL 0x0011** (module identification) — order number / MLFB and firmware
    version, encoded from the profile `s7:` block;
  - **SZL 0x001C** (component identification) — system name, module type, serial,
    copyright, plant id → `s7.read_szl`.
- **Read Var** — DB word reads return **live simulator values** (DB1 words map
  onto the same input/holding registers as Modbus, so `DB1.DBW0` is the real line
  pressure), checking the session overlay first → `s7.read_var`.
- **Write Var** — writes go **only to the attacker's session overlay** (isolation),
  are logged at `high`, and the raw written bytes are inventoried → `s7.write_var`.
- **PLC STOP / START (control)** — logged at **`critical`** ("PLC state-change
  attempt; simulated only"), the control call is captured as evidence, and a
  success ack is returned while the simulated plant keeps running → `s7.plc_control`.
- Any other function is audited (`s7.unknown_job`) and the raw PDU inventoried.

The exposed PLC identity is per-profile. The shipped profiles emulate dated
Siemens firmware as bait:

| Mode | Order number (MLFB) | Module | Firmware | System name |
|------|---------------------|--------|----------|-------------|
| `transport` | `6ES7 315-2EH14-0AB0` | CPU 315-2 PN/DP | V3.2.6 | `GASNODE07_S7` |
| `biomethane` | `6ES7 1512-1AK01-0AB0` | CPU 1512C-1 PN | V2.6.1 | `BIOUPGRADE_PLC` |

### IEC-104 emulation detail

`iec104.py` implements the telecontrol protocol spoken between a SCADA master
and an RTU/substation gateway over TCP/2404 — **APCI (`0x68`/len/4 control
octets) → ASDU (type, VSQ, cause-of-transmission, common address, information
objects)** — with full I/S/U frame handling and 15-bit send/receive sequence
numbers:

- **U-format** `STARTDT` / `STOPDT` / `TESTFR` → the matching `*_con`; data
  transfer is enabled only after `STARTDT` → `iec104.startdt` / `iec104.testfr`.
- **General Interrogation** (`C_IC_NA_1`, type 100) → activation confirmation,
  then the current value of **every monitored point** — measured short floats
  (`M_ME_NC_1`) from the live simulator plus single-point states
  (`M_SP_NA_1`) — with COT=20, then activation termination → `iec104.interrogation`.
- **Clock synchronisation** (`C_CS_NA_1`) → `actcon` with a fresh `CP56Time2a`.
- **Counter interrogation** (`C_CI_NA_1`) → `actcon` + `actterm`.
- **Control commands** (`C_SC_NA_1` single, `C_DC_NA_1` double, `C_SE_NC_1`
  set-point short-float, …) → logged at **`high`**, inventoried as evidence via
  `capture_call`, applied **only to the attacker's isolated session view**, and
  positively confirmed (`actcon` + `actterm`) so the attacker believes the
  command took effect — the simulated plant is untouched → `iec104.command`.
- **Spontaneous transmission** — while `STARTDT` is active, measured values are
  pushed periodically (`M_ME_TF_1`, COT=3, with `CP56Time2a`), so a passive
  observer sees a live installation (`spontaneous_seconds` in the profile).
- Any other ASDU is audited (`iec104.unknown_asdu`) and large ones inventoried.

Points and controls are defined per-profile in the `iec104:` block (common
address, monitored points by IOA/tag, control IOAs). If a profile omits the
block, measured points are synthesized from its HMI tag list.

### DNP3 emulation detail

`dnp3.py` implements the full DNP3 three-layer stack spoken between a SCADA
master and an outstation/RTU over TCP/20000:

    Data Link (0x05 0x64 | len | ctrl | dest | src | CRC, 16-byte data blocks
               each with their own CRC)
      -> Transport function (1-byte FIR/FIN/sequence)
        -> Application (app control | function | IIN | objects)

- **DNP3 CRC** — the link-layer CRC (poly `0x3D65`, reflected, one's-complement
  final) is computed on every header and data block, so frames are accepted by
  real masters and tools (verified against the CRC-16/DNP catalog check value
  `0xEA82`).
- **Data-link requests** — `Request Link Status` → `Link Status` (function 11),
  `Reset Link` / `Test Link` → `ACK`, with the source/destination addresses
  swapped and answered as the address the master targeted → `dnp3.link_status` /
  `dnp3.reset_link`.
- **READ Class 0 / static (integrity poll)** — a RESPONSE carrying the current
  value of every monitored point: analog inputs (`g30v5`, 32-bit float from the
  live simulator), binary inputs (`g1v2`), counters (`g20v1`), plus the output
  status points (`g10` / `g40`) reflecting this attacker's isolated control
  state → `dnp3.read`. Event-class-only polls get an empty (quiet) response.
- **Device restart bit** — the first responses assert IIN1.7 (device restart),
  as a freshly-started outstation would, until the master clears it with a
  `WRITE` of the Internal Indications (`g80v1`) → `dnp3.write`.
- **SELECT / OPERATE / DIRECT_OPERATE** — the control-tampering event: CROB
  (`g12`, relays) and analog output blocks (`g41`, set-points) are logged at
  **`high`** (SELECT, which only arms, at `notice`), inventoried as evidence via
  `capture_call`, applied **only to the attacker's isolated session view**, and
  positively confirmed with status = SUCCESS so the attacker believes the relay
  / set-point took effect. The simulated plant is untouched → `dnp3.control`.
- **COLD_RESTART / WARM_RESTART** — logged at **`critical`**, inventoried, and
  answered with a time-delay object — simulated only → `dnp3.restart`.
- **ENABLE/DISABLE unsolicited, DELAY_MEASURE, CONFIRM** — plausible answers.
- Any unsupported function is answered with the "function not supported" IIN bit
  and inventoried → `dnp3.unknown_function`.

Points and controls are defined per-profile in the `dnp3:` block (outstation
link address, monitored points by index/group/tag, control points by
index/group). If a profile omits the block, analog inputs are synthesized from
its HMI tag list.

### Audit event taxonomy

Every line in `data/audit/honeygas-audit.jsonl` carries `ts`, `event_id`,
`event`, `severity`, `site`, `session`, `src_ip`, `src_port`, `service`,
`protocol` and a free-form `data` object. Key events:

| Source | Event | Severity | Meaning |
|--------|-------|----------|---------|
| core | `honeygas.start` / `honeygas.stop` | notice | lifecycle |
| core | `service.listening` | info | a listener bound its port |
| core | `service.bind_failed` | warning | port bind failed (e.g. privileged port) |
| core | `sessions.purged` | debug | idle sessions / rate windows reclaimed |
| core | `isolation.connection_rejected` | warning | a per-attacker connection quota (per-IP / total / rate) refused a connection |
| core | `isolation.session_evicted` | warning | session cap reached; least-recently-seen session reclaimed |
| core | `alert.sink_started` | info | out-of-band alert sink enabled (lists the configured sinks) |
| quarantine | `capture.binary` | **critical** | an injected payload/file was captured |
| quarantine | `capture.call` | **critical** | an injected command/RPC was inventoried |
| modbus | `modbus.connect` / `modbus.read` | notice / info | connection / register poll |
| modbus | `modbus.write` | **high** | attacker wrote a register/coil (into overlay) |
| modbus | `modbus.read_device_id` | notice | FC43 banner grab |
| http | `http.login_attempt` | **high** | credential submission to the HMI |
| http | `http.request` / `http.probe` | info / notice | request / unknown-path probe |
| atg | `atg.connect` / `atg.command` | notice | ATG session / command |
| s7 | `s7.cotp_connect` / `s7.setup` | notice / info | S7 session setup |
| s7 | `s7.read_szl` | notice | PLC fingerprinting (SZL read) |
| s7 | `s7.read_var` | info | variable/DB read |
| s7 | `s7.write_var` | **high** | variable/DB write (into overlay) |
| s7 | `s7.plc_control` | **critical** | PLC STOP/START attempt |
| iec104 | `iec104.connect` / `iec104.startdt` | notice | session / STARTDT activation |
| iec104 | `iec104.interrogation` / `iec104.interrogation_response` | notice / info | General Interrogation + its live response |
| iec104 | `iec104.clock_sync` / `iec104.counter_interrogation` | notice | clock sync / counter interrogation |
| iec104 | `iec104.command` | **high** | control command / set-point (into session view) |
| iec104 | `iec104.spontaneous` | debug | periodic spontaneous value push |
| dnp3 | `dnp3.connect` / `dnp3.link_status` / `dnp3.reset_link` | notice / info | session / data-link requests |
| dnp3 | `dnp3.read` / `dnp3.write` | info / notice | Class 0 integrity read / Internal-Indications write |
| dnp3 | `dnp3.control` | **high** | SELECT/OPERATE on a CROB or analog output (into session view) |
| dnp3 | `dnp3.restart` | **critical** | COLD/WARM restart attempt |
| tcp | `tcp.connect` / `tcp.data` / `tcp.close` | notice / info | generic capture fallback (unused by default) |

### Out-of-band alerting

The audit file is the complete record; the **alert sink** (`honeygas/core/alerts.py`)
is the *push* side of it — it forwards the high-signal events, as they happen,
to the operator's own monitoring. It is the control layer's "alert silently"
piece: events go out-of-band and **nothing is ever sent back to the attacker**.

- **What is forwarded** — every event with `severity >= min_severity` (default
  `high`), so the control-tampering writes/commands (`*.write`, `iec104.command`,
  `dnp3.control`), the PLC/restart attempts and every capture (`critical`), and
  the quota breaches (`warning`, if you lower the threshold). The sink's own
  events (`alert.*`) are never re-dispatched.
- **syslog / CEF** — UDP or TCP to your SIEM (ArcSight / QRadar / Splunk /
  rsyslog). Each event becomes a CEF record:
  `CEF:0|HoneyGas|<site>|<ver>|<event>|<event>|<sev>|src=… spt=… proto=… app=… cs1=<session> …`
  with our six severities mapped to CEF 0–10.
- **webhook** — an HTTP `POST` of the full JSON event to a URL you control, with
  optional custom headers (e.g. an `Authorization` bearer token).
- **Non-blocking & fail-safe** — delivery runs on a background worker thread fed
  by a bounded queue, so a slow or unreachable SIEM never stalls the asyncio
  event loop or a protocol handler; a full queue drops (and counts) events, and
  any delivery error is swallowed. Alerting can never affect the honeypot or the
  attacker-facing responses.

Configure it under `alerts:` in `config/honeygas.yaml` (disabled by default):

```yaml
alerts:
  enabled: true
  min_severity: high            # debug|info|notice|warning|high|critical
  syslog:  {enabled: true, host: "10.0.0.5", port: 514, protocol: udp, facility: 16}
  webhook: {enabled: true, url: "https://siem.example/hooks/honeygas", timeout_seconds: 4.0}
```

### Data model (profile schema)

A profile YAML (`config/profile_<mode>.yaml`) is parsed by
`honeygas/sim/profiles.py:load_profile()` into these dataclasses:

- **`Profile`** — `name`, `mode`, `vendor`, `credentials[]`, `tags[]`, `modbus`,
  `hmi`, optional `atg`, optional `s7`, optional `iec104`, optional `dnp3`.
- **`TagSpec`** — `name`, `unit`, `kind` (`sine`/`counter`/`setpoint`), `base`,
  `amp`, `period`, `noise`, `rate`, `min`, `max`.
- **`ModbusMap`** — `unit` + four address→`RegEntry` maps (`input_registers`,
  `holding_registers`, `coils`, `discrete_inputs`). **`RegEntry`** = `tag`,
  `scale`, `static`, `label`.
- **`HmiSpec`** — `title` + `HmiValue[]` (`label`, `tag`, `unit`).
- **`Credential`** — `username`, `password` (the HMI's accepted weak creds).
- **`AtgSpec`** — `station` + `AtgTank[]` (`num`, `product`, `volume`,
  `tc_volume`, `ullage`, `height`, `water`, `temp`).
- **`Vendor`** — `manufacturer`, `product`, `firmware`, `serial` (Modbus/HTTP
  banners).
- **`S7Spec`** — `order_number`, `basic_hardware`, `firmware`, `module_type`,
  `system_name`, `serial`, `copyright`, `plant_id`, `pdu_size` (S7 Read SZL
  identity).
- **`Iec104Spec`** — `common_address`, `spontaneous_seconds`, `points[]`
  (**`Iec104Point`** = `ioa`, `tag`/`static`, `type_id` [13 float / 1 single],
  `scale`, `label`) and `commands[]` (**`Iec104Command`** = `ioa`, `type_id`
  [45 single / 46 double / 50 set-point], `label`).
- **`Dnp3Spec`** — `source_address` (outstation link address), `points[]`
  (**`Dnp3Point`** = `index`, `group` [30 analog input / 1 binary input /
  20 counter], `tag`/`static`, `scale`, `label`) and `controls[]`
  (**`Dnp3Control`** = `index`, `group` [12 CROB / 41 analog output], `label`).

---

## Quick start (local)

```bash
pip install -r requirements.txt
python -m honeygas --config config/honeygas.yaml
# or override the mode:
python -m honeygas --mode biomethane
```

Binding to ports < 1024 (502, 102) needs Administrator/root, or just remap
those ports in the config to high ports for local testing.

Watch events live (stdout echoes them) and tail the structured logs:

```bash
tail -f data/audit/honeygas-audit.jsonl
cat data/quarantine/inventory.jsonl
```

## Deployment (Docker, recommended)

### Single instance (all-in-one)

```bash
cd docker
docker compose up --build -d
docker compose logs -f
```

The compose stack runs the honeypot as a non-root user, read-only root
filesystem, all capabilities dropped, `no-new-privileges`, resource-limited, and
on an **internal** network with no outbound internet — defence-in-depth around a
service that is meant to be attacked. Captured data persists on the
`honeygas-data` volume.

### Two-site cloud deployment with Wazuh

To run a **gaseoducto (transport)** and a **biometano (biomethane)** site as two
independent cloud VMs feeding a **Wazuh** SIEM on a separate private network, see
**[docs/deployment-wazuh.md](docs/deployment-wazuh.md)**. That guide covers the
network topology and one-way-telemetry firewall model, the per-site instance
configs, Wazuh ingestion (native JSON + optional CEF) with cross-site
correlation, believability of the two sites, and **how/when the environment is
reset after a compromise**. Ready-to-use artifacts:

| Path | Role |
|------|------|
| [`config/honeygas.transport.yaml`](config/honeygas.transport.yaml) / [`config/honeygas.biomethane.yaml`](config/honeygas.biomethane.yaml) | per-site instance configs |
| [`docker/compose.transport.yml`](docker/compose.transport.yml) / [`docker/compose.biomethane.yml`](docker/compose.biomethane.yml) | one hardened stack per VM |
| [`docker/rebuild.sh`](docker/rebuild.sh) | container-level reset/clean |
| [`wazuh/`](wazuh/) | detection rules, host-agent config, optional CEF receiver |

## Data outputs

- `data/audit/honeygas-audit.jsonl` — one JSON event per line (SIEM-ready):
  connections, Modbus/S7 reads/writes, HTTP requests, login attempts, captures.
- `data/quarantine/inventory.jsonl` — one `CaptureRecord` per captured
  binary/call with hashes, type, size, source session, and (optional) YARA
  matches.
- `data/quarantine/<sha256>.quarantine` — the raw captured bytes, read-only.

Both `data/` subtrees are git-ignored (only `.gitkeep` placeholders are tracked),
so runtime captures never land in version control.

## Extending

- **New device profile:** copy a `config/profile_*.yaml`, edit tags/registers.
- **S7 PLC identity:** edit the `s7:` block in a profile (order number,
  firmware, module type, serial) to change what Read SZL fingerprinting
  returns. S7comm Read/Write Var map to the same process/register space as
  Modbus (DB words ↔ input/holding registers).
- **IEC-104 points:** edit the `iec104:` block in a profile (common address,
  monitored points by IOA/tag, control IOAs, spontaneous interval) to change
  what a General Interrogation returns and which controls an attacker can try.
- **DNP3 points:** edit the `dnp3:` block in a profile (outstation link address,
  monitored points by index/group/tag, control points by index/group) to change
  what a Class 0 integrity read returns and which controls an attacker can try.
- **New protocol:** subclass `honeygas.protocols.base.Service`, register it in
  `SERVICE_TYPES` in `honeygas/main.py`, add a listener entry in the config.
  All six shipped listeners are now full emulations; `honeygas/protocols/`
  (`s7comm.py`, `iec104.py`, `dnp3.py`) shows the pattern, and `tcp_capture.py`
  is the capture-only fallback for a brand-new port before you promote it.
- **YARA tagging:** set `quarantine.enable_yara: true`, drop rules at
  `config/rules.yar`, and `pip install yara-python`.

## Legal & ethical use

Run HoneyGas only on infrastructure and network segments you own or are
explicitly authorized to operate, in line with applicable law and your
organization's policies. Captured data may contain third-party malware and
attacker-controlled content — handle, store, and share it accordingly.
