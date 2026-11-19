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
  - [Audit event taxonomy](#audit-event-taxonomy)
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
| IEC 60870-5-104 | 2404 | `TcpCaptureService` | Fingerprint + capture (STARTDT confirm handshake) |
| DNP3         | 20000 | `TcpCaptureService` | Connection + payload capture |

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
   diagnostics field, and an unauthenticated S7 PLC STOP/START.
4. **Inject + exploit, while inventorying and auditing, isolated per attacker**:
   - *Inject malware* → `POST /firmware/upload`, S7 Write Var, and raw payloads
     on the capture ports are captured by `honeygas/core/quarantine.py`.
   - *Exploit the vuln* → the `/diagnostics` injection, unknown ATG commands and
     S7 PLC control are inventoried as **calls** (evidence), with canned success
     returned so the attacker stays engaged.
   - *Inventory the binary/call* → hashed (MD5/SHA1/SHA256), type-tagged (magic
     bytes), stored under `data/quarantine/`, and appended to `inventory.jsonl`.
   - *Audit the event* → every interaction is one JSON line in
     `data/audit/honeygas-audit.jsonl` (`honeygas/core/audit.py`).
   - *Isolated between attackers* → `honeygas/core/sessions.py` gives each
     source IP its own copy-on-write overlay, so one attacker's writes never
     appear in another's reads. Docker adds host/network isolation.

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
│   ├── profile_transport.yaml   # transport/distribution station profile (data only)
│   └── profile_biomethane.yaml  # biomethane upgrading plant profile (data only)
├── honeygas/
│   ├── __main__.py              # `python -m honeygas` entrypoint
│   ├── main.py                  # orchestrator: build context, start services, run loops
│   ├── core/
│   │   ├── config.py            # YAML → Config/Listener dataclasses
│   │   ├── context.py           # Context: the shared runtime bundle
│   │   ├── audit.py             # AuditLogger: structured JSONL events
│   │   ├── sessions.py          # SessionManager + per-attacker Session overlays
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
│       └── tcp_capture.py       # generic capture front-end (IEC-104, DNP3)
├── docker/
│   ├── Dockerfile               # non-root, slim runtime image
│   └── docker-compose.yml       # hardened stack (read-only, cap_drop, internal net)
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
| `context.py` | `Context` | Immutable bundle (`config`, `audit`, `sessions`, `quarantine`, `sim`, `profile`) handed to every service. |
| `audit.py` | `AuditLogger.log()`, `SEVERITIES` | Append one JSON object per event to the audit file; optional severity-filtered stdout echo. Severities: `debug < info < notice < warning < high < critical`. |
| `sessions.py` | `Session`, `SessionManager.get()` / `purge_idle()` | One `Session` per `(src_ip, service)`, each with a copy-on-write `overlay`, free-form `store`, and list of `captured` ids. |
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
- **`tcp_capture.py` — `TcpCaptureService`** — a generic capture front-end used
  for IEC-104 and DNP3. It performs a minimal protocol-plausible handshake (COTP
  CC / IEC-104 STARTDT confirm) to keep scanners talking, logs `tcp.connect` /
  `tcp.data` / `tcp.close`, and captures payloads over a size threshold. These
  two are the natural candidates to promote to full emulation next, following the
  S7comm pattern.

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

### Audit event taxonomy

Every line in `data/audit/honeygas-audit.jsonl` carries `ts`, `event_id`,
`event`, `severity`, `site`, `session`, `src_ip`, `src_port`, `service`,
`protocol` and a free-form `data` object. Key events:

| Source | Event | Severity | Meaning |
|--------|-------|----------|---------|
| core | `honeygas.start` / `honeygas.stop` | notice | lifecycle |
| core | `service.listening` | info | a listener bound its port |
| core | `service.bind_failed` | warning | port bind failed (e.g. privileged port) |
| core | `sessions.purged` | debug | idle sessions reclaimed |
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
| tcp | `tcp.connect` / `tcp.data` / `tcp.close` | notice / info | capture-port activity (IEC-104, DNP3) |

### Data model (profile schema)

A profile YAML (`config/profile_<mode>.yaml`) is parsed by
`honeygas/sim/profiles.py:load_profile()` into these dataclasses:

- **`Profile`** — `name`, `mode`, `vendor`, `credentials[]`, `tags[]`, `modbus`,
  `hmi`, optional `atg`, optional `s7`.
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
- **New protocol:** subclass `honeygas.protocols.base.Service`, register it in
  `SERVICE_TYPES` in `honeygas/main.py`, add a listener entry in the config.
  Modbus and S7comm are full emulations; IEC-104 and DNP3 are the natural
  candidates to promote from capture to full emulation next (see
  `honeygas/protocols/s7comm.py` for the pattern).
- **YARA tagging:** set `quarantine.enable_yara: true`, drop rules at
  `config/rules.yar`, and `pip install yara-python`.

## Legal & ethical use

Run HoneyGas only on infrastructure and network segments you own or are
explicitly authorized to operate, in line with applicable law and your
organization's policies. Captured data may contain third-party malware and
attacker-controlled content — handle, store, and share it accordingly.
