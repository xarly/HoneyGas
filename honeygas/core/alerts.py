"""Out-of-band alert sink.

The audit log (``audit.py``) is the complete, SIEM-ready record of everything
the honeypot observes. This module is the *push* side of that: it takes the
high-signal events (control tampering, captured payloads, quota breaches, ...)
and forwards them, as they happen, to the operator's own monitoring:

  * syslog in CEF format (ArcSight / QRadar / Splunk / rsyslog), UDP or TCP;
  * an HTTP webhook (JSON POST) for high/critical events.

Design constraints that make it safe for a honeypot:

  * **Decoupled** — ``AuditLogger`` only calls a duck-typed ``handle(record)``;
    it knows nothing about syslog/webhooks, and the sink never reaches back
    into the attacker-facing response path.
  * **Non-blocking** — events are handed to a background worker thread through
    a bounded queue, so a slow or unreachable SIEM can never stall the asyncio
    event loop or a protocol handler. A full queue drops (and counts) events
    rather than blocking.
  * **Silent** — nothing here is ever sent back to the attacker; alerting is
    purely out-of-band.
  * **Fail-safe** — every delivery is best-effort and fully guarded; a sink
    failure can never raise into the honeypot.
  * **Off by default** — destinations are the operator's own infrastructure,
    configured explicitly under ``alerts:`` in the config.

No third-party dependencies: UDP/TCP via ``socket``, HTTP via ``urllib``.
"""
from __future__ import annotations

import json
import queue
import socket
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .audit import SEVERITIES

VERSION = "0.1.0"

# Our severity -> CEF severity (0..10) and -> syslog severity (0 emerg .. 7 debug).
_CEF_SEVERITY = {"debug": 1, "info": 3, "notice": 4, "warning": 6, "high": 8, "critical": 10}
_SYSLOG_SEVERITY = {"debug": 7, "info": 6, "notice": 5, "warning": 4, "high": 3, "critical": 2}


# --------------------------------------------------------------------- config
@dataclass
class SyslogConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 514
    protocol: str = "udp"            # "udp" | "tcp"
    facility: int = 16               # local0


@dataclass
class WebhookConfig:
    enabled: bool = False
    url: str = ""
    timeout_seconds: float = 4.0
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class AlertConfig:
    enabled: bool = False
    min_severity: str = "high"
    queue_size: int = 2048
    syslog: SyslogConfig = field(default_factory=SyslogConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "AlertConfig":
        d = d or {}
        sy = d.get("syslog", {}) or {}
        wh = d.get("webhook", {}) or {}
        sev = str(d.get("min_severity", "high")).lower()
        if sev not in SEVERITIES:
            sev = "high"
        return cls(
            enabled=bool(d.get("enabled", False)),
            min_severity=sev,
            queue_size=max(16, int(d.get("queue_size", 2048))),
            syslog=SyslogConfig(
                enabled=bool(sy.get("enabled", False)),
                host=str(sy.get("host", "127.0.0.1")),
                port=int(sy.get("port", 514)),
                protocol=str(sy.get("protocol", "udp")).lower(),
                facility=int(sy.get("facility", 16)),
            ),
            webhook=WebhookConfig(
                enabled=bool(wh.get("enabled", False)),
                url=str(wh.get("url", "")),
                timeout_seconds=float(wh.get("timeout_seconds", 4.0)),
                headers={str(k): str(v) for k, v in (wh.get("headers", {}) or {}).items()},
            ),
        )


# ------------------------------------------------------------------ CEF format
def _esc_header(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _esc_ext(value: Any) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\n", "\\n").replace("\r", "\\n"))


def to_cef(record: dict, product: str, version: str = VERSION) -> str:
    """Render one audit record as a CEF message (header + extension)."""
    sev = _CEF_SEVERITY.get(record.get("severity", "info"), 5)
    sig = _esc_header(record.get("event", "event"))
    header = f"CEF:0|HoneyGas|{_esc_header(product)}|{_esc_header(version)}|{sig}|{sig}|{sev}|"

    ext: Dict[str, Any] = {}
    if record.get("src_ip"):
        ext["src"] = record["src_ip"]
    if record.get("src_port"):
        ext["spt"] = record["src_port"]
    if record.get("protocol"):
        ext["proto"] = record["protocol"]
    if record.get("service"):
        ext["app"] = record["service"]
    if record.get("session"):
        ext["cs1"] = record["session"]
        ext["cs1Label"] = "Session"
    if record.get("event_id"):
        ext["externalId"] = record["event_id"]
    ext["cat"] = record.get("event", "")
    ext["rt"] = int(time.time() * 1000)
    # Flatten the free-form data object into extension key=value pairs.
    for k, v in (record.get("data") or {}).items():
        ext[f"cs_{k}"] = v if isinstance(v, (int, float, str)) else json.dumps(v, default=str)

    parts = [f"{k}={_esc_ext(v)}" for k, v in ext.items()]
    return header + " ".join(parts)


def _syslog_line(record: dict, facility: int, product: str, host: str) -> bytes:
    pri = facility * 8 + _SYSLOG_SEVERITY.get(record.get("severity", "info"), 5)
    stamp = datetime.now().strftime("%b %d %H:%M:%S")
    tag = "honeygas"
    msg = to_cef(record, product)
    return f"<{pri}>{stamp} {host} {tag}: {msg}".encode("utf-8", errors="replace")


# -------------------------------------------------------------------- emitters
class SyslogEmitter:
    def __init__(self, cfg: SyslogConfig, product: str) -> None:
        self.cfg = cfg
        self.product = product
        self.host = socket.gethostname()
        self._sock: Optional[socket.socket] = None

    def _udp(self) -> socket.socket:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._sock

    def _tcp(self) -> socket.socket:
        if self._sock is None:
            s = socket.create_connection((self.cfg.host, self.cfg.port), timeout=4.0)
            self._sock = s
        return self._sock

    def emit(self, record: dict) -> None:
        line = _syslog_line(record, self.cfg.facility, self.product, self.host)
        if self.cfg.protocol == "tcp":
            try:
                self._tcp().sendall(line + b"\n")
            except OSError:
                self.close()                      # force reconnect next time
                self._tcp().sendall(line + b"\n")
        else:
            self._udp().sendto(line, (self.cfg.host, self.cfg.port))

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


class WebhookEmitter:
    def __init__(self, cfg: WebhookConfig) -> None:
        self.cfg = cfg

    def emit(self, record: dict) -> None:
        body = json.dumps(record, ensure_ascii=False, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json",
                   "User-Agent": "HoneyGas-AlertSink"}
        headers.update(self.cfg.headers)
        req = urllib.request.Request(self.cfg.url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.cfg.timeout_seconds) as resp:
            resp.read()                           # drain and discard

    def close(self) -> None:
        pass


# ------------------------------------------------------------------ dispatcher
class AlertDispatcher:
    """Receives audit records (``handle``) and forwards the high-signal ones to
    the configured emitters on a background worker thread."""

    def __init__(self, cfg: AlertConfig, site: str = "HoneyGas") -> None:
        self.cfg = cfg
        self.product = site or "HoneyGas"
        self._min_rank = SEVERITIES.index(cfg.min_severity) if cfg.min_severity in SEVERITIES else SEVERITIES.index("high")
        self._emitters: List[Any] = []
        if cfg.enabled:
            if cfg.syslog.enabled:
                self._emitters.append(SyslogEmitter(cfg.syslog, self.product))
            if cfg.webhook.enabled and cfg.webhook.url:
                self._emitters.append(WebhookEmitter(cfg.webhook))
        self.enabled = bool(cfg.enabled and self._emitters)

        self._q: "queue.Queue[dict]" = queue.Queue(maxsize=cfg.queue_size)
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        # Observability of the sink itself.
        self.sent = 0
        self.failed = 0
        self.dropped = 0

    @property
    def sinks(self) -> List[str]:
        names = []
        if self.cfg.syslog.enabled:
            names.append(f"syslog/{self.cfg.syslog.protocol}")
        if self.cfg.webhook.enabled and self.cfg.webhook.url:
            names.append("webhook")
        return names

    def start(self) -> None:
        if not self.enabled:
            return
        self._worker = threading.Thread(target=self._run, name="honeygas-alerts", daemon=True)
        self._worker.start()

    def handle(self, record: dict) -> None:
        """Called by AuditLogger for every event (on the event-loop thread).

        Fast and non-blocking: filters by severity and enqueues. Never raises.
        """
        if not self.enabled:
            return
        event = record.get("event", "")
        if event.startswith("alert."):            # never dispatch our own events
            return
        try:
            if SEVERITIES.index(record.get("severity", "info")) < self._min_rank:
                return
        except ValueError:
            return
        try:
            self._q.put_nowait(record)
        except queue.Full:
            self.dropped += 1

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                record = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            self._deliver(record)
        # Best-effort drain of anything still queued at shutdown.
        while True:
            try:
                self._deliver(self._q.get_nowait())
            except queue.Empty:
                break

    def _deliver(self, record: dict) -> None:
        delivered = False
        for emitter in self._emitters:
            try:
                emitter.emit(record)
                delivered = True
            except Exception:  # noqa: BLE001 - delivery is always best-effort
                self.failed += 1
        if delivered:
            self.sent += 1

    def stop(self, drain_timeout: float = 2.0) -> None:
        if self._worker is not None:
            self._stop.set()
            self._worker.join(timeout=drain_timeout)
            self._worker = None
        for emitter in self._emitters:
            try:
                emitter.close()
            except Exception:  # noqa: BLE001
                pass
