"""Capture and inventory of attacker-supplied artifacts.

This module is the heart of the "inventariar el binario o llamada ejecutada"
requirement. It handles two kinds of artifact:

  * binary  -- a payload/file an attacker uploads or injects (e.g. a fake
               "firmware image", a dropped ELF/PE, an exploit payload).
  * call    -- a command string / RPC an attacker tries to get executed
               (e.g. an injected shell command).

SAFETY CONTRACT
---------------
Captured artifacts are hashed, type-tagged, written to the quarantine store
and recorded in an inventory index. They are **never executed** and are stored
without any execute permission and with a neutralizing extension. Detonation
of samples, if ever desired, is an explicitly separate, out-of-band activity
for a dedicated isolated sandbox -- HoneyGas does not perform it.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Optional YARA support (guarded so the honeypot runs without it).
try:  # pragma: no cover - optional dependency
    import yara  # type: ignore
except Exception:  # noqa: BLE001
    yara = None


_MAGIC = [
    (b"\x7fELF", "elf"),
    (b"MZ", "pe/dos"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    (b"\xcf\xfa\xed\xfe", "macho64"),
    (b"PK\x03\x04", "zip/jar/office"),
    (b"\x1f\x8b", "gzip"),
    (b"%PDF", "pdf"),
    (b"#!", "script-shebang"),
    (b"\x50\x4b\x05\x06", "zip-empty"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ", "xz"),
]


def _detect_type(data: bytes) -> str:
    head = data[:16]
    for sig, name in _MAGIC:
        if head.startswith(sig):
            return name
    # Heuristic: mostly-printable -> text/script.
    sample = data[:512]
    if sample and sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) / len(sample) > 0.9:
        return "text"
    return "binary/unknown"


@dataclass
class CaptureRecord:
    capture_id: str
    ts: str
    kind: str                 # "binary" | "call"
    service: str
    session: str
    src_ip: Optional[str]
    size: int
    truncated: bool
    md5: str
    sha1: str
    sha256: str
    file_type: str
    stored_path: Optional[str]
    yara_matches: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)


class Quarantine:
    def __init__(
        self,
        directory: Path,
        max_bytes: int,
        audit,
        enable_yara: bool = False,
        yara_rules: Optional[Path] = None,
    ) -> None:
        self.dir = Path(directory)
        self.max_bytes = int(max_bytes)
        self.audit = audit
        self._lock = threading.Lock()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.dir / "inventory.jsonl"
        self.index_path.touch(exist_ok=True)

        self._rules = None
        if enable_yara and yara is not None and yara_rules and Path(yara_rules).exists():
            try:
                self._rules = yara.compile(filepath=str(yara_rules))
            except Exception as exc:  # noqa: BLE001
                self.audit.log("quarantine.yara_load_failed", severity="warning",
                               service="quarantine", error=str(exc))

    # ------------------------------------------------------------------ binary
    def capture_binary(
        self,
        data: bytes,
        *,
        session,
        service: str,
        src_ip: Optional[str] = None,
        meta: Optional[dict] = None,
    ) -> CaptureRecord:
        truncated = False
        if len(data) > self.max_bytes:
            data = data[: self.max_bytes]
            truncated = True

        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        ftype = _detect_type(data)

        # Store under the sha256, de-duplicating identical payloads. The
        # ".quarantine" extension + 0o400 perms ensure the OS will not treat
        # it as runnable.
        stored = self.dir / f"{sha256}.quarantine"
        with self._lock:
            if not stored.exists():
                stored.write_bytes(data)
                try:
                    os.chmod(stored, 0o400)
                except OSError:
                    pass  # best-effort on Windows

        matches: list[str] = []
        if self._rules is not None:
            try:
                matches = [m.rule for m in self._rules.match(data=data)]
            except Exception:  # noqa: BLE001
                matches = []

        rec = CaptureRecord(
            capture_id=sha256[:16] + "-" + hex(int(time.time()))[2:],
            ts=datetime.now(timezone.utc).isoformat(),
            kind="binary",
            service=service,
            session=getattr(session, "session_id", "-"),
            src_ip=src_ip,
            size=len(data),
            truncated=truncated,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            file_type=ftype,
            stored_path=str(stored),
            yara_matches=matches,
            meta=meta or {},
        )
        self._record(rec, session)
        self.audit.log(
            "capture.binary",
            severity="critical",
            session=rec.session,
            src_ip=src_ip,
            service=service,
            sha256=sha256,
            bytes=rec.size,
            file_type=ftype,
            yara=matches,
            filename=(meta or {}).get("filename"),
        )
        return rec

    # -------------------------------------------------------------------- call
    def capture_call(
        self,
        command: str,
        *,
        session,
        service: str,
        src_ip: Optional[str] = None,
        meta: Optional[dict] = None,
    ) -> CaptureRecord:
        """Inventory an injected command / RPC the attacker tried to execute.

        The command is recorded verbatim as evidence. It is NOT run.
        """
        data = command.encode("utf-8", errors="replace")
        sha256 = hashlib.sha256(data).hexdigest()
        rec = CaptureRecord(
            capture_id=sha256[:16] + "-" + hex(int(time.time()))[2:],
            ts=datetime.now(timezone.utc).isoformat(),
            kind="call",
            service=service,
            session=getattr(session, "session_id", "-"),
            src_ip=src_ip,
            size=len(data),
            truncated=False,
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=sha256,
            file_type="command",
            stored_path=None,
            yara_matches=[],
            meta={**(meta or {}), "command": command},
        )
        self._record(rec, session)
        self.audit.log(
            "capture.call",
            severity="critical",
            session=rec.session,
            src_ip=src_ip,
            service=service,
            cmd=command[:300],
            sha256=sha256,
        )
        return rec

    # ----------------------------------------------------------------- helpers
    def _record(self, rec: CaptureRecord, session) -> None:
        with self._lock:
            with self.index_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")
        try:
            session.captured.append(rec.capture_id)
        except AttributeError:
            pass
