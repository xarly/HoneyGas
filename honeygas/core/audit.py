"""Structured audit logging.

Every meaningful interaction with the honeypot becomes one JSON object written
as a line to the audit file (JSONL), suitable for ingestion by a SIEM. A short
human-readable line is optionally echoed to stdout.

The audit log is append-only and never contains data the honeypot executed --
it records what was *observed*.
"""
from __future__ import annotations

import json
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Severity ranking used for the stdout echo and for downstream filtering.
SEVERITIES = ("debug", "info", "notice", "warning", "high", "critical")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class AuditLogger:
    def __init__(
        self,
        audit_file: Path,
        site: str,
        echo_stdout: bool = True,
        level: str = "INFO",
    ) -> None:
        self.audit_file = Path(audit_file)
        self.site = site
        self.echo_stdout = echo_stdout
        self.min_level = level.lower()
        self._lock = threading.Lock()
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)
        # Touch the file so operators see it exists immediately.
        self.audit_file.touch(exist_ok=True)

    def _passes(self, severity: str) -> bool:
        try:
            return SEVERITIES.index(severity) >= SEVERITIES.index(self.min_level)
        except ValueError:
            return True

    def log(
        self,
        event: str,
        *,
        severity: str = "info",
        session: Optional[str] = None,
        src_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        service: Optional[str] = None,
        protocol: Optional[str] = None,
        **data: Any,
    ) -> dict:
        record = {
            "ts": _now_iso(),
            "event_id": uuid.uuid4().hex,
            "event": event,
            "severity": severity,
            "site": self.site,
            "session": session,
            "src_ip": src_ip,
            "src_port": src_port,
            "service": service,
            "protocol": protocol,
            "data": data,
        }
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            with self.audit_file.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            if self.echo_stdout and self._passes(severity):
                tag = severity.upper().ljust(8)
                src = f"{src_ip}:{src_port}" if src_ip else "-"
                summary = self._summarize(data)
                sys.stdout.write(
                    f"[{record['ts']}] {tag} {service or '-':10s} {src:21s} {event} {summary}\n"
                )
                sys.stdout.flush()
        return record

    @staticmethod
    def _summarize(data: dict) -> str:
        if not data:
            return ""
        keys = ("function", "address", "path", "method", "username", "cmd",
                "filename", "sha256", "bytes", "quantity", "values", "label")
        parts = [f"{k}={data[k]}" for k in keys if k in data]
        return " ".join(parts)
