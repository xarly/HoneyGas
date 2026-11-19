"""Per-attacker session isolation.

Each distinct source IP gets its own Session per service. A session carries:

  * overlay  -- a writable copy-on-write layer over the shared, read-only
                process baseline. Modbus/HMI writes land here, so one
                attacker's tampering is NEVER visible to another attacker.
  * store    -- free-form per-service scratch state (e.g. HMI auth flag).
  * captured -- quarantine record ids produced by this session.

This gives logical isolation inside a single process. For hard, kernel-level
isolation (one container/namespace per source), run HoneyGas behind the
compose stack in docker/ and front it with a per-source dispatcher.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple


@dataclass
class Session:
    session_id: str
    src_ip: str
    service: str
    created: float
    last_seen: float
    overlay: Dict[str, int] = field(default_factory=dict)   # "kind:addr" -> value
    store: Dict[str, Any] = field(default_factory=dict)     # service scratch
    captured: list = field(default_factory=list)            # quarantine ids
    events: int = 0

    def touch(self) -> None:
        self.last_seen = time.time()
        self.events += 1


class SessionManager:
    def __init__(self, idle_timeout: int = 1800) -> None:
        self.idle_timeout = idle_timeout
        self._sessions: Dict[Tuple[str, str], Session] = {}

    def get(self, src_ip: str, service: str) -> Tuple[Session, bool]:
        """Return (session, is_new) for this source+service."""
        key = (src_ip, service)
        now = time.time()
        sess = self._sessions.get(key)
        is_new = False
        if sess is None:
            sess = Session(
                session_id=uuid.uuid4().hex[:12],
                src_ip=src_ip,
                service=service,
                created=now,
                last_seen=now,
            )
            self._sessions[key] = sess
            is_new = True
        sess.touch()
        return sess, is_new

    def purge_idle(self) -> int:
        now = time.time()
        stale = [k for k, s in self._sessions.items()
                 if now - s.last_seen > self.idle_timeout]
        for k in stale:
            del self._sessions[k]
        return len(stale)

    def count(self) -> int:
        return len(self._sessions)
