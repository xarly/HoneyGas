"""Per-attacker session isolation.

Each distinct source IP gets its own Session per service. A session carries:

  * overlay  -- a writable copy-on-write layer over the shared, read-only
                process baseline. Modbus/HMI writes land here, so one
                attacker's tampering is NEVER visible to another attacker.
  * store    -- free-form per-service scratch state (e.g. HMI auth flag).
  * captured -- quarantine record ids produced by this session.

This gives logical isolation inside a single process. Two further bounds make
that isolation hold up under abuse (the in-process equivalent of a container's
memory/pids cgroup; see ``limits.py`` for the connection side):

  * ``overlay`` and ``store`` are ``BoundedDict``s, so one attacker cannot grow
    its own state without limit and pressure the shared process.
  * the number of live sessions is capped; when full, the least-recently-seen
    session is reclaimed (LRU), so a flood of source IPs cannot exhaust memory.

For hard, kernel-level isolation (one container/namespace per source), run
HoneyGas behind the compose stack in docker/ and front it with a per-source
dispatcher -- see the "Per-attacker isolation" section of the README.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from .limits import ResourceLimits


class BoundedDict(dict):
    """A dict that caps how many *distinct* keys it will hold.

    Updates to keys already present are always allowed; inserting a new key
    once ``max_entries`` is reached is dropped and counted in ``rejected``.
    ``max_entries == 0`` means unbounded. This bounds per-attacker memory
    growth transparently, so protocol code can keep writing ``d[k] = v`` with
    no awareness of the quota.
    """

    __slots__ = ("max_entries", "rejected")

    def __init__(self, max_entries: int = 0) -> None:
        super().__init__()
        self.max_entries = max_entries
        self.rejected = 0

    def _would_reject(self, key: Any) -> bool:
        return bool(self.max_entries) and key not in self and len(self) >= self.max_entries

    def __setitem__(self, key: Any, value: Any) -> None:
        if self._would_reject(key):
            self.rejected += 1
            return
        super().__setitem__(key, value)

    def setdefault(self, key: Any, default: Any = None) -> Any:
        if key not in self:
            if self._would_reject(key):
                self.rejected += 1
                return default
            super().__setitem__(key, default)
        return super().__getitem__(key)

    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        for k, v in dict(*args, **kwargs).items():
            self[k] = v


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
    def __init__(self, idle_timeout: int = 1800,
                 limits: Optional[ResourceLimits] = None,
                 audit: Optional[Any] = None) -> None:
        self.idle_timeout = idle_timeout
        self.limits = limits or ResourceLimits()
        self._audit = audit
        self._sessions: Dict[Tuple[str, str], Session] = {}
        self.evicted = 0

    def get(self, src_ip: str, service: str) -> Tuple[Session, bool]:
        """Return (session, is_new) for this source+service."""
        key = (src_ip, service)
        now = time.time()
        sess = self._sessions.get(key)
        is_new = False
        if sess is None:
            self._reclaim_if_full()
            sess = Session(
                session_id=uuid.uuid4().hex[:12],
                src_ip=src_ip,
                service=service,
                created=now,
                last_seen=now,
                overlay=BoundedDict(self.limits.max_overlay_entries),
                store=BoundedDict(self.limits.max_store_entries),
            )
            self._sessions[key] = sess
            is_new = True
        sess.touch()
        return sess, is_new

    def _reclaim_if_full(self) -> None:
        """Evict the least-recently-seen session when at the global cap, so a
        flood of distinct source IPs cannot exhaust process memory."""
        cap = self.limits.max_sessions
        if cap <= 0 or len(self._sessions) < cap:
            return
        victim_key = min(self._sessions, key=lambda k: self._sessions[k].last_seen)
        victim = self._sessions.pop(victim_key)
        self.evicted += 1
        if self._audit is not None:
            self._audit.log("isolation.session_evicted", severity="warning",
                            service="core", evicted_session=victim.session_id,
                            evicted_ip=victim.src_ip, evicted_service=victim.service,
                            cap=cap)

    def purge_idle(self) -> int:
        now = time.time()
        stale = [k for k, s in self._sessions.items()
                 if now - s.last_seen > self.idle_timeout]
        for k in stale:
            del self._sessions[k]
        return len(stale)

    def count(self) -> int:
        return len(self._sessions)
