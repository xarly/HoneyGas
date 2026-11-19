"""Per-attacker resource isolation (the in-process equivalent of cgroups).

Application-level session isolation (see ``sessions.py``) keeps one attacker's
*writes* out of another's *view*. It does nothing, though, to stop a single
source from exhausting the shared resources of the single honeypot process --
opening thousands of connections, flooding new connections, or growing its
session state without bound -- and thereby degrading our ability to observe
*other* attackers.

``ResourceGovernor`` bounds what one source IP may consume, the way a
per-container cgroup/pids limit would:

  * a cap on concurrent connections per source IP,
  * a global cap on concurrent connections across all sources,
  * a sliding-window cap on *new* connections per source IP per minute.

The session store adds the memory dimension (bounded overlay/store and an
LRU-reclaimed session cap); see ``sessions.py``.

Nothing here changes what the honeypot *says* to an attacker -- it only refuses
to let one source starve the rest. Rejections are audited so the quota itself
becomes a signal.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Tuple


@dataclass
class ResourceLimits:
    """Per-attacker / global resource ceilings. A value of 0 means unlimited.

    Defaults are deliberately generous: a honeypot wants to keep engaging real
    attackers (and the bursty scanners that precede them), so the ceilings are
    set to blunt abuse, not to trip on ordinary reconnaissance.
    """

    max_connections_per_ip: int = 32
    max_total_connections: int = 512
    connection_rate_per_minute: int = 240   # new connections / minute / source IP
    max_sessions: int = 8192                # global session cap (LRU-reclaimed)
    max_overlay_entries: int = 4096         # writable points held per session
    max_store_entries: int = 256            # scratch keys held per session

    @classmethod
    def from_dict(cls, d: dict | None) -> "ResourceLimits":
        d = d or {}
        base = cls()

        def _int(key: str, default: int) -> int:
            try:
                return max(0, int(d.get(key, default)))
            except (TypeError, ValueError):
                return default

        return cls(
            max_connections_per_ip=_int("max_connections_per_ip", base.max_connections_per_ip),
            max_total_connections=_int("max_total_connections", base.max_total_connections),
            connection_rate_per_minute=_int("connection_rate_per_minute",
                                            base.connection_rate_per_minute),
            max_sessions=_int("max_sessions", base.max_sessions),
            max_overlay_entries=_int("max_overlay_entries", base.max_overlay_entries),
            max_store_entries=_int("max_store_entries", base.max_store_entries),
        )


class ResourceGovernor:
    """Admission control for incoming connections, enforced uniformly for every
    protocol in ``Service._guarded``."""

    def __init__(self, limits: ResourceLimits | None = None) -> None:
        self.limits = limits or ResourceLimits()
        self._active_ip: Dict[str, int] = defaultdict(int)
        self._active_total = 0
        self._recent: Dict[str, Deque[float]] = defaultdict(deque)
        self.rejected = 0

    @property
    def active_total(self) -> int:
        return self._active_total

    def active_for(self, ip: str) -> int:
        return self._active_ip.get(ip, 0)

    def admit(self, ip: str, service: str) -> Tuple[bool, str]:
        """Try to admit one connection from ``ip``.

        Returns ``(True, "")`` and reserves a slot, or ``(False, reason)`` and
        reserves nothing. ``release(ip)`` must be called for every admission.
        """
        lim = self.limits
        now = time.monotonic()

        window: Deque[float] | None = None
        if lim.connection_rate_per_minute > 0:
            window = self._recent[ip]
            cutoff = now - 60.0
            while window and window[0] < cutoff:
                window.popleft()
            if len(window) >= lim.connection_rate_per_minute:
                self.rejected += 1
                return False, "rate_per_minute"

        if lim.max_total_connections > 0 and self._active_total >= lim.max_total_connections:
            self.rejected += 1
            return False, "max_total_connections"
        if lim.max_connections_per_ip > 0 and self._active_ip[ip] >= lim.max_connections_per_ip:
            self.rejected += 1
            return False, "max_connections_per_ip"

        if window is not None:
            window.append(now)
        self._active_ip[ip] += 1
        self._active_total += 1
        return True, ""

    def release(self, ip: str) -> None:
        if self._active_ip.get(ip, 0) > 0:
            self._active_ip[ip] -= 1
            if self._active_ip[ip] == 0:
                del self._active_ip[ip]
        if self._active_total > 0:
            self._active_total -= 1

    def purge_rate_windows(self) -> int:
        """Drop expired/empty per-IP rate windows so idle sources don't leak
        memory. Returns the number of source entries removed."""
        cutoff = time.monotonic() - 60.0
        drop = []
        for ip, window in self._recent.items():
            while window and window[0] < cutoff:
                window.popleft()
            if not window:
                drop.append(ip)
        for ip in drop:
            del self._recent[ip]
        return len(drop)

    def snapshot(self) -> dict:
        return {
            "active_total": self._active_total,
            "active_ips": len(self._active_ip),
            "rejected": self.rejected,
        }
