"""Lightweight process/"digital-twin" simulator.

Advances each simulated tag over time so that passive observers and polling
attackers see plausible, continuously-changing process data. This drives both
the Modbus register values and the HMI dashboard, and makes the honeypot's
traffic look like a real, live installation rather than static values.
"""
from __future__ import annotations

import math
import random
import time
from typing import Dict, List

from .profiles import TagSpec


class ProcessSimulator:
    def __init__(self, tags: List[TagSpec], tick_seconds: float = 2.0) -> None:
        self.tick_seconds = tick_seconds
        self._start = time.time()
        self._tags: Dict[str, TagSpec] = {t.name: t for t in tags}
        self._values: Dict[str, float] = {t.name: t.base for t in tags}

    def read(self, name: str) -> float:
        return self._values.get(name, 0.0)

    def unit(self, name: str) -> str:
        t = self._tags.get(name)
        return t.unit if t else ""

    def snapshot(self) -> Dict[str, float]:
        return dict(self._values)

    def tick(self) -> None:
        elapsed = time.time() - self._start
        for name, t in self._tags.items():
            if t.kind == "sine":
                v = (
                    t.base
                    + t.amp * math.sin(2 * math.pi * elapsed / max(t.period, 1.0))
                    + random.gauss(0.0, t.noise)
                )
            elif t.kind == "counter":
                v = self._values[name] + t.rate * self.tick_seconds
                if t.max and v > t.max:
                    v -= t.max
            elif t.kind == "setpoint":
                v = self._values[name] + random.gauss(0.0, max(t.noise, 0.0))
            else:
                v = t.base
            self._values[name] = min(max(v, t.min), t.max)


def build_simulator(profile, tick_seconds: float = 2.0) -> ProcessSimulator:
    return ProcessSimulator(profile.tags, tick_seconds=tick_seconds)
