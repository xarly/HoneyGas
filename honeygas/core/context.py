"""Shared runtime context handed to every protocol service."""
from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditLogger
from .config import Config
from .quarantine import Quarantine
from .sessions import SessionManager


@dataclass
class Context:
    config: Config
    audit: AuditLogger
    sessions: SessionManager
    quarantine: Quarantine
    sim: "object"      # honeygas.sim.process.ProcessSimulator
    profile: "object"  # honeygas.sim.profiles.Profile
