"""Configuration loading for HoneyGas.

Loads the main YAML config plus the profile YAML selected by `mode`, and
exposes them as plain dataclasses. Paths inside the config are resolved
relative to the project root (the parent of the config directory).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .alerts import AlertConfig
from .limits import ResourceLimits


@dataclass
class Listener:
    name: str
    type: str
    port: int
    enabled: bool = True
    label: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class Config:
    mode: str
    site_name: str
    bind_address: str
    tick_seconds: float
    audit_file: Path
    log_level: str
    echo_stdout: bool
    quarantine_dir: Path
    max_capture_bytes: int
    enable_yara: bool
    yara_rules: Path
    session_idle_timeout: int
    limits: ResourceLimits
    alerts: AlertConfig
    listeners: list[Listener]
    base_dir: Path
    raw: dict = field(default_factory=dict)


def _resolve(base: Path, value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else (base / p)


def load_config(path: str | Path) -> Config:
    cfg_path = Path(path).resolve()
    # <root>/config/honeygas.yaml -> <root>
    base_dir = cfg_path.parent.parent

    with cfg_path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    sim = raw.get("simulation", {}) or {}
    log = raw.get("logging", {}) or {}
    quar = raw.get("quarantine", {}) or {}
    iso = raw.get("isolation", {}) or {}

    listeners: list[Listener] = []
    for item in raw.get("listeners", []) or []:
        known = {"name", "type", "port", "enabled", "label"}
        extra = {k: v for k, v in item.items() if k not in known}
        listeners.append(
            Listener(
                name=item["name"],
                type=item["type"],
                port=int(item["port"]),
                enabled=bool(item.get("enabled", True)),
                label=item.get("label", ""),
                extra=extra,
            )
        )

    return Config(
        mode=raw.get("mode", "transport"),
        site_name=raw.get("site_name", "HONEYGAS"),
        bind_address=raw.get("bind_address", "0.0.0.0"),
        tick_seconds=float(sim.get("tick_seconds", 2.0)),
        audit_file=_resolve(base_dir, log.get("audit_file", "data/audit/honeygas-audit.jsonl")),
        log_level=str(log.get("level", "INFO")).upper(),
        echo_stdout=bool(log.get("echo_stdout", True)),
        quarantine_dir=_resolve(base_dir, quar.get("dir", "data/quarantine")),
        max_capture_bytes=int(quar.get("max_capture_bytes", 10 * 1024 * 1024)),
        enable_yara=bool(quar.get("enable_yara", False)),
        yara_rules=_resolve(base_dir, quar.get("yara_rules", "config/rules.yar")),
        session_idle_timeout=int(iso.get("session_idle_timeout_seconds", 1800)),
        limits=ResourceLimits.from_dict(iso.get("limits", {})),
        alerts=AlertConfig.from_dict(raw.get("alerts", {})),
        listeners=listeners,
        base_dir=base_dir,
        raw=raw,
    )


def load_profile_dict(base_dir: Path, mode: str) -> dict:
    """Load the raw profile dict for the given mode from config/profile_<mode>.yaml."""
    profile_path = base_dir / "config" / f"profile_{mode}.yaml"
    if not profile_path.exists():
        raise FileNotFoundError(f"Profile for mode '{mode}' not found: {profile_path}")
    with profile_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}
