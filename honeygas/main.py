"""HoneyGas orchestrator / entrypoint.

Loads config + the mode profile, builds the shared runtime context, starts the
enabled protocol services and the process-simulation loop, and runs until
interrupted.

Usage:
    python -m honeygas --config config/honeygas.yaml
    python -m honeygas --mode biomethane      # override the config's mode
"""
from __future__ import annotations

import argparse
import asyncio
import signal
import sys

from .core.alerts import AlertDispatcher
from .core.audit import AuditLogger
from .core.config import load_config, load_profile_dict
from .core.context import Context
from .core.limits import ResourceGovernor
from .core.quarantine import Quarantine
from .core.sessions import SessionManager
from .protocols.atg import AtgVeederService
from .protocols.dnp3 import Dnp3Service
from .protocols.http_hmi import HttpHmiService
from .protocols.iec104 import Iec104Service
from .protocols.modbus import ModbusService
from .protocols.opcua import OpcuaService
from .protocols.s7comm import S7CommService
from .protocols.tcp_capture import TcpCaptureService
from .sim.process import build_simulator
from .sim.profiles import load_profile

SERVICE_TYPES = {
    "modbus": ModbusService,
    "http_hmi": HttpHmiService,
    "atg_veeder": AtgVeederService,
    "s7comm": S7CommService,
    "iec104": Iec104Service,
    "dnp3": Dnp3Service,
    "opcua": OpcuaService,
    "tcp_capture": TcpCaptureService,
}


def build_context(config_path: str, mode_override: str | None) -> Context:
    config = load_config(config_path)
    if mode_override:
        config.mode = mode_override

    profile = load_profile(load_profile_dict(config.base_dir, config.mode))

    alerts = AlertDispatcher(config.alerts, site=config.site_name)
    alerts.start()
    audit = AuditLogger(
        audit_file=config.audit_file,
        site=config.site_name,
        echo_stdout=config.echo_stdout,
        level=config.log_level,
        sink=alerts,
    )
    if alerts.enabled:
        audit.log("alert.sink_started", severity="info", service="core",
                  sinks=alerts.sinks, min_severity=config.alerts.min_severity)
    quarantine = Quarantine(
        directory=config.quarantine_dir,
        max_bytes=config.max_capture_bytes,
        audit=audit,
        enable_yara=config.enable_yara,
        yara_rules=config.yara_rules,
    )
    governor = ResourceGovernor(config.limits)
    sessions = SessionManager(
        idle_timeout=config.session_idle_timeout,
        limits=config.limits,
        audit=audit,
    )
    sim = build_simulator(profile, tick_seconds=config.tick_seconds)

    return Context(
        config=config,
        audit=audit,
        sessions=sessions,
        quarantine=quarantine,
        sim=sim,
        profile=profile,
        governor=governor,
        alerts=alerts,
    )


def build_services(ctx: Context) -> list:
    services = []
    for lst in ctx.config.listeners:
        if not lst.enabled:
            continue
        cls = SERVICE_TYPES.get(lst.type)
        if cls is None:
            ctx.audit.log("service.unknown_type", severity="warning",
                          service=lst.name, type=lst.type)
            continue
        services.append(cls(name=lst.name, port=lst.port, ctx=ctx, label=lst.label))
    return services


async def _sim_loop(ctx: Context, stop: asyncio.Event) -> None:
    interval = max(ctx.config.tick_seconds, 0.2)
    while not stop.is_set():
        ctx.sim.tick()
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def _purge_loop(ctx: Context, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=60.0)
        except asyncio.TimeoutError:
            removed = ctx.sessions.purge_idle()
            windows = ctx.governor.purge_rate_windows()
            if removed or windows:
                ctx.audit.log("sessions.purged", severity="debug",
                              service="core", count=removed, rate_windows=windows)


async def run(ctx: Context) -> None:
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in ("SIGINT", "SIGTERM"):
        if hasattr(signal, sig):
            try:
                loop.add_signal_handler(getattr(signal, sig), stop.set)
            except (NotImplementedError, RuntimeError):
                pass  # Windows: fall back to KeyboardInterrupt

    services = build_services(ctx)
    ctx.audit.log(
        "honeygas.start", severity="notice", service="core",
        mode=ctx.profile.mode, profile=ctx.profile.name, site=ctx.config.site_name,
        services=[s.name for s in services],
    )

    started = []
    for svc in services:
        try:
            await svc.start()
            started.append(svc)
        except OSError as exc:
            ctx.audit.log("service.bind_failed", severity="warning",
                          service=svc.name, port=svc.port, error=str(exc))

    tasks = [
        asyncio.create_task(_sim_loop(ctx, stop)),
        asyncio.create_task(_purge_loop(ctx, stop)),
    ]
    try:
        await stop.wait()
    except KeyboardInterrupt:
        stop.set()
    finally:
        for t in tasks:
            t.cancel()
        for svc in started:
            await svc.stop()
        ctx.audit.log("honeygas.stop", severity="notice", service="core")
        ctx.alerts.stop()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="honeygas", description="Defensive ICS/OT honeypot")
    parser.add_argument("--config", default="config/honeygas.yaml", help="path to main config")
    parser.add_argument("--mode", choices=["transport", "biomethane"],
                        help="override the operating mode in the config")
    args = parser.parse_args(argv)

    ctx = build_context(args.config, args.mode)
    try:
        asyncio.run(run(ctx))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
