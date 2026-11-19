"""Base class for all protocol services."""
from __future__ import annotations

import asyncio
from typing import Optional

from ..core.context import Context


class Service:
    #: short protocol tag used in audit records
    protocol = "generic"

    def __init__(self, name: str, port: int, ctx: Context, label: str = "") -> None:
        self.name = name
        self.port = port
        self.ctx = ctx
        self.label = label
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        raise NotImplementedError

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    # connection admission --------------------------------------------------
    async def _serve(self, handler) -> None:
        """Start the TCP listener for ``handler`` with per-attacker admission
        control applied uniformly for every protocol.

        A protocol's ``start`` is just ``await self._serve(self._handle)``; the
        connection quotas and rate limiting in ``ResourceGovernor`` are enforced
        here, before the protocol handler (and the session) ever run.
        """
        async def _on_connect(reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> None:
            await self._guarded(reader, writer, handler)

        self._server = await asyncio.start_server(
            _on_connect, self.ctx.config.bind_address, self.port
        )
        self.audit.log("service.listening", service=self.name,
                       protocol=self.label or self.protocol, port=self.port,
                       severity="info")

    async def _guarded(self, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter, handler) -> None:
        ip, _port = self.peer(writer)
        gov = self.ctx.governor
        ok, reason = (True, "") if gov is None else gov.admit(ip, self.name)
        if not ok:
            self.audit.log("isolation.connection_rejected", severity="warning",
                           src_ip=ip, service=self.name,
                           protocol=self.label or self.protocol, reason=reason,
                           active_ip=gov.active_for(ip), active_total=gov.active_total)
            self._hard_close(writer)
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return
        try:
            await handler(reader, writer)
        finally:
            if gov is not None:
                gov.release(ip)

    @staticmethod
    def _hard_close(writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass

    # convenience accessors -------------------------------------------------
    @property
    def audit(self):
        return self.ctx.audit

    @property
    def sessions(self):
        return self.ctx.sessions

    @property
    def sim(self):
        return self.ctx.sim

    @property
    def quarantine(self):
        return self.ctx.quarantine

    @property
    def profile(self):
        return self.ctx.profile

    @staticmethod
    def peer(writer: asyncio.StreamWriter):
        info = writer.get_extra_info("peername") or ("?", 0)
        return info[0], info[1]
