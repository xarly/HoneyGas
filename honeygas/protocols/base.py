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
