"""Generic TCP capture service for protocols we fingerprint but don't fully
emulate yet (e.g. DNP3 on 20000). Modbus, S7comm and IEC-104 have dedicated
full-emulation services; this is the fallback pattern for the rest.

Goals:
  * Keep the port open and answer the initial handshake just enough that a
    scanner marks the service as "up" and keeps talking.
  * Log every connection and every chunk of bytes received.
  * Capture sizeable payloads to quarantine (inventory of injected data).

This gives useful coverage and evidence collection for these protocols without
claiming a fidelity the emulator doesn't have. Each can later be promoted to a
dedicated module like modbus.py.
"""
from __future__ import annotations

import asyncio

from .base import Service

# Minimal, believable handshake replies keyed by well-known port.
#  * 102   : COTP Connection Confirm (reply to a Connection Request TPDU)
#  * 2404  : IEC-104 STARTDT confirmation (reply to STARTDT act)
COTP_CC = bytes.fromhex("0300001611d00001000200c0010ac1020102c2020103")
IEC104_STARTDT_CON = bytes.fromhex("68040b000000")


class TcpCaptureService(Service):
    protocol = "tcp"

    async def start(self) -> None:
        await self._serve(self._handle)

    async def _handle(self, reader, writer) -> None:
        ip, port = self.peer(writer)
        sess, is_new = self.sessions.get(ip, self.name)
        label = self.label or self.name
        if is_new:
            self.audit.log("tcp.connect", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=label)
        total = 0
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                total += len(data)
                self.audit.log("tcp.data", severity="info", session=sess.session_id,
                               src_ip=ip, src_port=port, service=self.name, protocol=label,
                               bytes=len(data), head=data[:48].hex())

                # Inventory non-trivial payloads as evidence.
                if len(data) >= 64:
                    self.quarantine.capture_binary(
                        data, session=sess, service=self.name, src_ip=ip,
                        meta={"via": f"{self.name}.raw", "protocol": label},
                    )

                reply = self._handshake_reply(data)
                if reply:
                    writer.write(reply)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self.audit.log("tcp.close", severity="info", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=label,
                           bytes=total)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    def _handshake_reply(self, data: bytes) -> bytes:
        if self.port == 102 and len(data) >= 6 and data[0] == 0x03:
            # TPKT/COTP Connection Request -> Connection Confirm
            if len(data) > 5 and data[5] == 0xE0:
                return COTP_CC
        if self.port == 2404 and data[:2] == b"\x68\x04":
            # IEC-104 U-format STARTDT act (0x68 04 07 00 00 00) -> con
            if len(data) >= 3 and data[2] & 0x07:
                return IEC104_STARTDT_CON
        return b""
