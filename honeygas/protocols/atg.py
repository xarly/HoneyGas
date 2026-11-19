"""Veeder-Root style Automatic Tank Gauge (ATG) emulator.

Serial-over-TCP tank gauges (typically TCP/10001) are a classic, widely-scanned
exposure in fuel/gas distribution. Clients send a command framed with a leading
Ctrl-A (0x01) followed by a function code such as ``I20100`` (in-tank inventory
report). This emulator answers the common report commands with plausible tank
data from the profile and inventories any unrecognised command as evidence.

Inspired by the behaviour of the well-known GasPot research honeypot.
"""
from __future__ import annotations

import asyncio
from datetime import datetime

from .base import Service

SOH = 0x01  # Ctrl-A start of command
ETX = b"\x03"


class AtgVeederService(Service):
    protocol = "atg-veeder"

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self.ctx.config.bind_address, self.port
        )
        self.audit.log("service.listening", service=self.name, protocol=self.protocol,
                       port=self.port, severity="info")

    async def _handle(self, reader, writer) -> None:
        ip, port = self.peer(writer)
        sess, is_new = self.sessions.get(ip, self.name)
        if is_new:
            self.audit.log("atg.connect", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        try:
            while True:
                data = await reader.read(512)
                if not data:
                    break
                resp = self._respond(sess, ip, port, data)
                if resp:
                    writer.write(resp)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    def _respond(self, sess, ip, port, data: bytes) -> bytes:
        text = data.decode("latin1", "replace").strip()
        cmd = text[1:] if data and data[0] == SOH else text
        code = cmd[:6].upper()

        self.audit.log("atg.command", severity="notice", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                       cmd=code, raw=text[:120])

        if self.profile.atg is None:
            # No tank model in this mode: log/capture and return a terse error.
            if len(data) > 32:
                self.quarantine.capture_binary(data, session=sess, service=self.name,
                                                src_ip=ip, meta={"via": "atg.raw"})
            return b"9999FF1B\n"

        if code.startswith("I201"):      # In-Tank Inventory
            return self._inventory_report()
        if code.startswith("I202"):      # Delivery report
            return self._simple_report("DELIVERY REPORT", "NO DELIVERIES")
        if code.startswith("I203"):      # In-Tank Leak Detect
            return self._simple_report("IN-TANK LEAK DETECT", "TEST PASS")
        if code.startswith("I205"):      # Shift report
            return self._simple_report("SHIFT REPORT", "NO SHIFT DATA")

        # Unknown command -> capture as evidence, return ATG-style error code.
        self.quarantine.capture_call(text, session=sess, service=self.name, src_ip=ip,
                                     meta={"via": "atg.unknown_cmd"})
        return b"9999FF1B\n"

    def _header(self, title: str) -> str:
        now = datetime.now().strftime("%b %d, %Y %I:%M %p")
        atg = self.profile.atg
        return f"\x01\n{now}\n\n{atg.station}\n\n{title}\n"

    def _inventory_report(self) -> bytes:
        atg = self.profile.atg
        lines = [self._header("I20100 IN-TANK INVENTORY"),
                 "TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER   TEMP\n"]
        for t in atg.tanks:
            lines.append(
                f"{t.num:>3}  {t.product:<18} {t.volume:>8.0f} {t.tc_volume:>9.0f} "
                f"{t.ullage:>8.0f} {t.height:>8.2f} {t.water:>8.2f} {t.temp:>6.2f}\n"
            )
        return ("".join(lines) + "\n").encode("latin1") + ETX

    def _simple_report(self, title: str, note: str) -> bytes:
        return (self._header(title) + "\n" + note + "\n\n").encode("latin1") + ETX
