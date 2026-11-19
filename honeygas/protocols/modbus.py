"""Modbus/TCP server emulator.

Implements enough of Modbus/TCP to look like a real PLC/RTU to scanners and
Modbus clients (pymodbus, modpoll, Metasploit modbus modules, etc.):

  FC1  read coils            FC2  read discrete inputs
  FC3  read holding regs     FC4  read input regs
  FC5  write single coil     FC6  write single register
  FC15 write multiple coils  FC16 write multiple registers
  FC43/14 read device identification (returns the vulnerable-looking banner)

Register values come from the live process simulator (scaled to u16). WRITES
never touch the shared baseline -- they are stored in the attacker's own
session overlay, so each attacker sees only their own tampering. Every write
is audited at high severity (control-tampering is the event defenders care
about) and out-of-range probes are logged too.
"""
from __future__ import annotations

import asyncio
import struct

from .base import Service

# Modbus exception codes
EXC_ILLEGAL_FUNCTION = 0x01
EXC_ILLEGAL_ADDRESS = 0x02
EXC_ILLEGAL_VALUE = 0x03

_WRITABLE = {"coils", "holding_registers"}


class ModbusService(Service):
    protocol = "modbus"

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self.ctx.config.bind_address, self.port
        )
        self.audit.log("service.listening", service=self.name, protocol=self.protocol,
                       port=self.port, severity="info")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip, port = self.peer(writer)
        sess, is_new = self.sessions.get(ip, self.name)
        if is_new:
            self.audit.log("modbus.connect", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        try:
            while True:
                header = await reader.readexactly(7)
                tid, pid, length, unit = struct.unpack(">HHHB", header)
                pdu = await reader.readexactly(max(length - 1, 0))
                if not pdu:
                    break
                resp = self._dispatch(sess, ip, port, unit, pdu)
                out = struct.pack(">HHHB", tid, 0, len(resp) + 1, unit) + resp
                writer.write(out)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as exc:  # noqa: BLE001
            self.audit.log("modbus.error", severity="warning", session=sess.session_id,
                           src_ip=ip, service=self.name, error=str(exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ logic
    def _dispatch(self, sess, ip, port, unit, pdu: bytes) -> bytes:
        func = pdu[0]
        try:
            if func in (1, 2):
                return self._read_bits(sess, ip, port, func, pdu)
            if func in (3, 4):
                return self._read_regs(sess, ip, port, func, pdu)
            if func == 5:
                return self._write_single_coil(sess, ip, port, pdu)
            if func == 6:
                return self._write_single_reg(sess, ip, port, pdu)
            if func == 15:
                return self._write_multi_coils(sess, ip, port, pdu)
            if func == 16:
                return self._write_multi_regs(sess, ip, port, pdu)
            if func == 43:
                return self._read_device_id(sess, ip, port, pdu)
        except struct.error:
            return self._exc(func, EXC_ILLEGAL_VALUE)
        self.audit.log("modbus.unsupported", severity="notice", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, function=func,
                       raw=pdu.hex())
        return self._exc(func, EXC_ILLEGAL_FUNCTION)

    @staticmethod
    def _exc(func: int, code: int) -> bytes:
        return struct.pack(">BB", func | 0x80, code)

    def _kind_for(self, func: int) -> str:
        return {1: "coils", 2: "discrete_inputs", 3: "holding_registers",
                4: "input_registers"}[func]

    def _reg_value(self, sess, kind: str, addr: int) -> int:
        okey = f"{kind}:{addr}"
        if kind in _WRITABLE and okey in sess.overlay:
            return sess.overlay[okey]
        mp = getattr(self.profile.modbus, kind)
        entry = mp.get(addr)
        if entry is None:
            return 0
        if entry.static is not None:
            val = int(entry.static)
        elif entry.tag:
            val = int(round(self.sim.read(entry.tag) * entry.scale))
        else:
            val = 0
        if kind in ("coils", "discrete_inputs"):
            return 1 if val else 0
        return max(0, min(0xFFFF, val))

    def _read_bits(self, sess, ip, port, func, pdu) -> bytes:
        _, addr, qty = struct.unpack(">BHH", pdu[:5])
        if not 1 <= qty <= 2000:
            return self._exc(func, EXC_ILLEGAL_VALUE)
        kind = self._kind_for(func)
        bits = [self._reg_value(sess, kind, addr + i) for i in range(qty)]
        nbytes = (qty + 7) // 8
        buf = bytearray(nbytes)
        for i, b in enumerate(bits):
            if b:
                buf[i // 8] |= 1 << (i % 8)
        self.audit.log("modbus.read", severity="info", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, function=func,
                       address=addr, quantity=qty)
        return struct.pack(">BB", func, nbytes) + bytes(buf)

    def _read_regs(self, sess, ip, port, func, pdu) -> bytes:
        _, addr, qty = struct.unpack(">BHH", pdu[:5])
        if not 1 <= qty <= 125:
            return self._exc(func, EXC_ILLEGAL_VALUE)
        kind = self._kind_for(func)
        vals = [self._reg_value(sess, kind, addr + i) for i in range(qty)]
        self.audit.log("modbus.read", severity="info", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, function=func,
                       address=addr, quantity=qty)
        body = b"".join(struct.pack(">H", v) for v in vals)
        return struct.pack(">BB", func, len(body)) + body

    def _write_single_coil(self, sess, ip, port, pdu) -> bytes:
        _, addr, value = struct.unpack(">BHH", pdu[:5])
        on = 1 if value == 0xFF00 else 0
        sess.overlay[f"coils:{addr}"] = on
        self._audit_write(sess, ip, port, 5, addr, [on])
        return pdu[:5]

    def _write_single_reg(self, sess, ip, port, pdu) -> bytes:
        _, addr, value = struct.unpack(">BHH", pdu[:5])
        sess.overlay[f"holding_registers:{addr}"] = value
        self._audit_write(sess, ip, port, 6, addr, [value])
        return pdu[:5]

    def _write_multi_coils(self, sess, ip, port, pdu) -> bytes:
        _, addr, qty, nbytes = struct.unpack(">BHHB", pdu[:6])
        data = pdu[6:6 + nbytes]
        vals = []
        for i in range(qty):
            bit = (data[i // 8] >> (i % 8)) & 1 if i // 8 < len(data) else 0
            sess.overlay[f"coils:{addr + i}"] = bit
            vals.append(bit)
        self._audit_write(sess, ip, port, 15, addr, vals)
        return struct.pack(">BHH", 15, addr, qty)

    def _write_multi_regs(self, sess, ip, port, pdu) -> bytes:
        _, addr, qty, nbytes = struct.unpack(">BHHB", pdu[:6])
        data = pdu[6:6 + nbytes]
        vals = []
        for i in range(qty):
            (v,) = struct.unpack_from(">H", data, i * 2)
            sess.overlay[f"holding_registers:{addr + i}"] = v
            vals.append(v)
        self._audit_write(sess, ip, port, 16, addr, vals)
        return struct.pack(">BHH", 16, addr, qty)

    def _audit_write(self, sess, ip, port, func, addr, values) -> None:
        # Flag writes against named control points (ESD, valves, setpoints).
        label = self._label_for(func, addr)
        self.audit.log(
            "modbus.write",
            severity="high",
            session=sess.session_id,
            src_ip=ip,
            src_port=port,
            service=self.name,
            protocol=self.protocol,
            function=func,
            address=addr,
            values=values[:16],
            label=label,
            note="control-point write isolated to this attacker's session overlay",
        )

    def _label_for(self, func: int, addr: int) -> str:
        kind = "coils" if func in (5, 15) else "holding_registers"
        entry = getattr(self.profile.modbus, kind).get(addr)
        return entry.label if entry else ""

    def _read_device_id(self, sess, ip, port, pdu) -> bytes:
        # FC43 / MEI type 14: respond with vendor/product/version objects.
        v = self.profile.vendor
        objects = {
            0: v.manufacturer.encode(),
            1: v.product.encode(),
            2: v.firmware.encode(),
        }
        self.audit.log("modbus.read_device_id", severity="notice", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name)
        body = bytearray(struct.pack(">BBBBBB", 43, 14, 0x01, 0x81, 0x00, len(objects)))
        for oid, val in objects.items():
            body += struct.pack(">BB", oid, len(val)) + val
        return bytes(body)
