"""IEC 60870-5-104 (IEC-104) server emulator.

Full emulation of the telecontrol protocol spoken between a SCADA master and an
RTU/substation gateway over TCP/2404. This is the control-plane protocol of
choice in European gas/electricity SCADA, so a believable 104 outstation is a
strong lure.

    APCI (0x68 | len | 4 control octets)  ->  ASDU (type, VSQ, COT, CA, objects)

Handled interactions (what a real master / scanner actually sends):

  * U-format STARTDT / STOPDT / TESTFR  -> the matching *_con, and data transfer
                                           is enabled after STARTDT.
  * I-format General Interrogation       -> actcon, then the current value of
    (C_IC_NA_1, type 100)                   every monitored point (measured
                                            short floats + single points) with
                                            COT=20, then actterm. Values come
                                            from the live process simulator.
  * Clock synchronisation (C_CS_NA_1)    -> actcon.
  * Counter interrogation (C_CI_NA_1)    -> actcon + actterm.
  * Control commands (C_SC/C_DC/C_SE...) -> audited at HIGH severity, inventoried
                                            as evidence (capture_call), applied
                                            ONLY to the attacker's isolated
                                            session view, and positively
                                            confirmed (actcon + actterm) so the
                                            attacker believes the command took
                                            effect. The simulated plant is
                                            untouched.
  * Spontaneous transmission             -> while STARTDT is active, measured
                                            values are pushed periodically with
                                            a CP56Time2a time tag, so a passive
                                            observer sees a live installation.
  * Anything else                        -> audited; large ASDUs inventoried.

As with the rest of HoneyGas: nothing the attacker sends is executed; commands
and set-points only affect that attacker's isolated view.
"""
from __future__ import annotations

import asyncio
import struct
from datetime import datetime

from ..sim.profiles import Iec104Point
from .base import Service

# --------------------------------------------------------------- APCI framing
START = 0x68

# U-format control functions (first control octet).
U_STARTDT_ACT = 0x07
U_STARTDT_CON = 0x0B
U_STOPDT_ACT = 0x13
U_STOPDT_CON = 0x23
U_TESTFR_ACT = 0x43
U_TESTFR_CON = 0x83

# ASDU type identifications.
M_SP_NA_1 = 1       # single point
M_ME_NC_1 = 13      # measured value, short floating point
M_ME_TF_1 = 36      # measured value, short float, with CP56Time2a
C_SC_NA_1 = 45      # single command
C_DC_NA_1 = 46      # double command
C_RC_NA_1 = 47      # regulating step command
C_SE_NA_1 = 48      # set-point, normalized
C_SE_NB_1 = 49      # set-point, scaled
C_SE_NC_1 = 50      # set-point, short float
C_BO_NA_1 = 51      # bitstring of 32 bits
C_IC_NA_1 = 100     # (general) interrogation command
C_CI_NA_1 = 101     # counter interrogation command
C_CS_NA_1 = 103     # clock synchronisation command

COMMAND_TYPES = {C_SC_NA_1, C_DC_NA_1, C_RC_NA_1, C_SE_NA_1, C_SE_NB_1,
                 C_SE_NC_1, C_BO_NA_1}
TYPE_NAMES = {
    M_SP_NA_1: "M_SP_NA_1", M_ME_NC_1: "M_ME_NC_1", M_ME_TF_1: "M_ME_TF_1",
    C_SC_NA_1: "C_SC_NA_1", C_DC_NA_1: "C_DC_NA_1", C_RC_NA_1: "C_RC_NA_1",
    C_SE_NA_1: "C_SE_NA_1", C_SE_NB_1: "C_SE_NB_1", C_SE_NC_1: "C_SE_NC_1",
    C_BO_NA_1: "C_BO_NA_1", C_IC_NA_1: "C_IC_NA_1", C_CI_NA_1: "C_CI_NA_1",
    C_CS_NA_1: "C_CS_NA_1",
}

# Cause of transmission.
COT_PERIODIC = 1
COT_SPONT = 3
COT_REQ = 5
COT_ACT = 6
COT_ACTCON = 7
COT_DEACT = 8
COT_DEACTCON = 9
COT_ACTTERM = 10
COT_INTROGEN = 20       # interrogated by station interrogation (general)
COT_UNKNOWN_TYPE = 44
COT_PN = 0x40           # positive/negative confirm bit (set = negative)
COT_TEST = 0x80

# Length (bytes) of each command's information element, IOA (3) included.
_CMD_LEN = {
    C_SC_NA_1: 4, C_DC_NA_1: 4, C_RC_NA_1: 4,   # IOA(3) + 1 qualifier byte
    C_SE_NA_1: 6, C_SE_NB_1: 6,                  # IOA(3) + 2 value + 1 QOS
    C_SE_NC_1: 8,                                # IOA(3) + 4 float + 1 QOS
    C_BO_NA_1: 7,                                # IOA(3) + 4 bitstring
}


class _Conn:
    """Per-connection protocol state (sequence numbers + STARTDT flag)."""
    __slots__ = ("writer", "lock", "send_seq", "recv_seq", "started")

    def __init__(self, writer) -> None:
        self.writer = writer
        self.lock = asyncio.Lock()
        self.send_seq = 0
        self.recv_seq = 0
        self.started = False


class Iec104Service(Service):
    protocol = "iec104"

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self.ctx.config.bind_address, self.port
        )
        self.audit.log("service.listening", service=self.name,
                       protocol=self.label or self.protocol, port=self.port, severity="info")

    # ------------------------------------------------------------- connection
    async def _handle(self, reader, writer) -> None:
        ip, port = self.peer(writer)
        sess, is_new = self.sessions.get(ip, self.name)
        conn = _Conn(writer)
        if is_new:
            self.audit.log("iec104.connect", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        spont_task = None
        try:
            while True:
                apdu = await self._read_apdu(reader)
                if apdu is None:
                    break
                ctrl, asdu = apdu[:4], apdu[4:]
                fmt = self._frame_type(ctrl)
                if fmt == "U":
                    await self._handle_u(conn, sess, ip, port, ctrl)
                    if conn.started and spont_task is None and self._spont_seconds() > 0:
                        spont_task = asyncio.create_task(
                            self._spontaneous_loop(conn, sess, ip, port))
                elif fmt == "I":
                    conn.recv_seq = (conn.recv_seq + 1) & 0x7FFF
                    await self._handle_i(conn, sess, ip, port, asdu)
                # S-format frames just acknowledge our sends; nothing to do.
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as exc:  # noqa: BLE001
            self.audit.log("iec104.error", severity="warning", session=sess.session_id,
                           src_ip=ip, service=self.name, error=str(exc))
        finally:
            if spont_task is not None:
                spont_task.cancel()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _read_apdu(self, reader) -> bytes | None:
        """Read one APDU body (4 control octets + ASDU), re-syncing on 0x68."""
        first = await reader.read(1)
        if not first:
            return None
        while first[0] != START:
            first = await reader.read(1)
            if not first:
                return None
        length = (await reader.readexactly(1))[0]
        return await reader.readexactly(length)

    @staticmethod
    def _frame_type(ctrl: bytes) -> str:
        if len(ctrl) < 4:
            return "?"
        c0 = ctrl[0]
        if (c0 & 0x01) == 0:
            return "I"
        if (c0 & 0x03) == 0x01:
            return "S"
        return "U"

    # ------------------------------------------------------------------- U-fmt
    async def _handle_u(self, conn, sess, ip, port, ctrl: bytes) -> None:
        c0 = ctrl[0]
        if c0 == U_STARTDT_ACT:
            conn.started = True
            self.audit.log("iec104.startdt", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
            await self._send_raw(conn, self._u(U_STARTDT_CON))
        elif c0 == U_STOPDT_ACT:
            conn.started = False
            self.audit.log("iec104.stopdt", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
            await self._send_raw(conn, self._u(U_STOPDT_CON))
        elif c0 == U_TESTFR_ACT:
            self.audit.log("iec104.testfr", severity="info", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
            await self._send_raw(conn, self._u(U_TESTFR_CON))

    # ------------------------------------------------------------------- I-fmt
    async def _handle_i(self, conn, sess, ip, port, asdu: bytes) -> None:
        if len(asdu) < 6:
            await self._send_s(conn)
            return
        type_id = asdu[0]
        cot = asdu[2] & 0x3F
        ca = asdu[4] | (asdu[5] << 8)
        objects = asdu[6:]

        if type_id == C_IC_NA_1:
            await self._interrogation(conn, sess, ip, port, ca, objects)
        elif type_id == C_CI_NA_1:
            await self._counter_interrogation(conn, sess, ip, port, ca, objects)
        elif type_id == C_CS_NA_1:
            await self._clock_sync(conn, sess, ip, port, ca, objects)
        elif type_id in COMMAND_TYPES:
            await self._command(conn, sess, ip, port, type_id, cot, ca, objects)
        else:
            self.audit.log("iec104.unknown_asdu", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name,
                           type=TYPE_NAMES.get(type_id, type_id), cot=cot)
            if len(asdu) >= 16:
                self.quarantine.capture_binary(
                    asdu, session=sess, service=self.name, src_ip=ip,
                    meta={"via": "iec104.raw", "type": type_id})
            await self._send_s(conn)

    # ----------------------------------------------------------- interrogation
    async def _interrogation(self, conn, sess, ip, port, ca, objects: bytes) -> None:
        qoi = objects[3] if len(objects) >= 4 else 0x14   # 20 = station interrogation
        self.audit.log("iec104.interrogation", severity="notice", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                       ca=ca, qoi=qoi)
        # Activation confirmation.
        confirm = self._ioa(0) + bytes([qoi])
        await self._send_i(conn, self._asdu(C_IC_NA_1, COT_ACTCON, 1, confirm, ca))

        points = self._points()
        measured = [p for p in points if p.type_id == M_ME_NC_1]
        singles = [p for p in points if p.type_id == M_SP_NA_1]

        if measured:
            objs = b"".join(
                self._ioa(p.ioa) + struct.pack("<f", self._point_value(sess, p)) + b"\x00"
                for p in measured
            )
            await self._send_i(conn, self._asdu(M_ME_NC_1, COT_INTROGEN, len(measured), objs, ca))
        if singles:
            objs = b"".join(
                self._ioa(p.ioa) + bytes([1 if self._point_value(sess, p) >= 0.5 else 0])
                for p in singles
            )
            await self._send_i(conn, self._asdu(M_SP_NA_1, COT_INTROGEN, len(singles), objs, ca))

        # Activation termination.
        await self._send_i(conn, self._asdu(C_IC_NA_1, COT_ACTTERM, 1, confirm, ca))
        self.audit.log("iec104.interrogation_response", severity="info", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name,
                       measured=len(measured), single=len(singles))

    async def _counter_interrogation(self, conn, sess, ip, port, ca, objects: bytes) -> None:
        qcc = objects[3] if len(objects) >= 4 else 0x05
        self.audit.log("iec104.counter_interrogation", severity="notice",
                       session=sess.session_id, src_ip=ip, src_port=port,
                       service=self.name, ca=ca, qcc=qcc)
        confirm = self._ioa(0) + bytes([qcc])
        await self._send_i(conn, self._asdu(C_CI_NA_1, COT_ACTCON, 1, confirm, ca))
        await self._send_i(conn, self._asdu(C_CI_NA_1, COT_ACTTERM, 1, confirm, ca))

    async def _clock_sync(self, conn, sess, ip, port, ca, objects: bytes) -> None:
        self.audit.log("iec104.clock_sync", severity="notice", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        # Echo the IOA + a fresh CP56Time2a in the actcon.
        body = self._ioa(0) + self._cp56()
        await self._send_i(conn, self._asdu(C_CS_NA_1, COT_ACTCON, 1, body, ca))

    # ---------------------------------------------------------------- commands
    async def _command(self, conn, sess, ip, port, type_id, cot, ca, objects: bytes) -> None:
        ioa = (objects[0] | (objects[1] << 8) | (objects[2] << 16)) if len(objects) >= 3 else 0
        value = self._decode_command(type_id, objects)
        name = TYPE_NAMES.get(type_id, hex(type_id))
        label = self._command_label(ioa)

        self.audit.log("iec104.command", severity="high", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                       type=name, address=ioa, values=value, label=label,
                       note="control command isolated to this attacker's session view")
        self.quarantine.capture_call(
            f"{name} IOA={ioa} value={value}", session=sess, service=self.name, src_ip=ip,
            meta={"via": "iec104.command", "type": name, "ioa": ioa, "label": label})

        # Apply only to this attacker's isolated session view.
        if isinstance(value, (int, float)):
            sess.store.setdefault("iec104", {})[ioa] = float(value)

        # Mirror the information object back in the confirmations.
        clen = _CMD_LEN.get(type_id, max(len(objects), 4))
        mirror = objects[:clen]
        await self._send_i(conn, self._asdu(type_id, COT_ACTCON, 1, mirror, ca))
        await self._send_i(conn, self._asdu(type_id, COT_ACTTERM, 1, mirror, ca))

    @staticmethod
    def _decode_command(type_id, objects: bytes):
        if type_id in (C_SC_NA_1, C_RC_NA_1) and len(objects) >= 4:
            return objects[3] & 0x03
        if type_id == C_DC_NA_1 and len(objects) >= 4:
            return objects[3] & 0x03
        if type_id == C_SE_NC_1 and len(objects) >= 7:
            return round(struct.unpack("<f", objects[3:7])[0], 4)
        if type_id in (C_SE_NA_1, C_SE_NB_1) and len(objects) >= 5:
            return struct.unpack("<h", objects[3:5])[0]
        if type_id == C_BO_NA_1 and len(objects) >= 7:
            return struct.unpack("<I", objects[3:7])[0]
        return None

    def _command_label(self, ioa: int) -> str:
        spec = self.profile.iec104
        if spec:
            for c in spec.commands:
                if c.ioa == ioa:
                    return c.label
        return ""

    # ------------------------------------------------------------- spontaneous
    async def _spontaneous_loop(self, conn, sess, ip, port) -> None:
        points = [p for p in self._points() if p.type_id == M_ME_NC_1]
        if not points:
            return
        ca = self._ca()
        idx = 0
        try:
            while True:
                await asyncio.sleep(self._spont_seconds())
                if not conn.started:
                    continue
                p = points[idx % len(points)]
                idx += 1
                obj = (self._ioa(p.ioa)
                       + struct.pack("<f", self._point_value(sess, p))
                       + b"\x00" + self._cp56())
                await self._send_i(conn, self._asdu(M_ME_TF_1, COT_SPONT, 1, obj, ca))
                self.audit.log("iec104.spontaneous", severity="debug", session=sess.session_id,
                               src_ip=ip, service=self.name, address=p.ioa)
        except asyncio.CancelledError:
            pass
        except (ConnectionError, RuntimeError):
            pass

    # ----------------------------------------------------------------- helpers
    def _points(self) -> list:
        spec = self.profile.iec104
        if spec and spec.points:
            return spec.points
        # Fallback: synthesize measured floats from the HMI tag list.
        return [
            Iec104Point(ioa=1001 + i, tag=hv.tag, type_id=M_ME_NC_1, label=hv.label)
            for i, hv in enumerate(self.profile.hmi.values)
        ]

    def _ca(self) -> int:
        spec = self.profile.iec104
        return spec.common_address if spec else 1

    def _spont_seconds(self) -> float:
        spec = self.profile.iec104
        return spec.spontaneous_seconds if spec else 0.0

    def _point_value(self, sess, p: Iec104Point) -> float:
        override = sess.store.get("iec104", {})
        if p.ioa in override:
            return float(override[p.ioa])
        if p.static is not None:
            return float(p.static) * p.scale
        if p.tag:
            return self.sim.read(p.tag) * p.scale
        return 0.0

    # --------------------------------------------------------------- framing
    @staticmethod
    def _apci(body: bytes) -> bytes:
        return bytes([START, len(body)]) + body

    def _u(self, func: int) -> bytes:
        return self._apci(bytes([func, 0, 0, 0]))

    @staticmethod
    def _ioa(ioa: int) -> bytes:
        return bytes([ioa & 0xFF, (ioa >> 8) & 0xFF, (ioa >> 16) & 0xFF])

    @staticmethod
    def _asdu(type_id: int, cot: int, num: int, objects: bytes, ca: int,
              sq: bool = False, orig: int = 0) -> bytes:
        vsq = (0x80 if sq else 0) | (num & 0x7F)
        return bytes([type_id, vsq, cot & 0xFF, orig & 0xFF,
                      ca & 0xFF, (ca >> 8) & 0xFF]) + objects

    @staticmethod
    def _cp56() -> bytes:
        now = datetime.now()
        ms = now.second * 1000 + now.microsecond // 1000
        return bytes([
            ms & 0xFF, (ms >> 8) & 0xFF,
            now.minute & 0x3F,
            now.hour & 0x1F,
            (now.day & 0x1F) | ((now.isoweekday() & 0x07) << 5),
            now.month & 0x0F,
            (now.year - 2000) & 0x7F,
        ])

    async def _send_i(self, conn: _Conn, asdu: bytes) -> None:
        async with conn.lock:
            ns, nr = conn.send_seq, conn.recv_seq
            conn.send_seq = (conn.send_seq + 1) & 0x7FFF
            ctrl = bytes([(ns << 1) & 0xFE, (ns >> 7) & 0xFF,
                          (nr << 1) & 0xFE, (nr >> 7) & 0xFF])
            conn.writer.write(self._apci(ctrl + asdu))
            await conn.writer.drain()

    async def _send_s(self, conn: _Conn) -> None:
        async with conn.lock:
            nr = conn.recv_seq
            ctrl = bytes([0x01, 0x00, (nr << 1) & 0xFE, (nr >> 7) & 0xFF])
            conn.writer.write(self._apci(ctrl))
            await conn.writer.drain()

    async def _send_raw(self, conn: _Conn, frame: bytes) -> None:
        async with conn.lock:
            conn.writer.write(frame)
            await conn.writer.drain()
