"""DNP3 (Distributed Network Protocol 3) outstation emulator.

Full emulation of the three-layer DNP3 stack spoken between a SCADA master and
an outstation/RTU over TCP/20000 -- the dominant SCADA protocol in North
American gas/electric utilities and widely present in Europe:

    Data Link Layer (0x05 0x64 | len | ctrl | dest | src | CRC, data blocks
                     with per-block CRC)
      -> Transport Function (1-byte FIR/FIN/sequence header)
        -> Application Layer (app control | function | IIN | objects)

Handled interactions (what nmap `dnp3-info`, the Metasploit DNP3 modules and
opendnp3-based masters actually send):

  * Data-link Request Link Status / Reset Link / Test  -> Link Status / ACK,
    with correct DNP3 CRCs and source/destination swap.
  * Application READ of Class 0 / static groups         -> a RESPONSE carrying
    the current value of every monitored point (analog inputs as 32-bit float,
    binary inputs, counters) sourced from the live process simulator, plus the
    output-status points reflecting this attacker's isolated control state.
  * WRITE of the Internal Indications (clear restart)   -> restart bit cleared.
  * SELECT / OPERATE / DIRECT_OPERATE (CROB, analog)    -> the control-tampering
    event defenders care about: audited at HIGH severity, inventoried as
    evidence (capture_call), applied ONLY to the attacker's isolated session
    view, and positively confirmed (status = SUCCESS) so the attacker believes
    the relay/set-point took effect. The simulated plant is untouched.
  * COLD_RESTART / WARM_RESTART                         -> audited at CRITICAL,
    inventoried, answered with a time-delay object -- simulated only.
  * ENABLE/DISABLE unsolicited, DELAY_MEASURE, CONFIRM  -> plausible answers.
  * Anything else                                       -> answered with
    "function not supported" IIN and inventoried.

As with the rest of HoneyGas: nothing the attacker sends is executed, and
controls/writes only affect that attacker's isolated view.
"""
from __future__ import annotations

import asyncio
import struct

from ..core.sessions import BoundedDict
from ..sim.profiles import Dnp3Point
from .base import Service

# --------------------------------------------------------------- link layer
LINK_START = b"\x05\x64"

# Primary link function codes (PRM = 1).
LF_RESET_LINK = 0
LF_TEST_LINK = 2
LF_CONFIRMED_USER_DATA = 3
LF_UNCONFIRMED_USER_DATA = 4
LF_REQUEST_LINK_STATUS = 9
# Secondary link function codes (PRM = 0).
LF_ACK = 0
LF_LINK_STATUS = 11

# --------------------------------------------------------- application layer
# Request function codes.
FC_CONFIRM = 0
FC_READ = 1
FC_WRITE = 2
FC_SELECT = 3
FC_OPERATE = 4
FC_DIRECT_OPERATE = 5
FC_DIRECT_OPERATE_NR = 6
FC_COLD_RESTART = 13
FC_WARM_RESTART = 14
FC_ENABLE_UNSOL = 20
FC_DISABLE_UNSOL = 21
FC_DELAY_MEASURE = 23
# Response function codes.
FC_RESPONSE = 129

FC_NAMES = {
    FC_CONFIRM: "CONFIRM", FC_READ: "READ", FC_WRITE: "WRITE", FC_SELECT: "SELECT",
    FC_OPERATE: "OPERATE", FC_DIRECT_OPERATE: "DIRECT_OPERATE",
    FC_DIRECT_OPERATE_NR: "DIRECT_OPERATE_NR", FC_COLD_RESTART: "COLD_RESTART",
    FC_WARM_RESTART: "WARM_RESTART", FC_ENABLE_UNSOL: "ENABLE_UNSOLICITED",
    FC_DISABLE_UNSOL: "DISABLE_UNSOLICITED", FC_DELAY_MEASURE: "DELAY_MEASURE",
}

# Object groups.
G_BINARY_INPUT = 1
G_BINARY_OUTPUT = 10      # binary output status (read-back of CROB operates)
G_CROB = 12              # control relay output block (operate target)
G_COUNTER = 20
G_ANALOG_INPUT = 30
G_ANALOG_OUTPUT = 40     # analog output status (read-back of AO operates)
G_ANALOG_OUTPUT_BLOCK = 41
G_CLASS = 60
G_TIME_DELAY = 52
G_INTERNAL_INDICATIONS = 80

# Internal Indications bits (IIN1 high byte).
IIN1_RESTART = 0x80
IIN2_NO_FUNC_SUPPORT = 0x01
IIN2_OBJECT_UNKNOWN = 0x02

CONTROL_STATUS_SUCCESS = 0x00


def dnp3_crc(data: bytes) -> int:
    """DNP3 CRC-16 (poly 0x3D65, reflected -> 0xA6BC, final one's complement)."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def _crc_le(data: bytes) -> bytes:
    c = dnp3_crc(data)
    return bytes([c & 0xFF, (c >> 8) & 0xFF])


class _Conn:
    """Per-connection link/transport/application sequence state."""
    __slots__ = ("writer", "lock", "tseq", "src", "dest")

    def __init__(self, writer) -> None:
        self.writer = writer
        self.lock = asyncio.Lock()
        self.tseq = 0               # our outgoing transport sequence
        self.src = 1                # master address (learned from requests)
        self.dest = 1024            # the address the master targeted (our addr)


class Dnp3Service(Service):
    protocol = "dnp3"

    async def start(self) -> None:
        await self._serve(self._handle)

    # ------------------------------------------------------------- connection
    async def _handle(self, reader, writer) -> None:
        ip, port = self.peer(writer)
        sess, is_new = self.sessions.get(ip, self.name)
        conn = _Conn(writer)
        if is_new:
            self.audit.log("dnp3.connect", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        try:
            while True:
                frame = await self._read_link(reader)
                if frame is None:
                    break
                header, user = frame
                await self._dispatch_link(conn, sess, ip, port, header, user)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as exc:  # noqa: BLE001
            self.audit.log("dnp3.error", severity="warning", session=sess.session_id,
                           src_ip=ip, service=self.name, error=str(exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _read_link(self, reader):
        """Read one data-link frame, returning (header8, user_bytes) or None.

        CRCs on inbound data are not enforced (a honeypot stays lenient with
        malformed input); frames are delimited by the length field.
        """
        # Resynchronise to the 0x05 0x64 start octets.
        b = await reader.readexactly(1)
        while b != b"\x05":
            b = await reader.readexactly(1)
        b2 = await reader.readexactly(1)
        if b2 != b"\x64":
            return (b"", b"")          # not a real start; let the caller loop
        rest = await reader.readexactly(6)          # LEN CTRL DEST(2) SRC(2)
        await reader.readexactly(2)                 # header CRC (ignored)
        header = b"\x05\x64" + rest
        length = header[2]
        user_len = max(length - 5, 0)
        user = bytearray()
        remaining = user_len
        while remaining > 0:
            n = min(16, remaining)
            block = await reader.readexactly(n)
            await reader.readexactly(2)             # block CRC (ignored)
            user += block
            remaining -= n
        return header, bytes(user)

    async def _dispatch_link(self, conn, sess, ip, port, header, user) -> None:
        if not header:
            return
        ctrl = header[3]
        func = ctrl & 0x0F
        dest = header[4] | (header[5] << 8)
        src = header[6] | (header[7] << 8)
        conn.src = src          # reply to whoever addressed us
        conn.dest = dest        # answer as the address they targeted

        if func == LF_REQUEST_LINK_STATUS:
            self.audit.log("dnp3.link_status", severity="info", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                           master=src, outstation=dest)
            await self._send_link(conn, LF_LINK_STATUS, prm=0)
        elif func == LF_RESET_LINK:
            self.audit.log("dnp3.reset_link", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                           master=src)
            await self._send_link(conn, LF_ACK, prm=0)
        elif func == LF_TEST_LINK:
            await self._send_link(conn, LF_ACK, prm=0)
        elif func in (LF_CONFIRMED_USER_DATA, LF_UNCONFIRMED_USER_DATA) and len(user) >= 2:
            await self._handle_app(conn, sess, ip, port, user)
        # else: unknown link function -> silently ignore (keep the port open).

    # ------------------------------------------------------- application layer
    async def _handle_app(self, conn, sess, ip, port, user: bytes) -> None:
        # user[0] is the transport header (single-fragment requests assumed).
        app = user[1:]
        if len(app) < 2:
            return
        app_ctrl = app[0]
        func = app[1]
        objects = app[2:]
        seq = app_ctrl & 0x0F
        name = FC_NAMES.get(func, hex(func))

        if func == FC_READ:
            await self._read(conn, sess, ip, port, seq, objects)
        elif func == FC_WRITE:
            await self._write(conn, sess, ip, port, seq, objects)
        elif func in (FC_SELECT, FC_OPERATE, FC_DIRECT_OPERATE, FC_DIRECT_OPERATE_NR):
            await self._control(conn, sess, ip, port, seq, func, objects)
        elif func in (FC_COLD_RESTART, FC_WARM_RESTART):
            await self._restart(conn, sess, ip, port, seq, func)
        elif func in (FC_ENABLE_UNSOL, FC_DISABLE_UNSOL):
            self.audit.log("dnp3.unsolicited_config", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                           function=name)
            await self._send_app(conn, sess, seq, b"")
        elif func == FC_DELAY_MEASURE:
            await self._send_app(conn, sess, seq, self._time_delay(0))
        elif func == FC_CONFIRM:
            self.audit.log("dnp3.confirm", severity="debug", session=sess.session_id,
                           src_ip=ip, service=self.name)
        else:
            self.audit.log("dnp3.unknown_function", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                           function=name)
            if len(app) >= 8:
                self.quarantine.capture_binary(
                    app, session=sess, service=self.name, src_ip=ip,
                    meta={"via": "dnp3.raw", "function": name})
            await self._send_app(conn, sess, seq, b"", iin2=IIN2_NO_FUNC_SUPPORT)

    async def _read(self, conn, sess, ip, port, seq, objects: bytes) -> None:
        groups = self._requested_groups(objects)
        want_static = (not groups) or any(
            g in (G_BINARY_INPUT, G_BINARY_OUTPUT, G_COUNTER, G_ANALOG_INPUT,
                  G_ANALOG_OUTPUT) or (g == G_CLASS and v in (0, 1))
            for g, v in groups)
        unknown = any(g not in (G_BINARY_INPUT, G_BINARY_OUTPUT, G_COUNTER, G_ANALOG_INPUT,
                                G_ANALOG_OUTPUT, G_CLASS) for g, v in groups)
        self.audit.log("dnp3.read", severity="info", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                       groups=[f"g{g}v{v}" for g, v in groups] or ["class0"],
                       static=want_static)
        body = self._static_objects(sess) if want_static else b""
        iin2 = IIN2_OBJECT_UNKNOWN if unknown else 0
        await self._send_app(conn, sess, seq, body, iin2=iin2)

    async def _write(self, conn, sess, ip, port, seq, objects: bytes) -> None:
        clears_restart = len(objects) >= 3 and objects[0] == G_INTERNAL_INDICATIONS
        if clears_restart:
            self._dnp3_state(sess)["restart"] = False
        self.audit.log("dnp3.write", severity="notice", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                       clears_restart=clears_restart)
        await self._send_app(conn, sess, seq, b"")

    async def _control(self, conn, sess, ip, port, seq, func, objects: bytes) -> None:
        name = FC_NAMES.get(func, hex(func))
        ops = self._parse_control(objects)
        severity = "notice" if func == FC_SELECT else "high"
        for op in ops:
            label = self._control_label(op["group"], op["index"])
            self.audit.log("dnp3.control", severity=severity, session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                           function=name, group=op["group"], address=op["index"],
                           values=op["value"], label=label,
                           note="control isolated to this attacker's session view")
            self.quarantine.capture_call(
                f"{name} g{op['group']} index={op['index']} value={op['value']}",
                session=sess, service=self.name, src_ip=ip,
                meta={"via": "dnp3.control", "function": name, "group": op["group"],
                      "index": op["index"], "label": label})
            # OPERATE / DIRECT_OPERATE actually change this attacker's view;
            # SELECT only arms and leaves the isolated state untouched.
            if func != FC_SELECT:
                self._apply_control(sess, op)
        # Echo the control objects back with status = SUCCESS.
        await self._send_app(conn, sess, seq, self._control_response(ops))

    async def _restart(self, conn, sess, ip, port, seq, func) -> None:
        name = FC_NAMES.get(func, hex(func))
        self.audit.log("dnp3.restart", severity="critical", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                       function=name, note="device restart attempt; simulated only")
        self.quarantine.capture_call(
            f"{name}", session=sess, service=self.name, src_ip=ip,
            meta={"via": "dnp3.restart", "function": name})
        # Answer with a time-delay (coarse, seconds) object -- plant keeps running.
        await self._send_app(conn, sess, seq, self._time_delay(0))

    # ----------------------------------------------------------- object model
    @staticmethod
    def _requested_groups(objects: bytes):
        """Parse object headers in a READ, returning [(group, variation), ...]."""
        out = []
        i = 0
        n = len(objects)
        while i + 3 <= n:
            g, v, q = objects[i], objects[i + 1], objects[i + 2]
            i += 3
            out.append((g, v))
            qualifier = q & 0x0F
            if qualifier == 0x00:
                i += 2          # 1-byte start + stop
            elif qualifier == 0x01:
                i += 4          # 2-byte start + stop
            elif qualifier == 0x06:
                i += 0          # all objects, no range
            elif qualifier == 0x07:
                i += 1          # 1-byte count
            elif qualifier == 0x08:
                i += 2          # 2-byte count
            else:
                break           # count-prefixed data we don't need for a read
        return out

    def _points(self, group: int):
        spec = self.profile.dnp3
        if spec and spec.points:
            pts = [p for p in spec.points if p.group == group]
            if pts or group != G_ANALOG_INPUT:
                return sorted(pts, key=lambda p: p.index)
        if group == G_ANALOG_INPUT and (not spec or not spec.points):
            # Fallback: synthesise analog inputs from the HMI tag list.
            return [Dnp3Point(index=i, group=G_ANALOG_INPUT, tag=hv.tag, label=hv.label)
                    for i, hv in enumerate(self.profile.hmi.values)]
        return []

    def _controls(self, group: int):
        spec = self.profile.dnp3
        if not spec:
            return []
        return sorted((c for c in spec.controls if c.group == group), key=lambda c: c.index)

    def _point_value(self, sess, p: Dnp3Point) -> float:
        if p.static is not None:
            return float(p.static) * p.scale
        if p.tag:
            return self.sim.read(p.tag) * p.scale
        return 0.0

    def _static_objects(self, sess) -> bytes:
        """Build the Class 0 static response payload (object headers + data),
        sourcing live values and this attacker's isolated control state."""
        out = bytearray()

        binaries = self._points(G_BINARY_INPUT)
        if binaries:
            objs = [bytes([0x01 | (0x80 if self._point_value(sess, p) >= 0.5 else 0x00)])
                    for p in binaries]
            out += self._block(G_BINARY_INPUT, 2, binaries[0].index, objs)

        bo = self._controls(G_CROB)
        if bo:
            ovr = sess.store.get("dnp3_bo", {})
            objs = [bytes([0x01 | (0x80 if ovr.get(c.index, 0) else 0x00)]) for c in bo]
            out += self._block(G_BINARY_OUTPUT, 2, bo[0].index, objs)

        counters = self._points(G_COUNTER)
        if counters:
            objs = [bytes([0x01]) + struct.pack("<I", int(self._point_value(sess, p)) & 0xFFFFFFFF)
                    for p in counters]
            out += self._block(G_COUNTER, 1, counters[0].index, objs)

        analogs = self._points(G_ANALOG_INPUT)
        if analogs:
            objs = [bytes([0x01]) + struct.pack("<f", self._point_value(sess, p)) for p in analogs]
            out += self._block(G_ANALOG_INPUT, 5, analogs[0].index, objs)

        ao = self._controls(G_ANALOG_OUTPUT_BLOCK)
        if ao:
            ovr = sess.store.get("dnp3_ao", {})
            objs = [bytes([0x01]) + struct.pack("<f", float(ovr.get(c.index, 0.0))) for c in ao]
            out += self._block(G_ANALOG_OUTPUT, 3, ao[0].index, objs)

        return bytes(out)

    @staticmethod
    def _block(group: int, var: int, start: int, objs) -> bytes:
        """One object block with qualifier 0x00 (1-byte start/stop range)."""
        stop = start + len(objs) - 1
        return bytes([group, var, 0x00, start & 0xFF, stop & 0xFF]) + b"".join(objs)

    def _parse_control(self, objects: bytes):
        """Parse CROB (g12v1) / analog output block (g41) operate objects.

        Qualifier 0x17 (1-byte count + 1-byte index prefix) or 0x28 (2-byte
        count + 2-byte index prefix) carry the operated points.
        """
        ops = []
        if len(objects) < 4:
            return ops
        g, v, q = objects[0], objects[1], objects[2]
        i = 3
        if q == 0x07:                       # count, 1-byte (index implied 0..)
            count, isz = objects[i], 0
            i += 1
        elif q == 0x17:                     # count + 1-byte index prefix
            count, isz = objects[i], 1
            i += 1
        elif q == 0x28:                     # count + 2-byte index prefix
            count = objects[i] | (objects[i + 1] << 8)
            isz = 2
            i += 2
        else:
            return ops
        for _ in range(min(count, 32)):
            if isz == 1:
                if i + 1 > len(objects):
                    break
                index = objects[i]; i += 1
            elif isz == 2:
                if i + 2 > len(objects):
                    break
                index = objects[i] | (objects[i + 1] << 8); i += 2
            else:
                index = 0
            if g == G_CROB:                 # CROB: ctrl(1) count(1) on(4) off(4) status(1)
                if i + 11 > len(objects):
                    break
                control_code = objects[i]
                data = objects[i:i + 11]
                i += 11
                ops.append({"group": g, "var": v, "index": index,
                            "value": control_code & 0x0F, "raw": data})
            elif g == G_ANALOG_OUTPUT_BLOCK:
                vlen = {1: 4, 2: 2, 3: 4, 4: 8}.get(v, 4)
                if i + vlen + 1 > len(objects):
                    break
                raw = objects[i:i + vlen + 1]
                val = self._decode_ao(v, objects[i:i + vlen])
                i += vlen + 1
                ops.append({"group": g, "var": v, "index": index, "value": val, "raw": raw})
            else:
                break
        return ops

    @staticmethod
    def _decode_ao(var: int, raw: bytes):
        try:
            if var == 1:
                return struct.unpack("<i", raw[:4])[0]
            if var == 2:
                return struct.unpack("<h", raw[:2])[0]
            if var == 3:
                return round(struct.unpack("<f", raw[:4])[0], 4)
            if var == 4:
                return round(struct.unpack("<d", raw[:8])[0], 4)
        except struct.error:
            return None
        return None

    def _apply_control(self, sess, op) -> None:
        """Record the operate in this attacker's isolated session view only."""
        if op["group"] == G_CROB:
            store = sess.store.get("dnp3_bo")
            if store is None:
                store = BoundedDict(self.ctx.config.limits.max_overlay_entries)
                sess.store["dnp3_bo"] = store
            # Control code: 0x03 = LATCH_ON, 0x04 = LATCH_OFF, 0x41 = pulse-on, etc.
            code = op["value"]
            store[op["index"]] = 0 if code == 0x04 else 1
        elif op["group"] == G_ANALOG_OUTPUT_BLOCK and isinstance(op["value"], (int, float)):
            store = sess.store.get("dnp3_ao")
            if store is None:
                store = BoundedDict(self.ctx.config.limits.max_overlay_entries)
                sess.store["dnp3_ao"] = store
            store[op["index"]] = float(op["value"])

    def _control_response(self, ops) -> bytes:
        """Echo each operated object back with status = SUCCESS (qualifier 0x17)."""
        out = bytearray()
        for op in ops:
            raw = bytearray(op["raw"])
            raw[-1] = CONTROL_STATUS_SUCCESS            # force status to SUCCESS
            idx = op["index"]
            out += bytes([op["group"], op["var"], 0x17, 1, idx & 0xFF]) + bytes(raw)
        return bytes(out)

    def _control_label(self, group: int, index: int) -> str:
        for c in self._controls(group):
            if c.index == index:
                return c.label
        return ""

    @staticmethod
    def _time_delay(ms: int) -> bytes:
        # Group 52 var 2 (time delay, fine / ms), qualifier 0x07 count 1.
        return bytes([G_TIME_DELAY, 2, 0x07, 1]) + struct.pack("<H", ms & 0xFFFF)

    # ---------------------------------------------------------------- state
    @staticmethod
    def _dnp3_state(sess) -> dict:
        st = sess.store.get("dnp3")
        if st is None:
            st = {"restart": True}
            sess.store["dnp3"] = st
        return st

    def _iin(self, sess, iin2_extra: int = 0):
        iin1 = IIN1_RESTART if self._dnp3_state(sess).get("restart", True) else 0x00
        return iin1, iin2_extra & 0xFF

    # --------------------------------------------------------------- framing
    async def _send_app(self, conn, sess, seq, objects: bytes, iin2: int = 0) -> None:
        iin1, iin2b = self._iin(sess, iin2)
        app = bytes([0xC0 | (seq & 0x0F), FC_RESPONSE, iin1, iin2b]) + objects
        transport = bytes([0xC0 | (conn.tseq & 0x3F)]) + app   # FIR+FIN single fragment
        conn.tseq = (conn.tseq + 1) & 0x3F
        await self._send_user(conn, transport)

    async def _send_user(self, conn, user: bytes) -> None:
        await self._send_frame(conn, LF_UNCONFIRMED_USER_DATA, prm=1, user=user)

    async def _send_link(self, conn, func, prm: int) -> None:
        await self._send_frame(conn, func, prm=prm, user=b"")

    async def _send_frame(self, conn, func, prm: int, user: bytes) -> None:
        ctrl = ((prm & 1) << 6) | (func & 0x0F)         # DIR = 0 (from outstation)
        length = 5 + len(user)
        header = bytes([0x05, 0x64, length & 0xFF, ctrl,
                        conn.src & 0xFF, (conn.src >> 8) & 0xFF,
                        conn.dest & 0xFF, (conn.dest >> 8) & 0xFF])
        frame = bytearray(header) + _crc_le(header)
        i = 0
        while i < len(user):
            block = user[i:i + 16]
            frame += block + _crc_le(block)
            i += 16
        async with conn.lock:
            conn.writer.write(bytes(frame))
            await conn.writer.drain()
