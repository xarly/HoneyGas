"""S7comm (Siemens S7 Communication) server emulator.

Full emulation of the S7 protocol stack over ISO-TSAP / RFC1006 (TCP 102):

    TPKT (RFC 1006)  ->  COTP (ISO 8073)  ->  S7comm

Handled interactions (what real tools and scanners actually send):

  * COTP Connection Request  -> Connection Confirm (mirrors refs/TSAPs)
  * S7 Setup Communication   -> negotiated PDU size ack
  * Read SZL (Userdata)      -> Module Identification (SZL 0x0011) and
                                Component Identification (SZL 0x001C). This is
                                the fingerprint PLCScan / nmap `s7-info` /
                                Metasploit read to identify the PLC: order
                                number (MLFB), firmware version, module type,
                                system name, serial number, copyright.
  * Read Var                 -> values sourced from the live process simulator
                                (DB words mapped to the Modbus process map).
  * Write Var                -> stored in the attacker's SESSION OVERLAY only
                                (isolation), audited at high severity, and the
                                written bytes inventoried in quarantine.
  * PLC control (STOP/START) -> audited at CRITICAL severity as control
                                tampering; a success ack is returned but the
                                simulated plant keeps running.
  * Anything else            -> audited and the raw PDU inventoried.

As with the rest of HoneyGas: nothing the attacker sends is executed; writes
and control commands only affect that attacker's isolated view.
"""
from __future__ import annotations

import asyncio
import struct

from .base import Service

# ---------------------------------------------------------------- constants
TPKT_VER = 0x03
COTP_CR = 0xE0   # Connection Request
COTP_CC = 0xD0   # Connection Confirm
COTP_DT = 0xF0   # Data

S7_PROTO = 0x32
ROSCTR_JOB = 0x01
ROSCTR_ACK = 0x02
ROSCTR_ACK_DATA = 0x03
ROSCTR_USERDATA = 0x07

# Job function codes
F_SETUP = 0xF0
F_READ_VAR = 0x04
F_WRITE_VAR = 0x05
F_PLC_STOP = 0x29
F_PLC_CONTROL = 0x28

AREA_NAMES = {0x81: "I", 0x82: "Q", 0x83: "M", 0x84: "DB", 0x85: "DI",
              0x1C: "C", 0x1D: "T"}


class S7CommService(Service):
    protocol = "s7comm"

    async def start(self) -> None:
        await self._serve(self._handle)

    # ------------------------------------------------------------- connection
    async def _handle(self, reader, writer) -> None:
        ip, port = self.peer(writer)
        sess, is_new = self.sessions.get(ip, self.name)
        if is_new:
            self.audit.log("s7.connect", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        try:
            while True:
                head = await reader.readexactly(4)
                if head[0] != TPKT_VER:
                    break
                total = struct.unpack(">H", head[2:4])[0]
                rest = await reader.readexactly(max(total - 4, 0))
                reply = self._dispatch(sess, ip, port, rest)
                if reply:
                    writer.write(reply)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as exc:  # noqa: BLE001
            self.audit.log("s7.error", severity="warning", session=sess.session_id,
                           src_ip=ip, service=self.name, error=str(exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    # ----------------------------------------------------------------- COTP
    def _dispatch(self, sess, ip, port, cotp: bytes):
        if len(cotp) < 2:
            return None
        pdu_type = cotp[1]
        if pdu_type == COTP_CR:
            self.audit.log("s7.cotp_connect", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name)
            return self._tpkt(self._build_cc(cotp))
        if pdu_type == COTP_DT:
            # COTP DT header length = li + 1 (li is cotp[0]).
            s7 = cotp[cotp[0] + 1:]
            resp = self._handle_s7(sess, ip, port, s7)
            if resp is None:
                return None
            return self._tpkt(b"\x02\xf0\x80" + resp)
        return None

    def _build_cc(self, cr: bytes) -> bytes:
        try:
            li = cr[0]
            src_ref = cr[4:6]
            cls = cr[6]
            params = cr[7:li + 1]
            # Parse TLV params and swap the two TSAP selectors for the CC.
            tlvs = []
            i = 0
            while i + 2 <= len(params):
                code = params[i]
                length = params[i + 1]
                value = params[i + 2:i + 2 + length]
                tlvs.append([code, value])
                i += 2 + length
            src_tsap = dst_tsap = None
            for t in tlvs:
                if t[0] == 0xC1:
                    src_tsap = t[1]
                elif t[0] == 0xC2:
                    dst_tsap = t[1]
            out_params = b""
            for code, value in tlvs:
                if code == 0xC1 and dst_tsap is not None:
                    value = dst_tsap
                elif code == 0xC2 and src_tsap is not None:
                    value = src_tsap
                out_params += bytes([code, len(value)]) + value
            body = bytes([COTP_CC]) + src_ref + b"\x00\x02" + bytes([cls]) + out_params
            return bytes([len(body)]) + body
        except Exception:  # noqa: BLE001
            # Canned CC fallback.
            return bytes.fromhex("11d00001000200c0010ac1020102c2020100")

    # ------------------------------------------------------------------ S7
    def _handle_s7(self, sess, ip, port, s7: bytes):
        if len(s7) < 10 or s7[0] != S7_PROTO:
            if len(s7) >= 16:
                self.quarantine.capture_binary(s7, session=sess, service=self.name,
                                               src_ip=ip, meta={"via": "s7.raw"})
            return None
        rosctr = s7[1]
        pduref = struct.unpack(">H", s7[4:6])[0]
        param_len = struct.unpack(">H", s7[6:8])[0]
        data_len = struct.unpack(">H", s7[8:10])[0]
        param = s7[10:10 + param_len]
        data = s7[10 + param_len:10 + param_len + data_len]

        if rosctr == ROSCTR_JOB and param:
            func = param[0]
            if func == F_SETUP:
                return self._setup(sess, ip, port, pduref, param)
            if func == F_READ_VAR:
                return self._read_var(sess, ip, port, pduref, param)
            if func == F_WRITE_VAR:
                return self._write_var(sess, ip, port, pduref, param, data)
            if func in (F_PLC_STOP, F_PLC_CONTROL):
                return self._plc_control(sess, ip, port, pduref, func, param)
            self.audit.log("s7.unknown_job", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, function=func,
                           raw=param.hex())
            return self._error(pduref, 0x81, 0x04)  # function not implemented
        if rosctr == ROSCTR_USERDATA:
            return self._userdata(sess, ip, port, pduref, param, data)

        return None

    # ---------------------------------------------------------- setup comm
    def _setup(self, sess, ip, port, pduref, param) -> bytes:
        req_pdu = struct.unpack(">H", param[6:8])[0] if len(param) >= 8 else 240
        pdu_size = min(req_pdu or 240, self._pdu_size())
        self.audit.log("s7.setup", severity="info", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, pdu=pdu_size)
        resp_param = struct.pack(">BBHHH", F_SETUP, 0x00, 0x0001, 0x0001, pdu_size)
        return self._s7(ROSCTR_ACK_DATA, pduref, resp_param, b"", err=0x0000)

    def _pdu_size(self) -> int:
        return self.profile.s7.pdu_size if self.profile.s7 else 480

    # ------------------------------------------------------------- read var
    def _read_var(self, sess, ip, port, pduref, param) -> bytes:
        count = param[1] if len(param) > 1 else 0
        items = []
        off = 2
        for _ in range(count):
            spec = param[off:off + 12]
            if len(spec) < 12:
                break
            ts = spec[3]
            nelem = struct.unpack(">H", spec[4:6])[0]
            db = struct.unpack(">H", spec[6:8])[0]
            area = spec[8]
            addr = (spec[9] << 16) | (spec[10] << 8) | spec[11]
            byteaddr = addr >> 3
            items.append((ts, nelem, db, area, byteaddr))
            off += 12

        data = b""
        for ts, nelem, db, area, byteaddr in items:
            nelem = min(nelem, 64)
            words = [self._read_word(sess, area, db, byteaddr + 2 * i) for i in range(nelem)]
            payload = b"".join(struct.pack(">H", w) for w in words)
            data += struct.pack(">BBH", 0xFF, 0x04, len(payload) * 8) + payload
            if len(payload) % 2 and (ts, nelem, db, area, byteaddr) != items[-1]:
                data += b"\x00"
            self.audit.log("s7.read_var", severity="info", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name,
                           area=AREA_NAMES.get(area, hex(area)), address=f"DB{db}.{byteaddr}",
                           quantity=nelem)
        resp_param = bytes([F_READ_VAR, len(items)])
        return self._s7(ROSCTR_ACK_DATA, pduref, resp_param, data, err=0x0000)

    def _read_word(self, sess, area, db, byteaddr) -> int:
        key = f"s7:{area}:{db}:{byteaddr}"
        if key in sess.overlay:
            return sess.overlay[key] & 0xFFFF
        if area == 0x84:  # DB -> live process map
            idx = byteaddr // 2
            mb = self.profile.modbus
            entry = mb.input_registers.get(idx) or mb.holding_registers.get(idx)
            if entry:
                if entry.static is not None:
                    return entry.static & 0xFFFF
                if entry.tag:
                    return int(round(self.sim.read(entry.tag) * entry.scale)) & 0xFFFF
        return 0

    # ------------------------------------------------------------ write var
    def _write_var(self, sess, ip, port, pduref, param, data) -> bytes:
        count = param[1] if len(param) > 1 else 0
        # Parse the item address specs (same 12-byte layout as read).
        specs = []
        off = 2
        for _ in range(count):
            spec = param[off:off + 12]
            if len(spec) < 12:
                break
            db = struct.unpack(">H", spec[6:8])[0]
            area = spec[8]
            addr = (spec[9] << 16) | (spec[10] << 8) | spec[11]
            specs.append((db, area, addr >> 3))
            off += 12

        # Parse the data part (one data item per spec) and apply to the overlay.
        results = []
        doff = 0
        for (db, area, byteaddr) in specs:
            if doff + 4 > len(data):
                results.append(0x05)  # address out of range
                continue
            length_bits = struct.unpack(">H", data[doff + 2:doff + 4])[0]
            nbytes = (length_bits + 7) // 8
            raw = data[doff + 4:doff + 4 + nbytes]
            doff += 4 + nbytes + (nbytes % 2)  # items pad to even length
            # Store as words in this attacker's overlay only.
            vals = []
            for i in range(0, len(raw) - 1, 2):
                w = struct.unpack(">H", raw[i:i + 2])[0]
                sess.overlay[f"s7:{area}:{db}:{byteaddr + i}"] = w
                vals.append(w)
            results.append(0xFF)
            self.audit.log("s7.write_var", severity="high", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                           area=AREA_NAMES.get(area, hex(area)), address=f"DB{db}.{byteaddr}",
                           values=vals[:16],
                           note="control write isolated to this attacker's session overlay")
            if raw:
                self.quarantine.capture_binary(
                    raw, session=sess, service=self.name, src_ip=ip,
                    meta={"via": "s7.write_var", "area": AREA_NAMES.get(area, hex(area)),
                          "db": db, "byte": byteaddr})
        resp_param = bytes([F_WRITE_VAR, len(specs)])
        return self._s7(ROSCTR_ACK_DATA, pduref, resp_param, bytes(results), err=0x0000)

    # --------------------------------------------------------- plc control
    def _plc_control(self, sess, ip, port, pduref, func, param) -> bytes:
        # Extract the ASCII service name (e.g. "P_PROGRAM") for evidence.
        svc = "".join(chr(b) for b in param if 32 <= b < 127)
        action = "PLC_STOP" if func == F_PLC_STOP else "PLC_START/CONTROL"
        self.audit.log("s7.plc_control", severity="critical", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                       action=action, cmd=svc[:64],
                       note="attacker attempted PLC run-state change; simulated only")
        self.quarantine.capture_call(f"{action}:{svc}", session=sess, service=self.name,
                                     src_ip=ip, meta={"via": "s7.plc_control"})
        # Acknowledge success (the simulated plant keeps running regardless).
        return self._s7(ROSCTR_ACK, pduref, bytes([func]), b"", err=0x0000)

    # ------------------------------------------------------------ userdata
    def _userdata(self, sess, ip, port, pduref, param, data) -> bytes | None:
        # Userdata param: 00 01 12 <plen> <method> <type/funcgroup> <subfunc> <seq>
        if len(param) < 8:
            return None
        func_group = param[5] & 0x0F
        subfunc = param[6]
        seq = param[7]
        if func_group == 0x04 and subfunc == 0x01:  # CPU functions / Read SZL
            szl_id = struct.unpack(">H", data[4:6])[0] if len(data) >= 6 else 0
            szl_index = struct.unpack(">H", data[6:8])[0] if len(data) >= 8 else 0
            self.audit.log("s7.read_szl", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name,
                           szl_id=hex(szl_id), szl_index=hex(szl_index))
            return self._read_szl(pduref, szl_id, szl_index, seq)
        self.audit.log("s7.userdata", severity="notice", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name,
                       func_group=func_group, subfunc=subfunc)
        return None

    def _read_szl(self, pduref, szl_id, szl_index, seq) -> bytes:
        if szl_id == 0x0011:
            content = self._szl_0011()
        elif szl_id == 0x001C:
            content = self._szl_001c()
        else:
            # Unknown SZL: return an empty-but-valid partial list.
            content = struct.pack(">HHHH", szl_id, szl_index, 0, 0)
        data = struct.pack(">BBH", 0xFF, 0x09, len(content)) + content
        # Userdata response parameter (method=0x12 response, type/group 0x84).
        resp_param = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, seq,
                            0x00, 0x00, 0x00, 0x00])
        return self._s7(ROSCTR_USERDATA, pduref, resp_param, data)

    # ------------------------------------------------------- SZL builders
    def _szl_0011(self) -> bytes:
        s7 = self.profile.s7
        lenthdr = 0x001C  # 28 bytes per record
        major, minor, patch = s7.fw_tuple()

        def rec(index: int, mlfb: str, ver: tuple | None = None) -> bytes:
            b = struct.pack(">H", index)
            b += mlfb.encode("ascii", "replace")[:20].ljust(20, b" ")
            b += struct.pack(">H", 0x0000)          # BGTyp
            if ver:
                b += struct.pack(">H", ver[0])       # Ausbg1 (00, major)
                b += struct.pack(">BB", ver[1], ver[2])  # Ausbg2 (minor, patch)
            else:
                b += struct.pack(">HH", 0x0000, 0x0000)
            return b

        records = [
            rec(0x0001, s7.order_number),
            rec(0x0006, s7.basic_hardware),
            rec(0x0007, s7.basic_hardware, (major, minor, patch)),
        ]
        body = b"".join(records)
        return struct.pack(">HHHH", 0x0011, 0x0000, lenthdr, len(records)) + body

    def _szl_001c(self) -> bytes:
        s7 = self.profile.s7
        value_len = 32
        lenthdr = value_len + 2  # index(2) + value

        def rec(index: int, text: str) -> bytes:
            return struct.pack(">H", index) + \
                text.encode("ascii", "replace")[:value_len].ljust(value_len, b"\x00")

        fields = [
            (0x0001, s7.system_name),
            (0x0002, s7.module_type),
            (0x0003, s7.plant_id),
            (0x0004, s7.copyright),
            (0x0005, s7.serial),
            (0x0007, s7.module_type),
        ]
        records = [rec(i, t) for i, t in fields]
        body = b"".join(records)
        return struct.pack(">HHHH", 0x001C, 0x0000, lenthdr, len(records)) + body

    # --------------------------------------------------------------- framing
    def _s7(self, rosctr, pduref, param=b"", data=b"", err=None) -> bytes:
        hdr = struct.pack(">BBHHHH", S7_PROTO, rosctr, 0x0000, pduref,
                          len(param), len(data))
        if err is not None:
            hdr += struct.pack(">H", err)
        return hdr + param + data

    def _error(self, pduref, err_class, err_code) -> bytes:
        return self._s7(ROSCTR_ACK_DATA, pduref, b"", b"",
                        err=(err_class << 8) | err_code)

    def _tpkt(self, cotp: bytes) -> bytes:
        return struct.pack(">BBH", TPKT_VER, 0x00, len(cotp) + 4) + cotp
