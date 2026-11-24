"""OPC UA server emulator (binary protocol over opc.tcp, TCP/4840).

OPC UA is the modern industrial interoperability standard and the backbone of
new SCADA/MES deployments, so a believable opc.tcp server is a strong, current
lure. This emulates the UA-TCP transport and the UA Secure Conversation layer
with security mode **None** (what scanners and discovery clients use), plus the
core services:

    UA-TCP (HEL/ACK)  ->  SecureChannel (OPN)  ->  Message (MSG) services

Handled interactions (what opcua discovery tools and clients actually send):

  * HEL -> ACK                                  handshake / buffer negotiation.
  * OpenSecureChannel -> response               security None channel + token.
  * GetEndpoints / FindServers                  THE fingerprint path: returns a
                                                believable server (application
                                                name, product URI, the None
                                                endpoint) -> `opcua.get_endpoints`.
  * CreateSession / ActivateSession             a working session.
  * Read                                        node values from the live
                                                simulator (checking the session
                                                overlay first).
  * Write                                       the control-tampering event:
                                                audited HIGH, inventoried as
                                                evidence (capture_call), applied
                                                ONLY to the attacker's isolated
                                                session view, answered Good.
  * Browse                                      lists the variable nodes under
                                                the Objects folder.
  * CloseSession / CloseSecureChannel           tidy teardown.
  * Anything else                               a ServiceFault + inventory.

As with the rest of HoneyGas: nothing the attacker sends is executed, and
writes only affect that attacker's isolated view.
"""
from __future__ import annotations

import asyncio
import struct
import time

from ..core.sessions import BoundedDict
from ..sim.profiles import OpcuaNode
from .base import Service

# --------------------------------------------------- message type identifiers
MT_HELLO = b"HEL"
MT_ACK = b"ACK"
MT_ERROR = b"ERR"
MT_OPEN = b"OPN"
MT_CLOSE = b"CLO"
MT_MSG = b"MSG"

# Service request type NodeIds (numeric, namespace 0, DefaultBinary encoding).
REQ_OPEN_SECURE_CHANNEL = 446
REQ_CLOSE_SECURE_CHANNEL = 452
REQ_GET_ENDPOINTS = 428
REQ_FIND_SERVERS = 422
REQ_CREATE_SESSION = 461
REQ_ACTIVATE_SESSION = 467
REQ_CLOSE_SESSION = 473
REQ_READ = 631
REQ_WRITE = 673
REQ_BROWSE = 527

# Response type NodeIds.
RSP_OPEN_SECURE_CHANNEL = 449
RSP_GET_ENDPOINTS = 431
RSP_FIND_SERVERS = 425
RSP_CREATE_SESSION = 464
RSP_ACTIVATE_SESSION = 470
RSP_CLOSE_SESSION = 476
RSP_READ = 634
RSP_WRITE = 677
RSP_BROWSE = 530
RSP_SERVICE_FAULT = 397

REQ_NAMES = {
    REQ_OPEN_SECURE_CHANNEL: "OpenSecureChannel", REQ_CLOSE_SECURE_CHANNEL: "CloseSecureChannel",
    REQ_GET_ENDPOINTS: "GetEndpoints", REQ_FIND_SERVERS: "FindServers",
    REQ_CREATE_SESSION: "CreateSession", REQ_ACTIVATE_SESSION: "ActivateSession",
    REQ_CLOSE_SESSION: "CloseSession", REQ_READ: "Read", REQ_WRITE: "Write",
    REQ_BROWSE: "Browse",
}

# StatusCodes.
SC_GOOD = 0x00000000
SC_BAD_SERVICE_UNSUPPORTED = 0x800B0000
SC_BAD_NODE_ID_UNKNOWN = 0x80340000

POLICY_NONE = "http://opcfoundation.org/UA/SecurityPolicy#None"
TRANSPORT_URI = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"

# Variant built-in type ids.
VT_BOOLEAN = 1
VT_DOUBLE = 11

_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01


# ------------------------------------------------------------ binary encoders
def _u8(v):  return struct.pack("<B", v & 0xFF)
def _u16(v): return struct.pack("<H", v & 0xFFFF)
def _u32(v): return struct.pack("<I", v & 0xFFFFFFFF)
def _i32(v): return struct.pack("<i", v)
def _i64(v): return struct.pack("<q", v)
def _f64(v): return struct.pack("<d", v)


def _str(text):
    if text is None:
        return _i32(-1)
    b = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    return _i32(len(b)) + b


def _bytes(b):
    if b is None:
        return _i32(-1)
    return _i32(len(b)) + bytes(b)


def _now_ticks():
    return _i64(int((time.time() + _EPOCH_OFFSET) * 10_000_000))


def _node_numeric(ident, ns=0):
    if ns == 0 and ident <= 0xFF:
        return _u8(0x00) + _u8(ident)
    if ns <= 0xFF and ident <= 0xFFFF:
        return _u8(0x01) + _u8(ns) + _u16(ident)
    return _u8(0x02) + _u16(ns) + _u32(ident)


def _node_string(ident, ns=1):
    return _u8(0x03) + _u16(ns) + _str(ident)


def _localized_text(text, locale=None):
    mask = 0
    body = b""
    if locale is not None:
        mask |= 0x01
        body += _str(locale)
    if text is not None:
        mask |= 0x02
        body += _str(text)
    return _u8(mask) + body


def _qualified_name(name, ns=0):
    return _u16(ns) + _str(name)


def _ext_object_null():
    return _node_numeric(0, 0) + _u8(0x00)      # NodeId i=0 + "no body" encoding


def _diag_null():
    return _u8(0x00)


def _array(items):
    if items is None:
        return _i32(-1)
    return _i32(len(items)) + b"".join(items)


def _response_header(req_handle, service_result=SC_GOOD):
    return (_now_ticks() + _u32(req_handle) + _u32(service_result)
            + _diag_null() + _array([]) + _ext_object_null())


def _variant_double(v):
    return _u8(VT_DOUBLE) + _f64(float(v))


def _variant_bool(v):
    return _u8(VT_BOOLEAN) + _u8(1 if v else 0)


def _data_value(variant):
    # encodingMask: value(0x01) + sourceTimestamp(0x04) + serverTimestamp(0x08)
    return _u8(0x0D) + variant + _now_ticks() + _now_ticks()


def _data_value_status(code):
    return _u8(0x02) + _u32(code)               # status only


# ---------------------------------------------------------------- decoder
class _Dec:
    __slots__ = ("b", "o")

    def __init__(self, b):
        self.b = b
        self.o = 0

    def _adv(self, n):
        p = self.o
        self.o += n
        return p

    def u8(self):
        return self.b[self._adv(1)]

    def u16(self):
        return struct.unpack_from("<H", self.b, self._adv(2))[0]

    def u32(self):
        return struct.unpack_from("<I", self.b, self._adv(4))[0]

    def i32(self):
        return struct.unpack_from("<i", self.b, self._adv(4))[0]

    def skip(self, n):
        self.o += n

    def string(self):
        n = self.i32()
        if n < 0:
            return None
        return self.b[self._adv(n):self.o].decode("utf-8", "replace")

    def bytestring(self):
        n = self.i32()
        if n < 0:
            return None
        return self.b[self._adv(n):self.o]

    def node_id(self):
        """Return (namespace, identifier). identifier is int or str."""
        enc = self.u8() & 0x0F
        if enc == 0x00:
            return 0, self.u8()
        if enc == 0x01:
            ns = self.u8()
            return ns, self.u16()
        if enc == 0x02:
            ns = self.u16()
            return ns, self.u32()
        if enc == 0x03:
            ns = self.u16()
            return ns, self.string()
        if enc == 0x04:            # guid
            ns = self.u16()
            self.skip(16)
            return ns, None
        if enc == 0x05:            # bytestring
            ns = self.u16()
            return ns, self.bytestring()
        return 0, None

    def request_header(self):
        self.node_id()             # authenticationToken
        self.skip(8)               # timestamp
        handle = self.u32()        # requestHandle
        self.u32()                 # returnDiagnostics
        self.string()              # auditEntryId
        self.u32()                 # timeoutHint
        self.node_id()             # additionalHeader: typeId
        enc = self.u8()            # encoding
        if enc & 0x01:
            self.bytestring()
        elif enc & 0x02:
            self.bytestring()
        return handle


class _Conn:
    __slots__ = ("channel_id", "token_id", "seq", "session", "endpoint_url")

    def __init__(self):
        self.channel_id = 0
        self.token_id = 0
        self.seq = 0
        self.session = False
        self.endpoint_url = "opc.tcp://honeygas:4840"


class OpcuaService(Service):
    protocol = "opcua"

    async def start(self) -> None:
        await self._serve(self._handle)

    # ------------------------------------------------------------- connection
    async def _handle(self, reader, writer) -> None:
        ip, port = self.peer(writer)
        sess, is_new = self.sessions.get(ip, self.name)
        conn = _Conn()
        if is_new:
            self.audit.log("opcua.connect", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        try:
            while True:
                msg = await self._read_message(reader)
                if msg is None:
                    break
                mtype, _chunk, body = msg
                if mtype == MT_HELLO:
                    await self._hello(conn, writer, body)
                elif mtype == MT_OPEN:
                    await self._open(conn, sess, ip, port, writer, body)
                elif mtype == MT_MSG:
                    await self._message(conn, sess, ip, port, writer, body)
                elif mtype == MT_CLOSE:
                    break
                else:
                    break
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as exc:  # noqa: BLE001
            self.audit.log("opcua.error", severity="warning", session=sess.session_id,
                           src_ip=ip, service=self.name, error=str(exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _read_message(self, reader):
        header = await reader.readexactly(8)
        mtype = header[0:3]
        chunk = header[3:4]
        size = struct.unpack_from("<I", header, 4)[0]
        if size < 8 or size > 1_000_000:        # bound a malformed/abusive length
            return None
        body = await reader.readexactly(size - 8)
        return mtype, chunk, body

    @staticmethod
    def _frame(mtype, inner):
        return mtype + b"F" + _u32(8 + len(inner)) + inner

    async def _send(self, writer, frame):
        writer.write(frame)
        await writer.drain()

    # ------------------------------------------------------------------ HELLO
    async def _hello(self, conn, writer, body):
        dec = _Dec(body)
        try:
            dec.u32(); recv = dec.u32(); send = dec.u32(); dec.u32(); dec.u32()
            url = dec.string()
            if url:
                conn.endpoint_url = url
        except Exception:  # noqa: BLE001
            recv = send = 65536
        ack = (_u32(0) + _u32(min(recv or 65536, 65536)) + _u32(min(send or 65536, 65536))
               + _u32(0) + _u32(0))
        await self._send(writer, self._frame(MT_ACK, ack))

    # ------------------------------------------------------ OpenSecureChannel
    async def _open(self, conn, sess, ip, port, writer, body):
        dec = _Dec(body)
        dec.u32()                      # SecureChannelId (0 on first open)
        dec.string()                   # SecurityPolicyUri
        dec.bytestring()               # SenderCertificate
        dec.bytestring()               # ReceiverCertificateThumbprint
        dec.u32()                      # SequenceNumber
        req_id = dec.u32()             # RequestId
        dec.node_id()                  # body TypeId (OpenSecureChannelRequest)
        handle = dec.request_header()
        conn.channel_id = conn.channel_id or 1
        conn.token_id = conn.token_id or 1
        self.audit.log("opcua.open_channel", severity="info", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        # OpenSecureChannelResponse
        token = (_u32(conn.channel_id) + _u32(conn.token_id) + _now_ticks() + _u32(3600000))
        resp = (_response_header(handle) + _u32(0) + token + _bytes(b"\x00" * 32))
        conn.seq += 1
        inner = (_u32(conn.channel_id) + _str(POLICY_NONE) + _bytes(None) + _bytes(None)
                 + _u32(conn.seq) + _u32(req_id)
                 + _node_numeric(RSP_OPEN_SECURE_CHANNEL) + resp)
        await self._send(writer, self._frame(MT_OPEN, inner))

    # -------------------------------------------------------------- MSG layer
    async def _message(self, conn, sess, ip, port, writer, body):
        dec = _Dec(body)
        dec.u32()                      # SecureChannelId
        dec.u32()                      # TokenId
        dec.u32()                      # SequenceNumber
        req_id = dec.u32()             # RequestId
        _ns, type_id = dec.node_id()   # body TypeId
        name = REQ_NAMES.get(type_id, str(type_id))

        if type_id == REQ_GET_ENDPOINTS:
            rsp_id, payload = RSP_GET_ENDPOINTS, self._get_endpoints(conn, sess, ip, port, dec)
        elif type_id == REQ_FIND_SERVERS:
            rsp_id, payload = RSP_FIND_SERVERS, self._find_servers(conn, dec)
        elif type_id == REQ_CREATE_SESSION:
            rsp_id, payload = RSP_CREATE_SESSION, self._create_session(conn, sess, ip, port, dec)
        elif type_id == REQ_ACTIVATE_SESSION:
            rsp_id, payload = RSP_ACTIVATE_SESSION, self._activate_session(conn, sess, ip, port, dec)
        elif type_id == REQ_READ:
            rsp_id, payload = RSP_READ, self._read(conn, sess, ip, port, dec)
        elif type_id == REQ_WRITE:
            rsp_id, payload = RSP_WRITE, self._write(conn, sess, ip, port, dec)
        elif type_id == REQ_BROWSE:
            rsp_id, payload = RSP_BROWSE, self._browse(conn, dec)
        elif type_id == REQ_CLOSE_SESSION:
            handle = dec.request_header()
            self.audit.log("opcua.close_session", severity="info", session=sess.session_id,
                           src_ip=ip, service=self.name)
            rsp_id, payload = RSP_CLOSE_SESSION, _response_header(handle)
        elif type_id == REQ_CLOSE_SECURE_CHANNEL:
            return
        else:
            handle = 0
            try:
                handle = dec.request_header()
            except Exception:  # noqa: BLE001
                pass
            self.audit.log("opcua.unknown_service", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, request=name)
            if len(body) >= 32:
                self.quarantine.capture_binary(
                    body, session=sess, service=self.name, src_ip=ip,
                    meta={"via": "opcua.raw", "request": name})
            rsp_id = RSP_SERVICE_FAULT
            payload = _response_header(handle, SC_BAD_SERVICE_UNSUPPORTED)

        conn.seq += 1
        inner = (_u32(conn.channel_id) + _u32(conn.token_id) + _u32(conn.seq) + _u32(req_id)
                 + _node_numeric(rsp_id) + payload)
        await self._send(writer, self._frame(MT_MSG, inner))

    # ------------------------------------------------------------- discovery
    def _app_description(self, conn):
        spec = self.profile.opcua
        app_uri = spec.application_uri if spec else "urn:honeygas:server"
        prod_uri = spec.product_uri if spec else "urn:honeygas:product"
        name = spec.application_name if spec else "HoneyGas SCADA Server"
        return (_str(app_uri) + _str(prod_uri) + _localized_text(name)
                + _i32(0)                       # applicationType = Server
                + _str(None) + _str(None)       # gateway / discovery profile uri
                + _array([_str(conn.endpoint_url)]))

    def _endpoint_description(self, conn):
        user_token = (_str("anonymous") + _i32(0) + _str(None) + _str(None) + _str(None))
        return (_str(conn.endpoint_url) + self._app_description(conn) + _bytes(None)
                + _i32(1)                        # MessageSecurityMode = None
                + _str(POLICY_NONE)
                + _array([user_token])
                + _str(TRANSPORT_URI)
                + _u8(0))                        # securityLevel

    def _get_endpoints(self, conn, sess, ip, port, dec):
        handle = dec.request_header()
        self.audit.log("opcua.get_endpoints", severity="notice", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        return _response_header(handle) + _array([self._endpoint_description(conn)])

    def _find_servers(self, conn, dec):
        handle = dec.request_header()
        return _response_header(handle) + _array([self._app_description(conn)])

    # ---------------------------------------------------------------- session
    def _create_session(self, conn, sess, ip, port, dec):
        handle = dec.request_header()
        self.audit.log("opcua.create_session", severity="notice", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        session_id = _node_string("session-" + sess.session_id, 1)
        auth_token = _node_numeric(0x484F4E45 & 0xFFFFFFFF, 0)   # opaque numeric token
        return (_response_header(handle) + session_id + auth_token
                + _f64(3600000.0)                # revisedSessionTimeout
                + _bytes(b"\x00" * 32)           # serverNonce
                + _bytes(None)                   # serverCertificate
                + _array([self._endpoint_description(conn)])     # serverEndpoints
                + _array([])                     # serverSoftwareCertificates
                + _str(None) + _bytes(None)      # serverSignature (algorithm, signature)
                + _u32(0x1000000))               # maxRequestMessageSize

    def _activate_session(self, conn, sess, ip, port, dec):
        handle = dec.request_header()
        conn.session = True
        self.audit.log("opcua.activate_session", severity="info", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        return (_response_header(handle) + _bytes(b"\x00" * 32)
                + _array([]) + _array([]))       # results, diagnosticInfos

    # ------------------------------------------------------------- read/write
    def _nodes(self):
        spec = self.profile.opcua
        if spec and spec.nodes:
            return {n.ident: n for n in spec.nodes}
        return {hv.tag: OpcuaNode(ident=hv.tag, tag=hv.tag, label=hv.label)
                for hv in self.profile.hmi.values}

    def _node_value(self, sess, node):
        override = sess.store.get("opcua", {})
        if node.ident in override:
            val = override[node.ident]
        elif node.static is not None:
            val = float(node.static) * node.scale
        elif node.tag:
            val = self.sim.read(node.tag) * node.scale
        else:
            val = 0.0
        if node.kind == "bool":
            return _variant_bool(val >= 0.5)
        return _variant_double(val)

    def _read(self, conn, sess, ip, port, dec):
        handle = dec.request_header()
        dec.skip(8)                     # maxAge (Double)
        dec.i32()                       # timestampsToReturn
        count = dec.i32()
        nodes = self._nodes()
        results = []
        read = []
        for _ in range(max(count, 0)):
            ns, ident = dec.node_id()
            dec.u32()                   # attributeId
            dec.string()                # indexRange
            dec.u16(); dec.string()     # dataEncoding (QualifiedName)
            node = nodes.get(ident) if ns == 1 else None
            if node is not None:
                results.append(_data_value(self._node_value(sess, node)))
                read.append(str(ident))
            else:
                results.append(_data_value_status(SC_BAD_NODE_ID_UNKNOWN))
        self.audit.log("opcua.read", severity="info", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                       nodes=read)
        return _response_header(handle) + _array(results) + _array([])

    def _write(self, conn, sess, ip, port, dec):
        handle = dec.request_header()
        count = dec.i32()
        nodes = self._nodes()
        results = []
        for _ in range(max(count, 0)):
            ns, ident = dec.node_id()
            dec.u32()                   # attributeId
            dec.string()                # indexRange
            value = self._decode_data_value(dec)
            node = nodes.get(ident) if ns == 1 else None
            label = node.label if node else ""
            self.audit.log("opcua.write", severity="high", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                           address=str(ident), values=value, label=label,
                           note="write isolated to this attacker's session view")
            self.quarantine.capture_call(
                f"Write ns={ns};s={ident} value={value}", session=sess, service=self.name,
                src_ip=ip, meta={"via": "opcua.write", "node": str(ident), "label": label})
            if isinstance(value, (int, float)):
                bucket = sess.store.get("opcua")
                if bucket is None:
                    bucket = BoundedDict(self.ctx.config.limits.max_overlay_entries)
                    sess.store["opcua"] = bucket
                bucket[ident] = float(value)
            results.append(_u32(SC_GOOD))
        return _response_header(handle) + _array(results) + _array([])

    @staticmethod
    def _decode_data_value(dec):
        mask = dec.u8()
        value = None
        if mask & 0x01:
            vt = dec.u8() & 0x3F
            if vt == VT_BOOLEAN:
                value = 1 if dec.u8() else 0
            elif vt == VT_DOUBLE:
                value = round(struct.unpack_from("<d", dec.b, dec._adv(8))[0], 6)
            elif vt == 10:              # Float
                value = round(struct.unpack_from("<f", dec.b, dec._adv(4))[0], 6)
            elif vt in (6, 7):          # Int32 / UInt32
                value = dec.i32()
        if mask & 0x02:
            dec.u32()                   # status
        if mask & 0x04:
            dec.skip(8)
        if mask & 0x08:
            dec.skip(8)
        return value

    # ------------------------------------------------------------------ browse
    def _browse(self, conn, dec):
        handle = dec.request_header()
        dec.node_id(); dec.skip(8); dec.u32()    # view: nodeId, timestamp, viewVersion
        dec.u32()                                # requestedMaxReferencesPerNode
        count = dec.i32()
        out = []
        nodes = self._nodes()
        for _ in range(max(count, 0)):
            ns, ident = dec.node_id()            # nodeToBrowse
            dec.i32()                            # browseDirection
            dec.node_id()                        # referenceTypeId
            dec.u8()                             # includeSubtypes
            dec.u32(); dec.u32()                 # nodeClassMask, resultMask
            # The Objects folder (ns=0 i=85) lists our variables; anything else is empty.
            if ns == 0 and ident == 85:
                refs = [self._reference(n) for n in nodes.values()]
            else:
                refs = []
            out.append(_u32(SC_GOOD) + _bytes(None) + _array(refs))
        return _response_header(handle) + _array(out) + _array([])

    @staticmethod
    def _reference(node):
        return (_node_numeric(35)                # referenceTypeId = Organizes
                + _u8(1)                         # isForward
                + _node_string(node.ident, 1)    # nodeId (ExpandedNodeId)
                + _qualified_name(node.ident, 1)  # browseName
                + _localized_text(node.label or node.ident)  # displayName
                + _i32(2)                        # nodeClass = Variable
                + _node_numeric(63))             # typeDefinition = BaseDataVariableType
