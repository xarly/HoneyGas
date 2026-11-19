"""Vulnerable-looking SCADA/HMI web interface.

A minimal async HTTP/1.1 server that presents a plausible operator HMI and,
crucially, offers the two interaction surfaces the brief calls for:

  * "inject malware"      -> POST /firmware/upload accepts an uploaded image,
                             which is CAPTURED to quarantine (hashed, typed,
                             inventoried) and never executed. The HMI replies
                             with a fake "update successful" to keep the
                             attacker engaged.
  * "exploit the vuln"    -> /diagnostics exposes a command-injection-style
                             field. The injected command string is inventoried
                             as a "call" (evidence) and NOT run; canned output
                             is returned.

Default credentials (from the profile) are accepted as the way "in", and every
login attempt is logged. State (auth, uploads) is per-session, so attackers are
isolated from one another.

Implemented with the standard library only, and deliberately strict about not
reflecting attacker input in ways that could matter -- this is a sensor, not an
app.
"""
from __future__ import annotations

import asyncio
import html
from urllib.parse import parse_qs, urlparse

from .base import Service

_MAX_BODY = 25 * 1024 * 1024  # 25 MiB hard cap on a single request body


class HttpHmiService(Service):
    protocol = "http"

    async def start(self) -> None:
        await self._serve(self._handle)

    def _server_header(self) -> str:
        v = self.profile.vendor
        return f"{v.manufacturer}-HMI/{v.firmware}"

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip, port = self.peer(writer)
        sess, is_new = self.sessions.get(ip, self.name)
        if is_new:
            self.audit.log("http.connect", severity="notice", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol)
        try:
            request_line = await reader.readline()
            if not request_line:
                return
            try:
                method, raw_target, _ = request_line.decode("latin1").strip().split(" ", 2)
            except ValueError:
                return

            headers = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                if b":" in line:
                    k, _, val = line.decode("latin1").partition(":")
                    headers[k.strip().lower()] = val.strip()

            length = int(headers.get("content-length", "0") or "0")
            length = min(max(length, 0), _MAX_BODY)
            body = await reader.readexactly(length) if length else b""

            parsed = urlparse(raw_target)
            path = parsed.path
            self.audit.log("http.request", severity="info", session=sess.session_id,
                           src_ip=ip, src_port=port, service=self.name, protocol=self.protocol,
                           method=method, path=path, user_agent=headers.get("user-agent", ""),
                           bytes=len(body))

            status, ctype, payload = self._route(sess, ip, port, method, parsed, headers, body)
            self._write_response(writer, status, ctype, payload)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as exc:  # noqa: BLE001
            self.audit.log("http.error", severity="warning", session=sess.session_id,
                           src_ip=ip, service=self.name, error=str(exc))
            try:
                self._write_response(writer, "500 Internal Server Error",
                                     "text/plain", b"error")
            except Exception:  # noqa: BLE001
                pass
        finally:
            try:
                await writer.drain()
            except Exception:  # noqa: BLE001
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    def _write_response(self, writer, status, ctype, payload: bytes) -> None:
        head = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: {self._server_header()}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"X-Powered-By: {self.profile.vendor.product}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1")
        writer.write(head + payload)

    # ------------------------------------------------------------------ routes
    def _route(self, sess, ip, port, method, parsed, headers, body):
        path = parsed.path.rstrip("/") or "/"
        q = parse_qs(parsed.query)

        if path == "/" or path == "/login":
            if method == "POST":
                return self._do_login(sess, ip, port, body)
            return self._page_login()

        if path == "/api/status":
            return self._api_status()

        if path == "/dashboard":
            if not sess.store.get("authed"):
                return self._redirect_login()
            return self._page_dashboard()

        if path == "/firmware/upload":
            if method == "POST":
                return self._do_firmware_upload(sess, ip, port, headers, body)
            return self._page_firmware()

        if path == "/diagnostics":
            return self._do_diagnostics(sess, ip, port, method, q, body)

        # Record recon against sensitive-looking paths.
        self.audit.log("http.probe", severity="notice", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name, path=parsed.path)
        return ("404 Not Found", "text/html",
                b"<html><body><h1>404</h1></body></html>")

    # ------------------------------------------------------------------ pages
    def _chrome(self, title: str, inner: str) -> bytes:
        v = self.profile.vendor
        doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>{html.escape(self.profile.hmi.title)}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#0f1b2d;color:#dfe8f2;margin:0}}
header{{background:#13294b;padding:12px 20px;border-bottom:3px solid #3a7bd5}}
.card{{background:#15233b;margin:18px;padding:18px;border-radius:6px;max-width:720px}}
table{{width:100%;border-collapse:collapse}} td,th{{padding:6px 10px;border-bottom:1px solid #26405f;text-align:left}}
input{{padding:6px;background:#0f1b2d;border:1px solid #3a7bd5;color:#dfe8f2}}
button{{padding:7px 14px;background:#3a7bd5;border:0;color:#fff;cursor:pointer}}
.small{{color:#7f93ad;font-size:12px}}</style></head>
<body><header><b>{html.escape(self.profile.hmi.title)}</b>
<span class="small"> &nbsp; {html.escape(v.product)} &middot; fw {html.escape(v.firmware)} &middot; S/N {html.escape(v.serial)}</span>
</header>{inner}
<div class="card small">{html.escape(v.manufacturer)} industrial control &mdash; authorized personnel only</div>
</body></html>"""
        return doc.encode("utf-8")

    def _page_login(self):
        inner = """<div class="card"><h3>Operator Sign-in</h3>
<form method="POST" action="/login">
<p>User<br><input name="username" autocomplete="off"></p>
<p>Password<br><input name="password" type="password"></p>
<button type="submit">Sign in</button></form></div>"""
        return ("200 OK", "text/html", self._chrome("login", inner))

    def _page_dashboard(self):
        rows = []
        for item in self.profile.hmi.values:
            val = self.sim.read(item.tag)
            rows.append(f"<tr><td>{html.escape(item.label)}</td>"
                        f"<td><b>{val:.2f}</b> {html.escape(item.unit)}</td></tr>")
        inner = f"""<div class="card"><h3>Live Process Overview</h3>
<table><tr><th>Point</th><th>Value</th></tr>{''.join(rows)}</table></div>
<div class="card"><h3>Maintenance</h3>
<p><a style="color:#8ab6ff" href="/firmware/upload">Firmware update</a> &nbsp;|&nbsp;
<a style="color:#8ab6ff" href="/diagnostics">Network diagnostics</a></p></div>"""
        return ("200 OK", "text/html", self._chrome("dashboard", inner))

    def _page_firmware(self):
        inner = """<div class="card"><h3>Firmware Update</h3>
<form method="POST" action="/firmware/upload" enctype="multipart/form-data">
<p>Select controller firmware image (.bin):<br><input type="file" name="image"></p>
<button type="submit">Upload &amp; flash</button></form>
<p class="small">Device will reboot after flashing.</p></div>"""
        return ("200 OK", "text/html", self._chrome("firmware", inner))

    def _redirect_login(self):
        return ("302 Found\r\nLocation: /login", "text/html", b"")

    # ------------------------------------------------------------------ actions
    def _do_login(self, sess, ip, port, body: bytes):
        form = parse_qs(body.decode("latin1"))
        user = (form.get("username", [""])[0])[:128]
        pw = (form.get("password", [""])[0])[:128]
        accepted = any(c.username == user and c.password == pw
                       for c in self.profile.credentials)
        self.audit.log("http.login_attempt", severity="high", session=sess.session_id,
                       src_ip=ip, src_port=port, service=self.name,
                       username=user, password_len=len(pw), accepted=accepted,
                       default_cred=accepted)
        if accepted:
            sess.store["authed"] = True
            sess.store["user"] = user
            return self._page_dashboard()
        inner = '<div class="card"><h3>Sign-in failed</h3><p>Invalid credentials.</p>' \
                '<p><a style="color:#8ab6ff" href="/login">Try again</a></p></div>'
        return ("401 Unauthorized", "text/html", self._chrome("login", inner))

    def _do_firmware_upload(self, sess, ip, port, headers, body: bytes):
        filename = None
        payload = body
        # Extract the file part from a multipart body if present; otherwise
        # capture the raw body. Either way, we keep the bytes as evidence.
        ctype = headers.get("content-type", "")
        if "multipart/form-data" in ctype and b"filename=" in body:
            filename, payload = _extract_multipart_file(body)

        rec = self.quarantine.capture_binary(
            payload, session=sess, service=self.name, src_ip=ip,
            meta={"filename": filename, "via": "http.firmware_upload",
                  "content_type": ctype},
        )
        inner = f"""<div class="card"><h3>Firmware accepted</h3>
<p>Image received ({rec.size} bytes). Verifying signature and flashing&hellip;</p>
<p class="small">update id: {html.escape(rec.capture_id)}</p></div>"""
        # The attacker sees "success"; the payload is quarantined, not executed.
        return ("200 OK", "text/html", self._chrome("firmware", inner))

    def _do_diagnostics(self, sess, ip, port, method, q, body: bytes):
        host = ""
        if method == "POST":
            form = parse_qs(body.decode("latin1"))
            host = form.get("host", [""])[0]
        else:
            host = q.get("host", [""])[0]
        host = host[:1024]

        if host:
            # Treat the whole field as a potentially-injected command and
            # inventory it as evidence. Nothing is executed.
            self.quarantine.capture_call(
                host, session=sess, service=self.name, src_ip=ip,
                meta={"via": "http.diagnostics", "field": "host"},
            )
            # Return canned, benign output as if a simple ping had run.
            safe = html.escape(host.splitlines()[0] if host else "")
            inner = f"""<div class="card"><h3>Network diagnostics</h3>
<pre>PING {safe}: 56 data bytes
64 bytes from {safe}: icmp_seq=0 ttl=64 time=0.42 ms
64 bytes from {safe}: icmp_seq=1 ttl=64 time=0.39 ms
--- {safe} ping statistics ---
2 packets transmitted, 2 received, 0% packet loss</pre>
<form method="POST" action="/diagnostics">
<input name="host" placeholder="host or IP"><button>Run</button></form></div>"""
            return ("200 OK", "text/html", self._chrome("diag", inner))

        inner = """<div class="card"><h3>Network diagnostics</h3>
<form method="POST" action="/diagnostics">
<p>Ping host:<br><input name="host" placeholder="host or IP"></p>
<button type="submit">Run</button></form></div>"""
        return ("200 OK", "text/html", self._chrome("diag", inner))

    def _api_status(self):
        v = self.profile.vendor
        import json
        data = {
            "manufacturer": v.manufacturer,
            "product": v.product,
            "firmware": v.firmware,
            "serial": v.serial,
            "site": self.ctx.config.site_name,
            "mode": self.profile.mode,
            "points": {i.tag: round(self.sim.read(i.tag), 3) for i in self.profile.hmi.values},
        }
        return ("200 OK", "application/json", json.dumps(data).encode("utf-8"))


def _extract_multipart_file(body: bytes):
    """Best-effort extraction of (filename, file_bytes) from a multipart body."""
    filename = None
    try:
        # filename="..."
        idx = body.find(b"filename=")
        if idx != -1:
            start = body.find(b'"', idx) + 1
            end = body.find(b'"', start)
            if 0 < start < end:
                filename = body[start:end].decode("latin1", "replace") or None
        # payload starts after the first blank line following the headers
        marker = body.find(b"\r\n\r\n")
        if marker != -1:
            content = body[marker + 4:]
            # strip the trailing boundary (last CRLF + --boundary--)
            tail = content.rfind(b"\r\n--")
            if tail != -1:
                content = content[:tail]
            return filename, content
    except Exception:  # noqa: BLE001
        pass
    return filename, body
