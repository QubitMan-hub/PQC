"""The console: one page for the CA, its certificates, the edges and a connection test.

It listens on localhost and wants a bearer token on every API call. For remote access put `pqc tls edge --policy transition`
in front of it: browsers already do X25519MLKEM768, though they cannot verify ML-DSA certificates yet.
"""
import base64
import datetime as dt
import hashlib
import hmac
import http.client
import io
import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
import zipfile
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from cryptography import x509

from .. import HTTP_IDLE, NAME, __version__, build, content_length, explain, read_toml, tls
from ..pki import ALGORITHMS, CA, CAError, append, encrypted

log = logging.getLogger("pqc.console")
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
PQ_GROUPS = set(tls.PQC_GROUPS.split(":")) | {"MLKEM1024"}
KEYS = {"1.2.840.10045.2.1": "ECDSA", "1.2.840.113549.1.1.1": "RSA", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448"}


@dataclass
class Settings:
    listen: str = "127.0.0.1:8900"
    ca: str = ""
    edges: list = field(default_factory=list)
    check_updates: bool = False
    audit_log: str = "console-audit.jsonl"

    @classmethod
    def load(cls, path):
        return build(cls, read_toml(path).get("console", {}), "[console]")


def text(b, name, limit=255, required=True):
    v = b.get(name, "")
    if not isinstance(v, str) or len(v) > limit:
        raise ValueError(f"{name} must be text of at most {limit} characters")
    v = v.strip()
    if required and not v:
        raise ValueError(f"{name} is needed")
    return v


class App:
    def __init__(self, settings, token=None, passphrase=None):
        self.s, self.passphrase = settings, passphrase
        self.token = token or os.environ.get("PQC_CONSOLE_TOKEN") or secrets.token_urlsafe(24)
        self.latest, self.latest_checked = None, 0.0
        self.lock = threading.Lock()

    def ca(self):
        if not self.s.ca:
            raise CAError("no CA configured (start the console with --ca)")
        pw = self.passphrase or os.environ.get("PQC_CA_PASSPHRASE", "").encode()
        return CA(self.s.ca, pw if pw and encrypted(Path(self.s.ca) / "ca.key") else None)

    def audit(self, action, detail):
        line = json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "action": action, **detail})
        with self.lock:
            append(self.s.audit_log, line)
        log.info("console: %s %s", action, detail)

    def activity(self, n=12):
        try:
            with open(self.s.audit_log, encoding="utf-8", errors="replace") as f:
                lines = deque(f, n)
        except FileNotFoundError:
            return []
        out = []
        for line in reversed(lines):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out

    def authority(self, ca):
        out = {"subject": ca.cert.subject.rfc4514_string(), "algorithm": ca.algorithm, "folder": str(Path(self.s.ca).resolve()),
               "expires": ca.cert.not_valid_after_utc.date().isoformat(),
               "days_left": (ca.cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).days, "crl": None}
        try:
            crl = x509.load_pem_x509_crl((Path(self.s.ca) / "crl.pem").read_bytes())
            out["crl"] = {"updated": crl.last_update_utc.isoformat(), "next_update": crl.next_update_utc.isoformat(),
                          "hours_left": round((crl.next_update_utc - dt.datetime.now(dt.timezone.utc)).total_seconds() / 3600, 1),
                          "revoked": len(crl)}
        except (OSError, ValueError):
            pass
        return out

    def certificates(self):
        ca = self.ca()
        now = dt.datetime.now(dt.timezone.utc)
        records = ca.records()
        current = {r.path: r.serial for r in records if r.path}
        rows = [vars(r) | {"days_left": (dt.datetime.fromisoformat(r.not_after) - now).days, "has_files": current.get(r.path) == r.serial,
                           "renewed": bool(r.path) and current[r.path] != r.serial} for r in records]
        for r in rows:
            r.pop("path")
        return {"root": self.authority(ca), "certificates": rows[::-1]}

    def edges(self):
        """One row per route in each edge's /status; an address that is down or answers like something else is one error row."""
        out = []
        for url in self.s.edges:
            try:
                with NO_PROXY.open(url.rstrip("/") + "/status", timeout=3) as r:
                    status = json.loads(r.read(1 << 20))
                if not isinstance(status, dict) or not all(isinstance(v, dict) for v in status.values()):
                    raise ValueError("this address does not answer like an edge's /status")
                for name, v in status.items():
                    groups = v.get("groups") if isinstance(v.get("groups"), dict) else {}
                    out.append({"source": url, "name": name, **v, "quantum_safe": sum(c for g, c in groups.items() if g in PQ_GROUPS)})
            except (OSError, ValueError, http.client.HTTPException) as e:
                out.append({"source": url, "error": explain(e.reason if isinstance(e, urllib.error.URLError) else e)})
        return out

    def update(self):
        """The newest release when check_updates is on and it is newer; looked up at most once a day, in the background."""
        if not self.s.check_updates:
            return None
        if time.time() - self.latest_checked > 86400:
            self.latest_checked = time.time()

            def check():
                from .. import latest_release
                try:
                    self.latest = latest_release()
                except (OSError, ValueError) as e:
                    log.info("update check failed: %s", e)
            threading.Thread(target=check, daemon=True).start()
        return self.latest if self.latest and self.latest["newer"] else None

    def overview(self):
        out = {"product": NAME, "version": __version__, "update": self.update(), "activity": self.activity()}
        try:
            data = self.certificates()
            certs = data["certificates"]
            out["ca"] = data["root"]
            out["certificates"] = {"valid": sum(c["status"] == "valid" and c["days_left"] >= 0 for c in certs),
                                   "revoked": sum(c["status"] == "revoked" for c in certs),
                                   "expiring_30d": sum(c["status"] == "valid" and 0 <= c["days_left"] <= 30 for c in certs),
                                   "expired": sum(c["status"] == "valid" and c["days_left"] < 0 for c in certs)}
        except CAError as e:
            out["ca"], out["certificates"] = None, {"error": str(e)}
        edges = self.edges()
        up = [e for e in edges if "error" not in e]
        out["edges"] = {"routes": len(up), "unreachable": len(edges) - len(up), "active": sum(e.get("active", 0) for e in up),
                        "handshakes": sum(e.get("handshakes", 0) for e in up), "quantum_safe": sum(e["quantum_safe"] for e in up),
                        "failed": sum(e.get("handshake_failed", 0) for e in up)}
        return out

    def handle(self, method, path, body):
        routes = {
            ("GET", "/api/overview"): self.overview,
            ("GET", "/api/certificates"): self.certificates,
            ("GET", "/api/edges"): self.edges,
            ("POST", "/api/certificates/issue"): lambda: self.issue(body),
            ("POST", "/api/certificates/revoke"): lambda: self.revoke(body),
            ("POST", "/api/certificates/renew"): lambda: self.renew(body),
            ("POST", "/api/certificates/maintain"): self.maintain,
            ("POST", "/api/certificates/download"): lambda: self.download(body),
            ("POST", "/api/test"): lambda: self.test(body),
        }
        fn = routes.get((method, path))
        if not fn:
            return 404, {"error": "no such endpoint"}
        try:
            return 200, fn()
        except KeyError as e:
            return 400, {"error": f"missing field {e.args[0]}"}
        except (CAError, tls.TLSError, ValueError, OSError) as e:
            return 400, {"error": explain(e) if isinstance(e, OSError) else str(e)}
        except Exception:
            log.exception("%s %s failed", method, path)
            return 500, {"error": "internal error; the details are in the console's log"}

    def issue(self, b):
        kind, cn = text(b, "kind", 10), text(b, "common_name", 64)
        names = [n.strip() for n in text(b, "names", 2000, required=False).split(",") if n.strip()]
        algorithm = text(b, "algorithm", 20, required=False) or "ML-DSA-65"
        if algorithm not in ALGORITHMS:
            raise ValueError(f"algorithm must be one of {', '.join(ALGORITHMS)}")
        days = b.get("days", 397)
        if isinstance(days, str) and days.strip().isdigit():
            days = int(days)
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 3650:
            raise ValueError("days must be a whole number from 1 to 3650")
        _, rec = self.ca().issue(cn, kind, names, days, algorithm)
        self.audit("issue", {"serial": rec.serial, "common_name": cn, "kind": kind})
        return {"serial": rec.serial, "common_name": rec.common_name, "not_after": rec.not_after}

    def revoke(self, b):
        serial, reason = text(b, "serial", 64), text(b, "reason", 40, required=False) or "unspecified"
        ca = self.ca()
        ca.revoke(serial, reason)
        r = ca.find(serial)
        self.audit("revoke", {"serial": r.serial, "common_name": r.common_name, "reason": reason})
        return {"revoked": r.serial}

    def renew(self, b):
        ca = self.ca()
        r = ca.find(text(b, "serial", 64))
        if not r.path:
            raise ValueError("this certificate was signed from a request (CSR, EST or ACME); its key is with whoever asked for it, so renew it there")
        current = self._files(r)[0]
        if current != r.serial:
            raise ValueError(f"{r.common_name}'s folder already holds a newer certificate ({current}); renew that one")
        _, new = ca.renew(r.serial, out=r.path)
        self.audit("renew", {"serial": r.serial, "new_serial": new.serial, "common_name": r.common_name})
        return {"renewed": r.serial, "serial": new.serial, "not_after": new.not_after}

    def maintain(self):
        renewed, skipped = self.ca().maintain()
        self.audit("maintain", {"renewed": [r.serial for r in renewed]})
        return {"renewed": [r.common_name for r in renewed], "skipped": [r.common_name for r in skipped]}

    @staticmethod
    def _files(r):
        """The serial of the certificate now in the record's folder, and the folder."""
        folder = Path(r.path)
        try:
            cert = x509.load_pem_x509_certificate((folder / "cert.pem").read_bytes())
        except (OSError, ValueError):
            raise ValueError(f"the files for {r.common_name} are no longer in {folder}") from None
        return format(cert.serial_number, "x"), folder

    def download(self, b):
        """A zip with the certificate, its chain and the CA certificate; the private key only when asked for, never for a revoked
        or encrypted-key certificate, and the download is audited."""
        ca = self.ca()
        r = ca.find(text(b, "serial", 64))
        with_key = b.get("key") is True
        if not r.path:
            raise ValueError("this certificate was signed from a request (CSR, EST or ACME); the console has no files for it")
        current, folder = self._files(r)
        if current != r.serial:
            raise ValueError(f"this certificate was renewed; its folder now holds {current}, download that one")
        if with_key and r.status == "revoked":
            raise ValueError("this certificate is revoked; its key is not handed out")
        if with_key and encrypted(folder / "key.pem"):
            raise ValueError("this key is encrypted with a passphrase; copy it from the CA machine")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name in ("cert.pem", "chain.pem") + (("key.pem",) if with_key else ()):
                z.writestr(name, (folder / name).read_bytes())
            z.writestr("ca.crt", ca.anchor.read_bytes())
        self.audit("download", {"serial": r.serial, "common_name": r.common_name, "key": with_key})
        return Download(f"{r.common_name}-{r.serial[:8]}.zip".replace("/", "_"), buf.getvalue())

    def test(self, b):
        """Connect to host:port as a client of this CA: what was negotiated, or why it failed and what the server offers instead."""
        target = text(b, "target", 300)
        host, port = tls.hostport(target, "")
        if not host:
            raise ValueError("expected host:port, e.g. localhost:8443")
        policy = text(b, "policy", 20, required=False) or "strict"
        if policy not in tls.POLICIES:
            raise ValueError(f"policy must be one of {', '.join(tls.POLICIES)}")
        server_name = text(b, "server_name", 255, required=False) or None
        ca = self.ca()
        cert = key = None
        serial = text(b, "client", 64, required=False)
        if serial:
            r = ca.find(serial)
            if r.kind == "server":
                raise ValueError(f"{r.common_name} is a server certificate; choose a client or site certificate")
            if not r.path:
                raise ValueError("the console has no key for that certificate")
            folder = self._files(r)[1]
            if encrypted(folder / "key.pem"):
                raise ValueError("that client's key is encrypted; test it from the command line")
            cert, key = str(folder / "chain.pem"), str(folder / "key.pem")
        started = time.monotonic()
        out = {"target": target, "policy": policy, "client": serial or None, "client_status": r.status if serial else None}
        try:
            conn = tls.connect(host, port, tls.client_context(str(ca.anchor), cert, key, policy), server_name, 5.0)
            with conn:
                out |= {"ok": True, **self._named(conn.info()), "ms": round((time.monotonic() - started) * 1000)}
                refused = self._accepted(conn)
                if refused:
                    out |= {"ok": False, "refused_after_handshake": True, "error": refused}
        except (tls.TLSError, OSError) as e:
            out |= {"ok": False, "error": explain(e) if isinstance(e, OSError) else str(e), "offers": self._probe(host, port, server_name),
                    "ms": round((time.monotonic() - started) * 1000)}
        out["quantum_safe"] = out.get("group") in PQ_GROUPS
        self.audit("test", {"target": target, "ok": out["ok"], "client": out["client"]})
        return out

    @staticmethod
    def _accepted(conn):
        """In TLS 1.3 the server checks a client certificate after the client's side of the handshake is done, so a refusal
        arrives on the first read: an alert, or the connection closing. Silence means the server is waiting for a request."""
        try:
            data = conn.recv(timeout=0.8)
        except tls.TLSError as e:
            if "timed out" in str(e):
                return None
            return str(e)
        if data == b"":
            return ("the server closed the connection right after the handshake: either it refused the client certificate "
                    "(missing, untrusted or revoked), or the service behind it is down")
        return None

    @staticmethod
    def _named(info):
        return info | {"peer_key": KEYS.get(info["peer_key"], info["peer_key"])}

    @staticmethod
    def _probe(host, port, server_name):
        """What the server negotiates with an unverified, anything-goes client: tells 'classical only' from 'wrong CA'."""
        try:
            with tls.connect(host, port, tls.client_context(policy_name="transition", verify=False), server_name, 3.0) as c:
                return App._named(c.info())
        except (tls.TLSError, OSError):
            return None


class Download:
    def __init__(self, name, data):
        self.name, self.data = name, data


def page():
    return resources.files(__package__).joinpath("console.html").read_bytes()


def policy(html):
    """The page's one inline script is allowed by its hash, so no other script can run even if markup were ever injected."""
    script = html.split(b"<script>", 1)[1].split(b"</script>", 1)[0]
    digest = base64.b64encode(hashlib.sha256(script).digest()).decode()
    return (f"default-src 'self'; img-src 'self' data:; font-src data:; style-src 'self' 'unsafe-inline'; script-src 'sha256-{digest}'; "
            "frame-ancestors 'none'; form-action 'none'; base-uri 'none'")


class Backoff:
    """After 10 wrong tokens from one address within a minute, that address is refused until the minute is over."""

    def __init__(self, limit=10, window=60.0):
        self.limit, self.window, self.lock, self.failures = limit, window, threading.Lock(), {}

    def blocked(self, addr):
        with self.lock:
            recent = [t for t in self.failures.pop(addr, []) if time.monotonic() - t < self.window]
            if recent:
                self.failures[addr] = recent
            return len(recent) >= self.limit

    def failed(self, addr):
        with self.lock:
            self.failures.setdefault(addr, []).append(time.monotonic())


class Handler(BaseHTTPRequestHandler):
    """A loopback JSON API behind one HTML page: every answer uncached, unsniffable and under the page's CSP."""
    csp = ""

    def reply(self, status, body, ctype="application/json", extra=()):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.send_response(status)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                     ("Referrer-Policy", "no-referrer"), ("X-Frame-Options", "DENY"), ("Content-Security-Policy", self.csp), *extra):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def authorised(self, token):
        return hmac.compare_digest(self.headers.get("Authorization", "").removeprefix("Bearer ").encode(), token.encode())

    def json_body(self, limit):
        """The request's JSON object, or the (status, error) to answer instead."""
        n = content_length(self.headers)
        if n is None:
            return 400, {"error": "bad Content-Length"}
        if n > limit:
            return 413, {"error": "request too large"}
        try:
            body = json.loads(self.rfile.read(n)) if n else {}
        except ValueError:
            return 400, {"error": "invalid JSON"}
        return body if isinstance(body, dict) else (400, {"error": "the body must be a JSON object"})

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)


def serve(app):
    html = page()
    backoff = Backoff()

    class Console(Handler):
        csp, server_version, timeout = policy(html), f"{NAME}/{__version__}", HTTP_IDLE

        def route(self, method):
            path = self.path.split("?")[0]
            if method == "GET" and path in ("/", "/index.html"):
                return self.reply(200, html, "text/html; charset=utf-8")
            if not path.startswith("/api/"):
                return self.reply(404, {"error": "not found"})
            if backoff.blocked(self.client_address[0]):
                return self.reply(429, {"error": "too many wrong tokens; wait a minute"})
            if not self.authorised(app.token):
                backoff.failed(self.client_address[0])
                return self.reply(401, {"error": "missing or wrong token"})
            body = self.json_body(1 << 20)
            status, out = app.handle(method, path, body) if isinstance(body, dict) else body
            if isinstance(out, Download):
                return self.reply(status, out.data, "application/zip", [("Content-Disposition", f'attachment; filename="{out.name}"')])
            self.reply(status, out)

    return ThreadingHTTPServer(tls.hostport(app.s.listen, "127.0.0.1"), Console)
