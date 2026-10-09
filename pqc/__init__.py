import json
import logging
import math
import os
import re
import socket
import sys
import threading
import time
import tomllib
from dataclasses import MISSING
from pathlib import Path

NAME = "pqc"
__version__ = "0.1.0"
HTTP_IDLE = 30  # seconds an HTTP client may stay silent before its connection is closed
RELEASES = "https://api.github.com/repos/QubitMan-hub/PQC/releases?per_page=50"

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401
except ImportError:
    import cryptography
    raise ImportError(f"pqc needs cryptography 49 or newer for ML-KEM and ML-DSA, and this Python has {cryptography.__version__}: "
                      "pip install --upgrade 'cryptography>=49'") from None


def build(cls, d, where, **extra):
    """A settings dataclass from a TOML table, with clear errors for unknown, missing and mistyped settings."""
    fields = cls.__dataclass_fields__
    unknown = set(d) - set(fields)
    if unknown:
        raise ValueError(f"{where}: unknown settings {', '.join(sorted(unknown))}")
    missing = [n for n, f in fields.items() if n not in d and n not in extra and f.default is MISSING and f.default_factory is MISSING]
    if missing:
        raise ValueError(f"{where}: missing {', '.join(missing)}")
    for k, v in d.items():
        t = fields[k].type
        t = {"str": str, "int": int, "float": float, "bool": bool, "list": list, "dict": dict}.get(t, t)
        ok = isinstance(v, (int, float)) and not isinstance(v, bool) if t is float else isinstance(v, t) if isinstance(t, type) else True
        if t is int and isinstance(v, bool):
            ok = False
        if not ok:
            kind = {str: "text in quotes", int: "a whole number", float: "a number", bool: "true or false", list: "a list", dict: "a table"}
            raise ValueError(f"{where}: {k} must be {kind.get(t, t.__name__)}, not {v!r}")
        if t is float:
            try:
                finite = math.isfinite(v)
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError(f"{where}: {k} must be a finite number, not {v!r}")
    return cls(**d, **extra)


def read_text(path):
    """A text file as Windows tools save it too: UTF-8 with or without a byte-order mark, or UTF-16 (PowerShell 5 redirection)."""
    data = Path(path).read_bytes()
    for bom, codec in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if data.startswith(bom):
            return data.decode(codec)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"{path} is not UTF-8 text; save it as UTF-8") from None


def read_toml(path):
    try:
        return tomllib.loads(read_text(path))
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"{path}: {e}") from None


def env_passphrase(var):
    """The passphrase in environment variable `var`, None when no variable is named."""
    if not var:
        return None
    if var not in os.environ:
        raise ValueError(f"environment variable {var} is not set")
    return os.environ[var].encode()


def explain(e):
    """An OSError in words: 'host not found' rather than '[Errno -2] Name or service not known'."""
    if isinstance(e, socket.gaierror):
        return "host not found (not in DNS or the hosts file)"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused (nothing is listening on that port)"
    if isinstance(e, TimeoutError):
        return "no answer (timed out; is a firewall dropping it?)"
    if isinstance(e, ConnectionResetError):
        return "the connection was reset by the other side"
    if isinstance(e, OSError) and e.strerror:
        return f"{e.strerror}: {e.filename}" if e.filename else e.strerror
    return str(e)


METRICS, JSON, PEM = "text/plain; version=0.0.4; charset=utf-8", "application/json", "application/x-pem-file"


def serve_http(address, routes):
    """Answers GET on a background thread. `routes` maps a path to (content type, function returning the body as text, or
    None for 404); /healthz always answers ok."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from .tls import hostport
    routes = {"/healthz": ("text/plain; charset=utf-8", lambda: "ok\n"), **routes}

    class Handler(BaseHTTPRequestHandler):
        timeout = HTTP_IDLE

        def do_GET(self):
            ctype, fn = routes.get(self.path, (None, lambda: None))
            body = fn()
            if body is None:
                self.send_error(404)
                return
            body = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(hostport(address, "127.0.0.1"), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def content_length(headers):
    """An HTTP request's body length, or None unless the header is a plain non-negative number (int() would accept "-1",
    and reading -1 bytes reads until the client stops sending)."""
    values = headers.get_all("Content-Length", []) if hasattr(headers, "get_all") else [headers.get("Content-Length", "0")]
    if len(values) > 1 or headers.get("Transfer-Encoding"):
        return None
    v = values[0] if values else "0"
    return int(v) if 0 < len(v) <= 20 and v.isascii() and v.isdigit() else None


def file_stamp(path):
    """What changes when a file is rewritten, even twice within one timestamp tick: its mtime in ns, size and inode."""
    st = os.stat(path)
    return st.st_mtime_ns, st.st_size, st.st_ino


class ConfigWatch:
    """Follows a service's configuration file: when it changes (checked every few seconds) or on `poke()` (SIGHUP), the file
    is loaded again once it has stopped changing (an editor may write it in several steps) and, if it loads and validates,
    handed to `apply`. A file that does not load is logged and the running configuration stays as it is."""

    def __init__(self, path, load, apply, every=5.0, settle=0.3):
        self.path, self.load, self.apply, self.every, self.settle = path, load, apply, every, settle
        self.seen = file_stamp(self.path)
        self.wake, self.stopped = threading.Event(), False
        threading.Thread(target=self._loop, daemon=True, name="config").start()

    def poke(self):
        self.wake.set()

    def stop(self):
        self.stopped = True
        self.wake.set()

    def _loop(self):
        log = logging.getLogger(NAME)
        while True:
            poked = self.wake.wait(self.every)
            self.wake.clear()
            if self.stopped:
                return
            try:
                stamp = file_stamp(self.path)
                if stamp == self.seen and not poked:
                    continue
                while True:
                    time.sleep(self.settle)
                    now = file_stamp(self.path)
                    if now == stamp:
                        break
                    stamp = now
                self.seen = stamp
                new = self.load(self.path)
            except Exception as e:
                log.error("%s changed but cannot be used, keeping the running configuration: %s", self.path, e)
                continue
            log.info("%s changed; applying it", self.path)
            try:
                self.apply(new)
            except Exception:
                log.exception("applying %s failed", self.path)


def restart():
    """Replace this process with a fresh run of the same command (same PID, so systemd and supervisors keep following it)."""
    logging.getLogger(NAME).info("restarting to apply the new configuration")
    logging.shutdown()
    os.execv(sys.executable, [sys.executable, "-m", NAME, *sys.argv[1:]])


def latest_release(url=None, timeout=10):
    """The newest published release (tags vX.Y.Z) from GitHub, or from PQC_RELEASES_URL (a
    mirror inside your network). None when there is none. Nothing calls this unless asked to."""
    import http.client
    import urllib.request
    url = url or os.environ.get("PQC_RELEASES_URL") or RELEASES
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"the releases address must start with http:// or https://, not {url!r}")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = json.loads(r.read(5 << 20))
    except http.client.HTTPException as e:
        raise OSError(f"the releases address did not answer in HTTP: {e!r}") from None
    if not isinstance(data, list):
        raise ValueError("the releases address did not return a list of releases")
    found = [(tuple(map(int, m.groups())), r) for r in data if isinstance(r, dict) and not r.get("draft") and not r.get("prerelease")
             and (m := re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", str(r.get("tag_name", ""))))]
    if not found:
        return None
    v, r = max(found, key=lambda x: x[0])
    return {"version": ".".join(map(str, v)), "url": r.get("html_url", ""), "newer": v > tuple(map(int, __version__.split(".")))}
