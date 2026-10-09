"""Just enough HTTP/1.1 over a PQC TLS Connection for the EST enrollment service: one request per connection."""
import logging
import time

log = logging.getLogger("pqc.http")
MAX_HEAD, MAX_BODY = 16384, 1 << 20
REASONS = {200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
           405: "Method Not Allowed", 409: "Conflict", 413: "Payload Too Large", 500: "Internal Server Error"}


class HTTPError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def _read_message(conn, timeout):
    """One message within `timeout` seconds in total, so a client trickling a byte at a time cannot hold the connection."""
    deadline = time.monotonic() + timeout
    left = lambda: max(0.0, deadline - time.monotonic())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096, timeout=left())
        if not chunk:
            raise HTTPError(400, "connection closed before the headers ended")
        buf += chunk
        if len(buf) > MAX_HEAD:
            raise HTTPError(413, "headers too large")
    head, body = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if not sep:
            raise HTTPError(400, "malformed header")
        headers[k.strip().lower()] = v.strip()
    try:
        n = int(headers.get("content-length", "0"))
    except ValueError:
        raise HTTPError(400, "bad Content-Length") from None
    if n > MAX_BODY or n < 0:
        raise HTTPError(413, "body too large")
    while len(body) < n:
        chunk = conn.recv(min(65536, n - len(body)), timeout=left())
        if not chunk:
            raise HTTPError(400, "connection closed inside the body")
        body += chunk
    return lines[0], headers, body[:n]


def read_request(conn, timeout=15):
    first, headers, body = _read_message(conn, timeout)
    parts = first.split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise HTTPError(400, "malformed request line")
    return parts[0], parts[1], headers, body


def send_response(conn, status, body=b"", headers=None):
    head = [f"HTTP/1.1 {status} {REASONS.get(status, 'Status')}", f"Content-Length: {len(body)}", "Connection: close", "Cache-Control: no-store"]
    head += [f"{k}: {v}" for k, v in (headers or {}).items()]
    conn.sendall(("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body)


def request(conn, method, path, host, body=b"", headers=None, timeout=15):
    """Send one request and return (status, headers, body)."""
    head = [f"{method} {path} HTTP/1.1", f"Host: {host}", f"Content-Length: {len(body)}", "Connection: close"]
    head += [f"{k}: {v}" for k, v in (headers or {}).items()]
    conn.sendall(("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body)
    first, rheaders, rbody = _read_message(conn, timeout)
    try:
        status = int(first.split(" ")[1])
    except (IndexError, ValueError):
        raise HTTPError(502, f"malformed response {first!r}") from None
    return status, rheaders, rbody


def handler(app):
    """Adapt `app(method, path, headers, body, conn) -> (status, body, headers)` to a tls.server.Server handler."""
    def handle(conn, addr):
        try:
            method, path, headers, body = read_request(conn)
            status, out, extra = app(method, path, headers, body, conn)
        except HTTPError as e:
            status, out, extra = e.status, str(e).encode(), {"Content-Type": "text/plain"}
        except Exception:
            log.exception("http: request from %s failed", addr[0])
            status, out, extra = 500, b"internal error; see the server log", {"Content-Type": "text/plain"}
        send_response(conn, status, out, extra)
    return handle
