"""A threaded PQC TLS 1.3 server: connection limits, handshake timeouts, CRL checks, certificate hot-reload and stats."""
import ipaddress
import logging
import os
import socket
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from cryptography import x509

from .. import file_stamp
from ..pki import CAError, check_revocation, shared
from . import nodelay
from .openssl import TLSError

log = logging.getLogger("pqc.tls")


HINTS = {  # OpenSSL's words for the two ways a client without post-quantum support is refused
    "no shared signature algorithms": " (the client cannot verify ML-DSA certificates, as browsers today: use policy transition with a "
                                      "fallback certificate)",
    "no suitable key share": " (the client offers none of the key exchanges this policy allows: strict needs a post-quantum hybrid "
                             "such as X25519MLKEM768, cnsa2 needs ML-KEM-1024; update the client, or use policy transition)",
}


def open_files(needed):
    """Raise this process's open-file limit to its hard limit (systemd starts services with a soft limit of 1024, enough
    for only about 500 connections), and warn when `needed` still does not fit. None where there is no such limit."""
    try:
        import resource
    except ImportError:
        return None  # Windows: no per-process descriptor limit for sockets
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    for target in (hard, 65536, 10240):
        if target == resource.RLIM_INFINITY and sys.platform == "darwin":
            continue  # macOS accepts "unlimited" but its kernel caps descriptors far lower, silently
        if soft != resource.RLIM_INFINITY and (target == resource.RLIM_INFINITY or target > soft):
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
                soft = target
                break
            except (ValueError, OSError):
                continue
    if soft != resource.RLIM_INFINITY and needed > soft:
        log.warning("this process may open only %d files but its connection limits need about %d (two per connection); "
                    "raise LimitNOFILE (systemd) or ulimit -n, or lower max_connections", soft, needed)
    return soft


def is_loopback(host):
    """Connections from this machine (a sidecar, a health check, a local tunnel) are not rate-limited."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Revocation:
    """Checks client certificates against a CRL file, re-reading it whenever it changes. Fails closed."""

    def __init__(self, crl_path, ca_path):
        if not os.path.isfile(crl_path):
            raise ValueError(f"no CRL at {crl_path}: write one with 'pqc ca crl' (every client would be refused without it)")
        with open(ca_path, "rb") as f:
            self.crl_path, self.cas = crl_path, x509.load_pem_x509_certificates(f.read())
        self.stamp, self.data, self.swept = None, None, file_stamp(crl_path)

    def changed_since_sweep(self):
        m = file_stamp(self.crl_path)
        if m == self.swept:
            return False
        self.swept = m
        return True

    def check(self, serial, chain=()):
        """`chain` is the verified chain above the certificate, where an intermediate CA's certificate comes from."""
        m = file_stamp(self.crl_path)
        if m != self.stamp:
            self.data, self.stamp = shared(Path(self.crl_path).read_bytes), m
        check_revocation(serial, self.data, self.cas + list(chain))


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts, self.groups, self.active = Counter(), Counter(), 0

    def add(self, key, n=1):
        with self.lock:
            self.counts[key] += n

    def opened(self, group):
        with self.lock:
            self.counts["handshakes"] += 1
            self.groups[group] += 1
            self.active += 1

    def closed(self):
        with self.lock:
            self.active -= 1

    def snapshot(self):
        with self.lock:
            return {"active": self.active, **self.counts, "groups": dict(self.groups)}


class Server:
    """Accepts TCP connections, runs the PQC handshake, and hands each verified Connection to `handler(conn, address)`.

    `make_context` is called again whenever a watched file (certificate, key, CA) changes, so renewed certificates take effect
    without a restart. Existing connections keep the context they started with.
    """

    def __init__(self, address, make_context, handler, watch=(), crl=None, ca=None, max_connections=512,
                 handshake_timeout=10.0, name="tls", reuse_port=False, max_per_client=0, max_rate_per_client=50.0):
        self.address, self.make_context, self.handler, self.name = address, make_context, handler, name
        self.ctx = make_context()
        self.watch = {p: file_stamp(p) for p in watch if p}
        self.revocation = Revocation(crl, ca) if crl else None
        self.slots = threading.BoundedSemaphore(max_connections)
        self.max_connections, self.per_host = max_connections, max(8, max_connections // 16)
        self.per_client = max_per_client or max(16, max_connections // 8)
        self.lock, self.handshaking, self.open = threading.Lock(), Counter(), Counter()
        self.rate, self.buckets, self.warned = max_rate_per_client, {}, {}
        self.handshake_timeout = handshake_timeout
        self.stats = Stats()
        self.stopping = threading.Event()
        self.threads = set()
        self.live = {}  # connection -> (client certificate serial, chain above it), for closing revoked ones
        self.sock = socket.create_server(address, reuse_port=reuse_port, backlog=1024)
        self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1]

    def reload_if_changed(self):
        """Rebuild the context when a watched file changed. A missing or broken file keeps the old context serving."""
        try:
            changed = [p for p, m in self.watch.items() if file_stamp(p) != m]
            if not changed:
                return False
            ctx = self.make_context()
            self.watch = {p: file_stamp(p) for p in self.watch}
        except (TLSError, OSError, ValueError) as e:
            log.error("%s: keeping the old certificates, reload failed: %s", self.name, e)
            self.stats.add("reload_failed")
            return False
        self.ctx = ctx
        log.info("%s: reloaded certificates after %s changed", self.name, ", ".join(map(str, changed)))
        self.stats.add("reloads")
        return True

    def serve_forever(self):
        log.info("%s: listening on %s:%d", self.name, self.address[0] or "*", self.port)
        last_watch = time.monotonic()
        while not self.stopping.is_set():
            if time.monotonic() - last_watch > 5:
                self.reload_if_changed()
                last_watch = time.monotonic()
            self.close_revoked()
            try:
                sock, addr = self.sock.accept()
                nodelay(sock)
            except (socket.timeout, TimeoutError):
                continue
            except OSError as e:
                if self.stopping.is_set():
                    break
                self.stats.add("accept_failed")
                log.error("%s: accept failed, retrying: %s", self.name, e)
                time.sleep(0.5)
                continue
            if not self.slots.acquire(blocking=False):
                self.stats.add("refused_busy")
                self._refuse(addr[0], "connection limit reached")
                sock.close()
                continue
            refused = self._admit(addr[0])
            if refused:
                self.slots.release()
                self.stats.add("refused_host")
                self._refuse(addr[0], refused)
                sock.close()
                continue
            t = threading.Thread(target=self._run, args=(sock, addr, self.ctx), daemon=True)
            with self.lock:
                self.threads.add(t)
            t.start()

    def close_revoked(self):
        """When the CRL changes, close open connections whose client certificate it now revokes: a stolen device holding a
        long-lived connection (a database pool, MQTT, a tunnel) is cut off within a second or two, not at its next reconnect."""
        try:
            if not (self.revocation and self.revocation.changed_since_sweep()):
                return
        except OSError:
            return  # the CRL file is being replaced; the next pass sees it
        with self.lock:
            live = list(self.live.items())
        for conn, (serial, chain) in live:
            try:
                self.revocation.check(serial, chain)
            except (CAError, ValueError, OSError) as e:
                log.warning("%s: closing %s, its certificate is no longer accepted: %s", self.name, conn.peer_name, e)
                self.stats.add("revoked_closed")
                try:
                    conn.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _admit(self, host):
        """None, or why `host` waits. An address opens at most `rate` connections a second (bursts of twice that): a handshake
        costs milliseconds of CPU, so one machine reconnecting as fast as it can would otherwise take nearly all of it and
        slow everyone else's new connections 40-fold. Once half the connections are taken, an address with `per_host` handshakes unfinished, or
        `per_client` connections open, gets no more: one machine opening connections and sending nothing, before or after the
        handshake, cannot lock everyone else out. Below half, a busy partner behind one NAT address is not held back."""
        with self.lock:
            if self.rate and not is_loopback(host) and not self._take(host):
                return f"it opens more than {self.rate:g} connections a second (max_rate_per_client)"
            if len(self.threads) >= self.max_connections // 2:
                if self.handshaking[host] >= self.per_host:
                    return "too many unfinished handshakes from it"
                if self.open[host] >= self.per_client:
                    return f"it already holds {self.open[host]} connections (max_per_client)"
            self.handshaking[host] += 1
            self.open[host] += 1
            return None

    def _take(self, host):
        """Token bucket per address; called under the lock. Addresses quiet for a minute are forgotten."""
        t = time.monotonic()
        tokens, last = self.buckets.get(host, (2 * self.rate, t))
        tokens = min(2 * self.rate, tokens + (t - last) * self.rate)
        if len(self.buckets) > 10000:
            self.buckets = {h: v for h, v in self.buckets.items() if t - v[1] < 60}
        self.buckets[host] = (tokens - 1, t) if tokens >= 1 else (tokens, t)
        return tokens >= 1

    def _refuse(self, host, why):
        self._warn(host, "refusing", f"refusing {host}, {why}", why.split(" ", 1)[0])

    def _warn(self, host, kind, message, reason=""):
        """One warning per address and kind every 10 seconds: a flood is refused without filling the disk with log lines."""
        key, t = (host, kind, reason), time.monotonic()
        with self.lock:
            quiet = t - self.warned.get(key, -60) >= 10
            if quiet:
                self.warned[key] = t
                if len(self.warned) > 10000:
                    self.warned = {k: v for k, v in self.warned.items() if t - v < 60}
        if quiet:
            log.warning("%s: %s (repeats from this address are counted in /status, not logged, for 10 s)", self.name, message)

    def _handshake_over(self, host):
        with self.lock:
            self.handshaking[host] -= 1
            if not self.handshaking[host]:
                del self.handshaking[host]

    def _run(self, sock, addr, ctx):
        peer = f"{addr[0]}:{addr[1]}"
        conn = None
        try:
            try:
                conn = ctx.wrap(sock, timeout=self.handshake_timeout)
                cert = conn.peer_certificate()
                if self.revocation and cert:
                    self.revocation.check(cert.serial_number, conn.peer_chain()[1:])
            except (TLSError, CAError, OSError, ValueError) as e:
                if any(x in str(e) for x in ("Broken pipe", "Connection reset")):
                    self.stats.add("client_left")
                    log.info("%s: %s closed the connection during the handshake", self.name, peer)
                    return
                self.stats.add("handshake_failed")
                hint = next((h for k, h in HINTS.items() if k in str(e)), "")
                self._warn(addr[0], "rejected", f"rejected {peer}: {e}{hint}")
                return
            finally:
                self._handshake_over(addr[0])
            info = conn.info()
            if self.revocation and cert:
                conn.peer_name = peer
                with self.lock:
                    self.live[conn] = (cert.serial_number, conn.peer_chain()[1:])
            self.stats.opened(info["group"])
            log.info("%s: %s %s %s %s peer=%s", self.name, peer, info["version"], info["group"], info["cipher"], info["peer"] or "-")
            try:
                self.handler(conn, addr)
            except (TLSError, OSError) as e:
                log.info("%s: %s closed: %s", self.name, peer, e)
            except Exception:
                self.stats.add("handler_failed")
                log.exception("%s: %s: handler failed", self.name, peer)
            finally:
                self.stats.closed()
        finally:
            if conn:
                with self.lock:
                    self.live.pop(conn, None)
                conn.close()
            else:
                sock.close()
            self.slots.release()
            with self.lock:
                self.threads.discard(threading.current_thread())
                self.open[addr[0]] -= 1
                if not self.open[addr[0]]:
                    del self.open[addr[0]]

    def start(self):
        t = threading.Thread(target=self.serve_forever, daemon=True, name=self.name)
        t.start()
        return t

    def stop(self, grace=10.0):
        """Stop accepting, then give open connections up to `grace` seconds to finish."""
        self.stopping.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        deadline = time.monotonic() + grace
        with self.lock:
            threads = list(self.threads)
        for t in threads:
            t.join(max(0, deadline - time.monotonic()))
