"""A threaded PQC TLS 1.3 server: connection limits, handshake timeouts, CRL checks, certificate hot-reload and stats."""
import logging
import os
import socket
import threading
import time
from collections import Counter
from pathlib import Path

from cryptography import x509

from .. import file_stamp
from ..pki import CAError, check_revocation, shared
from .openssl import TLSError

log = logging.getLogger("pqc.tls")


HINTS = {  # OpenSSL's words for the two ways a client without post-quantum support is refused
    "no shared signature algorithms": " (the client cannot verify ML-DSA certificates, as browsers today: use policy transition with a "
                                      "fallback certificate)",
    "no suitable key share": " (the client offers no post-quantum key exchange: update it, or use policy transition)",
}


class Revocation:
    """Checks client certificates against a CRL file, re-reading it whenever it changes. Fails closed."""

    def __init__(self, crl_path, ca_path):
        if not os.path.isfile(crl_path):
            raise ValueError(f"no CRL at {crl_path}: write one with 'pqc ca crl' (every client would be refused without it)")
        with open(ca_path, "rb") as f:
            self.crl_path, self.cas = crl_path, x509.load_pem_x509_certificates(f.read())
        self.stamp, self.data = None, None

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
                 handshake_timeout=10.0, name="tls", reuse_port=False):
        self.address, self.make_context, self.handler, self.name = address, make_context, handler, name
        self.ctx = make_context()
        self.watch = {p: file_stamp(p) for p in watch if p}
        self.revocation = Revocation(crl, ca) if crl else None
        self.slots = threading.BoundedSemaphore(max_connections)
        self.max_connections, self.per_host = max_connections, max(8, max_connections // 16)
        self.lock, self.handshaking = threading.Lock(), Counter()
        self.handshake_timeout = handshake_timeout
        self.stats = Stats()
        self.stopping = threading.Event()
        self.threads = set()
        self.sock = socket.create_server(address, reuse_port=reuse_port, backlog=128)
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
            try:
                sock, addr = self.sock.accept()
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
                log.warning("%s: refusing %s, connection limit reached", self.name, addr[0])
                sock.close()
                continue
            if not self._admit(addr[0]):
                self.slots.release()
                self.stats.add("refused_host")
                log.warning("%s: refusing %s, too many unfinished handshakes from it", self.name, addr[0])
                sock.close()
                continue
            t = threading.Thread(target=self._run, args=(sock, addr, self.ctx), daemon=True)
            with self.lock:
                self.threads.add(t)
            t.start()

    def _admit(self, host):
        """Once half the connections are taken, a host with `per_host` handshakes still unfinished waits, so one machine
        opening sockets and sending nothing cannot lock everyone else out."""
        with self.lock:
            if self.handshaking[host] >= self.per_host and len(self.threads) >= self.max_connections // 2:
                return False
            self.handshaking[host] += 1
            return True

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
                log.warning("%s: rejected %s: %s%s", self.name, peer, e, hint)
                return
            finally:
                self._handshake_over(addr[0])
            info = conn.info()
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
                conn.close()
            else:
                sock.close()
            self.slots.release()
            with self.lock:
                self.threads.discard(threading.current_thread())

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
