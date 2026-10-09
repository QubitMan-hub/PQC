"""Replay: an attacker who recorded every byte a legitimate client sent, and sends them again on a new connection, gets
nothing done. The edge and EST both run on tls.server.Server, so this covers them all; ACME nonces,
one-time EST tokens and older CRLs have their own replay tests (test_acme, test_est, test_changes)."""
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from pqc import tls
from pqc.pki import CA
from pqc.tls.server import Server
from tests.helpers import REASON, wait


class Recorder:
    """A TCP relay that keeps a copy of every byte the client sends."""

    def __init__(self, target):
        self.target, self.sent = target, b""
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        client, _ = self.sock.accept()
        upstream = socket.create_connection(self.target)

        def pipe(a, b, keep):
            try:
                while data := a.recv(65536):
                    if keep:
                        self.sent += data
                    b.sendall(data)
                b.shutdown(socket.SHUT_WR)
            except OSError:  # the other side closed first
                pass
        threading.Thread(target=pipe, args=(upstream, client, False), daemon=True).start()
        pipe(client, upstream, True)


@unittest.skipIf(REASON, REASON)
class ReplayTest(unittest.TestCase):
    def setUp(self):
        d = Path(tempfile.mkdtemp())
        self.ca = CA.init(d / "pki", "Root")
        srv, _ = self.ca.issue("localhost", "server", ["127.0.0.1"], out=d / "srv")
        self.client_dir, _ = self.ca.issue("laptop", "client", out=d / "laptop")
        self.cafile = d / "pki" / "ca.crt"
        self.requests = []

        def handler(conn, addr):
            data = conn.recv(timeout=5)
            self.requests.append(data)
            conn.sendall(b"done: " + data)
        make = lambda: tls.server_context(srv / "chain.pem", srv / "key.pem", str(self.cafile), True)
        self.server = Server(("127.0.0.1", 0), make, handler, crl=str(d / "pki" / "crl.pem"), ca=str(self.cafile), handshake_timeout=5)
        self.server.start()
        self.addCleanup(self.server.stop, 1)

    def test_a_recorded_session_sent_again_is_refused_and_does_nothing(self):
        rec = Recorder(("127.0.0.1", self.server.port))
        ctx = tls.client_context(self.cafile, self.client_dir / "chain.pem", self.client_dir / "key.pem")
        with tls.connect("127.0.0.1", rec.port, ctx, "localhost", 5) as c:
            c.sendall(b"transfer 100 to alice")
            self.assertEqual(c.recv(timeout=5), b"done: transfer 100 to alice")
        self.assertTrue(wait(lambda: self.requests == [b"transfer 100 to alice"]))
        time.sleep(0.2)
        recorded = rec.sent
        for attempt in range(3):
            with self.subTest(attempt=attempt), socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as raw:
                raw.sendall(recorded)
                raw.shutdown(socket.SHUT_WR)
                answer = b""
                try:
                    while chunk := raw.recv(65536):
                        answer += chunk
                except OSError:
                    pass
                self.assertNotIn(b"done:", answer)
        time.sleep(0.5)
        self.assertEqual(self.requests, [b"transfer 100 to alice"], "a replayed session reached the application")
        self.assertGreaterEqual(self.server.stats.snapshot()["handshake_failed"], 3)

    def test_no_early_data_so_nothing_is_accepted_before_the_handshake_completes(self):
        ctx = tls.client_context(self.cafile, self.client_dir / "chain.pem", self.client_dir / "key.pem")
        for _ in range(2):  # a second connection could resume a session; neither may carry 0-RTT data
            with tls.connect("127.0.0.1", self.server.port, ctx, "localhost", 5) as c:
                c.sendall(b"ping")
                self.assertEqual(c.recv(timeout=5), b"done: ping")
        from pqc.tls.openssl import PROTOTYPES
        bound = [name for table in PROTOTYPES.values() for name, _, _ in table]
        # OpenSSL refuses 0-RTT unless max_early_data is set; the bridge binds no early-data call at all
        self.assertFalse([n for n in bound if "early_data" in n], "TLS 1.3 early data (replayable 0-RTT) must stay off")


if __name__ == "__main__":
    unittest.main()
