"""Real PQC handshakes. Needs OpenSSL 3.5+ (on Linux run with LD_LIBRARY_PATH pointing at it); skipped otherwise."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509

from pqc import tls
from pqc.pki import CA
from pqc.tls.edge import Edge, Route, metrics_text
from pqc.tls.server import Server
from tests.helpers import REASON, wait


def echo(conn, addr):
    while data := conn.recv(timeout=5):
        conn.sendall(data)


@unittest.skipIf(REASON, REASON)
class TLSTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        cls.ca = CA.init(d / "pki", "Test Root")
        cls.srv, _ = cls.ca.issue("localhost", "server", ["127.0.0.1"], passphrase=b"server-pass")
        cls.alice, _ = cls.ca.issue("alice", "client")
        cls.mallory, cls.mallory_rec = cls.ca.issue("mallory", "client")
        cls.ca.crl()
        cls.stranger = CA.init(d / "other", "Other Root")
        cls.stranger_client, _ = cls.stranger.issue("eve", "client")
        cls.cafile = str(d / "pki" / "ca.crt")
        cls.crl = str(d / "pki" / "crl.pem")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def server(self, policy="strict", mtls=False, handler=echo):
        make = lambda: tls.server_context(self.srv / "chain.pem", self.srv / "key.pem", self.cafile, mtls, policy, b"server-pass")
        s = Server(("127.0.0.1", 0), make, handler, crl=self.crl if mtls else None, ca=self.cafile, handshake_timeout=3)
        s.start()
        self.addCleanup(s.stop, 1)
        return s

    def client(self, who=None, policy="strict", ca=None):
        cert, key = (who / "chain.pem", who / "key.pem") if who else (None, None)
        return tls.client_context(ca or self.cafile, cert, key, policy)

    def roundtrip(self, port, ctx, name="localhost"):
        with tls.connect("127.0.0.1", port, ctx, name, timeout=3) as c:
            c.sendall(b"ping")
            return c.info(), c.recv(timeout=3)

    def test_a_client_without_post_quantum_support_gets_an_actionable_log_line(self):
        from pqc.tls.openssl import Context
        s = self.server()
        classical = Context(False, "X25519:secp256r1", None, tls.CIPHERSUITES, None, None, None, False)
        with self.assertLogs("pqc", "WARNING") as logs:
            with self.assertRaises(tls.TLSError):
                tls.connect("127.0.0.1", s.port, classical, "localhost", timeout=3)
            wait(lambda: any("post-quantum key exchange" in m for m in logs.output), 3)
        self.assertTrue(any("use policy transition" in m for m in logs.output), logs.output)

    def test_pqc_handshake_and_data(self):
        s = self.server()
        info, reply = self.roundtrip(s.port, self.client())
        self.assertEqual((info["version"], info["group"], info["peer_key"]), ("TLSv1.3", "X25519MLKEM768", "ML-DSA-65"))
        cert = x509.load_pem_x509_certificate((self.srv / "cert.pem").read_bytes())
        self.assertEqual(info["peer_serial"], format(cert.serial_number, "x"))
        self.assertEqual(reply, b"ping")
        self.assertEqual(s.stats.snapshot()["groups"], {"X25519MLKEM768": 1})

    def test_large_transfer(self):
        s = self.server()
        blob = bytes(range(256)) * 20000
        got = b""
        with tls.connect("127.0.0.1", s.port, self.client(), "localhost", timeout=5) as c:
            for i in range(0, len(blob), 65536):
                c.sendall(blob[i:i + 65536])
                while len(got) < min(i + 65536, len(blob)):
                    got += c.recv(timeout=5)
        self.assertEqual(got, blob)

    def test_strict_server_refuses_classical_key_exchange(self):
        s = self.server("strict")
        classical = tls.Context(False, "X25519:secp256r1", None, tls.CIPHERSUITES, ca=self.cafile)
        with self.assertRaisesRegex(tls.TLSError, "handshake failed"):
            self.roundtrip(s.port, classical)

    def test_transition_server_still_serves_classical_clients(self):
        s = self.server("transition")
        classical = tls.Context(False, "X25519", None, tls.CIPHERSUITES, ca=self.cafile)
        info, _ = self.roundtrip(s.port, classical)
        self.assertEqual(info["group"].lower(), "x25519")
        info, _ = self.roundtrip(s.port, self.client(policy="transition"))
        self.assertEqual(info["group"], "X25519MLKEM768")

    def test_certificate_must_match_the_name(self):
        s = self.server()
        self.roundtrip(s.port, self.client(), "127.0.0.1")
        with self.assertRaisesRegex(tls.TLSError, "hostname mismatch"):
            self.roundtrip(s.port, self.client(), "evil.example")

    def test_server_from_another_ca_is_rejected(self):
        s = self.server()
        with self.assertRaisesRegex(tls.TLSError, "certificate rejected"):
            self.roundtrip(s.port, self.client(ca=self.stranger.root / "ca.crt"))

    def test_mutual_tls(self):
        s = self.server(mtls=True)
        info, reply = self.roundtrip(s.port, self.client(self.alice))
        self.assertEqual(reply, b"ping")
        for who in (None, self.stranger_client):
            with self.subTest(who=who):
                with self.assertRaises((tls.TLSError, OSError)):
                    _, reply = self.roundtrip(s.port, self.client(who))
                    self.assertEqual(reply, b"")
                    raise tls.TLSError("closed")
        wait(lambda: s.stats.snapshot()["handshake_failed"] >= 2)
        self.assertGreaterEqual(s.stats.snapshot()["handshake_failed"], 2)

    def test_revoked_client_is_refused(self):
        s = self.server(mtls=True)
        self.roundtrip(s.port, self.client(self.mallory))
        self.ca.revoke(self.mallory_rec.serial, "keyCompromise")
        time.sleep(0.05)
        try:
            _, reply = self.roundtrip(s.port, self.client(self.mallory))
        except (tls.TLSError, OSError):
            reply = b""
        self.assertEqual(reply, b"")
        self.roundtrip(s.port, self.client(self.alice))

    def test_a_damaged_crl_refuses_everyone_and_says_why(self):
        crl = Path(self.tmp.name) / "damaged-crl.pem"
        crl.write_bytes(b"-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n")
        make = lambda: tls.server_context(self.srv / "chain.pem", self.srv / "key.pem", self.cafile, True, key_passphrase=b"server-pass")
        s = Server(("127.0.0.1", 0), make, echo, crl=str(crl), ca=self.cafile, handshake_timeout=3)
        s.start()
        self.addCleanup(s.stop, 1)
        with self.assertLogs("pqc", "WARNING") as logs:
            try:
                reply = self.roundtrip(s.port, self.client(self.alice))[1]
            except (tls.TLSError, OSError):
                reply = b""
            time.sleep(0.2)
        self.assertEqual(reply, b"")
        self.assertEqual(s.stats.snapshot()["handshake_failed"], 1)
        self.assertIn("CRL file is damaged", logs.output[0])

    def test_silent_client_times_out(self):
        s = self.server()
        with socket.create_connection(("127.0.0.1", s.port)) as raw:
            raw.settimeout(6)
            self.assertEqual(raw.recv(10), b"")
        for _ in range(50):  # the socket closes inside the timed-out handshake, a moment before the failure is counted
            if "handshake_failed" in s.stats.snapshot():
                break
            time.sleep(0.05)
        self.assertEqual(s.stats.snapshot()["handshake_failed"], 1)

    def test_one_host_opening_silent_sockets_cannot_lock_others_out(self):
        make = lambda: tls.server_context(self.srv / "chain.pem", self.srv / "key.pem", key_passphrase=b"server-pass")
        s = Server(("127.0.0.1", 0), make, echo, max_connections=32, handshake_timeout=10)
        s.start()
        self.addCleanup(s.stop, 1)
        silent = []
        for _ in range(64):
            c = socket.create_connection(("127.0.0.1", s.port), source_address=("127.0.0.2", 0))
            self.addCleanup(c.close)
            silent.append(c)
        time.sleep(0.5)
        self.assertEqual(self.roundtrip(s.port, self.client())[1], b"ping")
        self.assertGreater(s.stats.snapshot()["refused_host"], 0)

    def test_renewed_certificate_is_picked_up_without_restart(self):
        d = Path(self.tmp.name) / "hot"
        _, rec = self.ca.issue("localhost", "server", out=d)
        make = lambda: tls.server_context(d / "chain.pem", d / "key.pem")
        s = Server(("127.0.0.1", 0), make, echo, watch=[d / "chain.pem", d / "key.pem"])
        s.start()
        self.addCleanup(s.stop, 1)
        def serial():
            with tls.connect("127.0.0.1", s.port, self.client(), "localhost", 3) as c:
                return c.peer_certificate().serial_number
        before = serial()
        time.sleep(1.1)
        self.ca.renew(rec.serial, out=d)
        wait(lambda: serial() != before, 8)
        self.assertNotEqual(serial(), before)
        self.assertEqual(s.stats.snapshot()["reloads"], 1)
        (d / "chain.pem").rename(d / "moved.pem")
        self.assertFalse(s.reload_if_changed())
        self.assertEqual(s.stats.snapshot()["reload_failed"], 1)
        self.assertEqual(serial(), serial(), "a missing file keeps the old certificate serving")

    def test_wrong_key_passphrase_is_explained(self):
        with self.assertRaisesRegex(tls.TLSError, "passphrase"):
            tls.server_context(self.srv / "chain.pem", self.srv / "key.pem", policy_name="strict", key_passphrase=b"nope")


class Upstream(SimpleHTTPRequestHandler):
    def do_GET(self):
        body = (b"x" * 100000) if self.path == "/big" else b"hello " + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@unittest.skipIf(REASON, REASON)
class EdgeTest(unittest.TestCase):
    def test_legacy_client_through_tunnel_and_edge(self):
        d = Path(tempfile.mkdtemp())
        ca = CA.init(d / "pki", "Root")
        srv, _ = ca.issue("edge.local", "server", out=d / "edge")
        branch, _ = ca.issue("branch", "client", out=d / "branch")
        ca.crl()
        app = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=app.serve_forever, daemon=True).start()
        self.addCleanup(app.server_close)
        self.addCleanup(app.shutdown)
        def free():
            with socket.create_server(("127.0.0.1", 0)) as s:
                return s.getsockname()[1]
        edge_port, tunnel_port = free(), free()
        edge = Edge(Route("web", "terminate", f"127.0.0.1:{edge_port}", f"127.0.0.1:{app.server_address[1]}", cert=str(srv / "chain.pem"),
                          key=str(srv / "key.pem"), ca=str(d / "pki/ca.crt"), require_client_cert=True, crl=str(d / "pki/crl.pem")))
        tunnel = Edge(Route("tunnel", "originate", f"127.0.0.1:{tunnel_port}", f"127.0.0.1:{edge_port}", server_name="edge.local",
                            ca=str(d / "pki/ca.crt"), cert=str(branch / "chain.pem"), key=str(branch / "key.pem")))
        for e in (edge, tunnel):
            threading.Thread(target=e.serve_forever, daemon=True).start()
            self.addCleanup(e.stop)
        time.sleep(0.5)
        get = lambda path: urllib.request.urlopen(f"http://127.0.0.1:{tunnel_port}{path}", timeout=10).read()
        self.assertEqual(get("/a"), b"hello /a")
        with ThreadPoolExecutor(16) as pool:
            results = list(pool.map(get, ["/big"] * 50))
        self.assertTrue(all(r == b"x" * 100000 for r in results))
        self.assertIn('pqc_group_total{edge="web",group="X25519MLKEM768"} 51', metrics_text([edge, tunnel]))
        self.assertEqual(edge.stats.snapshot().get("handshake_failed", 0), 0)

    def test_a_client_that_pauses_longer_than_the_handshake_deadline_still_gets_everything(self):
        d = Path(tempfile.mkdtemp())
        ca = CA.init(d / "pki", "Root")
        srv, _ = ca.issue("localhost", "server", ["127.0.0.1"], out=d / "srv")
        up = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(up.close)
        size = 8 << 20

        def upstream():
            c, _ = up.accept()
            with c:
                c.sendall(b"x" * size)
        threading.Thread(target=upstream, daemon=True).start()
        edge = Edge(Route("slow", "terminate", "127.0.0.1:0", f"127.0.0.1:{up.getsockname()[1]}", cert=str(srv / "chain.pem"),
                          key=str(srv / "key.pem"), handshake_timeout=1.0)).start()
        self.addCleanup(edge.stop)
        with tls.connect("127.0.0.1", edge.port, tls.client_context(str(d / "pki" / "ca.crt")), "localhost", 10) as c:
            got = len(c.recv())
            time.sleep(2.5)
            while data := c.recv():
                got += len(data)
        self.assertEqual(got, size)

    @unittest.skipUnless(sys.platform.startswith("linux"), "socket buffer sizes are exact on Linux")
    def test_close_notify_reaches_a_client_that_has_not_read_yet(self):
        # A payload that just fills the socket buffers left no room for close_notify, and the client saw "unexpected eof"
        d = Path(tempfile.mkdtemp())
        ca = CA.init(d / "pki", "Root")
        srv, _ = ca.issue("localhost", "server", ["127.0.0.1"], out=d / "srv")
        sctx, cctx = tls.server_context(str(srv / "chain.pem"), str(srv / "key.pem")), tls.client_context(str(d / "pki" / "ca.crt"))
        ls = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(ls.close)
        for size in range(96 << 10, 320 << 10, 8 << 10):
            def serve():
                s, _ = ls.accept()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                with sctx.wrap(s, timeout=10) as c:
                    c.sendall(b"x" * size)
            t = threading.Thread(target=serve, daemon=True)
            t.start()
            raw = socket.create_connection(ls.getsockname())
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            with cctx.wrap(raw, "localhost", 10) as c:
                got = len(c.recv())
                time.sleep(0.2)
                while data := c.recv():
                    got += len(data)
            t.join(10)
            self.assertEqual(got, size)

    @unittest.skipUnless(sys.platform.startswith("linux"), "SO_REUSEPORT spreads connections on Linux only")
    def test_workers_share_the_port_and_the_metrics_add_up(self):
        d = Path(tempfile.mkdtemp())
        ca = CA.init(d / "pki", "Root")
        srv, _ = ca.issue("localhost", "server", ["127.0.0.1"], out=d / "srv")
        ports = []
        for _ in range(2):
            with socket.create_server(("127.0.0.1", 0)) as s:
                ports.append(s.getsockname()[1])
        edge = subprocess.Popen([sys.executable, "-m", "pqc", "tls", "edge", "--listen", f"127.0.0.1:{ports[0]}", "--target", "127.0.0.1:1",
                                 "--cert", srv / "chain.pem", "--key", srv / "key.pem", "--workers", "3", "--metrics", f"127.0.0.1:{ports[1]}"],
                                stderr=subprocess.PIPE, text=True)
        self.addCleanup(edge.stderr.close)
        self.addCleanup(edge.wait)
        self.addCleanup(edge.kill)
        listening = 0
        while listening < 3:
            line = edge.stderr.readline()
            self.assertTrue(line, "edge exited")
            listening += "edge: listening" in line
        status = lambda: json.load(urllib.request.urlopen(f"http://127.0.0.1:{ports[1]}/status", timeout=5))["edge"]
        ctx = tls.client_context(d / "pki" / "ca.crt")
        for _ in range(30):
            tls.connect("127.0.0.1", ports[0], ctx, "localhost", 5).close()
        time.sleep(2.5)
        self.assertEqual(status()["handshakes"], 30)
        workers = subprocess.run(["pgrep", "-P", str(edge.pid)], capture_output=True, text=True).stdout.split()
        self.assertEqual(len(workers), 2)
        edge.kill()
        edge.wait()
        time.sleep(2.5)
        def running(pid):
            try:
                return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
            except OSError:
                return False
        self.assertFalse([w for w in workers if running(w)], "workers outlived the parent")

    def test_originate_reloads_a_renewed_client_certificate(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            ca = CA.init(d / "pki", "Root")
            _, rec = ca.issue("branch", "client", out=d / "branch")
            e = Edge(Route("t", "originate", "127.0.0.1:0", "127.0.0.1:1", ca=str(d / "pki" / "ca.crt"),
                           cert=str(d / "branch" / "chain.pem"), key=str(d / "branch" / "key.pem"))).bind()
            self.addCleanup(e.stop)
            first = e.client_context()
            self.assertIs(e.client_context(), first)
            time.sleep(0.05)
            ca.renew(rec.serial, out=d / "branch")
            os.utime(d / "branch" / "chain.pem", (time.time() + 5, time.time() + 5))
            self.assertIsNot(e.client_context(), first)
            self.assertEqual(e.stats.snapshot()["reloads"], 1)

    def test_route_validation(self):
        with self.assertRaisesRegex(ValueError, "cert and key"):
            Route("x", "terminate", "0.0.0.0:1", "127.0.0.1:2").validate()
        with self.assertRaisesRegex(ValueError, "mode"):
            Route("x", "sideways", "0.0.0.0:1", "127.0.0.1:2").validate()
        with self.assertRaisesRegex(ValueError, "transition"):
            Route("x", "terminate", "0.0.0.0:1", "127.0.0.1:2", cert="c", key="k", fallback_cert="f", fallback_key="g").validate()
        with self.assertRaisesRegex(ValueError, "go together"):
            Route("x", "terminate", "0.0.0.0:1", "127.0.0.1:2", policy="transition", cert="c", key="k", fallback_cert="f").validate()


if __name__ == "__main__":
    unittest.main()
