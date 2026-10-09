import io
import json
import logging
import os
import random
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pqc import tls
from pqc.console import App, Backoff, Settings, page, policy, serve
from pqc.pki import CA
from pqc.tls.server import Server

from .helpers import REASON

TOKEN = "console-token-9d1a07"


class ConsoleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.ca = CA.init(self.d / "pki", "Console Root")
        self.ca.crl()
        self.app = App(Settings(listen="127.0.0.1:0", ca=str(self.d / "pki"), edges=["http://127.0.0.1:1"],
                                audit_log=str(self.d / "audit.jsonl")), token=TOKEN)
        self.httpd = serve(self.app)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def call(self, path, body=None, token=TOKEN, raw=False):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = r.read()
            return r.status, dict(r.headers), data if raw else json.loads(data)

    def error(self, path, body=None, token=TOKEN):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.call(path, body, token)
        return e.exception.code, json.loads(e.exception.read())

    def actions(self):
        return [json.loads(line)["action"] for line in (self.d / "audit.jsonl").read_text().splitlines()]

    def test_page_is_public_but_the_api_needs_the_token(self):
        with urllib.request.urlopen(self.base + "/", timeout=5) as r:
            self.assertIn(b"PQC console", r.read())
            csp = r.headers["Content-Security-Policy"]
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn(policy(page()).split("script-src ")[1].split(";")[0], csp)
        self.assertEqual(csp.split("script-src ")[1].split(";")[0].count("'"), 2, "one hash, no 'self' or 'unsafe-inline'")
        for token in ("", "wrong", TOKEN[:-1]):
            self.assertEqual(self.error("/api/overview", token=token)[0], 401)

    def test_the_page_runs_one_inline_script_and_never_writes_markup_from_data(self):
        html = page().decode()
        self.assertEqual(html.count("<script"), 1)
        self.assertNotIn("innerHTML =", html.replace("t.innerHTML = markup", ""), "data goes in with textContent, never as markup")

    def test_repeated_wrong_tokens_are_slowed_down(self):
        codes = []
        for token in ["wrong"] * 10 + [TOKEN]:
            try:
                codes.append(self.call("/api/overview", token=token)[0])
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        self.assertEqual(codes, [401] * 10 + [429])

    def test_ambiguous_negative_and_oversized_bodies_get_an_error(self):
        for headers in (b"Content-Length: -1", b"Content-Length: " + b"9" * 5000, b"Content-Length: 0\r\nContent-Length: 1",
                        b"Content-Length: 0\r\nTransfer-Encoding: chunked", b"Content-Length: 2000000"):
            with self.subTest(headers=headers[:60]), socket.create_connection(self.httpd.server_address, timeout=5) as s:
                s.sendall(b"POST /api/test HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode() + b"\r\n" + headers + b"\r\n\r\n")
                self.assertRegex(s.recv(200).split(b"\r\n")[0], rb" 4(00|13) ")
        self.assertEqual(self.error("/api/certificates/revoke", ["serial"])[0], 400)
        self.assertEqual(self.call("/api/overview")[0], 200)

    def test_overview_reports_the_ca_crl_certificates_and_edges(self):
        _, headers, o = self.call("/api/overview")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(o["ca"]["algorithm"], "ML-DSA-87")
        self.assertEqual(o["ca"]["crl"]["revoked"], 0)
        self.assertGreater(o["ca"]["crl"]["hours_left"], 100)
        self.assertEqual(o["certificates"], {"valid": 0, "revoked": 0, "expiring_30d": 0, "expired": 0})
        self.assertEqual((o["edges"]["routes"], o["edges"]["unreachable"]), (0, 1))

    def test_issue_renew_revoke_and_maintain_are_audited(self):
        r = self.call("/api/certificates/issue", {"kind": "server", "common_name": "api.acme", "names": "10.0.0.5", "days": 20})[2]
        c = self.call("/api/certificates")[2]["certificates"][0]
        self.assertEqual((c["common_name"], c["names"], c["status"], c["has_files"]), ("api.acme", ["api.acme", "10.0.0.5"], "valid", True))
        self.assertNotIn("path", c, "the API does not list folders of private keys")
        new = self.call("/api/certificates/renew", {"serial": r["serial"]})[2]
        rows = {x["serial"]: x for x in self.call("/api/certificates")[2]["certificates"]}
        self.assertTrue(rows[r["serial"]]["renewed"])
        self.assertTrue(rows[new["serial"]]["has_files"])
        self.assertIn("newer certificate", self.error("/api/certificates/renew", {"serial": r["serial"]})[1]["error"])
        self.call("/api/certificates/revoke", {"serial": r["serial"], "reason": "superseded"})
        self.assertEqual(self.call("/api/overview")[2]["ca"]["crl"]["revoked"], 1)
        self.assertEqual(self.call("/api/certificates/maintain", {})[2]["renewed"], [])
        self.assertEqual(self.actions(), ["issue", "renew", "revoke", "maintain"])
        self.assertEqual([a["action"] for a in self.call("/api/overview")[2]["activity"]], ["maintain", "revoke", "renew", "issue"])

    def test_download_gives_the_key_only_when_asked_and_never_for_a_revoked_certificate(self):
        r = self.call("/api/certificates/issue", {"kind": "client", "common_name": "partner"})[2]
        _, headers, data = self.call("/api/certificates/download", {"serial": r["serial"]}, raw=True)
        self.assertEqual(headers["Content-Type"], "application/zip")
        self.assertIn(f'partner-{r["serial"][:8]}.zip', headers["Content-Disposition"])
        self.assertEqual(sorted(zipfile.ZipFile(io.BytesIO(data)).namelist()), ["ca.crt", "cert.pem", "chain.pem"])
        z = zipfile.ZipFile(io.BytesIO(self.call("/api/certificates/download", {"serial": r["serial"], "key": True}, raw=True)[2]))
        self.assertIn(b"PRIVATE KEY", z.read("key.pem"))
        self.assertEqual(z.read("ca.crt"), (self.d / "pki" / "ca.crt").read_bytes())
        self.assertNotIn("key.pem", zipfile.ZipFile(io.BytesIO(self.call("/api/certificates/download", {"serial": r["serial"], "key": "yes"}, raw=True)[2])).namelist(),
                         "only a JSON true hands out the key")
        self.call("/api/certificates/revoke", {"serial": r["serial"]})
        self.assertIn("revoked", self.error("/api/certificates/download", {"serial": r["serial"], "key": True})[1]["error"])
        audit = [json.loads(line) for line in (self.d / "audit.jsonl").read_text().splitlines()]
        self.assertEqual([(a["action"], a.get("key")) for a in audit if a["action"] == "download"], [("download", False), ("download", True), ("download", False)])

    def test_an_encrypted_key_is_not_handed_out(self):
        _, rec = self.ca.issue("vault", "client", passphrase=b"pw")
        self.assertIn("encrypted", self.error("/api/certificates/download", {"serial": rec.serial, "key": True})[1]["error"])
        self.assertEqual(self.call("/api/certificates/download", {"serial": rec.serial}, raw=True)[0], 200)

    def test_a_csr_signed_certificate_has_no_files_to_download_or_renew(self):
        from cryptography.hazmat.primitives.asymmetric import mldsa
        _, rec = self.ca.sign(mldsa.MLDSA65PrivateKey.generate().public_key(), "est-device", "client")
        for path in ("/api/certificates/download", "/api/certificates/renew"):
            self.assertIn("request", self.error(path, {"serial": rec.serial})[1]["error"])

    def test_a_broken_edge_or_a_bug_is_an_answer_not_a_dropped_connection(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Odd(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"edge1": "not-a-dict"} if self.path.startswith("/a") else [1, 2]).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        odd = ThreadingHTTPServer(("127.0.0.1", 0), Odd)
        threading.Thread(target=odd.serve_forever, daemon=True).start()
        self.addCleanup(odd.server_close)
        self.addCleanup(odd.shutdown)
        port = odd.server_address[1]
        self.app.s.edges = [f"http://127.0.0.1:{port}/a", f"http://127.0.0.1:{port}/b", "http://127.0.0.1:1"]
        edges = self.call("/api/edges")[2]
        self.assertEqual([("error" in e) for e in edges], [True, True, True])
        self.assertIn("nothing is listening", edges[2]["error"])
        self.app.certificates = lambda: 1 / 0
        code, body = self.error("/api/certificates")
        self.assertEqual(code, 500)
        self.assertIn("console's log", body["error"])

    def test_edge_status_counts_quantum_safe_handshakes(self):
        from pqc import serve_http
        status = {"web": {"mode": "terminate", "listen": "0.0.0.0:8443", "target": "127.0.0.1:8080", "policy": "transition", "active": 2,
                          "handshakes": 5, "handshake_failed": 1, "groups": {"X25519MLKEM768": 3, "X25519": 2}}}
        httpd = serve_http("127.0.0.1:0", {"/status": ("application/json", lambda: json.dumps(status))})
        self.addCleanup(httpd.shutdown)
        self.app.s.edges = [f"http://127.0.0.1:{httpd.server_address[1]}"]
        e = self.call("/api/edges")[2][0]
        self.assertEqual((e["name"], e["quantum_safe"], e["active"]), ("web", 3, 2))
        self.assertEqual(self.call("/api/overview")[2]["edges"], {"routes": 1, "unreachable": 0, "active": 2, "handshakes": 5, "quantum_safe": 3, "failed": 1})

    def test_bad_requests_are_explained(self):
        for path, body, message in (("/api/certificates/issue", {"kind": "admin", "common_name": "x"}, "kind"),
                                    ("/api/certificates/issue", {"kind": "server", "common_name": "x", "algorithm": "RSA"}, "algorithm"),
                                    ("/api/certificates/issue", {"kind": "server", "common_name": "x", "days": 0}, "days"),
                                    ("/api/certificates/issue", {"kind": "server"}, "common_name"),
                                    ("/api/certificates/revoke", {}, "serial"),
                                    ("/api/test", {"target": "nohost"}, "host:port"),
                                    ("/api/test", {"target": ":443"}, "host:port"),
                                    ("/api/test", {"target": "localhost:1", "policy": "loose"}, "policy")):
            with self.subTest(path=path, body=body):
                code, out = self.error(path, body)
                self.assertEqual(code, 400)
                self.assertIn(message, out["error"])
        self.assertEqual(self.error("/api/nothing")[0], 404)

    def test_a_closed_port_is_explained(self):
        out = self.call("/api/test", {"target": "127.0.0.1:1"})[2]
        self.assertFalse(out["ok"])
        self.assertIn("nothing is listening", out["error"])
        self.assertIsNone(out["offers"])

    def test_the_token_never_appears_in_responses_logs_or_the_audit_log(self):
        log = io.StringIO()
        handler = logging.StreamHandler(log)
        logging.getLogger("pqc").addHandler(handler)
        logging.getLogger("pqc").setLevel(logging.DEBUG)
        self.addCleanup(logging.getLogger("pqc").removeHandler, handler)
        bodies = []
        for token, path, body in ((TOKEN, "/api/certificates/issue", {"kind": "client", "common_name": "a"}), (TOKEN[:-1], "/api/overview", None),
                                  (TOKEN, "/api/certificates/revoke", {"serial": "zz"}), (TOKEN, "/api/nope", {"x": TOKEN})):
            try:
                bodies.append(json.dumps(self.call(path, body, token)[2]))
            except urllib.error.HTTPError as e:
                bodies.append(e.read().decode())
        if os.name != "nt":
            self.assertEqual(os.stat(self.d / "audit.jsonl").st_mode & 0o077, 0, "the audit log is owner-only")
        for where, text in (("responses", "".join(bodies)), ("log", log.getvalue()), ("audit", (self.d / "audit.jsonl").read_text())):
            self.assertNotIn(TOKEN, text, where)
            self.assertNotIn("PRIVATE KEY", text, where)


@unittest.skipIf(REASON, REASON)
class ConnectionTestTest(unittest.TestCase):
    """The 'Test a connection' page against a real edge-like server with mutual TLS and a CRL."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        cls.ca = CA.init(d / "pki", "Root")
        srv, _ = cls.ca.issue("localhost", "server", ["127.0.0.1"])
        cls.ca.crl()
        cafile, crl = str(d / "pki" / "ca.crt"), str(d / "pki" / "crl.pem")

        def wait(conn, addr):
            conn.recv(timeout=5)
        cls.mtls = Server(("127.0.0.1", 0), lambda: tls.server_context(srv / "chain.pem", srv / "key.pem", cafile, True), wait,
                          crl=crl, ca=cafile, handshake_timeout=3)
        cls.mtls.start()
        other = CA.init(d / "other", "Other")
        osrv, _ = other.issue("localhost", "server")
        cls.stranger = Server(("127.0.0.1", 0), lambda: tls.server_context(osrv / "chain.pem", osrv / "key.pem"), wait, handshake_timeout=3)
        cls.stranger.start()
        cls.app = App(Settings(ca=str(d / "pki"), audit_log=str(d / "audit.jsonl")), token="t")

    @classmethod
    def tearDownClass(cls):
        cls.mtls.stop(1)
        cls.stranger.stop(1)
        cls.tmp.cleanup()

    def connect(self, port, **body):
        status, out = self.app.handle("POST", "/api/test", {"target": f"localhost:{port}", **body})
        self.assertEqual(status, 200, out)
        return out

    def test_mutual_tls_passes_with_a_client_certificate_and_is_refused_without_or_after_revocation(self):
        port = self.mtls.port
        serial = self.app.handle("POST", "/api/certificates/issue", {"kind": "client", "common_name": "partner"})[1]["serial"]
        ok = self.connect(port, client=serial)
        self.assertEqual((ok["ok"], ok["group"], ok["peer_key"], ok["quantum_safe"]), (True, "X25519MLKEM768", "ML-DSA-65", True))
        bare = self.connect(port)
        self.assertFalse(bare["ok"])
        self.assertTrue(bare["refused_after_handshake"])
        self.app.handle("POST", "/api/certificates/revoke", {"serial": serial})
        time.sleep(1.1)  # the server notices a rewritten CRL by its timestamp
        revoked = self.connect(port, client=serial)
        self.assertFalse(revoked["ok"])
        self.assertEqual(revoked["client_status"], "revoked")

    def test_a_server_from_another_ca_is_refused_and_what_it_offers_is_shown(self):
        out = self.connect(self.stranger.port)
        self.assertFalse(out["ok"])
        self.assertEqual((out["offers"]["group"], out["offers"]["peer_key"]), ("X25519MLKEM768", "ML-DSA-65"))

    def test_a_server_certificate_cannot_be_used_as_the_client(self):
        serial = self.app.handle("POST", "/api/certificates/issue", {"kind": "server", "common_name": "web"})[1]["serial"]
        self.assertIn("server certificate", self.app.handle("POST", "/api/test", {"target": "localhost:1", "client": serial})[1]["error"])


class ConsoleRobustnessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.ca = CA.init(self.d / "pki", "Root")
        self.ca.crl()
        self.app = App(Settings(ca=str(self.d / "pki"), audit_log=str(self.d / "audit.jsonl")), token="t")

    def test_two_administrators_at_once(self):
        def admin(who):
            done = []
            for i in range(6):
                status, out = self.app.handle("POST", "/api/certificates/issue", {"kind": "client", "common_name": f"{who}-{i}"})
                self.assertEqual(status, 200, out)
                done.append(out["serial"])
            for s in done[::2]:
                self.assertEqual(self.app.handle("POST", "/api/certificates/revoke", {"serial": s})[0], 200)
            return done
        with ThreadPoolExecutor(2) as pool:
            issued = [s for f in [pool.submit(admin, "ann"), pool.submit(admin, "bo")] for s in f.result()]
        recs = {r.serial: r for r in CA(self.d / "pki").records()}
        self.assertLessEqual(set(issued), set(recs))
        self.assertEqual(sum(r.status == "revoked" for r in recs.values()), 6)
        self.assertEqual(len((self.d / "audit.jsonl").read_text().splitlines()), 18)

    def test_malformed_input_never_gets_an_internal_error(self):
        rnd = random.Random(7)
        junk = lambda: rnd.choice([None, True, 0, -1, 10 ** 30, 1.5, "", " ", "x" * 300, "../../etc", "<script>", [], {}, ["a"], {"a": 1}, "ab", "a:b", "localhost:0"])
        routes = ["/api/certificates/issue", "/api/certificates/revoke", "/api/certificates/renew", "/api/certificates/download", "/api/test"]
        for _ in range(600):
            body = {rnd.choice(["kind", "common_name", "names", "days", "algorithm", "serial", "reason", "key", "target", "policy", "client",
                                "server_name"]): junk() for _ in range(rnd.randrange(5))}
            route = rnd.choice(routes)
            status, out = self.app.handle("POST", route, body)
            self.assertLess(status, 500, (route, body, out))

    def test_an_empty_serial_never_matches_a_certificate(self):
        self.ca.issue("only.test", "server")
        for body in ({"serial": ""}, {"serial": {}}, {"serial": 1}, {"serial": "ab"}):
            self.assertEqual(self.app.handle("POST", "/api/certificates/revoke", body)[0], 400)
        self.assertEqual(self.ca.records()[0].status, "valid")

    def test_settings_file_is_checked(self):
        p = self.d / "c.toml"
        p.write_text('[console]\nlisten = "127.0.0.1:9000"\nedges = ["http://127.0.0.1:9100"]\n', encoding="utf-8")
        self.assertEqual(Settings.load(p).edges, ["http://127.0.0.1:9100"])
        for bad in ('[console]\nbogus = 1\n', '[console]\nedges = "x"\n'):
            p.write_text(bad, encoding="utf-8")
            with self.assertRaises(ValueError):
                Settings.load(p)


class CommandTest(unittest.TestCase):
    def test_console_without_a_ca_says_how_to_make_one(self):
        import contextlib
        from pqc.cli import main
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as e:
            main(["console", "--ca", str(Path(d) / "none"), "--no-browser"])
        self.assertEqual(e.exception.code, 1)
        self.assertIn("pqc ca init", err.getvalue())


class BackoffTest(unittest.TestCase):
    def test_an_address_is_refused_for_the_window_and_then_forgotten(self):
        b = Backoff(limit=2, window=0.2)
        b.failed("10.0.0.1")
        self.assertFalse(b.blocked("10.0.0.1"))
        b.failed("10.0.0.1")
        self.assertTrue(b.blocked("10.0.0.1"))
        self.assertFalse(b.blocked("10.0.0.2"))
        time.sleep(0.3)
        self.assertFalse(b.blocked("10.0.0.1"))
        self.assertEqual(b.failures, {})


if __name__ == "__main__":
    unittest.main()
