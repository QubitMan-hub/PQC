"""ACME against the `acme` client library (certbot's), when it is installed: accounts, http-01, ML-DSA issuance, revocation, EAB."""
import datetime as dt
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from pqc.pki.acme import Service, b64u, create_eab, make_csr, serve
from pqc.pki import CA, CAError, check_revocation

try:
    import josepy as jose
    from acme import challenges, client, errors, messages
    REASON = None
except ImportError:
    REASON = "needs the acme package (pip install -e .[integration])"


class Challenges(BaseHTTPRequestHandler):
    tokens = {}

    def do_GET(self):
        body = self.tokens.get(self.path.rsplit("/", 1)[-1], "").encode()
        self.send_response(200 if body else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start(httpd, test):
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    test.addCleanup(httpd.server_close)
    test.addCleanup(httpd.shutdown)
    return httpd.server_address[1]


class HTTPSListenerTest(unittest.TestCase):
    def test_the_https_listener_takes_tls_1_3_only(self):
        import ssl
        d = Path(tempfile.mkdtemp())
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
                .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
        (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        httpd = serve(Service(CA.init(d / "pki", "Root"), "https://localhost"), "127.0.0.1:0", str(d / "c.pem"), str(d / "k.pem"))
        port = start(httpd, self)

        def get(version):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            ctx.minimum_version = ctx.maximum_version = version
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, ctx.wrap_socket(raw) as s:
                s.sendall(b"GET /directory HTTP/1.0\r\n\r\n")
                return s.recv(200)
        self.assertTrue(get(ssl.TLSVersion.TLSv1_3).startswith(b"HTTP/1.0 200"))
        with self.assertRaises(ssl.SSLError):
            get(ssl.TLSVersion.TLSv1_2)


@unittest.skipIf(REASON, REASON)
class ACMETest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.ca = CA.init(self.d / "pki", "ACME Root")
        self.web = start(ThreadingHTTPServer(("127.0.0.1", 0), Challenges), self)
        self.httpd = serve(Service(self.ca, "http://placeholder", allow=["*.test", "localhost", "127.0.0.1"], http_port=self.web,
                                     allow_local=True), "127.0.0.1:0")
        self.svc = self.httpd.service
        self.url = self.svc.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        start(self.httpd, self)

    def acme(self, key=None):
        key = key or jose.JWKEC(key=ec.generate_private_key(ec.SECP256R1()))
        net = client.ClientNetwork(key, alg=jose.ES256 if isinstance(key, jose.JWKEC) else jose.RS256, user_agent="pqc-test")
        return client.ClientV2(client.ClientV2.get_directory(self.url + "/directory", net), net), key

    def obtain(self, c, key, names):
        out = Path(tempfile.mkdtemp(dir=self.d)) / names[0]  # a new key per order, as a renewal makes
        csr = (make_csr(names, out) / "csr.pem").read_bytes()
        with self.assertRaisesRegex(CAError, "already holds a key"):
            make_csr(names, out)
        order = c.new_order(csr)
        for authz in order.authorizations:
            chall = next(ch for ch in authz.body.challenges if isinstance(ch.chall, challenges.HTTP01))
            response, validation = chall.response_and_validation(key)
            Challenges.tokens[chall.chall.encode("token")] = validation
            c.answer_challenge(chall, response)
        return c.poll_and_finalize(order, dt.datetime.now() + dt.timedelta(seconds=20))

    def test_certbot_client_gets_an_ml_dsa_certificate_and_revokes_it(self):
        c, key = self.acme()
        c.new_account(messages.NewRegistration.from_data(email="ops@acme.test", terms_of_service_agreed=True))
        order = self.obtain(c, key, ["localhost", "127.0.0.1"])
        chain = x509.load_pem_x509_certificates(order.fullchain_pem.encode())
        leaf = chain[0]
        leaf.verify_directly_issued_by(self.ca.cert)
        self.assertEqual(leaf.signature_algorithm_oid.dotted_string, "2.16.840.1.101.3.4.3.19")
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), ["localhost"])
        self.assertEqual([str(i) for i in san.get_values_for_type(x509.IPAddress)], ["127.0.0.1"])
        self.assertEqual(self.ca.records()[0].kind, "server")

        again = self.obtain(c, key, ["localhost", "127.0.0.1"])
        self.assertNotEqual(again.fullchain_pem, order.fullchain_pem)

        other, _ = self.acme()
        other.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
        with self.assertRaises(errors.Error):
            other.revoke(leaf, 1)
        c.revoke(leaf, 1)
        with self.assertRaisesRegex(Exception, "revoked"):
            check_revocation(leaf.serial_number, (self.d / "pki" / "crl.pem").read_bytes(), self.ca.cert)

    def test_identifiers_are_proved_and_limited(self):
        c, key = self.acme()
        c.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
        with self.assertRaisesRegex(messages.Error, "does not issue"):
            c.new_order((make_csr(["evil.example"], self.d / "e") / "csr.pem").read_bytes())
        order = c.new_order((make_csr(["localhost"], self.d / "a") / "csr.pem").read_bytes())
        chall = next(ch for ch in order.authorizations[0].body.challenges if isinstance(ch.chall, challenges.HTTP01))
        c.answer_challenge(chall, chall.response(key))
        with self.assertRaises(errors.ValidationError):
            c.poll_and_finalize(order, dt.datetime.now() + dt.timedelta(seconds=15))
        self.assertEqual(self.ca.records(), [])

    def test_classical_keys_are_refused(self):
        c, key = self.acme(jose.JWKRSA(key=rsa.generate_private_key(65537, 2048)))
        c.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
        k = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(k, hashes.SHA256()))
        order = c.new_order(csr.public_bytes(serialization.Encoding.PEM))
        chall = next(ch for ch in order.authorizations[0].body.challenges if isinstance(ch.chall, challenges.HTTP01))
        response, validation = chall.response_and_validation(key)
        Challenges.tokens[chall.chall.encode("token")] = validation
        c.answer_challenge(chall, response)
        with self.assertRaisesRegex(messages.Error, "ML-DSA"):
            c.poll_and_finalize(order, dt.datetime.now() + dt.timedelta(seconds=15))

    def test_external_account_binding(self):
        self.svc.require_eab = True
        c, key = self.acme()
        with self.assertRaisesRegex(messages.Error, "external account"):
            c.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
        kid, hmac_key = create_eab(self.d / "pki", "web team")
        eab = messages.ExternalAccountBinding.from_data(account_public_key=key.public_key(), kid=kid, hmac_key=hmac_key,
                                                         directory=c.directory)
        c.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True, external_account_binding=eab))
        c2, key2 = self.acme()
        eab2 = messages.ExternalAccountBinding.from_data(account_public_key=key2.public_key(), kid=kid, hmac_key=hmac_key, directory=c2.directory)
        with self.assertRaisesRegex(messages.Error, "not valid"):
            c2.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True, external_account_binding=eab2))

    def test_bad_content_length_is_refused_at_once(self):
        import socket
        for length, status in ((b"-1", b"400"), (b"abc", b"400"), (b"99999999", b"413"), (b"9" * 5000, b"400")):
            with socket.create_connection(self.httpd.server_address, timeout=5) as s:
                s.sendall(b"POST /acme/new-account HTTP/1.1\r\nHost: x\r\nContent-Length: " + length + b"\r\n\r\n")
                self.assertIn(status, s.recv(200).split(b"\r\n")[0], length)

    def test_forged_and_replayed_requests(self):
        import urllib.request
        import urllib.error
        key = rsa.generate_private_key(65537, 2048)
        n = lambda i: b64u(i.to_bytes((i.bit_length() + 7) // 8, "big"))
        jwk = {"kty": "RSA", "n": n(key.public_key().public_numbers().n), "e": n(65537)}

        def post(path, payload, nonce, sign_with=key, url=None):
            protected = b64u(json.dumps({"alg": "RS256", "jwk": jwk, "nonce": nonce, "url": url or self.url + path}).encode())
            body = b64u(json.dumps(payload).encode())
            sig = sign_with.sign(f"{protected}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
            req = urllib.request.Request(self.url + path, json.dumps({"protected": protected, "payload": body, "signature": b64u(sig)}).encode(),
                                         {"Content-Type": "application/jose+json"})
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())

        def nonce():
            with urllib.request.urlopen(urllib.request.Request(self.url + "/new-nonce", method="HEAD")) as r:
                return r.headers["Replay-Nonce"]

        good = nonce()
        self.assertEqual(post("/new-account", {"termsOfServiceAgreed": True}, good)[0], 201)
        status, err = post("/new-account", {"termsOfServiceAgreed": True}, good)
        self.assertEqual((status, err["type"]), (400, "urn:ietf:params:acme:error:badNonce"))
        status, err = post("/new-account", {}, nonce(), sign_with=rsa.generate_private_key(65537, 2048))
        self.assertEqual((status, err["type"]), (403, "urn:ietf:params:acme:error:unauthorized"))
        status, err = post("/new-account", {}, nonce(), url=self.url + "/new-order")
        self.assertEqual(status, 401)

    @unittest.skipUnless(os.name != "nt" and (shutil.which("certbot") or (Path(sys.executable).parent / "certbot").exists()), "needs certbot (not on Windows)")
    def test_certbot_cli_with_an_ml_dsa_csr(self):
        with socket.create_server(("127.0.0.1", 0)) as s:
            port = s.getsockname()[1]
        self.svc.http_port = port
        make_csr(["localhost"], self.d / "req")
        certbot = shutil.which("certbot") or str(Path(sys.executable).parent / "certbot")
        r = subprocess.run([certbot, "certonly", "--non-interactive", "--agree-tos", "--register-unsafely-without-email",
                            "--server", self.url + "/directory", "--standalone", "--http-01-port", str(port), "--http-01-address", "127.0.0.1",
                            "--csr", str(self.d / "req" / "csr.der"), "--cert-path", str(self.d / "cert.pem"), "--fullchain-path", str(self.d / "full.pem"),
                            "--chain-path", str(self.d / "chain.pem"), "--config-dir", str(self.d / "c"), "--work-dir", str(self.d / "w"),
                            "--logs-dir", str(self.d / "l")], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        leaf = x509.load_pem_x509_certificate((self.d / "cert.pem").read_bytes())
        leaf.verify_directly_issued_by(self.ca.cert)



class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:1/internal")
        self.end_headers()

    def log_message(self, *a):
        pass


class ValidationTest(unittest.TestCase):
    def test_http01_does_not_follow_redirects_to_other_addresses(self):
        with tempfile.TemporaryDirectory() as d:
            web = start(ThreadingHTTPServer(("127.0.0.1", 0), Redirect), self)
            svc = Service(CA.init(Path(d) / "pki", "R"), "http://acme", http_port=web, validate_async=False, allow_local=True)
            svc.state["authz"]["z"] = {"account": "a", "identifier": {"type": "ip", "value": "127.0.0.1"}, "status": "pending",
                                       "token": "t", "challenge_status": "pending", "error": None, "validated": None}
            svc.validate("z", "t.tp")
            detail = svc.state["authz"]["z"]["error"]["detail"]
        self.assertIn("302", detail)
        self.assertNotIn("refused", detail)

    def test_validation_never_reaches_loopback_or_metadata_addresses_by_default(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            svc = Service(CA.init(Path(d) / "pki", "R"), "http://acme", validate_async=False)
            for n, ip in enumerate(["127.0.0.1", "169.254.169.254", "::1", "0.0.0.0", "10.0.0.5"]):
                svc.state["authz"][str(n)] = {"account": "a", "identifier": {"type": "ip", "value": ip}, "status": "pending",
                                              "token": "t", "challenge_status": "pending", "error": None, "validated": None}
                with self.subTest(ip=ip), mock.patch("pqc.pki.acme.FETCH.open", side_effect=OSError("connection refused")) as fetch:
                    svc.validate(str(n), "t.tp")
                    self.assertEqual(svc.state["authz"][str(n)]["status"], "invalid")
                    self.assertEqual(fetch.called, ip == "10.0.0.5", "private networks are validated; the others never reached")

    def test_a_target_that_does_not_speak_http_fails_the_challenge(self):
        with tempfile.TemporaryDirectory() as d:
            srv = socket.create_server(("127.0.0.1", 0))
            self.addCleanup(srv.close)

            def answer():
                conn, _ = srv.accept()
                conn.recv(4096)
                conn.sendall(b"not http\r\n\r\n")
                conn.close()
            threading.Thread(target=answer, daemon=True).start()
            svc = Service(CA.init(Path(d) / "pki", "R"), "http://acme", http_port=srv.getsockname()[1], validate_async=False,
                          allow_local=True)
            svc.state["authz"]["z"] = {"account": "a", "identifier": {"type": "ip", "value": "127.0.0.1"}, "status": "pending",
                                       "token": "t", "challenge_status": "pending", "error": None, "validated": None}
            svc.validate("z", "t.tp")
            self.assertEqual(svc.state["authz"]["z"]["status"], "invalid")

    def test_wrong_json_types_are_malformed_requests_not_crashes(self):
        from pqc.pki.acme import Problem
        with tempfile.TemporaryDirectory() as d:
            svc = Service(CA.init(Path(d) / "pki", "R"), "http://acme")
            for prot in ({"kid": 5}, {"jwk": "x"}, ["x"]):
                prot = prot if isinstance(prot, list) else {"alg": "ES256", "nonce": svc.nonce(), "url": "http://acme/new-order", **prot}
                body = json.dumps({"protected": b64u(json.dumps(prot).encode()), "payload": "", "signature": "AA"}).encode()
                with self.assertRaises(Problem) as e:
                    svc.handle("POST", "/new-order", body)
                self.assertEqual(e.exception.kind, "malformed")
            for ids in (["x"], 1, [None], None):
                with self.assertRaisesRegex(Problem, "list of 1 to 100"):
                    svc.new_order({"identifiers": ids}, "acct")


if __name__ == "__main__":
    unittest.main()
