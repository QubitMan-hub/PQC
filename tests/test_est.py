import base64
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

from cryptography import x509

from pqc import tls
from pqc.pki import est
from pqc.pki import CA, CAError, generate
from tests.helpers import REASON


@unittest.skipIf(REASON, REASON)
class ESTTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.ca = CA.init(self.d / "pki", "Enrollment Root")
        srv, _ = self.ca.issue("localhost", "server", ["127.0.0.1"], out=self.d / "srv")
        self.server = est.serve(self.d / "pki", "127.0.0.1:0", srv / "chain.pem", srv / "key.pem")
        self.server.start()
        self.addCleanup(self.server.stop, 1)
        self.url = f"https://localhost:{self.server.port}"
        self.cafile = self.d / "pki" / "ca.crt"

    def test_trust_bootstrap_by_fingerprint(self):
        got = est.fetch_ca(self.url, est.fingerprint(self.ca.cert), self.d / "ca.crt")
        self.assertEqual(got, self.ca.cert)
        with self.assertRaisesRegex(CAError, "do not trust"):
            est.fetch_ca(self.url, "00" * 32, self.d / "bad.crt")

    def test_enroll_once_with_a_token_bound_to_one_name(self):
        token = est.create_token(self.ca, "web1.acme", "server", ["10.0.0.7"])
        cert = est.enroll(self.url, token, "web1.acme", ["web1.acme", "10.0.0.7"], self.d / "web1", self.cafile)
        cert.verify_directly_issued_by(self.ca.cert)
        self.assertEqual((self.d / "web1" / "cert.pem").read_bytes().count(b"BEGIN"), 1)
        self.assertIn(b"PRIVATE KEY", (self.d / "web1" / "key.pem").read_bytes())
        with self.assertRaisesRegex(CAError, "401.*already used"):
            est.enroll(self.url, token, "web1.acme", [], self.d / "again", self.cafile)
        key = (self.d / "web1" / "key.pem").read_bytes()
        second = est.create_token(self.ca, "web1.acme", "server")
        with self.assertRaisesRegex(CAError, "already holds a key.*--renew"):
            est.enroll(self.url, second, "web1.acme", [], self.d / "web1", self.cafile)
        self.assertEqual((self.d / "web1" / "key.pem").read_bytes(), key)
        est.enroll(self.url, second, "web1.acme", [], self.d / "web1b", self.cafile)  # the refused attempt did not spend the token
        log = (self.d / "pki" / "est-audit.jsonl").read_text()
        self.assertIn('"enrolled"', log)

    def test_tokens_cannot_be_stretched_or_guessed(self):
        token = est.create_token(self.ca, "web2.acme", "server")
        with self.assertRaisesRegex(CAError, "403.*this token is for web2.acme"):
            est.enroll(self.url, token, "admin.acme", [], self.d / "x", self.cafile)
        with self.assertRaisesRegex(CAError, "403"):
            est.enroll(self.url, token, "web2.acme", ["web2.acme", "evil.acme"], self.d / "x", self.cafile)
        tid = token.split(".")[0]
        with self.assertRaisesRegex(CAError, "401"):
            est.enroll(self.url, f"{tid}.wrong-secret", "web2.acme", [], self.d / "x", self.cafile)
        expired = est.create_token(self.ca, "web3.acme", "server", hours=-1)
        with self.assertRaisesRegex(CAError, "401.*expired"):
            est.enroll(self.url, expired, "web3.acme", [], self.d / "x", self.cafile)
        self.assertNotIn(token.split(".")[1], (self.d / "pki" / "tokens.json").read_text())

    def test_a_classical_key_does_not_burn_the_token(self):
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509.oid import NameOID
        token = est.create_token(self.ca, "web4.acme", "server")
        tid, _, secret = token.partition(".")
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "web4.acme")]))
               .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()))
        auth = base64.b64encode(f"{tid}:{secret}".encode()).decode()
        with self.assertRaisesRegex(CAError, "403.*ML-DSA"):
            est._call(self.url, tls.client_context(self.cafile), "/simpleenroll", base64.encodebytes(csr.public_bytes(Encoding.DER)),
                      {"Content-Type": "application/pkcs10", "Authorization": f"Basic {auth}"}, "localhost")
        est.enroll(self.url, token, "web4.acme", [], self.d / "web4", self.cafile)

    def test_renewal_in_place_keeps_identity(self):
        token = est.create_token(self.ca, "db.acme", "server")
        first = est.enroll(self.url, token, "db.acme", [], self.d / "db", self.cafile, algorithm="ML-DSA-87")
        self.assertIsNone(est.renew(self.url, self.d / "db", within_days=30))
        second = est.renew(self.url, self.d / "db")
        self.assertIsInstance(second.public_key(), type(first.public_key()), "renewal must keep ML-DSA-87")
        self.assertNotEqual(first.serial_number, second.serial_number)
        self.assertEqual(x509.load_pem_x509_certificate((self.d / "db" / "cert.pem").read_bytes()), second)
        self.ca.revoke(format(second.serial_number, "x"))
        time.sleep(0.05)
        with self.assertRaisesRegex(CAError, "403.*revoked"):
            est.renew(self.url, self.d / "db")

    def test_a_token_names_a_valid_host_and_survives_a_failed_signing(self):
        with self.assertRaisesRegex(CAError, "not a valid host name"):
            est.create_token(self.ca, "bad name!", "server")
        token = est.create_token(self.ca, "db.acme", "server")
        tid, _, secret = token.partition(".")
        headers = {"authorization": "Basic " + base64.b64encode(f"{tid}:{secret}".encode()).decode()}
        csr = x509.load_der_x509_csr(base64.b64decode(est._csr(generate("ML-DSA-65"), "db.acme", [])))
        svc = est.Service(self.ca)
        with mock.patch.object(self.ca, "sign", side_effect=CAError("the CA key is not available")):
            with self.assertRaisesRegex(CAError, "not available"):
                svc.enroll(csr, headers)
        self.assertEqual(svc.enroll(csr, headers).subject.rfc4514_string(), "CN=db.acme")

    def test_a_crash_while_signing_leaves_the_token_spent(self):
        import subprocess
        import sys
        import textwrap
        token = est.create_token(self.ca, "crash.acme", "server")
        child = textwrap.dedent("""
            import base64, os, sys
            from unittest import mock
            from cryptography import x509
            from pqc.pki import CA, est, generate
            ca = CA(sys.argv[1])
            tid, _, secret = sys.argv[2].partition(".")
            csr = x509.load_der_x509_csr(base64.b64decode(est._csr(generate("ML-DSA-65"), "crash.acme", [])))
            with mock.patch.object(ca, "sign", side_effect=lambda *a: os._exit(9)):
                est.Service(ca).enroll(csr, {"authorization": "Basic " + base64.b64encode(f"{tid}:{secret}".encode()).decode()})
        """)
        self.assertEqual(subprocess.run([sys.executable, "-c", child, str(self.d / "pki"), token]).returncode, 9)
        tid, _, secret = token.partition(".")
        csr = x509.load_der_x509_csr(base64.b64decode(est._csr(generate("ML-DSA-65"), "crash.acme", [])))
        with self.assertRaisesRegex(est.HTTPError, "already used"):
            est.Service(self.ca).enroll(csr, {"authorization": "Basic " + base64.b64encode(f"{tid}:{secret}".encode()).decode()})

    def test_renewal_cannot_become_someone_else(self):
        token = est.create_token(self.ca, "app.acme", "server")
        est.enroll(self.url, token, "app.acme", [], self.d / "app", self.cafile)
        ctx = tls.client_context(self.cafile, self.d / "app" / "chain.pem", self.d / "app" / "key.pem")
        with self.assertRaisesRegex(CAError, "403.*keeps its identity"):
            est._call(self.url, ctx, "/simplereenroll", est._csr(generate("ML-DSA-65"), "ca-admin.acme", []), {})
        with self.assertRaisesRegex(CAError, "401"):
            est._call(self.url, tls.client_context(self.cafile), "/simplereenroll", est._csr(generate("ML-DSA-65"), "app.acme", []), {})


class HTTPTest(unittest.TestCase):
    def test_a_request_trickled_a_byte_at_a_time_runs_out_of_time(self):
        from pqc.tls import http

        class Trickle:
            def recv(self, size, timeout):
                if timeout <= 0:
                    raise tls.TLSError("read timed out")
                time.sleep(0.1)
                return b"x"
        start = time.monotonic()
        with self.assertRaises(tls.TLSError):
            http.read_request(Trickle(), timeout=1)
        self.assertLess(time.monotonic() - start, 2)


if __name__ == "__main__":
    unittest.main()
