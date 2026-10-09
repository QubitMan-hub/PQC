"""Secrets stay secret: passphrases, enrollment token secrets and private keys never appear in output, logs,
audit trails or files at rest, including on the error paths."""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from pqc.pki import CA, generate
from pqc.pki.est import Service, create_token
from pqc.tls.http import HTTPError

CA_PASS, KEY_PASS = "ca-pass-7f3e91", "key-pass-2b8c44"


def everything_under(d):
    return b"".join(p.read_bytes() for p in Path(d).rglob("*") if p.is_file())


class SecretsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)

    def run_cli(self, *args, ok=True):
        env = {**os.environ, "PQC_CA_PASSPHRASE": CA_PASS, "KEY_PASS": KEY_PASS}
        r = subprocess.run([sys.executable, "-m", "pqc", "--log-json", "-v", *map(str, args)], cwd=self.d, capture_output=True, text=True, env=env)
        if ok and r.returncode:
            raise AssertionError(r.stderr)
        return r.stdout + r.stderr

    def test_passphrases_and_token_secrets_never_leave_where_they_belong(self):
        out = self.run_cli("ca", "init", "--dir", "pki", "--name", "Root", "--encrypt")
        out += self.run_cli("ca", "issue", "--dir", "pki", "server", "api.test", "--out", "api", "--key-passphrase-env", "KEY_PASS")
        token = self.run_cli("ca", "token", "--dir", "pki", "client", "dev.test").strip().splitlines()[-1]
        secret = token.split(".", 1)[1]
        out += self.run_cli("ca", "list", "--dir", "pki") + self.run_cli("ca", "crl", "--dir", "pki")
        out += self.run_cli("ca", "maintain", "--dir", "pki") + self.run_cli("doctor", "--ca", "pki", ok=False)
        env = {**os.environ, "PQC_CA_PASSPHRASE": "wrong-" + CA_PASS}
        out += subprocess.run([sys.executable, "-m", "pqc", "ca", "issue", "--dir", "pki", "client", "x"], cwd=self.d,
                              capture_output=True, text=True, env=env).stderr
        at_rest = everything_under(self.d)
        for s in (CA_PASS, KEY_PASS, secret):
            with self.subTest(secret=s):
                self.assertNotIn(s, out)
                self.assertNotIn(s.encode(), at_rest)
        self.assertNotIn("PRIVATE KEY", out)
        self.assertIn(b"ENCRYPTED PRIVATE KEY", (self.d / "api" / "key.pem").read_bytes())

    def test_enrollment_audit_never_records_a_token_secret(self):
        ca = CA.init(self.d / "pki", "Root")
        token = create_token(ca, "dev.test", "client", [], 1)
        tid, secret = token.split(".", 1)
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        key = generate("ML-DSA-44")
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dev.test")]))
               .sign(key, None).public_bytes(serialization.Encoding.DER))
        est = Service(ca)
        for auth in (f"{tid}:wrong{secret}", f"{tid}:{secret}", f"{tid}:{secret}"):
            try:
                est("POST", "/.well-known/est/simpleenroll", {"authorization": "Basic " + base64.b64encode(auth.encode()).decode()},
                    base64.b64encode(csr), None)
            except HTTPError:
                pass
        audit = (self.d / "pki" / "est-audit.jsonl").read_text()
        self.assertEqual([json.loads(line)["event"] for line in audit.splitlines()], ["enroll_refused", "enrolled", "enroll_refused"])
        self.assertNotIn(secret, audit)
        self.assertNotIn(secret.encode(), everything_under(self.d / "pki"))
        if os.name != "nt":
            self.assertEqual(os.stat(self.d / "pki" / "est-audit.jsonl").st_mode & 0o077, 0, "the audit log is owner-only")

if __name__ == "__main__":
    unittest.main()
