"""`pqc doctor --ca --config`: the deployment checks name what is wrong, and a weakened setting is a warning, not silence."""
import os
import tempfile
import time
import unittest
from pathlib import Path

from pqc import checks
from pqc.pki import CA


def find(results, text):
    return next((lvl for lvl, m in results if text in m), None)


class ChecksTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)

    def test_ca_checks(self):
        ca = CA.init(self.d / "pki", "Root")
        (self.d / "pki" / "crl.pem").unlink()
        self.assertEqual(find(checks.ca(self.d / "pki"), "cannot start"), "fail")
        ca.crl()
        ca.issue("soon.test", "server", days=10)
        r = checks.ca(self.d / "pki")
        self.assertEqual(find(r, "not encrypted"), "warn")
        self.assertEqual(find(r, "CRL valid"), "ok")
        self.assertEqual(find(r, "expire within 30 days"), "warn")
        if os.name != "nt":
            os.chmod(self.d / "pki" / "ca.key", 0o640)
            self.assertEqual(find(checks.ca(self.d / "pki"), "read by its group"), "warn")
            os.chmod(self.d / "pki" / "ca.key", 0o644)
            self.assertEqual(find(checks.ca(self.d / "pki"), "read by every user"), "fail")
        ca.crl(days=0)
        time.sleep(1.1)
        self.assertEqual(find(checks.ca(self.d / "pki"), "CRL expired"), "fail")
        CA.init(self.d / "enc", "Encrypted", passphrase=b"pw").crl()
        self.assertEqual(find(checks.ca(self.d / "enc"), "is encrypted"), "ok")
        self.assertEqual(find(checks.ca(self.d / "missing"), "CA at"), "fail")

    def test_expired_or_future_ca_fails_deployment_check(self):
        import datetime as dt
        from unittest.mock import patch
        ca = CA.init(self.d/'pki', 'Root')
        for moment in (ca.cert.not_valid_after_utc + dt.timedelta(seconds=1), ca.cert.not_valid_before_utc - dt.timedelta(seconds=1)):
            with patch('pqc.checks.now', return_value=moment):
                self.assertEqual(find(checks.ca(self.d/'pki'), 'expired or not yet valid'), 'fail')

    def test_damaged_ca_files_are_problems_not_crashes(self):
        CA.init(self.d / "pki", "Root")
        other = CA.init(self.d / "other", "Other")
        crl = self.d / "pki" / "crl.pem"
        for name, data in (("damaged", b"-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n"), ("another CA's", other.crl())):
            with self.subTest(name):
                crl.write_bytes(data)
                self.assertEqual(find(checks.ca(self.d / "pki"), "damaged or not signed"), "fail")
        ca = CA(self.d / "pki")
        out, _ = ca.issue("gone.test", "server", out=self.d / "gone")
        ca.crl()
        self.assertIsNone(find(checks.ca(self.d / "pki"), "without their files"))
        (out / "key.pem").unlink()
        self.assertEqual(find(checks.ca(self.d / "pki"), "without their files"), "warn")
        (self.d / "pki" / "index.json").write_text("[{")
        self.assertEqual(find(checks.ca(self.d / "pki"), "index.json cannot be read"), "fail")

    def write(self, text):
        p = self.d / "c.toml"
        p.write_text(text, encoding="utf-8")
        return p

    def test_config_checks(self):
        ca = CA.init(self.d / "pki", "Root")
        ca.crl()
        srv, _ = ca.issue("localhost", "server", out=self.d / "srv")
        files = f'cert = "{(srv / "chain.pem").as_posix()}"\nkey = "{(srv / "key.pem").as_posix()}"\nca = "{(self.d / "pki" / "ca.crt").as_posix()}"\n'
        route = '[[edge]]\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\n' + files
        r = checks.config(self.write(route + 'policy = "transition"\n'))
        self.assertEqual(find(r, "loads"), "ok")
        self.assertEqual(find(r, "policy transition"), "warn")
        r = checks.config(self.write(route + f'require_client_cert = true\ncrl = "{(self.d / "pki" / "crl.pem").as_posix()}"\n'))
        self.assertEqual(find(r, "set crl_url"), "warn")
        r = checks.config(self.write(route.replace((srv / "key.pem").as_posix(), (self.d / "nope.pem").as_posix())))
        self.assertEqual(find(r, "does not exist"), "fail")
        self.assertEqual(find(checks.config(self.write('[[edge]]\nmode = "sideways"\nlisten = "x:1"\ntarget = "y:2"\n')), "mode"), "fail")
        self.assertEqual(find(checks.config(self.write('[nothing]\n')), "no [[edge]]"), "fail")


    def test_exit_codes_make_it_a_deployment_gate(self):
        import subprocess
        import sys
        CA.init(self.d / "pki", "Root").crl()
        ca = CA(self.d / "pki")
        srv, _ = ca.issue("localhost", "server", out=self.d / "srv")
        route = ('[[edge]]\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\n'
                 f'cert = "{(srv / "chain.pem").as_posix()}"\nkey = "{(srv / "key.pem").as_posix()}"\n')
        good = self.write(route)
        exposed = self.d / "exposed.toml"
        exposed.write_text(route + 'policy = "transition"\n', encoding="utf-8")
        broken = self.d / "broken.toml"
        broken.write_text('[[edge]]\nmode = "sideways"\nlisten = "x:1"\ntarget = "y:2"\n', encoding="utf-8")
        run = lambda *a: subprocess.run([sys.executable, "-m", "pqc", "doctor", *map(str, a)], capture_output=True, text=True).returncode
        from pqc import tls
        try:
            tls.lib()
        except tls.OpenSSLUnavailable:
            self.assertEqual(run("--config", good), 3)
            return
        self.assertEqual(run("--config", good), 0)
        self.assertEqual(run("--config", exposed), 0)
        self.assertEqual(run("--strict", "--config", exposed), 1)
        self.assertEqual(run("--strict", "--config", broken), 2)


if __name__ == "__main__":
    unittest.main()
