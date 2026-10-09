"""Crash consistency: a process killed at a random moment (SIGKILL, or TerminateProcess on Windows: no clean-up runs) while it
issues and revokes must leave state that still loads, and never a certificate the CA cannot revoke."""
import random
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from cryptography import x509

from pqc import checks
from pqc.pki import CA, verify_crl

CA_WORK = textwrap.dedent("""
    import sys
    from pqc.pki import CA
    ca, n = CA(sys.argv[1]), 0
    while True:
        n += 1
        _, rec = ca.issue(f"host{n}.test", "server")
        if n % 2:
            ca.revoke(rec.serial)
""")

def killed(args, rnd, ready=lambda: True):
    """Kill the worker at a random moment once `ready()` holds, so a slow machine still kills it mid-work, not mid-start-up."""
    p = subprocess.Popen([sys.executable, "-c", *args], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 60
    while not ready() and p.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(rnd.uniform(0.4, 1.5))
    if p.poll() is not None:
        raise AssertionError(f"the worker died on its own: {p.stderr.read().decode()[-500:]}")
    p.kill()
    p.wait()
    p.stderr.close()


class CrashTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.rnd = random.Random(7)

    def test_a_killed_ca_leaves_every_certificate_revocable(self):
        root = self.d / "pki"
        CA.init(root, "Root")
        for round_ in range(8):
            killed([CA_WORK, str(root)], self.rnd)
            with self.subTest(round=round_):
                ca = CA(root)
                known = {r.serial for r in ca.records()}
                cas = x509.load_pem_x509_certificates((root / "ca.crt").read_bytes())
                verify_crl((root / "crl.pem").read_bytes(), cas)
                on_disk = {format(x509.load_pem_x509_certificate(p.read_bytes()).serial_number, "x") for p in root.glob("issued/*/cert.pem")}
                self.assertLessEqual(on_disk, known, "a certificate reached disk that the CA has no record of, so it cannot be revoked")
                listed = {format(r.serial_number, "x") for r in x509.load_pem_x509_crl((root / "crl.pem").read_bytes())}
                missing = {r.serial for r in ca.records() if r.status == "revoked"} - listed
                if missing:
                    self.assertEqual(next(lvl for lvl, m in checks.ca(root) if "not in crl.pem" in m), "fail")
                    ca.crl()
        self.assertGreater(len(CA(root).records()), 8)

if __name__ == "__main__":
    unittest.main()
