"""Races on shared state: the CA folder written by several processes at once (the CLI and the enrollment server
may share it), and a revocation landing while clients are connecting."""
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from cryptography import x509

from pqc import tls
from pqc.pki import CA, CAError, locked, verify_crl
from pqc.tls.server import Server
from tests.helpers import REASON


WORKER = textwrap.dedent("""
    import sys
    from pqc.pki import CA
    ca = CA(sys.argv[1])
    for i in range(5):
        _, rec = ca.issue(f"p{sys.argv[2]}-{i}.test", "server")
        if i % 2:
            ca.revoke(rec.serial)
""")


def listed(root):
    return {format(r.serial_number, "x") for r in x509.load_pem_x509_crl((Path(root) / "crl.pem").read_bytes())}


class RaceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.root = self.d / "pki"
        self.ca = CA.init(self.root, "Root")

    def test_windows_lock_waits_for_contention_and_never_remembers_failed_acquisition(self):
        import errno
        import os
        from types import SimpleNamespace
        from pqc import storage
        windows = SimpleNamespace(name="nt", open=os.open, fdopen=os.fdopen,
                                  O_RDWR=os.O_RDWR, O_CREAT=os.O_CREAT, O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0))
        crt = mock.Mock(LK_NBLCK=2, LK_UNLCK=0)
        for failure in (OSError(errno.EIO, "I/O failure"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), mock.patch.object(storage, "os", windows), \
                    mock.patch.dict(sys.modules, {"msvcrt": crt}), mock.patch.object(storage.time, "sleep") as sleep:
                crt.locking.reset_mock()
                crt.locking.side_effect = [failure]
                with self.assertRaises(type(failure)):
                    with storage.locked(self.root):
                        self.fail("failed acquisition entered protected state")
                # Longer contention must wait, and a previous failure must not bypass locking.
                crt.locking.side_effect = [OSError(errno.EACCES, "busy")] * 12 + [None, None]
                with storage.locked(self.root):
                    with storage.locked(self.root):
                        self.assertEqual(crt.locking.call_count, 14)
                self.assertEqual(sleep.call_count, 12)
                self.assertEqual(crt.locking.call_args.args[1], crt.LK_UNLCK)

    def test_processes_issuing_and_revoking_at_once_lose_nothing(self):
        procs = [subprocess.Popen([sys.executable, "-c", WORKER, str(self.root), str(n)]) for n in range(6)]
        self.assertEqual([p.wait(120) for p in procs], [0] * 6)
        recs = CA(self.root).records()
        self.assertEqual(len(recs), 30)
        self.assertEqual(len({r.serial for r in recs}), 30)
        revoked = {r.serial for r in recs if r.status == "revoked"}
        self.assertEqual(len(revoked), 12)
        self.assertEqual(revoked, listed(self.root))
        verify_crl((self.root / "crl.pem").read_bytes(), x509.load_pem_x509_certificates((self.root / "ca.crt").read_bytes()))

    def test_enrollment_tokens_and_eab_keys_made_at_once_are_all_kept(self):
        worker = textwrap.dedent("""
            import sys
            from pqc.pki import CA
            from pqc.pki.acme import create_eab
            from pqc.pki.est import create_token
            for i in range(5):
                create_token(CA(sys.argv[1]), f"t{sys.argv[2]}-{i}.test", "server")
                create_eab(sys.argv[1])
        """)
        procs = [subprocess.Popen([sys.executable, "-c", worker, str(self.root), str(n)]) for n in range(6)]
        self.assertEqual([p.wait(120) for p in procs], [0] * 6)
        from pqc.pki.acme import eab_keys
        from pqc.pki.est import _load_tokens
        self.assertEqual((len(_load_tokens(self.root)), len(eab_keys(self.root))), (30, 30))

    def test_renewing_and_revoking_the_same_certificate_at_once(self):
        for n in range(6):
            _, rec = self.ca.issue(f"race{n}.test", "server")
            with ThreadPoolExecutor(2) as pool:
                renewed = pool.submit(self.ca.renew, rec.serial)
                revoked = pool.submit(self.ca.revoke, rec.serial)
            self.assertIsNone(revoked.exception())
            if renewed.exception() is None:
                new = renewed.result()[1]
                self.assertEqual(self.ca.find(new.serial).status, "valid", "a renewal before the revocation keeps its new certificate")
            else:
                self.assertIn("revoked", str(renewed.exception()), "a renewal after the revocation must be refused")
            self.assertIn(rec.serial, listed(self.root))

    def test_renewal_waiting_for_the_ca_lock_cannot_bypass_a_revocation(self):
        _, record = self.ca.issue("blocked.test", "server")
        read, started = threading.Event(), threading.Event()
        original = self.ca.find

        def observe(serial):
            result = original(serial)
            if threading.current_thread() is not threading.main_thread():
                read.set()
            return result

        def renew():
            started.set()
            return self.ca.renew(record.serial)

        with mock.patch.object(self.ca, "find", side_effect=observe), ThreadPoolExecutor(1) as pool:
            with locked(self.root):
                pending = pool.submit(renew)
                self.assertTrue(started.wait(5))
                read_before_lock = read.wait(0.25)
                self.ca.revoke(record.serial)
            with self.assertRaisesRegex(CAError, "revoked"):
                pending.result(5)
        self.assertFalse(read_before_lock, "renewal must read revocation state while holding the CA lock")
        self.assertEqual(len(self.ca.records()), 1, "no replacement certificate may be issued after revocation")

    @unittest.skipIf(REASON, REASON)
    def test_no_handshake_succeeds_once_the_revocation_is_written(self):
        srv, _ = self.ca.issue("localhost", "server", ["127.0.0.1"], out=self.d / "srv")
        who, rec = self.ca.issue("laptop", "client", out=self.d / "laptop")
        cafile = str(self.root / "ca.crt")

        def echo(conn, addr):
            conn.sendall(b"ok")
        make = lambda: tls.server_context(srv / "chain.pem", srv / "key.pem", cafile, True)
        s = Server(("127.0.0.1", 0), make, echo, crl=str(self.root / "crl.pem"), ca=cafile, handshake_timeout=5)
        s.start()
        self.addCleanup(s.stop, 1)
        ctx = tls.client_context(cafile, who / "chain.pem", who / "key.pem")
        results, stop, revoked_at = [], threading.Event(), []

        def hammer():
            while not stop.is_set():
                start = time.monotonic()
                try:
                    with tls.connect("127.0.0.1", s.port, ctx, "localhost", 5) as c:
                        ok = c.recv(timeout=5) == b"ok"
                except (tls.TLSError, OSError):
                    ok = False
                results.append((start, ok))
        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        time.sleep(0.5)
        self.ca.revoke(rec.serial)
        revoked_at.append(time.monotonic())
        time.sleep(1.0)
        stop.set()
        for t in threads:
            t.join()
        before = [ok for t0, ok in results if t0 < revoked_at[0] - 0.2]
        after = [ok for t0, ok in results if t0 > revoked_at[0]]
        self.assertTrue(before and all(before), "the client worked before the revocation")
        self.assertTrue(after)
        self.assertFalse(any(after), "a handshake that started after the CRL was written succeeded")


if __name__ == "__main__":
    unittest.main()
