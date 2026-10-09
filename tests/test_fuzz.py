"""Malformed input, seeded so failures reproduce: every entry point that reads something from outside must answer with its own
error (never a crash, a hang or a half-written file)."""
import base64
import json
import os
import random
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from pqc.pki import CA
from pqc.pki.acme import Problem, Service
from pqc.tls.http import HTTPError, _read_message


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def junk(rnd, depth=0):
    k = rnd.randrange(9 if depth < 3 else 5)
    if k == 0:
        return None
    if k == 1:
        return rnd.choice([True, False])
    if k == 2:
        return rnd.choice([0, -1, 1, 10 ** 30, rnd.randrange(-2 ** 40, 2 ** 40)])
    if k == 3:
        return rnd.choice(["", "x" * rnd.randrange(300), "../../etc/passwd", "\x00", "server", "a,b,,c", "ünï"])
    if k == 4:
        return b64(os.urandom(rnd.randrange(80)))
    if k == 5:
        return [junk(rnd, depth + 1) for _ in range(rnd.randrange(4))]
    if k == 6:
        return {rnd.choice(["alg", "jwk", "kid", "nonce", "url", "kty", "crv", "x", "identifiers", "csr", "type", "value"]): junk(rnd, depth + 1)
                for _ in range(rnd.randrange(5))}
    if k == 7:
        return b64(json.dumps(junk(rnd, depth + 1)).encode())
    return rnd.random()


class FuzzTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.rnd = random.Random(20260928)

    def test_acme_answers_every_request_with_an_acme_problem(self):
        ca = CA.init(self.d / "pki", "Root")
        svc, rnd = Service(ca, "http://127.0.0.1:14000", allow=["*.test"], validate_async=False), self.rnd
        paths = ["/directory", "/new-nonce", "/new-account", "/new-order", "/acct/1", "/order/x", "/authz/x", "/chall/x", "/finalize/x",
                 "/cert/x", "/revoke-cert", "/key-change", "/../../etc/passwd", "/" + "a" * 3000]
        for n in range(1500):
            body = rnd.choice([os.urandom(rnd.randrange(400)), json.dumps(junk(rnd)).encode(),
                               json.dumps({"protected": b64(json.dumps({"alg": rnd.choice(["ES256", "none", "HS256", 5]), "nonce": svc.nonce(),
                                                                        "url": "http://127.0.0.1:14000" + rnd.choice(paths),
                                                                        rnd.choice(["jwk", "kid"]): junk(rnd)}).encode()),
                                           "payload": b64(json.dumps(junk(rnd)).encode()), "signature": b64(os.urandom(64))}).encode()])
            try:
                svc.handle(rnd.choice(["GET", "POST", "HEAD"]), rnd.choice(paths), body)
            except Problem:
                pass

    def test_the_http_reader_rejects_malformed_messages(self):
        rnd = self.rnd

        class Conn:
            def __init__(self, data):
                self.data = data

            def recv(self, n, timeout=None):
                chunk, self.data = self.data[:rnd.randrange(1, n + 1)], self.data[n:]
                return chunk
        samples = [b"POST / HTTP/1.1\r\nContent-Length: " + v + b"\r\n\r\nabc" for v in (b"-1", b"99999999", b"x", b"\xff", b"")]
        for n in range(600):
            data = rnd.choice(samples + [os.urandom(rnd.randrange(300)), b"GET / HTTP/1.1\r\n" + os.urandom(50) + b"\r\n\r\n"])
            try:
                _read_message(Conn(data), 1)
            except HTTPError:
                pass

if __name__ == "__main__":
    unittest.main()
