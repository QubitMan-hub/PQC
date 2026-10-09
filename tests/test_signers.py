import json
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pqc import tls
from pqc.pki import signers
from pqc.pki import CA, CAError, check_revocation, generate, key_pem, signed_by
from pqc.tls.server import Server
from tests.helpers import REASON
from tests.test_tls import echo


SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


class FakeKMS:
    """Answers like AWS KMS for one ML-DSA key; signs only the external mu, as the real service does for MessageType EXTERNAL_MU."""

    def __init__(self, key):
        self.key, self.calls = key, []

    def get_public_key(self, KeyId):
        return {"PublicKey": self.key.public_key().public_bytes(serialization.Encoding.DER, SPKI), "KeySpec": "ML_DSA_65"}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        assert (MessageType, SigningAlgorithm, len(Message)) == ("EXTERNAL_MU", "ML_DSA_SHAKE_256", 64)
        self.calls.append(KeyId)
        return {"Signature": self.key.sign_mu(Message)}


class SignerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, ca):
        out, rec = ca.issue("api.example.com", "server")
        leaf = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        leaf.verify_directly_issued_by(ca.cert)
        ca.cert.verify_directly_issued_by(ca.cert)
        ca.revoke(rec.serial)
        with self.assertRaisesRegex(CAError, "revoked"):
            check_revocation(leaf.serial_number, (ca.root / "crl.pem").read_bytes(), ca.cert)

    def test_aws_kms(self):
        kms = FakeKMS(generate("ML-DSA-65"))
        with mock.patch.dict(sys.modules, boto3=types.SimpleNamespace(client=lambda *a, **k: kms)):
            ca = CA.init(self.d / "kms", "KMS Root", "ML-DSA-65", signer_config={"type": "aws-kms", "key_id": "alias/pki-root"})
            self.assertFalse((self.d / "kms" / "ca.key").exists())
            self.check(ca)
        self.assertEqual(set(kms.calls), {"alias/pki-root"})
        self.assertGreaterEqual(len(kms.calls), 3)

    def test_signing_command(self):
        key = generate("ML-DSA-87")
        (self.d / "hsm.key").write_bytes(key_pem(key))
        (self.d / "hsm.pub").write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, SPKI))
        (self.d / "sign.py").write_text("import sys\nfrom cryptography.hazmat.primitives.serialization import load_pem_private_key\n"
                                        "k = load_pem_private_key(open(sys.argv[1], 'rb').read(), None)\n"
                                        "sys.stdout.buffer.write(k.sign(sys.stdin.buffer.read()))\n")
        cfg = {"type": "command", "command": [sys.executable, str(self.d / "sign.py"), str(self.d / "hsm.key")], "public_key": str(self.d / "hsm.pub")}
        self.check(CA.init(self.d / "hsm", "HSM Root", signer_config=cfg))
        (self.d / "hsm" / "signer.json").write_text(json.dumps(cfg | {"command": [sys.executable, "-c", "raise SystemExit(3)"]}))
        with self.assertRaisesRegex(signers.SignerError, "failed"):
            CA(self.d / "hsm").issue("x", "client")
        (self.d / "hsm" / "signer.json").write_text(json.dumps(cfg | {"command": [sys.executable, "-c", "print('HSM ready')"]}))
        with self.assertRaisesRegex(CAError, "does not verify"):
            CA(self.d / "hsm").issue("y", "client")
        self.assertEqual([r.common_name for r in CA(self.d / "hsm").records()], ["api.example.com"])

    def test_intermediate_ml_dsa(self):
        root = CA.init(self.d / "root", "Root")
        sub = CA.init(self.d / "sub", "Issuing", "ML-DSA-65", parent=root)
        self.assertEqual(sub.anchor.read_bytes(), (self.d / "root" / "ca.crt").read_bytes())
        sub.cert.verify_directly_issued_by(root.cert)
        self.assertEqual(sub.cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 0)
        self.assertEqual([r.kind for r in root.records()], ["ca"])
        out, _ = sub.issue("api", "server")
        chain = x509.load_pem_x509_certificates((out / "chain.pem").read_bytes())
        self.assertEqual([c.subject for c in chain], [chain[0].subject, sub.cert.subject, root.cert.subject])
        chain[0].verify_directly_issued_by(sub.cert)
        with self.assertRaisesRegex(CAError, "path length 0"):
            CA.init(self.d / "deeper", "Deeper", parent=sub)


@unittest.skipIf(REASON, REASON)
class SLHDSARootTest(unittest.TestCase):
    """An SLH-DSA root (hash-based, a different hardness assumption from ML-DSA) over an ML-DSA issuing CA, checked by a real
    TLS handshake: OpenSSL builds and verifies the whole chain."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.d = Path(cls.tmp.name)
        cls.root = CA.init(d / "root", "Hash Root", "SLH-DSA-SHA2-128f", passphrase=b"pw")
        cls.sub = CA.init(d / "sub", "Issuing", parent=cls.root)
        cls.srv, _ = cls.sub.issue("localhost", "server")
        cls.alice, _ = cls.sub.issue("alice", "client")
        cls.bob, cls.bob_rec = cls.sub.issue("bob", "client")
        cls.sub.crl()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_root(self):
        self.assertEqual(self.root.cert.signature_algorithm_oid.dotted_string, signers.OIDS["SLH-DSA-SHA2-128f"])
        self.assertTrue(signed_by(self.root.cert, self.root.cert.tbs_certificate_bytes, self.root.cert.signature))
        self.assertTrue(signed_by(self.root.cert, self.sub.cert.tbs_certificate_bytes, self.sub.cert.signature))
        tbs = self.sub.cert.tbs_certificate_bytes
        self.assertFalse(signed_by(self.root.cert, tbs[:-1] + bytes([tbs[-1] ^ 1]), self.sub.cert.signature))
        self.assertEqual(CA(self.d / "root", b"pw").signer.algorithm, "SLH-DSA-SHA2-128f")
        with self.assertRaises(CAError):
            CA(self.d / "root", b"wrong").signer
        self.root.revoke(self.root.records()[0].serial)
        with self.assertRaisesRegex(CAError, "revoked"):
            check_revocation(self.sub.cert.serial_number, (self.d / "root" / "crl.pem").read_bytes(), self.root.cert)

    def test_mutual_tls_through_the_chain(self):
        anchor = str(self.sub.anchor)
        make = lambda: tls.server_context(self.srv / "chain.pem", self.srv / "key.pem", anchor, True)
        s = Server(("127.0.0.1", 0), make, echo, crl=str(self.d / "sub" / "crl.pem"), ca=anchor, handshake_timeout=3)
        s.start()
        self.addCleanup(s.stop, 1)

        def ping(who):
            ctx = tls.client_context(anchor, who / "chain.pem", who / "key.pem")
            with tls.connect("127.0.0.1", s.port, ctx, "localhost", timeout=5) as c:
                c.sendall(b"ping")
                return c.recv(timeout=5), [x.subject.rfc4514_string() for x in c.peer_chain()]

        reply, chain = ping(self.alice)
        self.assertEqual(reply, b"ping")
        self.assertEqual(chain, ["CN=localhost", "CN=Issuing", "CN=Hash Root"])
        self.sub.revoke(self.bob_rec.serial)
        time.sleep(0.05)
        try:
            reply = ping(self.bob)[0]
        except (tls.TLSError, OSError):
            reply = b""
        self.assertEqual(reply, b"")
        self.assertEqual(ping(self.alice)[0], b"ping")


if __name__ == "__main__":
    unittest.main()
