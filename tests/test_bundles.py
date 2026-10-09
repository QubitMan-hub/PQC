import tempfile
import unittest
from pathlib import Path

from cryptography import x509

from pqc.tls.bundles import SERVICES, create
from pqc.pki import CA, CAError
from pqc.tls.edge import load_config


class BundleTest(unittest.TestCase):
    def test_every_service_generates_a_valid_edge(self):
        with tempfile.TemporaryDirectory() as d:
            for name in SERVICES:
                out = create(name, Path(d) / name, f"{name}.example.com", policy="transition")
                routes, metrics = load_config(out / "edge.toml")
                self.assertEqual((routes[0].target, routes[0].policy, metrics), (f"{name}:{SERVICES[name]['port']}", "transition", "0.0.0.0:9100"))
                cert = x509.load_pem_x509_certificate((out / "edge" / "cert.pem").read_bytes())
                self.assertIn(f"{name}.example.com", cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
                compose = (out / "docker-compose.yml").read_text()
                self.assertIn(f'ports: ["{SERVICES[name]["public"]}:{SERVICES[name]["public"]}"]', compose)
                self.assertEqual(compose.count("ports:"), 1, "only the edge may publish a port")
                self.assertFalse((out / "pki" / "ca.key").exists(), "the CA key must not ship inside the bundle")
                self.assertTrue((out / "ca.key.KEEP-OFFLINE").exists())
                readme = (out / "README.txt").read_text()
                self.assertIn("pqc tls connect", readme)
                self.assertNotIn("Chrome", readme)
            with self.assertRaises(CAError):
                create("nginx", Path(d) / "nginx", "again.example.com")

    def test_existing_ca_and_mutual_tls(self):
        with tempfile.TemporaryDirectory() as d:
            ca = CA.init(Path(d) / "corp", "Corp Root")
            out = create("mqtt", Path(d) / "mqtt", "broker.corp", ca_dir=ca.root, require_client_cert=True)
            r = load_config(out / "edge.toml")[0][0]
            self.assertTrue(r.require_client_cert)
            self.assertEqual(r.crl, "/pki/crl.pem")
            self.assertTrue((ca.root / "ca.key").exists())
            self.assertIn("mosquitto_passwd", (out / "README.txt").read_text())

    def test_an_encrypted_ca_needs_its_passphrase_and_leaves_nothing_behind_without_it(self):
        with tempfile.TemporaryDirectory() as d:
            ca = CA.init(Path(d) / "corp", "Corp Root", passphrase=b"pw")
            with self.assertRaisesRegex(CAError, "cannot open the CA key"):
                create("nginx", Path(d) / "web", "web.corp", ca_dir=ca.root)
            self.assertFalse((Path(d) / "web").exists())
            self.assertTrue((create("nginx", Path(d) / "web", "web.corp", ca_dir=ca.root, passphrase=b"pw") / "edge" / "key.pem").exists())

    def test_a_folder_with_other_files_is_never_written_over(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "app"
            out.mkdir()
            (out / "README.txt").write_text("ours")
            with self.assertRaisesRegex(CAError, "already has README.txt"):
                create("nginx", out, "web.corp")
            self.assertEqual((out / "README.txt").read_text(), "ours")
            self.assertEqual(sorted(p.name for p in out.iterdir()), ["README.txt"])


if __name__ == "__main__":
    unittest.main()
