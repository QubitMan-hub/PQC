"""The command line fails with one clear line and exit code 1, never a traceback or a silent success."""
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from pqc import tls
from pqc.cli import main
from pqc.pki import CA
from tests.helpers import REASON


class CLITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.ca = CA.init(self.d / "pki", "Root")
        self.srv, _ = self.ca.issue("localhost", "server", ["localhost", "127.0.0.1"], out=self.d / "srv")

    def fails(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as e:
            main([str(a) for a in argv])
        self.assertEqual(e.exception.code, 1, err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        return err.getvalue()

    def test_json_logs_keep_the_traceback(self):
        import json
        import logging
        import sys
        from pqc.cli import JSONFormatter
        try:
            1 / 0
        except ZeroDivisionError:
            r = logging.LogRecord("x", logging.ERROR, __file__, 1, "handler failed", None, sys.exc_info())
        self.assertIn("ZeroDivisionError", json.loads(JSONFormatter().format(r))["exception"])

    @unittest.skipIf(REASON, REASON)
    def test_edge_start_up_errors(self):
        edge = ["tls", "edge", "--listen", "127.0.0.1:0", "--target", "127.0.0.1:1"]
        self.assertIn("nope.pem", self.fails(*edge, "--cert", self.d / "nope.pem", "--key", self.srv / "key.pem"))
        self.assertIn("needs the CA", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--require-client-cert"))
        self.assertIn("ML-DSA-87", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--policy", "cnsa2"))
        self.assertTrue((self.d / "pki" / "crl.pem").is_file())
        self.assertIn("ca crl", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--require-client-cert",
                                           "--ca", self.d / "pki" / "ca.crt", "--crl", self.d / "nope-crl.pem"))
        self.assertIn("fixed listen port", self.fails(*edge, "--cert", self.srv / "chain.pem", "--key", self.srv / "key.pem", "--workers", "2"))

    @unittest.skipIf(REASON, REASON)
    def test_connect_prints_a_reply_that_arrives_in_pieces(self):
        import time
        from pqc.tls.server import Server

        def reply(conn, addr):
            conn.recv(timeout=5)
            conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
            time.sleep(0.3)
            conn.sendall(b'{"allergies": ["penicillin"]}')
        s = Server(("127.0.0.1", 0), lambda: tls.server_context(self.srv / "chain.pem", self.srv / "key.pem"), reply)
        s.start()
        self.addCleanup(s.stop, 1)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            main(["tls", "connect", f"127.0.0.1:{s.port}", "--server-name", "localhost", "--ca", str(self.d / "pki" / "ca.crt"), "--send", "GET /"])
        self.assertEqual(e.exception.code, 0)
        self.assertIn("penicillin", out.getvalue())

    @unittest.skipIf(REASON, REASON)
    def test_network_errors_are_in_words(self):
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        ca = ["--ca", self.d / "pki" / "ca.crt"]
        self.assertIn("--server-name nosuch.invalid", self.fails("tls", "connect", "nosuch.invalid:443", *ca))
        self.assertIn("connection refused", self.fails("tls", "connect", f"127.0.0.1:{closed}", *ca))
        self.assertIn("0 to 65535", self.fails("tls", "connect", "127.0.0.1:99999", *ca))

    def test_passphrase_prompts_without_a_terminal_say_what_to_do(self):
        from unittest import mock
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.d)
        with mock.patch("sys.stdin", io.StringIO("")):
            for flags in ((), ("--encrypt",)):
                self.assertIn("--no-encrypt", self.fails("ca", "init", "--name", "T", "--dir", "ca2", *flags))
        self.assertFalse((self.d / "ca2" / "ca.crt").exists())

    def test_the_ca_key_is_encrypted_unless_asked_not_to(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"PQC_CA_PASSPHRASE": "pw"}), contextlib.redirect_stdout(io.StringIO()):
            for argv in (["--dir", self.d / "enc"], ["--dir", self.d / "plain", "--no-encrypt"]):
                with self.assertRaises(SystemExit) as e:
                    main(["ca", "init", "--name", "T", *map(str, argv)])
                self.assertEqual(e.exception.code, 0)
        self.assertIn(b"ENCRYPTED", (self.d / "enc" / "ca.key").read_bytes())
        self.assertNotIn(b"ENCRYPTED", (self.d / "plain" / "ca.key").read_bytes())

    @unittest.skipIf(REASON, REASON)
    def test_the_one_minute_tour_shows_post_quantum_in_and_classical_out(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            main(["try"])
        self.assertEqual(e.exception.code, 0, out.getvalue())
        for seen in ("X25519MLKEM768", "ML-DSA-65", "knows nothing about post-quantum", "refused, as it should be"):
            self.assertIn(seen, out.getvalue())

    def test_config_files_name_what_is_missing_or_wrong(self):
        cfg = self.d / "c.toml"
        cfg.write_text('[[edge]]\nname = "a"\nlisten = "127.0.0.1:0"\n')
        self.assertIn("missing mode, target", self.fails("tls", "edge", "--config", cfg))
        cfg.write_text('[[edge]]\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\nmax_connections = "lots"\n')
        self.assertIn("max_connections must be a whole number", self.fails("tls", "edge", "--config", cfg))
        cfg.write_text('[[edge]]\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\nmax_connections = true\n')
        self.assertIn("max_connections must be a whole number", self.fails("tls", "edge", "--config", cfg))
        for number in ("nan", "inf", "-inf"):
            cfg.write_text(f'[[edge]]\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\nidle_timeout = {number}\n')
            self.assertIn("idle_timeout must be a finite number", self.fails("tls", "edge", "--config", cfg))
        text = '[[edge]]\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\n'
        for data in (b"\xef\xbb\xbf" + text.encode(), b"\xff\xfe" + text.encode("utf-16-le")):
            cfg.write_bytes(data)
            self.assertIn("terminate needs cert and key", self.fails("tls", "edge", "--config", cfg))
        cfg.write_bytes(b"\x80\x81 not text")
        self.assertIn("is not UTF-8 text", self.fails("tls", "edge", "--config", cfg))

    def test_nothing_to_do_is_an_error(self):
        for argv in (("ca", "crl", "--days", "0"), ("ca", "maintain", "--crl-days", "-1"), ("ca", "token", "server", "web", "--hours", "0")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
                main([*argv, "--dir", str(self.d / "nowhere")])
            self.assertIn("expected a number above 0", err.getvalue(), argv)

    def test_every_option_explains_itself(self):
        import argparse
        from pqc.cli import parser
        missing = []

        def walk(p, path):
            for a in p._actions:
                if isinstance(a, argparse._SubParsersAction):
                    for name, sub in a.choices.items():
                        walk(sub, [*path, name])
                elif not a.help:
                    missing.append(" ".join([*path, "/".join(a.option_strings) or a.dest]))
        walk(parser(), ["pqc"])
        self.assertEqual(missing, [])

    def test_first_steps_are_explained(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            main([])
        self.assertEqual(e.exception.code, 0)
        self.assertIn("pqc try", out.getvalue())
        cfg = self.d / "edge.toml"
        cfg.write_text('[[route]]\nlisten = "0.0.0.0:443"\n')
        self.assertIn("found [[route]]", self.fails("tls", "edge", "--config", cfg))

    def test_bundles_never_invent_a_ca_or_leave_half_a_folder(self):
        self.assertIn("no CA at", self.fails("tls", "bundle", "nginx", "--host", "web.example", "--ca", self.d / "typo", "--out", self.d / "b1"))
        self.assertFalse((self.d / "typo").exists())
        self.assertIn("not a valid host name", self.fails("tls", "bundle", "nginx", "--host", "bad host", "--out", self.d / "b2"))
        self.assertFalse((self.d / "b2").exists())

if __name__ == "__main__":
    unittest.main()




def test_guided_enrollment_keeps_secrets_out_of_output_and_requires_trust(tmp_path, capsys):
    import datetime as dt
    import pytest
    from types import SimpleNamespace
    from unittest.mock import patch
    args = ['ca', 'enroll', '--guide', '--out', str(tmp_path/'device')]
    cert = SimpleNamespace(serial_number=1, not_valid_after_utc=dt.datetime.now(dt.timezone.utc))
    with patch('sys.stdin.isatty', return_value=True), patch('pqc.checks.prerequisites', return_value=[]), \
            patch('builtins.input', side_effect=['https://ca.example:9443', 'device-1', 'a'*64]), \
            patch('getpass.getpass', side_effect=['PRIVATE_TOKEN', 'PRIVATE_PASSWORD', 'PRIVATE_PASSWORD']), \
            patch.dict(os.environ, {'PQC_ENROLL_TOKEN': ''}), \
            patch('pqc.pki.est.fetch_ca') as fetch, patch('pqc.pki.est.enroll', return_value=cert) as enroll:
        with pytest.raises(SystemExit) as result:
            main(args)
        assert result.value.code == 0
        assert fetch.call_args.args[1] == 'a'*64
        assert enroll.call_args.kwargs['passphrase'] == b'PRIVATE_PASSWORD'
        assert enroll.call_args.args[1] == 'PRIVATE_TOKEN'
        assert 'PRIVATE_' not in capsys.readouterr().out
    with patch('sys.stdin.isatty', return_value=False), patch('pqc.pki.est.enroll') as enroll:
        with pytest.raises(SystemExit) as result:
            main(args)
        assert result.value.code != 0
        enroll.assert_not_called()
