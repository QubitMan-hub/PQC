"""Property-based tests: rules that must hold for every input, searched by Hypothesis (derandomized, so CI runs are
reproducible) where test_fuzz throws seeded junk. Each failure shrinks to the smallest counterexample."""
import tempfile
import unittest
from pathlib import Path

try:
    from hypothesis import given, settings, strategies as st
except ImportError:  # the test extra installs it
    raise unittest.SkipTest("needs hypothesis (pip install -e .[test])") from None

from pqc.pki import CA, CAError, general_names
from pqc.pki.acme import Problem, b64u, jwk_key, unb64u
from pqc.pki.signers import _tlv, children, encode
from pqc.tls import hostport
from pqc.tls.http import HTTPError, _read_message

PROPERTY = settings(max_examples=150, deadline=None, derandomize=True)


class Pieces:
    """A connection that hands a message over in the pieces given, as a network may."""

    def __init__(self, parts):
        self.parts = list(parts)

    def recv(self, n, timeout=None):
        if not self.parts:
            return b""
        head, self.parts[0] = self.parts[0][:n], self.parts[0][n:]
        if not self.parts[0]:
            self.parts.pop(0)
        return head


def cut(data, points):
    points = sorted({p for p in points if 0 < p < len(data)})
    return [data[a:b] for a, b in zip([0, *points], [*points, len(data)])]


class HTTPProperties(unittest.TestCase):
    @PROPERTY
    @given(st.dictionaries(st.from_regex(r"[A-Za-z][A-Za-z0-9-]{0,15}", fullmatch=True), st.from_regex(r"[ -~]{0,40}", fullmatch=True),
                           max_size=6), st.binary(max_size=400), st.lists(st.integers(0, 2000), max_size=12))
    def test_a_message_reads_the_same_however_the_network_splits_it(self, headers, body, points):
        headers = {k.lower(): v.strip() for k, v in headers.items() if k.lower() != "content-length"}
        raw = ("POST /x HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + f"Content-Length: {len(body)}\r\n\r\n").encode() + body
        first, got, rest = _read_message(Pieces(cut(raw, points)), 5)
        self.assertEqual((first, rest), ("POST /x HTTP/1.1", body))
        self.assertEqual({k: v for k, v in got.items() if k != "content-length"}, headers)

    @PROPERTY
    @given(st.binary(max_size=600), st.lists(st.integers(0, 600), max_size=8))
    def test_any_bytes_give_a_message_or_an_http_error(self, raw, points):
        try:
            _read_message(Pieces(cut(raw, points)), 5)
        except HTTPError:
            pass


class EncodingProperties(unittest.TestCase):
    @PROPERTY
    @given(st.integers(0, 255), st.binary(max_size=70000))
    def test_der_lengths_round_trip_short_and_long_form(self, tag, content):
        der = encode(tag, content)
        t, start, end = _tlv(der)
        self.assertEqual((t, der[start:end], end), (tag, content, len(der)))

    @PROPERTY
    @given(st.lists(st.tuples(st.integers(0, 255), st.binary(max_size=300)), max_size=8))
    def test_a_sequence_splits_back_into_its_elements(self, items):
        parts = [encode(t, c) for t, c in items]
        self.assertEqual(children(encode(0x30, b"".join(parts))), parts)

    @PROPERTY
    @given(st.binary(max_size=200))
    def test_base64url_round_trips(self, data):
        self.assertEqual(unb64u(b64u(data)), data)


class ParsingProperties(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.ca = CA.init(Path(cls.tmp.name) / "pki", "Root")
        for n in range(4):
            cls.ca.issue(f"h{n}.test", "server")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @PROPERTY
    @given(st.one_of(st.from_regex(r"[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?(\.[a-z0-9]{1,10}){0,3}", fullmatch=True), st.ip_addresses().map(str)),
           st.integers(0, 65535))
    def test_every_host_and_port_round_trips(self, host, port):
        text = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        self.assertEqual(hostport(text), (host, port))

    @PROPERTY
    @given(st.text(max_size=60))
    def test_any_address_text_parses_or_raises_value_error(self, text):
        try:
            hostport(text)
        except ValueError:
            pass

    @PROPERTY
    @given(st.data())
    def test_find_matches_exactly_what_the_text_names(self, data):
        recs = self.ca.records()
        real = st.tuples(st.sampled_from(recs), st.integers(0, 40), st.booleans()).map(
            lambda t: t[0].serial[:t[1]].upper() if t[2] else t[0].serial[:t[1]])
        text = data.draw(st.one_of(st.text(max_size=50), real))
        wanted = text.strip().lower() if isinstance(text, str) else ""
        named = [r for r in recs if len(wanted) >= 8 and r.serial.startswith(wanted)]
        try:
            rec = self.ca.find(text)
        except CAError:
            self.assertNotEqual(len(named), 1, f"{text!r} names one certificate but found none")
            return
        self.assertEqual([rec.serial], [r.serial for r in named])

    @PROPERTY
    @given(st.lists(st.text(max_size=80), max_size=4))
    def test_names_are_valid_or_refused(self, names):
        try:
            general_names(names)
        except CAError:
            pass

    @PROPERTY
    @given(st.dictionaries(st.sampled_from(["kty", "crv", "x", "y", "n", "e"]),
                           st.one_of(st.text(max_size=40), st.sampled_from(["RSA", "EC", "OKP", "P-256", "Ed25519", "AQAB"]))))
    def test_account_keys_are_accepted_or_refused_as_acme_problems(self, jwk):
        try:
            jwk_key(jwk)
        except Problem:
            pass


if __name__ == "__main__":
    unittest.main()
