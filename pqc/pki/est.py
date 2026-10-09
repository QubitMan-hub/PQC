"""Certificate enrollment over post-quantum TLS: EST (RFC 7030).

A new machine enrolls with a one-time token that the CA operator created for exactly one name; its key is generated on the
machine and never leaves it. A machine with a valid certificate renews it over mutual TLS (simplereenroll) and cannot change its
identity. Only a hash of each token is stored.
"""
import base64
import datetime as dt
import hashlib
import hmac
import json
import secrets
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import NameOID

from .. import tls
from . import CA, CAError, USAGE, algorithm_of, cert_pem, check_revocation, append, general_names, generate, key_pem, locked, names_of, now, write
from ..tls.http import HTTPError, request

PREFIX = "/.well-known/est"
PKCS7 = {"Content-Type": "application/pkcs7-mime; smime-type=certs-only", "Content-Transfer-Encoding": "base64"}


def _tokens_path(root):
    return Path(root) / "tokens.json"


def _load_tokens(root):
    p = _tokens_path(root)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def create_token(ca, common_name, kind, names=(), hours=24):
    """A one-time enrollment token for exactly this name. Returns the only copy of the secret."""
    if kind not in USAGE:
        raise CAError(f"kind must be one of {', '.join(USAGE)}")
    if not 1 <= len(common_name) <= 64:
        raise CAError("the common name must be 1 to 64 characters")
    tid, secret = secrets.token_hex(8), secrets.token_urlsafe(24)
    names = list(dict.fromkeys(([common_name] if kind != "client" else []) + list(names)))
    general_names(names)
    entry = {"id": tid, "hash": hashlib.sha256(secret.encode()).hexdigest(), "common_name": common_name, "kind": kind, "names": names,
             "expires": (now() + dt.timedelta(hours=hours)).isoformat(), "used": ""}
    with locked(ca.root):
        write(_tokens_path(ca.root), json.dumps(_load_tokens(ca.root) + [entry], indent=1).encode(), secret=True)
    return f"{tid}.{secret}"


def _pkcs7(certs):
    return base64.encodebytes(pkcs7.serialize_certificates(certs, Encoding.DER))


class Service:
    """The EST endpoints, as an app for tls.http.handler."""

    def __init__(self, ca, audit_log=None):
        self.ca = ca
        self.audit_log = Path(audit_log or Path(ca.root) / "est-audit.jsonl")

    def chain(self):
        return x509.load_pem_x509_certificates(self.ca.chain())

    def audit(self, event, **detail):
        append(self.audit_log, json.dumps({"time": now().isoformat(), "event": event, **detail}))

    def __call__(self, method, path, headers, body, conn):
        try:
            if path == f"{PREFIX}/cacerts" and method == "GET":
                return 200, _pkcs7(self.chain()), PKCS7
            if path in (f"{PREFIX}/simpleenroll", f"{PREFIX}/simplereenroll") and method == "POST":
                try:
                    csr = x509.load_der_x509_csr(base64.b64decode(b"".join(body.split()), validate=True))
                except ValueError:
                    raise HTTPError(400, "the body must be a base64 DER PKCS#10 request") from None
                if not csr.is_signature_valid:
                    raise HTTPError(400, "the request's signature does not verify")
                cert = self.renew(csr, conn) if path.endswith("reenroll") else self.enroll(csr, headers)
                return 200, _pkcs7([cert] + self.chain()), PKCS7
            raise HTTPError(404, "no such EST endpoint")
        except CAError as e:
            raise HTTPError(403, str(e)) from None

    def enroll(self, csr, headers):
        auth = headers.get("authorization", "")
        try:
            tid, _, secret = base64.b64decode(auth.removeprefix("Basic ")).decode().partition(":")
        except ValueError:
            tid = secret = ""
        cn, names = names_of(csr)
        with locked(self.ca.root):
            tokens = _load_tokens(self.ca.root)
            t = next((t for t in tokens if t["id"] == tid), None)
            if not auth.startswith("Basic ") or not t or not hmac.compare_digest(t["hash"], hashlib.sha256(secret.encode()).hexdigest()):
                self.audit("enroll_refused", reason="bad token", token=tid[:16], common_name=cn)
                raise HTTPError(401, "missing or wrong enrollment token")
            if t["used"] or dt.datetime.fromisoformat(t["expires"]) < now():
                self.audit("enroll_refused", reason="token used or expired", token=tid, common_name=cn)
                raise HTTPError(401, "this enrollment token was already used or has expired")
            if cn != t["common_name"] or not set(names) <= set(t["names"]):
                self.audit("enroll_refused", reason="names outside the token", token=tid, common_name=cn, names=names)
                raise CAError(f"this token is for {t['common_name']} {t['names']}, not {cn} {names}")
            if not algorithm_of(csr.public_key()):
                raise CAError("the request must carry an ML-DSA key; the token was not used")
            # spent on disk before anything is signed: a crash from here on leaves the token used up, never reusable
            t["used"] = now().isoformat()
            write(_tokens_path(self.ca.root), json.dumps(tokens, indent=1).encode(), secret=True)
            try:
                cert, rec = self.ca.sign(csr.public_key(), cn, t["kind"], names or t["names"])
            except Exception:
                t["used"] = ""
                write(_tokens_path(self.ca.root), json.dumps(tokens, indent=1).encode(), secret=True)
                raise
        self.audit("enrolled", serial=rec.serial, common_name=cn, kind=t["kind"], token=tid)
        return cert

    def renew(self, csr, conn):
        current = conn.peer_certificate()
        if current is None:
            raise HTTPError(401, "re-enrollment needs the current certificate (mutual TLS)")
        crl = Path(self.ca.root) / "crl.pem"
        if crl.exists():
            check_revocation(current.serial_number, crl.read_bytes(), self.ca.cert)
        rec = next((r for r in self.ca.records() if r.serial == format(current.serial_number, "x")), None)
        cn, names = names_of(csr)
        if not rec or rec.status != "valid":
            raise CAError("the presenting certificate is not a valid certificate of this CA")
        if cn != rec.common_name or not set(names) <= set(rec.names):
            self.audit("renew_refused", serial=rec.serial, common_name=cn, names=names)
            raise CAError(f"a renewal keeps its identity: {rec.common_name} {rec.names}")
        cert, new = self.ca.sign(csr.public_key(), cn, rec.kind, names or rec.names)
        self.audit("renewed", serial=new.serial, replaces=rec.serial, common_name=cn)
        return cert


# --- client -----------------------------------------------------------------------------------------------------------


def _target(url):
    u = urlparse(url if "://" in url else f"https://{url}")
    if u.scheme != "https" or not u.hostname:
        raise CAError(f"EST URLs look like https://ca.example.com:9443, not {url}")
    return u.hostname, u.port or 443


def _parse_certs(body, key=None):
    """With `key`: its certificate first, then each issuer. PKCS#7 keeps certificates as a sorted set, so the order they arrive
    in means nothing."""
    try:
        certs = pkcs7.load_der_pkcs7_certificates(base64.b64decode(b"".join(body.split())))
    except ValueError:
        raise CAError("the EST server returned something that is not a certificate") from None
    if key is None:
        return certs
    chain = [c for c in certs if c.public_key() == key.public_key()][:1]
    if not chain:
        raise CAError("the EST server did not return a certificate for our key")
    while nxt := next((c for c in certs if c.subject == chain[-1].issuer and c not in chain), None):
        chain.append(nxt)
    return chain


def _call(url, ctx, path, body=b"", headers=None, server_name=None):
    host, port = _target(url)
    with tls.connect(host, port, ctx, server_name or host, timeout=15) as conn:
        status, _, out = request(conn, "POST" if body else "GET", PREFIX + path, host, body, headers)
    if status != 200:
        raise CAError(f"EST server said {status}: {out.decode(errors='replace').strip()}")
    return out


def fetch_ca(url, fingerprint, out, server_name=None):
    """Bootstrap trust: download the CA certificate and accept it only if its SHA-256 fingerprint matches the one given."""
    host, port = _target(url)
    ctx = tls.client_context(verify=False)  # RFC 7030 bootstrap: the CA certificate is pinned by fingerprint below
    with tls.connect(host, port, ctx, server_name or host, timeout=15) as conn:
        status, _, body = request(conn, "GET", PREFIX + "/cacerts", host)
    if status != 200:
        raise CAError(f"EST server said {status}")
    certs = _parse_certs(body)
    want = fingerprint.replace(":", "").lower()
    match = [c for c in certs if hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest() == want]
    if not match:
        raise CAError("the CA certificate does not match the fingerprint you were given: do not trust this server")
    write(Path(out), cert_pem(match[0]))
    return match[0]


def fingerprint(cert):
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def _csr(key, common_name, names):
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName(general_names(names)), critical=False)
    return base64.encodebytes(b.sign(key, None).public_bytes(Encoding.DER))


def _save(out, key, certs, ca_cert, passphrase):
    out = Path(out)
    write(out / "key.pem", key_pem(key, passphrase), secret=True)
    write(out / "cert.pem", cert_pem(certs[0]))
    write(out / "chain.pem", b"".join(cert_pem(c) for c in certs))
    write(out / "ca.crt", cert_pem(ca_cert))


def enroll(url, token, common_name, names=(), out=".", ca=None, algorithm="ML-DSA-65", passphrase=None, server_name=None):
    """First enrollment with a one-time token. Writes key.pem, cert.pem, chain.pem and ca.crt into `out`."""
    if (Path(out) / "key.pem").exists():
        raise CAError(f"{out} already holds a key; renew it with 'ca enroll URL --renew {out}', or choose another --out")
    ca_cert = x509.load_pem_x509_certificate(Path(ca).read_bytes())
    key = generate(algorithm)
    tid, _, secret = token.partition(".")
    auth = base64.b64encode(f"{tid}:{secret}".encode()).decode()
    body = _call(url, tls.client_context(ca), "/simpleenroll", _csr(key, common_name, names),
                 {"Content-Type": "application/pkcs10", "Authorization": f"Basic {auth}"}, server_name)
    certs = _parse_certs(body, key)
    _save(out, key, certs, ca_cert, passphrase)
    return certs[0]


def renew(url, folder, algorithm=None, within_days=None, passphrase=None, server_name=None):
    """Re-enroll with the current certificate in `folder` and replace it in place (servers pick it up without a restart), with a
    new key of the same algorithm unless `algorithm` is given. With `within_days`, do nothing until it is that close to expiry."""
    folder = Path(folder)
    current = x509.load_pem_x509_certificate((folder / "cert.pem").read_bytes())
    if within_days is not None and current.not_valid_after_utc - now() > dt.timedelta(days=within_days):
        return None
    cn, names = names_of(current)
    key = generate(algorithm or algorithm_of(current.public_key()) or "ML-DSA-65")
    ctx = tls.client_context(folder / "ca.crt", folder / "chain.pem", folder / "key.pem", key_passphrase=passphrase)
    certs = _parse_certs(_call(url, ctx, "/simplereenroll", _csr(key, cn, names), {"Content-Type": "application/pkcs10"}, server_name), key)
    _save(folder, key, certs, x509.load_pem_x509_certificate((folder / "ca.crt").read_bytes()), passphrase)
    return certs[0]


def serve(ca_dir, listen, cert, key, passphrase=None, key_passphrase=None):
    """Run the EST service on a PQC TLS listener (client certificates requested, not required)."""
    from ..tls import hostport
    from ..tls.http import handler
    from ..tls.server import Server
    ca = CA(ca_dir, passphrase)
    ca.signer  # a wrong passphrase fails now, not at the first enrollment
    cafile = str(ca.anchor)
    make = lambda: tls.server_context(cert, key, cafile, policy_name="strict", key_passphrase=key_passphrase,
                                         request_client_cert=True, any_purpose=True)
    return Server(hostport(listen), make, handler(Service(ca)), watch=[cert, key], name="est")

