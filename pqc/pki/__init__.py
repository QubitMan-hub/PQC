"""A post-quantum certificate authority: ML-DSA or SLH-DSA roots, intermediate CAs, server and client certificates, revocation
and CRLs. The CA key can live in a file, in AWS KMS, or behind any HSM signing tool (see signers.py)."""
import datetime as dt
import functools
import ipaddress
import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path

from ..storage import locked as locked, shared as shared, write as write, append as append

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CAError(Exception):
    pass


from . import signers  # noqa: E402 (signers.SignerError is a CAError)

ALGORITHMS = {"ML-DSA-44": mldsa.MLDSA44PrivateKey, "ML-DSA-65": mldsa.MLDSA65PrivateKey, "ML-DSA-87": mldsa.MLDSA87PrivateKey}
PUBLIC = {"ML-DSA-44": mldsa.MLDSA44PublicKey, "ML-DSA-65": mldsa.MLDSA65PublicKey, "ML-DSA-87": mldsa.MLDSA87PublicKey}
USAGE = {"server": [ExtendedKeyUsageOID.SERVER_AUTH], "client": [ExtendedKeyUsageOID.CLIENT_AUTH],
         "site": [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]}
CA_ALGORITHMS = list(PUBLIC) + signers.SLH_DSA
REASONS = {r.value: r for r in x509.ReasonFlags if r not in (x509.ReasonFlags.unspecified, x509.ReasonFlags.remove_from_crl)}


@dataclass
class Record:
    serial: str
    common_name: str
    kind: str
    algorithm: str
    not_after: str
    names: list
    status: str = "valid"
    revoked_at: str = ""
    reason: str = ""
    path: str = ""


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def generate(algorithm):
    if algorithm not in ALGORITHMS:
        raise CAError(f"unknown algorithm {algorithm}; choose from {', '.join(ALGORITHMS)}")
    return ALGORITHMS[algorithm].generate()


def algorithm_of(public_key):
    return next((a for a, cls in PUBLIC.items() if isinstance(public_key, cls)), None)


def key_pem(key, passphrase=None):
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


def encrypted(path):
    """True when the PEM key at `path` exists and is passphrase-protected."""
    p = Path(path)
    return p.exists() and b"ENCRYPTED" in p.read_bytes()[:64]


def cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


HOSTNAME = re.compile(r"(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", re.I)


def general_names(names):
    out = []
    for n in names:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            if len(n) > 253 or not HOSTNAME.fullmatch(n):
                raise CAError(f"{n!r} is not a valid host name or IP address") from None
            if n.rsplit(".", 1)[-1].isdigit():
                raise CAError(f"{n!r} looks like an IP address but is not a valid one") from None
            out.append(x509.DNSName(n))
    return out


def names_of(obj):
    """The common name and SAN host names and addresses of a certificate or a signing request."""
    cn = obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    try:
        san = obj.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName) + [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    return (cn[0].value if cn else ""), names


class CA:
    def __init__(self, root, passphrase=None):
        self.root = Path(root)
        if not (self.root / "ca.crt").exists():
            raise CAError(f"no CA at {self.root}; run 'pqc ca init' first")
        self.cert = x509.load_pem_x509_certificate((self.root / "ca.crt").read_bytes())
        self.ski = self.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        self.passphrase = passphrase

    @functools.cached_property
    def signer(self):
        """Opened on first use, so listing and reporting need no passphrase."""
        try:
            signer = signers.from_config(self.root, self.passphrase)
        except (signers.SignerError, OSError, KeyError, ValueError) as e:
            if self.passphrase and ("Incorrect password" in str(e) or "decrypt" in str(e)):
                raise CAError("cannot open the CA key: wrong passphrase") from None
            raise CAError(f"cannot open the CA key: {e}") from None
        if signer.spki != _spki(self.cert):
            raise CAError("the CA key does not match ca.crt")
        return signer

    @property
    def algorithm(self):
        return signers.spki_algorithm(_spki(self.cert))

    @property
    def anchor(self):
        """The file clients and servers should trust: this CA's root."""
        return self.root / "root.crt" if (self.root / "root.crt").exists() else self.root / "ca.crt"

    def chain(self):
        """This CA's certificate and every CA above it, the part of a chain a leaf appends to itself."""
        f = self.root / "chain.pem"
        return f.read_bytes() if f.exists() else cert_pem(self.cert)

    @classmethod
    def init(cls, root, name, algorithm="ML-DSA-87", days=3650, passphrase=None, parent=None, signer_config=None):
        """A self-signed root, or with `parent` an intermediate CA it signs. `signer_config` (a dict written to signer.json)
        keeps the key in AWS KMS or an HSM instead of ca.key."""
        root = Path(root)
        if (root / "ca.crt").exists():
            raise CAError(f"a CA already exists at {root}")
        if algorithm not in CA_ALGORITHMS:
            raise CAError(f"unknown algorithm {algorithm}; choose from {', '.join(CA_ALGORITHMS)}")
        if not 1 <= len(name) <= 64:
            raise CAError("the CA name must be 1 to 64 characters")
        if parent and parent.cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0:
            raise CAError(f"{parent.cert.subject.rfc4514_string()} was created with path length 0 and cannot sign CAs; start a new root")
        root.mkdir(parents=True, exist_ok=True)
        if signer_config:
            write(root / "signer.json", json.dumps(signer_config, indent=1).encode())
        elif algorithm in ALGORITHMS:
            write(root / "ca.key", key_pem(generate(algorithm), passphrase), secret=True)
        else:
            write(root / "ca.key", signers.OpenSSLSigner.generate(algorithm, passphrase), secret=True)
        try:
            signer = signers.from_config(root, passphrase)
        except (signers.SignerError, OSError, KeyError, ValueError) as e:
            raise CAError(f"cannot use the CA key: {e}") from None
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        not_after = now() + dt.timedelta(days=days)
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(parent.cert.subject if parent else subject)
             .serial_number(x509.random_serial_number()).not_valid_before(now())
             .not_valid_after(min(not_after, parent.cert.not_valid_after_utc) if parent else not_after)
             .add_extension(x509.BasicConstraints(ca=True, path_length=0 if parent else None), critical=True)
             .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
             .add_extension(x509.SubjectKeyIdentifier(signer.key_id), critical=False))
        if parent:
            b = b.add_extension(parent.aki(), critical=False)
            with locked(parent.root):
                cert = signers.sign(b, parent.signer, signer.spki)
                parent._record(cert, name, "ca", signer.algorithm, cert.not_valid_after_utc, [], str(root.resolve()))
            write(root / "root.crt", parent.anchor.read_bytes())
            write(root / "chain.pem", cert_pem(cert) + parent.chain())
        else:
            cert = signers.sign(b, signer, signer.spki)
        write(root / "ca.crt", cert_pem(cert))
        write(root / "index.json", b"[]")
        ca = cls(root, passphrase)
        ca.crl()
        return ca

    def aki(self):
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(self.ski)

    def records(self):
        return [Record(**r) for r in json.loads((self.root / "index.json").read_text(encoding="utf-8"))]

    def _save(self, records):
        write(self.root / "index.json", ("[\n" + ",\n".join(json.dumps(vars(r)) for r in records) + "\n]\n").encode())

    def find(self, serial):
        """The one certificate whose serial is `serial` or starts with it; at least 8 hex characters, so an empty or tiny prefix
        can never pick a certificate by accident."""
        if not isinstance(serial, str) or not re.fullmatch(r"[0-9a-fA-F]{8,40}", serial.strip()):
            raise CAError(f"a serial is written in hex, at least its first 8 characters (as `ca list` shows them), not {serial!r}")
        serial = serial.strip().lower()
        match = [r for r in self.records() if r.serial == serial or r.serial.startswith(serial)]
        if len(match) != 1:
            raise CAError(f"{'no' if not match else 'more than one'} certificate matches serial {serial}")
        return match[0]

    def sign(self, public_key, common_name, kind, names=(), days=397):
        """Issue a leaf certificate for any ML-DSA public key."""
        cert, algorithm, not_after, names = self._certify(public_key, common_name, kind, names, days)
        with locked(self.root):
            rec = self._record(cert, common_name, kind, algorithm, not_after, names)
        return cert, rec

    def _certify(self, public_key, common_name, kind, names, days):
        if not isinstance(kind, str) or kind not in USAGE:
            raise CAError(f"kind must be one of {', '.join(USAGE)}")
        if not isinstance(days, int) or isinstance(days, bool) or days < 1:
            raise CAError(f"days must be a whole number of at least 1, not {days!r}")
        days = min(days, 36500)
        if not isinstance(common_name, str) or not all(isinstance(n, str) for n in names):
            raise CAError("the common name and other names must be text")
        algorithm = algorithm_of(public_key)
        if not algorithm:
            raise CAError("only ML-DSA keys can be certified")
        if not 1 <= len(common_name) <= 64:
            raise CAError("the common name must be 1 to 64 characters")
        names = list(names) or ([common_name] if kind != "client" else [])
        general_names(names)
        not_after = min(now() + dt.timedelta(days=days), self.cert.not_valid_after_utc)
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
             .issuer_name(self.cert.subject).public_key(public_key).serial_number(x509.random_serial_number())
             .not_valid_before(now()).not_valid_after(not_after)
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
             .add_extension(x509.ExtendedKeyUsage(USAGE[kind]), critical=False)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
             .add_extension(self.aki(), critical=False))
        if names:
            b = b.add_extension(x509.SubjectAlternativeName(general_names(names)), critical=False)
        return signers.sign(b, self.signer), algorithm, not_after, names

    def _record(self, cert, common_name, kind, algorithm, not_after, names, path=""):
        rec = Record(serial=format(cert.serial_number, "x"), common_name=common_name, kind=kind,
                     algorithm=algorithm, not_after=not_after.isoformat(), names=names, path=path)
        self._save(self.records() + [rec])
        return rec

    def issue(self, common_name, kind, names=(), days=397, algorithm="ML-DSA-65", out=None, passphrase=None, replace=False):
        """Generate a key pair and certificate; writes cert.pem, key.pem and chain.pem to `out`, which must not hold a key yet
        unless `replace` (renewal in place). Holds the CA lock throughout, so two renewals of one folder cannot mix their files."""
        with locked(self.root):
            if out and not replace and (Path(out) / "key.pem").exists():
                raise CAError(f"{out} already holds a key; choose another --out, or replace it with 'ca renew SERIAL --out {out}'")
            key = generate(algorithm)
            names = list(dict.fromkeys(([common_name] if kind != "client" else []) + list(names)))
            cert, algorithm, not_after, names = self._certify(key.public_key(), common_name, kind, names, days)
            safe = re.sub(r"[^\w.-]", "_", common_name)
            out = Path(out or self.root / "issued" / f"{safe}-{format(cert.serial_number, 'x')[:8]}")
            # recorded before any file holds it: a crash in between leaves a record without files, which can still be revoked,
            # never a certificate on disk that the CA does not know about
            rec = self._record(cert, common_name, kind, algorithm, not_after, names, str(out.resolve()))
            write(out / "key.pem", key_pem(key, passphrase), secret=True)
            write(out / "cert.pem", cert_pem(cert))
            write(out / "chain.pem", cert_pem(cert) + self.chain())
        return out, rec

    def sign_csr(self, csr_pem, kind, days=397):
        try:
            csr = x509.load_pem_x509_csr(csr_pem) if b"-----BEGIN" in csr_pem else x509.load_der_x509_csr(csr_pem)
        except ValueError:
            raise CAError("not a certificate signing request (PEM or DER)") from None
        if not csr.is_signature_valid:
            raise CAError("the CSR's signature does not verify")
        cn, names = names_of(csr)
        return self.sign(csr.public_key(), cn or "unnamed", kind, names, days)

    def revoke(self, serial, reason="unspecified"):
        if not isinstance(reason, str) or reason != "unspecified" and reason not in REASONS:
            raise CAError(f"reason must be one of: unspecified, {', '.join(REASONS)}")
        with locked(self.root):
            self._revoke(serial, reason)
            return self.crl()

    def _revoke(self, serial, reason):
        recs = self.records()
        rec = self.find(serial)
        for r in recs:
            if r.serial == rec.serial:
                if r.status == "revoked":
                    raise CAError(f"{r.serial} is already revoked")
                r.status, r.revoked_at, r.reason = "revoked", now().isoformat(), reason
        self._save(recs)

    def crl(self, days=7):
        """Sign and write a fresh CRL listing every revoked certificate."""
        with locked(self.root):
            return self._crl(days)

    def _crl(self, days):
        b = x509.CertificateRevocationListBuilder().issuer_name(self.cert.subject).last_update(now()).next_update(now() + dt.timedelta(days=days))
        for r in self.records():
            if r.status == "revoked":
                rb = x509.RevokedCertificateBuilder().serial_number(int(r.serial, 16)).revocation_date(dt.datetime.fromisoformat(r.revoked_at))
                if r.reason in REASONS:
                    rb = rb.add_extension(x509.CRLReason(REASONS[r.reason]), critical=False)
                b = b.add_revoked_certificate(rb.build())
        crl = signers.sign(b.add_extension(self.aki(), critical=False), self.signer)
        data = crl.public_bytes(serialization.Encoding.PEM)
        write(self.root / "crl.pem", data)
        return data

    def renew(self, serial, days=397, algorithm=None, out=None, passphrase=None):
        """A new key and certificate with the same name, SANs and (unless `algorithm` is given) algorithm; the old one stays
        valid until it expires or is revoked."""
        with locked(self.root):
            r = self.find(serial)
            if r.status == "revoked":
                raise CAError(f"{r.serial} is revoked; issue a new certificate instead of renewing it")
            return self.issue(r.common_name, r.kind, r.names, days, algorithm or r.algorithm, out, passphrase, replace=True)

    def maintain(self, renew_within=30, crl_days=7, algorithm=None):
        """Re-sign the CRL, and renew certificates expiring within `renew_within` days into the folder they were issued to, where
        edges pick them up without a restart. Run it daily. Encrypted leaf keys are reported, not renewed."""
        with locked(self.root):
            return self._maintain(renew_within, crl_days, algorithm)

    def _maintain(self, renew_within, crl_days, algorithm):
        newest = {}
        for r in self.records():
            if r.status == "valid" and r.kind != "ca" and r.path and (r.path not in newest or r.not_after > newest[r.path].not_after):
                newest[r.path] = r
        cutoff, renewed, skipped = now() + dt.timedelta(days=renew_within), [], []
        for r in newest.values():
            if dt.datetime.fromisoformat(r.not_after) > cutoff:
                continue
            key = Path(r.path) / "key.pem"
            if not key.exists() or encrypted(key):
                skipped.append(r)
                continue
            renewed.append(self.renew(r.serial, algorithm=algorithm, out=r.path)[1])
        self.crl(crl_days)
        return renewed, skipped

    def expiring(self, within_days=30):
        cutoff = now() + dt.timedelta(days=within_days)
        return [r for r in self.records() if r.status == "valid" and dt.datetime.fromisoformat(r.not_after) <= cutoff]


def _spki(cert):
    return signers.children(signers.children(cert.public_bytes(serialization.Encoding.DER))[0])[6]


def signed_by(issuer, tbs, signature):
    """True if `issuer`'s key made this signature; SLH-DSA keys, which pyca/cryptography cannot load, go through OpenSSL."""
    try:
        issuer.public_key().verify(signature, tbs)
        return True
    except UnsupportedAlgorithm:
        return signers.verify(_spki(issuer), tbs, signature)
    except InvalidSignature:
        return False
    except TypeError:
        raise CAError(f"{issuer.subject.rfc4514_string()} has a classical key; certificates and CRLs here are signed with ML-DSA or "
                      "SLH-DSA, so it cannot be their issuer") from None


def verify_crl(crl_pem, ca_certs):
    """The CRL, if one of `ca_certs` signed it and it has not expired; CAError otherwise."""
    try:
        crl = x509.load_pem_x509_crl(crl_pem)
    except ValueError:
        raise CAError("the CRL file is damaged or not a CRL; re-sign it with 'pqc ca crl'") from None
    issuers = [c for c in (ca_certs if isinstance(ca_certs, (list, tuple)) else [ca_certs]) if c.subject == crl.issuer]
    if not any(signed_by(c, crl.tbs_certlist_bytes, crl.signature) for c in issuers):
        raise CAError("the CRL was not signed by this CA")
    if crl.next_update_utc and crl.next_update_utc < now():
        raise CAError(f"the CRL expired at {crl.next_update_utc.isoformat()}")
    return crl


def check_revocation(serial, crl_pem, ca_certs):
    """Raise if the certificate with this serial number is revoked, or if the CRL is forged or stale. Fails closed.
    `ca_certs` is the issuing CA's certificate, or several of which one issued the CRL."""
    r = verify_crl(crl_pem, ca_certs).get_revoked_certificate_by_serial_number(serial)
    if r is not None:
        raise CAError(f"certificate {serial:x} was revoked on {r.revocation_date_utc.date()}")


def fetch_crl(url, dest, ca_certs, timeout=10):
    """Download the CRL published at `url` and keep it at `dest`. Only a CRL that the CA signed, that has not expired and that
    is not older than the copy already kept replaces it, so a forged, stale or replayed download changes nothing. True when
    the copy changed."""
    import http.client
    import urllib.request
    if not url.startswith(("http://", "https://")):
        raise CAError(f"crl_url must start with http:// or https://, not {url!r}")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = r.read(20 << 20)
    except (OSError, ValueError, http.client.HTTPException) as e:
        raise CAError(f"cannot fetch the CRL from {url}: {e}") from None
    if not data.lstrip().startswith(b"-----BEGIN"):
        try:
            data = x509.load_der_x509_crl(data).public_bytes(serialization.Encoding.PEM)
        except ValueError:
            raise CAError(f"{url} did not return a CRL") from None
    new = verify_crl(data, ca_certs)
    dest = Path(dest)
    if dest.exists():
        old = dest.read_bytes()
        if old == data:
            return False
        try:
            if x509.load_pem_x509_crl(old).last_update_utc > new.last_update_utc:
                raise CAError(f"{url} served a CRL older than the one kept at {dest}; keeping the newer one")
        except ValueError:
            pass
    write(dest, data)
    return True


def follow_crl(url, dest, ca_path, every=60.0):
    """Keep `dest` in step with the CRL published at `url`: fetched once now, which must work unless a copy is already kept,
    then every `every` seconds in the background. Returns an Event that stops it. Failures are logged and the old copy is
    kept; once it expires, every client is refused (fail closed)."""
    import logging
    log = logging.getLogger("pqc.crl")
    cas = x509.load_pem_x509_certificates(Path(ca_path).read_bytes())
    try:
        if fetch_crl(url, dest, cas):
            log.info("CRL from %s saved to %s", url, dest)
    except CAError as e:
        if not Path(dest).exists():
            raise
        log.error("%s; keeping %s", e, dest)
    stop = threading.Event()

    def loop():
        while not stop.wait(every):
            try:
                if fetch_crl(url, dest, cas):
                    log.info("CRL from %s changed; saved to %s", url, dest)
            except Exception as e:  # the follower must outlive any one bad answer, or the kept copy silently expires
                log.error("%s; keeping %s", e, dest)
    threading.Thread(target=loop, daemon=True, name="crl").start()
    return stop
