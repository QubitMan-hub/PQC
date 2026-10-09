"""Where a CA's signatures come from: a key file, an SLH-DSA key through OpenSSL 3.5, AWS KMS, or any HSM tool on the command line.

pyca/cryptography can only sign certificates with keys it holds. For every other signer the certificate or CRL is built with a
stand-in ML-DSA key, and its to-be-signed bytes are re-encoded with the real signature algorithm (and, for a self-signed root,
the real public key) before the real signer signs them.
"""
import base64
import ctypes
import hashlib
import json
import subprocess
import weakref
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from . import CAError

DER = serialization.Encoding.DER
NIST_SIG = "2.16.840.1.101.3.4.3."
SLH_DSA: list[str] = [f"SLH-DSA-{h}-{b}{v}" for h in ("SHA2", "SHAKE") for b in (128, 192, 256) for v in "sf"]
OIDS = {"ML-DSA-44": NIST_SIG + "17", "ML-DSA-65": NIST_SIG + "18", "ML-DSA-87": NIST_SIG + "19"} | {
    a: NIST_SIG + str(20 + i) for i, a in enumerate(SLH_DSA)}


class SignerError(CAError):
    pass


def _tlv(data, pos=0):
    """Tag, content start and end of the DER element at `pos`."""
    tag, n, p = data[pos], data[pos + 1], pos + 2
    if n & 0x80:
        k = n & 0x7F
        n, p = int.from_bytes(data[p:p + k], "big"), p + k
    return tag, p, p + n


def children(der):
    """The elements inside one DER SEQUENCE."""
    _, p, end = _tlv(der)
    out = []
    while p < end:
        e = _tlv(der, p)[2]
        out.append(der[p:e])
        p = e
    return out


def encode(tag, content):
    n = len(content)
    size = (n.bit_length() + 7) // 8
    return bytes([tag]) + (bytes([n]) if n < 128 else bytes([0x80 | size]) + n.to_bytes(size, "big")) + content


def algorithm_identifier(dotted):
    a = [int(x) for x in dotted.split(".")]
    body = bytes([40 * a[0] + a[1]])
    for v in a[2:]:
        chunk = [v & 0x7F]
        while v := v >> 7:
            chunk.append(0x80 | (v & 0x7F))
        body += bytes(reversed(chunk))
    return encode(0x30, encode(0x06, body))


def spki_algorithm(spki):
    ident = children(spki)[0]
    return next((a for a, oid in OIDS.items() if algorithm_identifier(oid) == ident), None)


def public_key_bits(spki):
    bits = children(spki)[1]
    return bits[_tlv(bits)[1] + 1:]


class Signer:
    algorithm = spki = None

    @property
    def oid(self):
        return OIDS[self.algorithm]

    @property
    def key_id(self):
        """RFC 5280 method 1: SHA-1 of the public key bits, the same value cryptography puts in SubjectKeyIdentifier."""
        return hashlib.sha1(public_key_bits(self.spki), usedforsecurity=False).digest()  # an identifier, not a security function

    def sign(self, data):
        raise NotImplementedError


class KeySigner(Signer):
    def __init__(self, key):
        from . import algorithm_of
        self.key, self.algorithm = key, algorithm_of(key.public_key())
        self.spki = key.public_key().public_bytes(DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, data):
        return self.key.sign(data)


class OpenSSLSigner(Signer):
    """A private key OpenSSL 3.5 understands and pyca/cryptography does not, such as SLH-DSA (FIPS 205)."""

    def __init__(self, pem, passphrase=None):
        from ..tls.openssl import errors, lib
        L_ = lib()
        bio = L_.BIO_new_mem_buf(pem, len(pem))
        self.pkey = L_.PEM_read_bio_PrivateKey(bio, None, None, passphrase or b"")
        L_.BIO_free(bio)
        if not self.pkey:
            raise SignerError(f"cannot open the key: {errors()}")
        weakref.finalize(self, L_.EVP_PKEY_free, self.pkey)
        self.algorithm = L_.EVP_PKEY_get0_type_name(self.pkey).decode()
        buf = ctypes.create_string_buffer(L_.i2d_PUBKEY(self.pkey, None))
        L_.i2d_PUBKEY(self.pkey, ctypes.byref(ctypes.c_void_p(ctypes.addressof(buf))))
        self.spki = buf.raw
        if self.algorithm not in OIDS:
            raise SignerError(f"{self.algorithm} keys cannot sign certificates")

    @staticmethod
    def generate(algorithm, passphrase=None):
        """A new key as PKCS#8 PEM, encrypted with AES-256 when a passphrase is given."""
        from ..tls.openssl import errors, lib
        L_ = lib()
        ctx, pkey = L_.EVP_PKEY_CTX_new_from_name(None, algorithm.encode(), None), ctypes.c_void_p()
        try:
            if not ctx or L_.EVP_PKEY_keygen_init(ctx) != 1 or L_.EVP_PKEY_generate(ctx, ctypes.byref(pkey)) != 1:
                raise SignerError(f"cannot generate {algorithm}: {errors()}")
        finally:
            L_.EVP_PKEY_CTX_free(ctx)
        bio = L_.BIO_new(L_.BIO_s_mem())
        try:
            cipher = L_.EVP_aes_256_cbc() if passphrase else None
            if L_.PEM_write_bio_PKCS8PrivateKey(bio, pkey, cipher, passphrase, len(passphrase or b""), None, None) != 1:
                raise SignerError(f"cannot write the key: {errors()}")
            ptr = ctypes.c_char_p()
            return ctypes.string_at(ptr, L_.BIO_ctrl(bio, 3, 0, ctypes.byref(ptr)))
        finally:
            L_.BIO_free(bio)
            L_.EVP_PKEY_free(pkey)

    def sign(self, data):
        from ..tls.openssl import errors, lib
        L_ = lib()
        md, n = L_.EVP_MD_CTX_new(), ctypes.c_size_t()
        try:
            if L_.EVP_DigestSignInit_ex(md, None, None, None, None, self.pkey, None) != 1 or L_.EVP_DigestSign(md, None, ctypes.byref(n), data, len(data)) != 1:
                raise SignerError(f"cannot sign: {errors()}")
            sig = ctypes.create_string_buffer(n.value)
            if L_.EVP_DigestSign(md, sig, ctypes.byref(n), data, len(data)) != 1:
                raise SignerError(f"cannot sign: {errors()}")
            return sig.raw[:n.value]
        finally:
            L_.EVP_MD_CTX_free(md)


def verify(spki, data, signature):
    """Check a signature with OpenSSL, for keys pyca/cryptography cannot load."""
    from ..tls.openssl import lib
    L_ = lib()
    buf = ctypes.create_string_buffer(spki, len(spki))
    pkey = L_.d2i_PUBKEY(None, ctypes.byref(ctypes.c_void_p(ctypes.addressof(buf))), len(spki))
    md = L_.EVP_MD_CTX_new()
    try:
        return bool(pkey) and L_.EVP_DigestVerifyInit_ex(md, None, None, None, None, pkey, None) == 1 and \
            L_.EVP_DigestVerify(md, signature, len(signature), data, len(data)) == 1
    finally:
        L_.EVP_MD_CTX_free(md)
        L_.EVP_PKEY_free(pkey)
        L_.ERR_clear_error()


class KMSSigner(Signer):
    """An ML-DSA key in AWS KMS (key spec ML_DSA_44/65/87). Signs the 64-byte external mu, so certificates and CRLs of any
    size fit in one Sign call and the message never leaves this machine."""

    def __init__(self, key_id, region=None, client=None):
        if client is None:
            try:
                import boto3
            except ImportError:
                raise SignerError("AWS KMS signing needs boto3 (pip install \"pqc[kms]\")") from None
            client = boto3.client("kms", region_name=region)
        self.client, self.kms_key = client, key_id
        r = client.get_public_key(KeyId=key_id)
        self.spki, self.algorithm = r["PublicKey"], r["KeySpec"].replace("_", "-")
        if self.algorithm not in OIDS:
            raise SignerError(f"KMS key {key_id} is {r['KeySpec']}, not ML-DSA")
        self.tr = hashlib.shake_256(public_key_bits(self.spki)).digest(64)

    def sign(self, data):
        mu = hashlib.shake_256(self.tr + b"\x00\x00" + data).digest(64)
        r = self.client.sign(KeyId=self.kms_key, Message=mu, MessageType="EXTERNAL_MU", SigningAlgorithm="ML_DSA_SHAKE_256")
        return r["Signature"]


class CommandSigner(Signer):
    """Any signing tool: the command reads the bytes to sign on stdin and writes the raw signature to stdout (a PKCS#11 HSM via
    pkcs11-tool, a remote signing service, a smart card). The public key file tells us the algorithm."""

    def __init__(self, command, public_key):
        self.command = [str(c) for c in command]
        self.spki = _pem_body(Path(public_key).read_bytes())
        self.algorithm = spki_algorithm(self.spki)
        if not self.algorithm:
            raise SignerError(f"{public_key}: not an ML-DSA or SLH-DSA public key")

    def sign(self, data):
        try:
            r = subprocess.run(self.command, input=data, capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise SignerError(f"signing command gave no signature within 120 s: {' '.join(self.command)}") from None
        if r.returncode:
            raise SignerError(f"signing command failed ({r.returncode}): {r.stderr.decode(errors='replace').strip()}")
        return r.stdout


def _valid(spki, data, signature):
    try:
        serialization.load_der_public_key(spki).verify(signature, data)
        return True
    except (UnsupportedAlgorithm, ValueError):
        return verify(spki, data, signature)
    except Exception:
        return False


def _pem_body(pem):
    lines = pem.decode().strip().splitlines()
    return base64.b64decode("".join(l for l in lines if not l.startswith("-----")))


def from_config(root, passphrase=None):
    """The signer of the CA in `root`: `signer.json` when present, otherwise the key in `ca.key`."""
    root = Path(root)
    cfg = root / "signer.json"
    if cfg.exists():
        c = json.loads(cfg.read_text(encoding="utf-8"))
        kind = c.get("type")
        if kind == "aws-kms":
            return KMSSigner(c["key_id"], c.get("region"))
        if kind == "command":
            return CommandSigner(c["command"], root / c.get("public_key", "signer.pub.pem"))
        raise SignerError(f"{cfg}: type must be aws-kms or command")
    pem = (root / "ca.key").read_bytes()
    try:
        return KeySigner(serialization.load_pem_private_key(pem, passphrase))
    except UnsupportedAlgorithm:
        return OpenSSLSigner(pem, passphrase)
    except (TypeError, ValueError) as e:
        try:
            return OpenSSLSigner(pem, passphrase)
        except Exception:
            raise SignerError(str(e)) from None


def sign(builder, signer, spki=None):
    """Sign a CertificateBuilder or CertificateRevocationListBuilder. `spki` is the subject's public key as DER, for keys
    pyca/cryptography cannot load (an SLH-DSA root); the builder must not have a public key set then."""
    if spki:
        try:
            builder, spki = builder.public_key(serialization.load_der_public_key(spki)), None
        except (UnsupportedAlgorithm, ValueError):
            pass
    if isinstance(signer, KeySigner) and not spki:
        return builder.sign(signer.key, None)
    stand_in = mldsa.MLDSA44PrivateKey.generate()
    if spki:
        builder = builder.public_key(stand_in.public_key())
    obj = builder.sign(stand_in, None)
    swap = {algorithm_identifier(OIDS["ML-DSA-44"]): algorithm_identifier(signer.oid)}
    if spki:
        swap[KeySigner(stand_in).spki] = spki
    tbs = encode(0x30, b"".join(swap.get(p, p) for p in children(children(obj.public_bytes(DER))[0])))
    signature = signer.sign(tbs)
    if not _valid(signer.spki, tbs, signature):
        raise SignerError("the CA's signer returned a signature that does not verify with the CA's public key (a different key, "
                          "or a signing tool that printed something besides the signature); nothing was issued")
    der = encode(0x30, tbs + algorithm_identifier(signer.oid) + encode(0x03, b"\x00" + signature))
    return x509.load_der_x509_crl(der) if isinstance(obj, x509.CertificateRevocationList) else x509.load_der_x509_certificate(der)
