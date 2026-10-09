"""PQC TLS 1.3: policies, contexts and a client helper on top of the OpenSSL bridge."""
import socket
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

from .openssl import Connection, Context, OpenSSLUnavailable, TLSError, lib

PQC_GROUPS = "X25519MLKEM768:SecP384r1MLKEM1024:SecP256r1MLKEM768"
CIPHERSUITES = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"


@dataclass(frozen=True)
class Policy:
    """What a peer may negotiate. `strict` is post-quantum only; `transition` prefers PQC but still talks to classical peers;
    `cnsa2` is NSA CNSA 2.0: ML-KEM-1024, ML-DSA-87 and AES-256 only."""
    name: str
    groups: str
    sigalgs: str | None
    ciphersuites: str = CIPHERSUITES


POLICIES = {
    "strict": Policy("strict", PQC_GROUPS, "mldsa87:mldsa65:mldsa44"),
    "transition": Policy("transition", PQC_GROUPS + ":X25519:secp256r1:secp384r1", None),
    "cnsa2": Policy("cnsa2", "SecP384r1MLKEM1024:MLKEM1024", "mldsa87", "TLS_AES_256_GCM_SHA384"),
}


def policy(name):
    if name not in POLICIES:
        raise TLSError(f"unknown policy {name}; choose from {', '.join(POLICIES)}")
    return POLICIES[name]


def _check_cnsa2(p, cert):
    """CNSA 2.0 allows only ML-DSA-87 signatures, so a smaller certificate would fail every handshake; say so at start-up."""
    if p.name != "cnsa2" or not cert:
        return
    from ..pki import algorithm_of
    try:
        leaf = x509.load_pem_x509_certificates(Path(cert).read_bytes())[0]
    except (OSError, ValueError):
        return
    found = algorithm_of(leaf.public_key())
    if found != "ML-DSA-87":
        raise TLSError(f"the cnsa2 policy needs an ML-DSA-87 certificate, but {cert} holds {found or 'a non-ML-DSA key'}; "
                       "issue one with --algorithm ML-DSA-87")


def server_context(cert, key, ca=None, require_client_cert=False, policy_name="strict", key_passphrase=None, request_client_cert=False,
                   any_purpose=False, fallback=None):
    """`request_client_cert` asks for a client certificate and verifies it if one is sent, but lets clients without one in.
    `any_purpose` accepts a client certificate whose extended key usage is not clientAuth (the chain is still verified).
    `fallback` (cert, key) is a classical certificate for browsers and other clients that cannot verify ML-DSA yet; it needs
    a policy that allows classical signatures (transition)."""
    p = policy(policy_name)
    if (require_client_cert or request_client_cert) and not ca:
        raise TLSError("checking client certificates needs the CA that issued them")
    if fallback and p.sigalgs:
        raise TLSError(f"a fallback certificate needs the transition policy; {p.name} only allows ML-DSA signatures")
    _check_cnsa2(p, cert)
    return Context(True, p.groups, p.sigalgs, p.ciphersuites, cert, key, key_passphrase, ca, True, require_client_cert, request_client_cert,
                   any_purpose, fallback)


def client_context(ca=None, cert=None, key=None, policy_name="strict", key_passphrase=None, verify=True):
    p = policy(policy_name)
    if verify and not ca:
        raise TLSError("verifying the server needs a CA certificate (or pass verify=False for a probe)")
    _check_cnsa2(p, cert)
    return Context(False, p.groups, p.sigalgs, p.ciphersuites, cert, key, key_passphrase, ca, verify)


def connect(host, port, ctx, server_name=None, timeout=10.0):
    """Open a verified TLS 1.3 connection; the certificate must match `server_name` (defaults to `host`)."""
    sock = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap(sock, server_name or host, timeout)


__all__ = ["Connection", "Context", "OpenSSLUnavailable", "POLICIES", "Policy", "TLSError", "client_context", "connect", "lib",
           "server_context"]


def hostport(s, default_host="0.0.0.0"):
    host, _, port = s.rpartition(":")
    if not (port.isascii() and port.isdigit() and int(port) <= 65535):
        raise ValueError(f"expected host:port with a port from 0 to 65535, got {s!r}")
    return host.strip("[]") or default_host, int(port)
