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
    `fallback` (cert, key) is a trusted classical certificate, preferred for clients offering both signature families.
    It needs transition policy; clients offering only ML-DSA still get the primary certificate."""
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
    sock = nodelay(_dial(host, port, timeout))
    return ctx.wrap(sock, server_name or host, timeout)


def _dial(host, port, timeout):
    """For "localhost", IPv4 first: Windows tries ::1 first and, when the server listens on 127.0.0.1 only, waits two
    seconds after the refusal before trying IPv4."""
    if host.lower() != "localhost":
        return socket.create_connection((host, port), timeout=timeout)
    try:
        return socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except ConnectionRefusedError:
        return socket.create_connection(("::1", port), timeout=timeout)


def nodelay(sock):
    """Send each write at once. With Nagle's algorithm on, a reply that follows a small unacknowledged write waits up to
    40 ms for the peer's delayed ACK, which multiplies request/response latency (databases, Redis, APIs)."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass  # not TCP (a Unix socket in tests), or already closed
    return sock


__all__ = ["Connection", "Context", "OpenSSLUnavailable", "POLICIES", "Policy", "TLSError", "client_context", "connect", "lib",
           "server_context"]


def listen(address, backlog=1024, reuse_port=False):
    """A listening socket for (host, port). An IPv6 host gets an IPv6 socket; "::" (every interface, the default) also takes
    IPv4 clients, and falls back to IPv4 alone on a machine without IPv6."""
    if ":" not in address[0]:
        return socket.create_server(address, backlog=backlog, reuse_port=reuse_port)
    try:
        return socket.create_server(address, family=socket.AF_INET6, backlog=backlog, reuse_port=reuse_port,
                                    dualstack_ipv6=address[0] == "::" and socket.has_dualstack_ipv6())
    except OSError:
        if address[0] != "::":
            raise
        return socket.create_server(("0.0.0.0", address[1]), backlog=backlog, reuse_port=reuse_port)  # no IPv6 here


def http_server(listen_on, handler, server_class=None):
    """A ThreadingHTTPServer on "host:port" (default host 127.0.0.1), on the same socket listen() gives."""
    from http.server import ThreadingHTTPServer
    httpd = (server_class or ThreadingHTTPServer)(("127.0.0.1", 0), handler, bind_and_activate=False)
    httpd.socket.close()
    httpd.socket = listen(hostport(listen_on, "127.0.0.1"), backlog=128)
    httpd.address_family = httpd.socket.family
    httpd.server_address = httpd.socket.getsockname()[:2]
    httpd.server_name, httpd.server_port = httpd.server_address
    return httpd


def hostport(s, default_host="0.0.0.0"):
    host, _, port = s.rpartition(":")
    if not (port.isascii() and port.isdigit() and int(port) <= 65535):
        raise ValueError(f"expected host:port with a port from 0 to 65535, got {s!r}")
    return host.strip("[]") or default_host, int(port)
