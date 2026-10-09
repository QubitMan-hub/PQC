"""TLS 1.3 + mTLS: the edge, its bundles, and a test server and client."""
import os
import socket
import sys
import threading

from .. import ConfigWatch, env_passphrase, explain, tls
from .common import ca_passphrase, policy, run_until_signal, show, tls_client_args


def cmd_tls(a):
    if a.tls_cmd == "serve":
        from ..tls.server import Server
        make = lambda: tls.server_context(a.cert, a.key, a.ca, a.require_client_cert, a.policy, env_passphrase(a.key_passphrase_env))

        def echo(conn, addr):
            while data := conn.recv(timeout=300):
                conn.sendall(data)

        srv = Server(tls.hostport(a.listen), make, echo, watch=[a.cert, a.key, a.ca], crl=a.crl, ca=a.ca, name="serve")
        run_until_signal(srv.serve_forever, srv.stop)
        return 0
    host, port = tls.hostport(a.target, "")
    ctx = tls.client_context(a.ca, a.cert, a.key, a.policy, env_passphrase(a.key_passphrase_env))
    try:
        conn = tls.connect(host, port, ctx, a.server_name, a.timeout)
    except socket.gaierror as e:
        raise tls.TLSError(f"{host}: {explain(e)}; connect by address and name the certificate with --server-name {host}") from None
    with conn:
        out = conn.info()
        if a.send is not None:
            try:
                conn.sendall(a.send.encode())
                reply = conn.recv()
                while reply and (more := _more(conn)):
                    reply += more
            except (tls.TLSError, OSError) as e:
                reply, out["error"] = b"", explain(e)
            if not reply:
                raise tls.TLSError("the server closed the connection right after the handshake: either it refused our client certificate "
                                   "(missing, untrusted or revoked), or the service behind it is down (see the server's log)"
                                   f"{': ' + out['error'] if out.get('error') else ''}")
            out["reply"] = reply.decode(errors="replace")
    show(out, a.json)
    return 0


def _more(conn):
    """The rest of a reply that arrives in several pieces: read until the server closes or is quiet for a second."""
    try:
        return conn.recv(timeout=1.0)
    except (tls.TLSError, OSError):
        return b""


def cmd_edge(a):
    from ..tls.edge import WORKER, Edge, Route, Workers, load_config, reconcile, report, serve_metrics
    if not (a.config or a.target):
        raise ValueError("edge needs --config or --target")
    if a.config:
        routes, metrics = load_config(a.config)
    else:
        routes = [Route(name="edge", mode=a.mode, listen=a.listen, target=a.target, policy=a.policy, cert=a.cert or "", key=a.key or "",
                        key_passphrase_env=a.key_passphrase_env or "", ca=a.ca or "", require_client_cert=a.require_client_cert,
                        crl=a.crl or "", crl_url=a.crl_url or "", server_name=a.server_name or "", proxy_protocol=a.proxy_protocol,
                        fallback_cert=a.fallback_cert or "", fallback_key=a.fallback_key or "")]
        metrics = a.metrics
    if a.workers < 1:
        raise ValueError("--workers must be 1 or more")
    worker = bool(os.environ.get(WORKER))
    shared = a.workers > 1 or worker
    if shared:
        if any(tls.hostport(r.listen)[1] == 0 for r in routes):
            raise ValueError("--workers needs a fixed listen port, not 0")
        if not sys.platform.startswith("linux"):
            raise ValueError("--workers needs Linux, where the kernel spreads connections over the processes (SO_REUSEPORT)")
    edges = [Edge(r).bind(reuse_port=shared) for r in routes]
    workers = Workers(a.workers) if a.workers > 1 and not worker else None
    if worker:
        threading.Thread(target=report, args=(edges,), daemon=True).start()
    elif metrics:
        serve_metrics(metrics, edges, workers)
    for e in edges:
        threading.Thread(target=e.serve_forever, daemon=True, name=e.route.name).start()
    watch = ConfigWatch(a.config, load_config, lambda new: reconcile(edges, new[0], shared)) if a.config else None
    done = threading.Event()

    def stop():
        if watch:
            watch.stop()
        for e in list(edges):
            e.stop()
        if workers:
            workers.stop()
        done.set()
    run_until_signal(done.wait, stop, watch.poke if watch else None)
    return 0


def cmd_bundle(a):
    from ..tls.bundles import create
    out = create(a.service, a.out or f"{a.service}-pqc", a.host, a.ca, a.mtls, a.policy, ca_passphrase(a.ca) if a.ca else None)
    print((out / "README.txt").read_text())
    return 0

def add(sub):
    t = sub.add_parser("tls", help="TLS 1.3 + mTLS: post-quantum edge, server and client").add_subparsers(dest="tls_cmd", required=True)
    p = t.add_parser("edge", help="post-quantum TLS in front of any TCP service, or a tunnel to one")
    p.set_defaults(func=cmd_edge)
    p.add_argument("--config", help="TOML file with [[edge]] routes; replaces the flags below")
    p.add_argument("--mode", choices=["terminate", "originate"], default="terminate",
                   help="terminate: post-quantum TLS in front of --target; originate: plain local clients reach a remote edge at --target")
    p.add_argument("--listen", default="0.0.0.0:8443", help="host:port (default: every interface, port 8443)")
    p.add_argument("--target", help="upstream host:port (terminate) or remote edge host:port (originate)")
    policy(p)
    for flag, text in (("--cert", "the edge's certificate chain (chain.pem)"), ("--key", "its private key (key.pem)"),
                       ("--key-passphrase-env", "the key's passphrase is in this environment variable"),
                       ("--ca", "CA certificate that client certificates (terminate) or the remote edge (originate) must chain to"),
                       ("--crl", "refuse certificates revoked in this CRL file"),
                       ("--crl-url", "fetch the CRL from here every minute (from `ca publish`), into --crl"),
                       ("--server-name", "originate: the name in the remote edge's certificate, if not its host"),
                       ("--metrics", "host:port for /metrics (Prometheus), /healthz and /status, e.g. 127.0.0.1:9100")):
        p.add_argument(flag, help=text)
    p.add_argument("--fallback-cert", help="with --policy transition: an ECDSA or RSA certificate for browsers that cannot verify ML-DSA")
    p.add_argument("--fallback-key", help="the fallback certificate's private key")
    p.add_argument("--require-client-cert", action="store_true", help="mutual TLS")
    p.add_argument("--proxy-protocol", action="store_true", help="send a PROXY v1 header so the upstream sees the client address")
    p.add_argument("--workers", type=int, default=1, help="processes sharing the listen ports, e.g. one per CPU core (Linux)")
    from ..tls.bundles import SERVICES
    p = t.add_parser("bundle", help="nginx, postgres, pgvector or mqtt behind the edge, with certificates and a compose file")
    p.set_defaults(func=cmd_bundle)
    p.add_argument("service", choices=list(SERVICES))
    p.add_argument("--host", required=True, help="the name clients use; goes in the certificate")
    p.add_argument("--out", help="folder to create (default: SERVICE-pqc)")
    p.add_argument("--ca", help="use this existing CA folder instead of creating one")
    p.add_argument("--mtls", action="store_true", help="clients must present a certificate from the CA")
    policy(p)
    p = t.add_parser("serve", help="an echo server, for testing clients")
    p.set_defaults(func=cmd_tls)
    p.add_argument("--listen", default="0.0.0.0:8443", help="host:port (default: every interface, port 8443)")
    p.add_argument("--cert", required=True, help="chain.pem")
    p.add_argument("--key", required=True)
    p.add_argument("--key-passphrase-env")
    p.add_argument("--ca", help="CA that signs client certificates")
    p.add_argument("--require-client-cert", action="store_true", help="mutual TLS")
    p.add_argument("--crl", help="refuse revoked client certificates")
    policy(p)
    p = t.add_parser("connect", help="handshake, optionally send a message, print what was negotiated")
    p.set_defaults(func=cmd_tls)
    tls_client_args(p)
    p.add_argument("--ca", required=True)
    p.add_argument("--cert", help="client certificate, for mutual TLS")
    p.add_argument("--key")
    p.add_argument("--key-passphrase-env")
    p.add_argument("--send", help="message to send; the reply is printed")
