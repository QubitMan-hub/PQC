"""doctor and try: check this machine, and a one-minute tour."""
import json
import logging
import sys
from pathlib import Path

from .. import NAME, __version__, explain, serve_http, tls
from ..pki import CA


def cmd_doctor(a):
    if getattr(a, 'json', False):
        from .. import checks
        rows = checks.prerequisites()
        rows += [{'product': 'deployment', 'level': level, 'message': message, 'action': ''}
                 for level, message in ([r for d in a.ca for r in checks.ca(d)] + [r for f in a.config for r in checks.config(f)])]
        print(json.dumps({'version': __version__, 'checks': rows}, indent=2))
        return 2 if any(r['level'] == 'fail' for r in rows) else 1 if a.strict and any(r['level'] == 'warn' for r in rows) else 0
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    print(f"{NAME} {__version__}, Python {sys.version.split()[0]}")
    print(f"Certificate authority: ready (cryptography {cryptography.__version__}, with its own {backend.openssl_version_text()})")
    try:
        lib = tls.lib()
        ctx = tls.client_context(verify=False)  # only checks that a context can be built; nothing connects
        ctx.close()
        print(f"TLS edge: ready (this machine's {lib.version}; groups {tls.PQC_GROUPS})")
        broken = False
    except tls.TLSError as e:
        print(f"TLS edge: not available: {e}")
        broken = True
    from .. import checks
    fails = warns = 0
    if a.check_updates:
        from .. import latest_release
        try:
            latest = latest_release()
        except (OSError, ValueError) as e:
            print(f"updates: cannot check: {explain(e) if isinstance(e, OSError) else e}")
        else:
            print(f"updates: {latest['version']} is out: {latest['url']}" if latest and latest["newer"] else f"updates: {__version__} is the newest release")
    if a.ca or a.config:
        results = [r for d in a.ca for r in checks.ca(d)] + [r for f in a.config for r in checks.config(f)]
        mark = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}
        for level, msg in results:
            print(f"{mark[level]}  {msg}")
        fails, warns = sum(r[0] == "fail" for r in results), sum(r[0] == "warn" for r in results)
        print(f"\n{fails} problem(s), {warns} warning(s)")
    return 3 if broken else 2 if fails else 1 if warns and a.strict else 0


def cmd_try(a):
    """A self-contained tour, nothing to set up: a CA, a plain web server, the post-quantum edge in front of it, a
    post-quantum client that gets through and a classical one that does not. Everything lives in a temporary folder."""
    import tempfile
    from ..tls.edge import Edge, Route
    from ..tls.openssl import Context
    tls.lib()  # say at once when this machine's OpenSSL cannot do post-quantum TLS, not halfway through the tour
    logging.getLogger(NAME).setLevel(logging.ERROR)
    step = lambda n, text: print(f"\n{n}. {text}")
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        step(1, "A private certificate authority (ML-DSA-87 root) issues the edge an ML-DSA-65 certificate.")
        ca = CA.init(d / "pki", "Try Root")
        ca.issue("localhost", "server", ["127.0.0.1"], out=d / "edge")
        web = serve_http("127.0.0.1:0", {"/": ("text/plain; charset=utf-8",
                                               lambda: "Hello from a web server that knows nothing about post-quantum cryptography\n")})
        step(2, f"An ordinary web server starts on 127.0.0.1:{web.server_address[1]}. It has no post-quantum support.")
        edge = Edge(Route("try", "terminate", "127.0.0.1:0", f"127.0.0.1:{web.server_address[1]}", cert=str(d / "edge" / "chain.pem"),
                          key=str(d / "edge" / "key.pem"))).start()
        try:
            step(3, f"The pqc edge starts in front of it on 127.0.0.1:{edge.port}, accepting post-quantum clients only.")
            step(4, "A post-quantum client asks for the page through the edge:")
            with tls.connect("127.0.0.1", edge.port, tls.client_context(d / "pki" / "ca.crt"), "localhost", 10) as c:
                c.sendall(b"GET / HTTP/1.0\r\n\r\n")
                reply = b""
                while chunk := c.recv(timeout=10):
                    reply += chunk
                info = c.info()
            print(f"   key exchange  {info['group']}   (post-quantum: X25519 combined with ML-KEM-768)")
            print(f"   certificate   {info['peer_key']}   (post-quantum signature)")
            page = reply.split(b"\r\n\r\n", 1)[-1].decode().strip()
            print(f"   page          {page}")
            step(5, "A client that only knows classical key exchange (X25519) tries the same:")
            # a classical client on purpose: the tour shows the edge refusing it
            classical = Context(False, "X25519", None, tls.CIPHERSUITES, None, None, None, str(d / "pki" / "ca.crt"), True)
            try:
                tls.connect("127.0.0.1", edge.port, classical, "localhost", 10).close()
                print("   it got through, which it should not have")
                return 1
            except (tls.TLSError, OSError):
                print("   refused, as it should be: no connection falls back to a key exchange a future quantum computer could break")
            classical.close()
        finally:
            edge.stop(0)
            web.shutdown()
            web.server_close()
    print("\nThat is the TLS product: post-quantum protection in front of a service that did not change.\n"
          "Next: pqc tls edge --help, and https://github.com/QubitMan-hub/PQC")
    return 0


def add(sub):
    p = sub.add_parser("doctor", help="check that this machine can run the CA and the TLS edge",
                       epilog="exit codes: 0 safe, 1 warnings (with --strict), 2 unsafe configuration, 3 broken installation")
    p.set_defaults(func=cmd_doctor)
    p.add_argument("--json", action="store_true", help="structured local prerequisite checks and actionable diagnostics")
    p.add_argument("--check-updates", action="store_true", help="also ask GitHub whether a newer release is out (the only request it makes)")
    p.add_argument("--ca", action="append", default=[], metavar="DIR", help="check a CA: key protection, CRL freshness, certificates expiring")
    p.add_argument("--strict", action="store_true", help="warnings fail too (exit 1); a deployment gate")
    p.add_argument("--config", action="append", default=[], metavar="FILE",
                   help="check an edge configuration: it loads, its files exist, nothing weakens it")

    p = sub.add_parser("try", help="a one-minute tour: the post-quantum edge in front of a web server, nothing to set up")
    p.set_defaults(func=cmd_try)
