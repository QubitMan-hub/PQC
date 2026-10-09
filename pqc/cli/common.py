"""What several products' commands share: passphrases, output, numbers, signals and the TLS client options."""
import argparse
import getpass
import json
import logging
import os
import signal
import sys
from pathlib import Path

from .. import NAME, tls
from ..pki import CAError, encrypted

CA_PASS_ENV = "PQC_CA_PASSPHRASE"


def ask(prompt, instead):
    """A passphrase typed at the terminal; without one (a pipe, a service, CI) a clear error naming the alternative."""
    try:
        if not sys.stdin.isatty():
            raise EOFError
        return getpass.getpass(prompt).encode()
    except EOFError:
        raise ValueError(f"no terminal to type the passphrase in: {instead}") from None


def ca_passphrase(root, new=False):
    """From PQC_CA_PASSPHRASE or a prompt, and only when the CA key is (or will be) encrypted."""
    if not new and not encrypted(Path(root) / "ca.key"):
        return None
    if os.environ.get(CA_PASS_ENV):
        return os.environ[CA_PASS_ENV].encode()
    if not new:
        return ask("CA passphrase: ", f"set {CA_PASS_ENV}")
    instead = f"set {CA_PASS_ENV}, or pass --no-encrypt to leave the CA key unencrypted"
    p1, p2 = ask("New CA passphrase: ", instead), ask("Repeat: ", instead)
    if p1 != p2:
        raise CAError("the passphrases do not match")
    return p1


def show(obj, as_json):
    if as_json:
        print(json.dumps(obj, indent=1, default=str))
    else:
        for k, v in obj.items():
            print(f"{k:>14}  {', '.join(map(str, v)) if isinstance(v, (list, tuple)) else 'none' if v is None else v}")


def positive(kind):
    def check(s):
        try:
            v = kind(s)
        except ValueError:
            v = 0
        if not v > 0:
            raise argparse.ArgumentTypeError(f"expected a number above 0, got {s!r}")
        return v
    return check


def run_until_signal(run, stop, reload=None):
    """Run until SIGINT or SIGTERM calls `stop`. With `reload`, SIGHUP (`systemctl reload`) calls it, where the platform has one."""
    def handle(*_):
        logging.getLogger(NAME).info("shutting down")
        stop()
    signal.signal(signal.SIGINT, handle)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle)
    if reload and hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda *_: reload())
    run()


def tls_client_args(p):
    p.add_argument("target", help="host:port")
    p.add_argument("--server-name", help="name the certificate must match (default: host)")
    policy(p)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true")


def policy(p):
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict", help="strict: post-quantum only (default); transition: also classical clients; cnsa2: ML-KEM-1024 and ML-DSA-87 only")
