"""TLS 1.3 + mTLS: the certificate authority, EST enrollment and ACME."""
import argparse
import getpass
import json
import os
import sys
import threading
from pathlib import Path

from .. import PEM, env_passphrase, serve_http
from ..pki import ALGORITHMS, CA, CA_ALGORITHMS, REASONS, CAError, encrypted
from .common import CA_PASS_ENV, ask, ca_passphrase, positive, run_until_signal


def cmd_ca(a):
    if a.ca_cmd == "init":
        parent = None
        if a.parent:
            pw = None
            if encrypted(Path(a.parent) / "ca.key"):
                pw = os.environ.get("PQC_PARENT_CA_PASSPHRASE", "").encode() or ask("Parent CA passphrase: ", "set PQC_PARENT_CA_PASSPHRASE")
            parent = CA(a.parent, pw)
        if a.signer_command and not a.signer_public_key:
            raise CAError("--signer-command needs --signer-public-key")
        signer = ({"type": "aws-kms", "key_id": a.kms, **({"region": a.kms_region} if a.kms_region else {})} if a.kms else
                  {"type": "command", "command": a.signer_command, "public_key": str(Path(a.signer_public_key).resolve())} if a.signer_command else None)
        ca = CA.init(a.dir, a.name, a.algorithm, a.days, ca_passphrase(a.dir, new=True) if not (a.no_encrypt or signer) else None, parent, signer)
        what = f"intermediate CA under '{parent.cert.subject.rfc4514_string()}'" if parent else "root"
        print(f"created {ca.algorithm} {what} '{a.name}' in {a.dir} (serial {ca.cert.serial_number:x}); clients trust {ca.anchor}, servers check {Path(a.dir) / 'crl.pem'}")
        return 0
    ca = CA(a.dir, None if a.ca_cmd in ("list", "publish") else ca_passphrase(a.dir))
    if a.ca_cmd == "issue":
        out, r = ca.issue(a.common_name, a.kind, a.san, a.days, a.algorithm, a.out, env_passphrase(a.key_passphrase_env))
        print(f"issued {r.kind} certificate {r.serial} for {r.common_name} ({r.algorithm}), valid until {r.not_after}")
        print(f"  {out / 'cert.pem'}\n  {out / 'chain.pem'}  (certificate + CA: what servers and mTLS clients present)\n  {out / 'key.pem'}")
    elif a.ca_cmd == "sign-csr":
        cert, r = ca.sign_csr(Path(a.csr).read_bytes(), a.kind, a.days)
        from ..pki import cert_pem
        Path(a.out).write_bytes(cert_pem(cert))
        print(f"signed {r.serial} for {r.common_name} -> {a.out}")
    elif a.ca_cmd == "revoke":
        ca.revoke(a.serial, a.reason)
        print(f"revoked {ca.find(a.serial).serial}; {Path(a.dir) / 'crl.pem'} updated (servers with crl_url fetch it from 'ca publish'; copy it to any others)")
    elif a.ca_cmd == "crl":
        ca.crl(a.days)
        print(f"wrote {Path(a.dir) / 'crl.pem'}")
    elif a.ca_cmd == "renew":
        out, r = ca.renew(a.serial, a.days, a.algorithm, a.out, env_passphrase(a.key_passphrase_env))
        print(f"renewed as {r.serial}, valid until {r.not_after}, in {out}")
    elif a.ca_cmd == "token":
        from ..pki.est import create_token
        t = create_token(ca, a.common_name, a.kind, a.san, a.hours)
        print(f"one-time enrollment token for {a.common_name} ({a.kind}), valid {a.hours} h. It is shown only once:\n{t}")
    elif a.ca_cmd == "serve":
        from cryptography.x509 import load_pem_x509_certificate
        from ..pki.est import fingerprint, serve
        srv = serve(a.dir, a.listen, a.cert, a.key, ca_passphrase(a.dir), env_passphrase(a.key_passphrase_env))
        print(f"EST enrollment on https://{a.listen}/.well-known/est; CA fingerprint (give it to clients):\n{fingerprint(load_pem_x509_certificate(ca.anchor.read_bytes()))}")
        run_until_signal(srv.serve_forever, srv.stop)
    elif a.ca_cmd == "publish":
        crl, anchor = Path(a.dir) / "crl.pem", ca.anchor
        read = lambda f: lambda: f.read_text(encoding="ascii") if f.exists() else None
        httpd = serve_http(a.listen, {"/crl.pem": (PEM, read(crl)), "/ca.crt": (PEM, read(anchor))})
        host, port = httpd.server_address[:2]
        print(f"publishing http://{host}:{port}/crl.pem (read fresh on every request) and /ca.crt; set crl_url to it on edges and gateways")
        stop = threading.Event()
        run_until_signal(stop.wait, lambda: (httpd.shutdown(), stop.set()))
    elif a.ca_cmd == "maintain":
        renewed, skipped = ca.maintain(a.renew_within, a.crl_days)
        for r in renewed:
            print(f"renewed {r.common_name} -> {r.serial[:16]} in {r.path}, valid until {r.not_after[:10]}")
        for r in skipped:
            print(f"NOT renewed {r.common_name} ({r.serial[:16]}, expires {r.not_after[:10]}): its key is encrypted; renew it by hand")
        print(f"CRL re-signed, valid {a.crl_days} days")
        return 1 if skipped else 0
    elif a.ca_cmd == "list":
        rows = ca.expiring(a.expiring) if a.expiring is not None else ca.records()
        if a.json:
            print(json.dumps([vars(r) for r in rows], indent=1))
        for r in [] if a.json else rows:
            print(f"{r.serial[:16]:16}  {r.status:7}  {r.kind:6}  {r.not_after[:10]}  {r.algorithm:9}  {r.common_name}  {' '.join(r.names)}")
    return 0


def cmd_acme(a):
    from ..pki import acme
    if a.ca_cmd == "csr":
        out = acme.make_csr(a.names, a.out, a.algorithm, env_passphrase(a.key_passphrase_env))
        print(f"{out / 'key.pem'} (keep secret), {out / 'csr.pem'} and {out / 'csr.der'}\n"
              f"certbot certonly --csr {out / 'csr.der'} --server https://ACME-HOST/directory ...")
        return 0
    if a.ca_cmd == "eab":
        kid, key = acme.create_eab(a.dir, a.note)
        print(f"external account binding for one client (shown once):\n  key id:   {kid}\n  HMAC key: {key}\n"
              f"certbot: --eab-kid {kid} --eab-hmac-key {key}")
        return 0
    ca = CA(a.dir, ca_passphrase(a.dir))
    ca.signer  # a wrong passphrase fails now, not at the first order
    base = a.base_url or f"{'https' if a.tls_cert else 'http'}://{a.listen}"
    httpd = acme.serve(acme.Service(ca, base, a.allow, a.require_eab, a.http_port, days=a.days, allow_local=a.allow_local_validation), a.listen, a.tls_cert, a.tls_key)
    print(f"ACME directory: {base}/directory (issuing ML-DSA certificates from {ca.cert.subject.rfc4514_string()})")
    run_until_signal(httpd.serve_forever, lambda: threading.Thread(target=httpd.shutdown).start())
    return 0


def cmd_enroll(a):
    from ..pki import est
    key_passphrase = env_passphrase(a.key_passphrase_env)
    if getattr(a, 'guide', False):
        if a.renew:
            raise CAError('--guide is for first enrollment; use --renew with an existing device folder')
        if not sys.stdin.isatty():
            raise CAError('--guide needs an interactive terminal; automation should supply enrollment flags and secret environment variables')
        from ..checks import prerequisites
        failures = [r for r in prerequisites() if r['level'] == 'fail']
        if failures:
            raise CAError(failures[0]['message'] + '. ' + failures[0]['action'])
        a.url = a.url or input('Enrollment service HTTPS URL: ').strip()
        a.common_name = a.common_name or input('Device or service name assigned by your administrator: ').strip()
        if not a.ca and not a.ca_fingerprint:
            a.ca_fingerprint = input('CA SHA-256 fingerprint supplied by your administrator: ').strip()
        a.token = a.token or os.environ.get('PQC_ENROLL_TOKEN') or getpass.getpass('One-time enrollment token: ')
        if not key_passphrase:
            key_passphrase = getpass.getpass('New local key passphrase: ').encode()
            if not key_passphrase or key_passphrase != getpass.getpass('Repeat key passphrase: ').encode():
                raise CAError('A nonempty matching passphrase is required for guided enrollment')
    if not a.url or not a.url.startswith('https://'):
        raise CAError('Supply an HTTPS enrollment URL, or use --guide')
    if a.renew:
        cert = est.renew(a.url, a.renew, within_days=a.within_days, passphrase=key_passphrase, server_name=a.server_name)
        print(f"{a.renew}: " + (f"renewed, new serial {cert.serial_number:x}, valid until {cert.not_valid_after_utc.date()}" if cert
                                else f"still valid for more than {a.within_days} days, nothing to do"))
        return 0
    token = a.token or os.environ.get("PQC_ENROLL_TOKEN")
    if not (token and a.common_name):
        raise CAError("first enrollment needs the token (PQC_ENROLL_TOKEN, or --token) and --cn (renewal needs --renew FOLDER)")
    ca = a.ca
    if not ca:
        if not a.ca_fingerprint:
            raise CAError("give --ca FILE or --ca-fingerprint SHA256 (from `pqc ca serve`) so the CA can be trusted")
        ca = Path(a.out) / "ca.crt"
        est.fetch_ca(a.url, a.ca_fingerprint, ca, a.server_name)
    cert = est.enroll(a.url, token, a.common_name, a.san, a.out, ca, passphrase=key_passphrase, server_name=a.server_name)
    print(f"enrolled {a.common_name}: serial {cert.serial_number:x}, valid until {cert.not_valid_after_utc.date()}, files in {a.out}")
    print(f"renew it daily from cron: pqc ca enroll {a.url} --renew {a.out} --within-days 30")
    return 0

def add(sub, common):
    ca = sub.add_parser("ca", help="TLS 1.3 + mTLS: the post-quantum certificate authority, EST and ACME").add_subparsers(dest="ca_cmd", required=True)
    p = ca.add_parser("init", parents=[common], help="create a root or intermediate CA",
                      epilog='example: pqc ca init --name "Example Root CA" --dir pki')
    p.add_argument("--name", required=True, help="the CA's name, shown in every certificate it issues, e.g. \"Acme PQC Root\"")
    p.add_argument("--algorithm", choices=CA_ALGORITHMS, default="ML-DSA-87", help="SLH-DSA keys need OpenSSL 3.5+")
    p.add_argument("--parent", help="the CA folder that signs this one, making it an intermediate CA")
    p.add_argument("--kms", metavar="KEY_ID", help="keep the CA key in AWS KMS (an ML_DSA_* key); needs boto3")
    p.add_argument("--kms-region", help="the KMS key's AWS region (default: from your AWS configuration)")
    p.add_argument("--signer-command", nargs="+", metavar="ARG", help="an HSM tool that reads data on stdin and writes the signature")
    p.add_argument("--signer-public-key", help="PEM public key of the --signer-command key")
    p.add_argument("--days", type=int, default=3650, help="the CA certificate's lifetime (default: 3650, ten years)")
    enc = p.add_mutually_exclusive_group()
    enc.add_argument("--encrypt", action="store_true", help=argparse.SUPPRESS)  # the default now; still accepted from older scripts
    enc.add_argument("--no-encrypt", action="store_true",
                     help=f"leave the CA key unencrypted (by default it is encrypted, passphrase from {CA_PASS_ENV} or a prompt)")
    for name in ("issue", "renew"):
        p = ca.add_parser(name, parents=[common], help="issue a key and certificate" if name == "issue" else "new key and certificate, same names",
                          epilog="example: pqc ca issue server web.corp.example --dir pki --out web" if name == "issue" else
                          "example: pqc ca renew 3f9a1c2e7b --dir pki --out web (serials from `ca list`)")
        if name == "issue":
            p.add_argument("kind", choices=["server", "client", "site"], help="site: both server and client")
            p.add_argument("common_name", help="the name it certifies: a host name such as web.corp.example, or a person or device")
            p.add_argument("--san", action="append", default=[], help="DNS name or IP (repeatable; servers default to the common name)")
        else:
            p.add_argument("serial", help="from `ca list`; the first 8 or more hex characters are enough")
        p.add_argument("--algorithm", choices=list(ALGORITHMS), default="ML-DSA-65" if name == "issue" else None,
                       help=None if name == "issue" else "default: the algorithm of the certificate being renewed")
        p.add_argument("--days", type=int, default=397)
        p.add_argument("--out", help="folder for cert.pem, chain.pem and key.pem")
        p.add_argument("--key-passphrase-env", help="encrypt the new key with the passphrase in this environment variable")
    p = ca.add_parser("sign-csr", parents=[common], help="certify a key generated elsewhere")
    p.add_argument("csr")
    p.add_argument("--kind", choices=["server", "client", "site"], required=True)
    p.add_argument("--days", type=int, default=397)
    p.add_argument("--out", required=True, help="the certificate file to write")
    p = ca.add_parser("revoke", parents=[common], help="revoke a certificate and refresh the CRL")
    p.add_argument("serial")
    p.add_argument("--reason", default="unspecified", choices=["unspecified", *REASONS],
                   help="recorded in the CRL; keyCompromise when the key was stolen or exposed")
    p = ca.add_parser("crl", parents=[common], help="re-sign the CRL (do this before it expires)")
    p.add_argument("--days", type=positive(int), default=7, help="how long the CRL is valid (default: 7); re-sign it before then")
    p = ca.add_parser("maintain", parents=[common], help="renew what expires soon and refresh the CRL (run daily)")
    p.add_argument("--renew-within", type=int, default=30, metavar="DAYS", help="renew certificates expiring within DAYS (default: 30)")
    p.add_argument("--crl-days", type=positive(int), default=7, help="how long the re-signed CRL is valid (default: 7 days)")
    p = ca.add_parser("list", parents=[common], help="list issued certificates")
    p.add_argument("--expiring", type=int, metavar="DAYS", help="only those expiring within DAYS")
    p.add_argument("--json", action="store_true")
    p = ca.add_parser("token", parents=[common], help="one-time enrollment token for one name (for `ca enroll`)")
    p.add_argument("kind", choices=["server", "client", "site"])
    p.add_argument("common_name")
    p.add_argument("--san", action="append", default=[])
    p.add_argument("--hours", type=positive(float), default=24, help="how long the token can be used (default: 24)")
    p = ca.add_parser("publish", parents=[common], help="serve crl.pem and ca.crt over HTTP, for edges and gateways to follow (crl_url)")
    p.add_argument("--listen", default="0.0.0.0:8080", help="host:port (default: every interface, port 8080)")
    p = ca.add_parser("serve", parents=[common], help="EST enrollment service (RFC 7030) over post-quantum TLS")
    p.add_argument("--listen", default="0.0.0.0:9443", help="host:port (default: every interface, port 9443)")
    p.add_argument("--cert", required=True, help="the service's own server chain.pem")
    p.add_argument("--key", required=True)
    p.add_argument("--key-passphrase-env")
    for c in ca.choices.values():
        c.set_defaults(func=cmd_ca)
    p = ca.add_parser("enroll", help="get or renew a certificate from an EST service; the key stays on this machine")
    p.set_defaults(func=cmd_enroll)
    p.add_argument("url", nargs="?", help="https://ca.example.com:9443")
    p.add_argument("--guide", action="store_true", help="interactive enrollment with pinned CA trust and an encrypted local key")
    p.add_argument("--token", help="one-time token from `ca token`; better in PQC_ENROLL_TOKEN, since other users can read command lines")
    p.add_argument("--cn", dest="common_name")
    p.add_argument("--san", action="append", default=[])
    p.add_argument("--out", default=".")
    p.add_argument("--ca", help="trusted CA certificate")
    p.add_argument("--ca-fingerprint", help="or the CA's SHA-256 fingerprint, to download and pin it")
    p.add_argument("--renew", metavar="FOLDER", help="renew the certificate in FOLDER in place")
    p.add_argument("--within-days", type=int, help="with --renew: only when it expires within this many days")
    p.add_argument("--server-name")
    p.add_argument("--key-passphrase-env")
    p = ca.add_parser("acme", parents=[common], help="ACME (RFC 8555) service: ML-DSA certificates for clients that take a CSR (certbot --csr)")
    p.set_defaults(func=cmd_acme)
    p.add_argument("--listen", default="127.0.0.1:14000", help="host:port (default: this machine only, port 14000)")
    p.add_argument("--base-url", help="the URL clients use, e.g. https://acme.corp.example (default from --listen)")
    p.add_argument("--allow", action="append", default=[], help="names or patterns this CA issues for, e.g. '*.corp.example' (repeatable)")
    p.add_argument("--require-eab", action="store_true", help="clients need an external account binding key (see `ca eab`)")
    p.add_argument("--http-port", type=int, default=80, help="port for http-01 validation")
    p.add_argument("--allow-local-validation", action="store_true",
                   help="let http-01 validation reach loopback and link-local addresses (refused by default; private networks are allowed)")
    p.add_argument("--days", type=int, default=90, help="lifetime of issued certificates")
    p.add_argument("--tls-cert", help="a certificate ACME clients trust (classical: clients cannot verify ML-DSA yet)")
    p.add_argument("--tls-key")
    p = ca.add_parser("eab", parents=[common], help="an ACME external account binding key for one client")
    p.set_defaults(func=cmd_acme)
    p.add_argument("--note", default="")
    p = ca.add_parser("csr", help="an ML-DSA key and CSR, for certbot --csr")
    p.set_defaults(func=cmd_acme)
    p.add_argument("names", nargs="+")
    p.add_argument("--out", default=".")
    p.add_argument("--algorithm", choices=list(ALGORITHMS), default="ML-DSA-65")
    p.add_argument("--key-passphrase-env")
