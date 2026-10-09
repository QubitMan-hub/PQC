"""Deployment checks for `pqc doctor --ca DIR --config FILE`: each check is (level, message) with level ok,
warn or fail."""
import datetime as dt
import os
from pathlib import Path

from cryptography import x509

from . import read_toml
from .pki import CA, CAError, encrypted, now, signed_by


def _private(path):
    """A key file readable by everyone fails, by its group warns (Kubernetes mounts secrets group-readable for fsGroup). POSIX
    permissions only; Windows ACLs are not checked."""
    if os.name == "nt":
        return []
    mode = os.stat(path).st_mode
    if mode & 0o004:
        return [("fail", f"{path} can be read by every user (chmod 600 it)")]
    return [("warn", f"{path} can be read by its group (chmod 600 it unless the group is this service's)")] if mode & 0o040 else []


def ca(root):
    root, out = Path(root), []
    try:
        c = CA(root)
    except (CAError, OSError, ValueError) as e:
        return [("fail", f"CA at {root}: {e}")]
    left = (c.cert.not_valid_after_utc - now()).days
    valid_now = c.cert.not_valid_before_utc <= now() < c.cert.not_valid_after_utc
    out.append(("fail" if not valid_now else "ok" if left > 365 else "warn",
                f"CA {c.cert.subject.rfc4514_string()} ({c.algorithm}) " +
                (f"valid for {left} more days" if valid_now else "is expired or not yet valid; restore a valid CA before serving certificates")))
    if (root / "signer.json").exists():
        out.append(("ok", "CA key is held by an external signer (KMS or HSM)"))
    else:
        out += _private(root / "ca.key")
        out.append(("ok", "CA key is encrypted") if encrypted(root / "ca.key") else
                   ("warn", "CA key is not encrypted (created with --no-encrypt): anyone who copies ca.key can issue certificates; use KMS, an HSM or an encrypted key"))
    try:
        records = c.records()
    except (OSError, ValueError, TypeError) as e:
        return out + [("fail", f"{root / 'index.json'} cannot be read ({e}): restore it from a backup")]
    crl = root / "crl.pem"
    try:
        listed = x509.load_pem_x509_crl(crl.read_bytes()) if crl.exists() else None
    except ValueError:
        listed = False
    if listed is None:
        out.append(("fail", f"no {crl}: mutual-TLS services cannot start (pqc ca crl)"))
    elif listed is False or not signed_by(c.cert, listed.tbs_certlist_bytes, listed.signature):
        out.append(("fail", f"{crl} is damaged or not signed by this CA; every client would be refused (pqc ca crl)"))
    else:
        missing = [r.common_name for r in records if r.status == "revoked" and listed.get_revoked_certificate_by_serial_number(int(r.serial, 16)) is None]
        if missing:
            out.append(("fail", f"{len(missing)} revoked certificate(s) not in crl.pem ({', '.join(missing[:5])}): run pqc ca crl"))
        nxt = listed.next_update_utc
        days = (nxt - now()) / dt.timedelta(days=1)
        out.append(("fail" if days < 0 else "warn" if days < 2 else "ok",
                    f"CRL {'expired' if days < 0 else 'valid for'} {abs(days):.1f} days{'' if days >= 2 else ': run pqc ca maintain'}"))
    newest = {}
    for r in records:
        if r.status == "valid" and r.kind != "ca" and r.path and dt.datetime.fromisoformat(r.not_after) > now():
            newest[r.path] = max(newest.get(r.path, r), r, key=lambda x: x.not_after)
    gone = [r for r in newest.values() if not all((Path(r.path) / f).exists() for f in ("cert.pem", "key.pem", "chain.pem"))]
    if gone:
        out.append(("warn", f"{len(gone)} valid certificate(s) recorded without their files ({', '.join(r.common_name for r in gone[:5])}): "
                            "moved elsewhere, or a crash while issuing; revoke any whose files are gone for good"))
    soon = c.expiring(30)
    out.append(("warn", f"{len(soon)} certificate(s) expire within 30 days: {', '.join(r.common_name for r in soon[:5])} "
                        "(pqc ca maintain renews them)") if soon else ("ok", "no certificate expires within 30 days"))
    return out


def _files(where, d, names):
    out = []
    for k in [n for n in names if not (n == "crl" and d.get("crl_url"))]:  # with crl_url the copy appears at the first fetch
        p = d.get(k)
        if not p:
            continue
        if not Path(p).exists():
            out.append(("fail", f"{where}: {k} = {p} does not exist"))
        elif k in ("key", "private_key"):
            out += _private(p)
    return out


def config(path):
    """Load the file with the loader for its kind, then look for settings that work but weaken the deployment."""
    from .tls.edge import load_config as edge
    try:
        doc = read_toml(path)
    except OSError as e:
        return [("fail", f"{path}: {e.strerror or e}")]
    except ValueError as e:
        return [("fail", str(e))]
    if "edge" not in doc:
        return [("fail", f"{path}: no [[edge]] section")]
    kind = "edge"
    try:
        edge(path)
    except (OSError, ValueError, CAError) as e:
        return [("fail", f"{path}: {e}")]
    out = [("ok", f"{path}: {kind} configuration loads")]
    keys = ("cert", "key", "ca", "crl", "fallback_cert", "fallback_key", "private_key")
    for i, r in enumerate(doc.get("edge", [])):
        where = f"{path} edge {r.get('name', i + 1)}"
        out += _files(where, r, keys)
        if r.get("policy") == "transition":
            out.append(("warn", f"{where}: policy transition lets clients without post-quantum key exchange in; fine for browsers, "
                                "use strict for everything else"))
        if r.get("require_client_cert") and not r.get("crl"):
            out.append(("fail", f"{where}: mutual TLS without a CRL accepts revoked clients"))
        if r.get("crl") and not r.get("crl_url"):
            out.append(("warn", f"{where}: the CRL is a local file; unless this machine is the CA, set crl_url so revocations arrive"))
    return out


def prerequisites():
    """Local-only capability checks with next actions; no account credentials or source collected."""
    from . import tls
    try:
        context = tls.client_context(verify=False)  # only checks that a context can be built; nothing connects
        context.close()
        return [{'product': 'tls', 'level': 'ok', 'message': 'OpenSSL supports strict PQ TLS contexts', 'action': ''}]
    except (tls.TLSError, OSError) as error:
        return [{'product': 'tls', 'level': 'fail', 'message': str(error), 'action': 'Install OpenSSL 3.5+ for this architecture; run pqc doctor again before enrollment'}]
