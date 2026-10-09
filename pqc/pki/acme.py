"""ACME (RFC 8555) in front of the pqc CA, so standard ACME clients obtain and renew ML-DSA certificates.

Accounts sign requests with classical keys (RS256, ES256/384/512 or EdDSA), as every ACME client does. The certificates they
get are ML-DSA: the CSR must carry an ML-DSA public key (certbot `--csr`, or `pqc` generating it). Identifiers are
proved with http-01 (RFC 8555) for DNS names and IP addresses (RFC 8738). External account binding (RFC 8555 7.3.4) keeps
strangers from registering. The ACME service itself speaks ordinary HTTPS, because ACME clients cannot yet verify ML-DSA
server certificates: give it a classical certificate, or run it on localhost behind a terminating proxy.
"""
import base64
import collections
import datetime as dt
import fnmatch
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import secrets
import socket
import ssl
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .. import HTTP_IDLE, NAME, __version__, content_length
from . import CAError, cert_pem, locked, now, write

log = logging.getLogger("pqc.acme")
ERR = "urn:ietf:params:acme:error:"
CURVES = {"P-256": (ec.SECP256R1(), hashes.SHA256(), "ES256"), "P-384": (ec.SECP384R1(), hashes.SHA384(), "ES384"),
          "P-521": (ec.SECP521R1(), hashes.SHA512(), "ES512")}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """http-01 validation talks only to the identifier's own host and port: a redirect would let a client make this server
    probe other (internal) addresses and read the answer from the error."""

    def redirect_request(self, *args):
        return None


FETCH = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
REASONS = {0: "unspecified", 1: "keyCompromise", 3: "affiliationChanged", 4: "superseded", 5: "cessationOfOperation"}


class Problem(Exception):
    def __init__(self, kind, detail, status=400):
        super().__init__(detail)
        self.kind, self.detail, self.status = kind, detail, status


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text):
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise Problem("malformed", "bad base64url") from None


def _int(v):
    return int.from_bytes(unb64u(v), "big")


def jwk_key(jwk):
    """The public key in a JWK, and the JWS algorithms it may sign with."""
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            key = rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
            if key.key_size < 2048:
                raise Problem("badPublicKey", "RSA account keys must be at least 2048 bits")
            return key, {"RS256"}
        if kty == "EC" and jwk.get("crv") in CURVES:
            return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), CURVES[jwk["crv"]][0]).public_key(), {CURVES[jwk["crv"]][2]}
        if kty == "OKP" and jwk.get("crv") == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(unb64u(jwk["x"])), {"EdDSA"}
    except (KeyError, ValueError):
        raise Problem("badPublicKey", "the account key is malformed") from None
    raise Problem("badPublicKey", "account keys must be RSA, P-256, P-384, P-521 or Ed25519")


def thumbprint(jwk):
    """RFC 7638: SHA-256 over the required members, sorted, without whitespace."""
    need = {"RSA": ("e", "kty", "n"), "EC": ("crv", "kty", "x", "y"), "OKP": ("crv", "kty", "x")}[jwk["kty"]]
    return b64u(hashlib.sha256(json.dumps({k: jwk[k] for k in need}, separators=(",", ":"), sort_keys=True).encode()).digest())


def verify(key, alg, data, sig):
    try:
        if alg == "RS256":
            key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        elif alg.startswith("ES"):
            n = (key.curve.key_size + 7) // 8
            if len(sig) != 2 * n:
                raise InvalidSignature
            key.verify(encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big")),
                       data, ec.ECDSA(CURVES[{256: "P-256", 384: "P-384", 521: "P-521"}[key.curve.key_size]][1]))
        else:
            key.verify(sig, data)
    except InvalidSignature:
        raise Problem("unauthorized", "the request's signature does not verify", 403) from None


def validation_address(host, port, allow_local=False):
    """The address http-01 validation connects to, resolved once so a second DNS answer cannot redirect it. Loopback,
    link-local (cloud metadata services live there), multicast and reserved addresses are refused unless `allow_local`:
    otherwise anyone allowed to order could make the CA probe them. Private networks are allowed, since an internal CA's
    clients live on them; `allow` patterns and EAB limit who can order."""
    try:
        found = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except (OSError, UnicodeError) as e:
        raise OSError(f"cannot resolve {host}: {e}") from None
    for a in found:
        a = getattr(a, "ipv4_mapped", None) or a
        if not allow_local and (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved):
            raise OSError(f"{host} resolves to {a}, which this CA does not validate (start it with --allow-local-validation to permit it)")
    return str(min(found, key=lambda a: a.version))


def _iso(t):
    return t.replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Service:
    """The ACME resources. State lives in `<ca>/acme/state.json`; everything goes through one lock."""

    def __init__(self, ca, base_url, allow=(), require_eab=False, http_port=80, validate_async=True, days=90, allow_local=False):
        self.ca, self.base, self.days, self.allow_local = ca, base_url.rstrip("/"), days, allow_local
        self.allow, self.require_eab, self.http_port, self.validate_async = list(allow), require_eab, http_port, validate_async
        self.dir = Path(ca.root) / "acme"
        self.lock = threading.RLock()
        self.nonces = collections.OrderedDict()
        f = self.dir / "state.json"
        self.state = json.loads(f.read_text()) if f.exists() else {"accounts": {}, "orders": {}, "authz": {}, "certs": {}}

    def save(self):
        write(self.dir / "state.json", json.dumps(self.state, indent=1).encode(), secret=True)

    def url(self, *parts):
        return "/".join([self.base, *parts])

    def nonce(self):
        n = b64u(secrets.token_bytes(18))
        with self.lock:
            self.nonces[n] = True
            while len(self.nonces) > 10000:
                self.nonces.popitem(last=False)
        return n

    def directory(self):
        return {"newNonce": self.url("new-nonce"), "newAccount": self.url("new-account"), "newOrder": self.url("new-order"),
                "revokeCert": self.url("revoke-cert"),
                "meta": {"externalAccountRequired": self.require_eab}}

    def parse(self, url, body):
        """Check a flattened JWS: nonce, URL, key and signature. Returns (payload or None, account id or None, jwk)."""
        try:
            jws = json.loads(body)
            protected = json.loads(unb64u(jws["protected"]))
            alg, sig = protected["alg"], unb64u(jws["signature"])
            if not (isinstance(protected, dict) and isinstance(protected.get("kid", ""), str) and isinstance(protected.get("jwk", {}), dict)
                    and isinstance(jws.get("payload", ""), str)):
                raise TypeError
        except (ValueError, KeyError, TypeError, AttributeError):
            raise Problem("malformed", "the body must be a flattened JWS") from None
        with self.lock:
            if self.nonces.pop(protected.get("nonce"), None) is None:
                raise Problem("badNonce", "unknown or reused nonce")
        if protected.get("url") != url:
            raise Problem("unauthorized", "the JWS url does not match the request", 401)
        if ("jwk" in protected) == ("kid" in protected):
            raise Problem("malformed", "exactly one of jwk and kid is required")
        account = None
        if "kid" in protected:
            account = protected["kid"].rsplit("/", 1)[-1]
            acct = self.state["accounts"].get(account)
            if not protected["kid"].startswith(self.url("acct", "")) or not acct:
                raise Problem("accountDoesNotExist", "no such account", 400)
            if acct["status"] != "valid":
                raise Problem("unauthorized", "this account is deactivated", 401)
            jwk = acct["jwk"]
        else:
            jwk = protected["jwk"]
        key, algs = jwk_key(jwk)
        if alg not in algs:
            raise Problem("badSignatureAlgorithm", f"use {', '.join(sorted(algs))} with this key")
        verify(key, alg, f"{jws['protected']}.{jws.get('payload', '')}".encode(), sig)
        try:
            payload = json.loads(unb64u(jws["payload"])) if jws.get("payload") else None
        except ValueError:
            raise Problem("malformed", "the payload is not JSON") from None
        if payload is not None and not isinstance(payload, dict):
            raise Problem("malformed", "the payload must be a JSON object")
        return payload, account, jwk

    def handle(self, method, path, body):
        """Returns (status, body, headers)."""
        if method == "GET" and path == "/directory":
            return 200, self.directory(), {}
        if path == "/new-nonce" and method in ("GET", "HEAD"):
            return 204 if method == "GET" else 200, None, {"Cache-Control": "no-store"}
        if method != "POST":
            raise Problem("malformed", "use POST (or POST-as-GET)", 405)
        payload, account, jwk = self.parse(self.url(path.lstrip("/")), body)
        parts = path.strip("/").split("/")
        with self.lock:
            if parts == ["new-account"]:
                return self.new_account(payload or {}, jwk, account)
            if not account:
                if parts == ["revoke-cert"]:
                    raise Problem("unauthorized", "revoke with the account that ordered the certificate (kid)", 401)
                raise Problem("malformed", "this request needs the account URL (kid)")
            if parts == ["new-order"]:
                return self.new_order(payload or {}, account)
            if parts == ["revoke-cert"]:
                return self.revoke(payload or {}, account)
            if len(parts) == 2:
                kind, rid = parts
                fn = {"acct": self.account, "order": self.order, "authz": self.authz, "chall": self.challenge,
                      "finalize": self.finalize, "cert": self.certificate}.get(kind)
                if fn:
                    return fn(rid, payload, account)
        raise Problem("malformed", "no such resource", 404)

    def new_account(self, p, jwk, account):
        if account:
            raise Problem("malformed", "newAccount takes a jwk, not a kid")
        tp = thumbprint(jwk)
        existing = next((i for i, a in self.state["accounts"].items() if a["thumbprint"] == tp), None)
        if existing:
            return 200, self.account_view(existing), {"Location": self.url("acct", existing)}
        if p.get("onlyReturnExisting"):
            raise Problem("accountDoesNotExist", "no account for this key")
        eab_kid = None
        if self.require_eab or p.get("externalAccountBinding"):
            eab_kid = self.check_eab(p.get("externalAccountBinding"), jwk)
        aid = secrets.token_hex(8)
        self.state["accounts"][aid] = {"jwk": jwk, "thumbprint": tp, "status": "valid", "contact": p.get("contact", []),
                                       "created": _iso(now()), "eab": eab_kid}
        self.save()
        log.info("account %s created%s", aid, f" (EAB {eab_kid})" if eab_kid else "")
        return 201, self.account_view(aid), {"Location": self.url("acct", aid)}

    def check_eab(self, eab, jwk):
        if not eab:
            raise Problem("externalAccountRequired", "this server needs external account binding (ask the CA operator for a key)")
        try:
            protected = json.loads(unb64u(eab["protected"]))
            kid = protected["kid"]
            inner = json.loads(unb64u(eab["payload"]))
        except (KeyError, ValueError, TypeError):
            raise Problem("malformed", "bad externalAccountBinding") from None
        with locked(self.ca.root):
            keys = eab_keys(self.ca.root)
            k = keys.get(kid)
            if not k or k.get("used") or protected.get("alg") != "HS256" or protected.get("url") != self.url("new-account") or inner != jwk:
                raise Problem("unauthorized", "the external account binding is not valid", 401)
            mac = hmac.new(unb64u(k["hmac"]), f"{eab['protected']}.{eab['payload']}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(mac, unb64u(eab.get("signature", ""))):
                raise Problem("unauthorized", "the external account binding is not valid", 401)
            k["used"] = _iso(now())
            write(Path(self.ca.root) / "acme" / "eab.json", json.dumps(keys, indent=1).encode(), secret=True)
        return kid

    def account_view(self, aid):
        a = self.state["accounts"][aid]
        return {"status": a["status"], "contact": a["contact"], "orders": self.url("acct", aid, "orders")}

    def account(self, aid, p, account):
        if aid != account:
            raise Problem("unauthorized", "not your account", 403)
        if p and p.get("status") == "deactivated":
            self.state["accounts"][aid]["status"] = "deactivated"
            self.save()
        return 200, self.account_view(aid), {}

    def allowed(self, value):
        return not self.allow or any(fnmatch.fnmatch(value, pat) for pat in self.allow)

    def new_order(self, p, account):
        ids = p.get("identifiers")
        if not (isinstance(ids, list) and 1 <= len(ids) <= 100 and all(isinstance(i, dict) for i in ids)):
            raise Problem("malformed", "an order needs a list of 1 to 100 identifiers")
        clean = []
        for i in ids:
            t, v = i.get("type"), str(i.get("value", "")).lower().rstrip(".")
            if t == "ip":
                try:
                    v = str(ipaddress.ip_address(v))
                except ValueError:
                    raise Problem("rejectedIdentifier", f"{v} is not an IP address") from None
            elif t != "dns" or not v or "*" in v or len(v) > 253:
                raise Problem("rejectedIdentifier", f"{v or t}: only DNS names (no wildcards: http-01 cannot prove them) and IP addresses")
            if not self.allowed(v):
                raise Problem("rejectedIdentifier", f"this CA does not issue for {v}")
            clean.append({"type": t, "value": v})
        oid, expires = secrets.token_hex(8), now() + dt.timedelta(days=7)
        authz = []
        for ident in clean:
            reuse = next((i for i, a in self.state["authz"].items() if a["account"] == account and a["identifier"] == ident
                          and a["status"] == "valid" and a["expires"] > _iso(now())), None)
            if not reuse:
                reuse = secrets.token_hex(8)
                self.state["authz"][reuse] = {"account": account, "identifier": ident, "status": "pending", "expires": _iso(now() + dt.timedelta(days=30)),
                                              "token": b64u(secrets.token_bytes(32)), "challenge_status": "pending", "error": None, "validated": None}
            authz.append(reuse)
        self.state["orders"][oid] = {"account": account, "status": "pending", "identifiers": clean, "authorizations": authz,
                                     "expires": _iso(expires), "cert": None, "error": None}
        self.refresh(oid)
        self.save()
        return 201, self.order_view(oid), {"Location": self.url("order", oid)}

    def refresh(self, oid):
        o = self.state["orders"][oid]
        if o["status"] in ("pending", "ready"):
            states = [self.state["authz"][a]["status"] for a in o["authorizations"]]
            if o["expires"] < _iso(now()):
                o["status"] = "invalid"
            elif "invalid" in states:
                o["status"], o["error"] = "invalid", {"type": ERR + "unauthorized", "detail": "an authorization failed"}
            elif all(s == "valid" for s in states):
                o["status"] = "ready"

    def order_view(self, oid):
        o = self.state["orders"][oid]
        out = {"status": o["status"], "expires": o["expires"], "identifiers": o["identifiers"],
               "authorizations": [self.url("authz", a) for a in o["authorizations"]], "finalize": self.url("finalize", oid)}
        if o["cert"]:
            out["certificate"] = self.url("cert", o["cert"])
        if o["error"]:
            out["error"] = o["error"]
        return out

    def _own(self, table, rid, account):
        item = self.state[table].get(rid)
        if not item or item["account"] != account:
            raise Problem("malformed", "no such resource", 404)
        return item

    def order(self, oid, p, account):
        self._own("orders", oid, account)
        self.refresh(oid)
        return 200, self.order_view(oid), {}

    def challenge_view(self, aid):
        a = self.state["authz"][aid]
        c = {"type": "http-01", "url": self.url("chall", aid), "token": a["token"], "status": a["challenge_status"]}
        if a["validated"]:
            c["validated"] = a["validated"]
        if a["error"]:
            c["error"] = a["error"]
        return c

    def authz(self, aid, p, account):
        a = self._own("authz", aid, account)
        if p and p.get("status") == "deactivated":
            a["status"] = "deactivated"
            self.save()
        return 200, {"status": a["status"], "expires": a["expires"], "identifier": a["identifier"], "challenges": [self.challenge_view(aid)]}, {
            "Link": f'<{self.url("authz", aid)}>;rel="up"'}

    def challenge(self, aid, p, account):
        a = self._own("authz", aid, account)
        if p is not None and a["challenge_status"] == "pending" and a["status"] == "pending":
            a["challenge_status"] = "processing"
            self.save()
            key_authz = f"{a['token']}.{self.state['accounts'][account]['thumbprint']}"
            if self.validate_async:
                threading.Thread(target=self.validate, args=(aid, key_authz), daemon=True).start()
            else:
                self.validate(aid, key_authz)
        return 200, self.challenge_view(aid), {"Link": f'<{self.url("authz", aid)}>;rel="up"'}

    def validate(self, aid, key_authz):
        a = self.state["authz"][aid]
        name = a["identifier"]["value"]
        host = f"[{name}]" if ":" in name else name
        url = f"http://{host}:{self.http_port}/.well-known/acme-challenge/{a['token']}"
        try:
            ip = validation_address(name, self.http_port, self.allow_local)
            pinned = f"http://{f'[{ip}]' if ':' in ip else ip}:{self.http_port}/.well-known/acme-challenge/{a['token']}"
            with FETCH.open(urllib.request.Request(pinned, headers={"Host": f"{host}:{self.http_port}"}), timeout=10) as r:
                got = r.read(4096).decode(errors="replace").strip()
            ok, detail = got == key_authz, f"{url} answered something else"
        except (OSError, ValueError, http.client.HTTPException) as e:
            ok, detail = False, f"could not fetch {url}: {e or type(e).__name__}"
        with self.lock:
            a["challenge_status"] = a["status"] = "valid" if ok else "invalid"
            if ok:
                a["validated"] = _iso(now())
            else:
                a["error"] = {"type": ERR + ("incorrectResponse" if "answered" in detail else "connection"), "detail": detail}
            self.save()
        log.info("http-01 for %s: %s", a["identifier"]["value"], "valid" if ok else detail)

    def finalize(self, oid, p, account):
        o = self._own("orders", oid, account)
        self.refresh(oid)
        if o["status"] != "ready":
            raise Problem("orderNotReady", f"the order is {o['status']}", 403)
        try:
            csr = x509.load_der_x509_csr(unb64u(p["csr"]))
        except (KeyError, TypeError, ValueError):
            raise Problem("badCSR", "the csr is not a DER PKCS#10 request") from None
        if not csr.is_signature_valid:
            raise Problem("badCSR", "the CSR's signature does not verify")
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = {("dns", n.lower()) for n in san.get_values_for_type(x509.DNSName)} | {("ip", str(i)) for i in san.get_values_for_type(x509.IPAddress)}
        except x509.ExtensionNotFound:
            names = set()
        cn = [c.value.lower() for c in csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
        wanted = {(i["type"], i["value"]) for i in o["identifiers"]}
        if names | {("dns", c) for c in cn if ("ip", c) not in wanted} != wanted:
            raise Problem("badCSR", "the CSR must name exactly the identifiers of the order")
        o["status"] = "processing"
        try:
            values = [i["value"] for i in o["identifiers"]]
            cert, rec = self.ca.sign(csr.public_key(), cn[0] if cn else values[0], "server", values, self.days)
        except CAError as e:
            o["status"] = "ready"
            raise Problem("badCSR", f"{e}; ask for an ML-DSA key (for example certbot --csr with a CSR from `pqc csr`)") from None
        cid = secrets.token_hex(8)
        self.state["certs"][cid] = {"account": account, "serial": rec.serial, "pem": (cert_pem(cert) + self.ca.chain()).decode()}
        o["status"], o["cert"] = "valid", cid
        self.save()
        log.info("issued %s for %s (order %s)", rec.serial, ", ".join(values), oid)
        return 200, self.order_view(oid), {"Location": self.url("order", oid)}

    def certificate(self, cid, p, account):
        c = self._own("certs", cid, account)
        return 200, c["pem"].encode(), {"Content-Type": "application/pem-certificate-chain"}

    def revoke(self, p, account):
        try:
            cert = x509.load_der_x509_certificate(unb64u(p["certificate"]))
        except (KeyError, TypeError, ValueError):
            raise Problem("malformed", "certificate must be base64url DER") from None
        serial = format(cert.serial_number, "x")
        if not any(c["serial"] == serial and c["account"] == account for c in self.state["certs"].values()):
            raise Problem("unauthorized", "this account did not order that certificate", 403)
        reason = p.get("reason", 0)
        if not isinstance(reason, int) or isinstance(reason, bool) or reason not in REASONS:
            raise Problem("badRevocationReason", f"reason must be one of {sorted(REASONS)}")
        try:
            self.ca.revoke(serial, REASONS[reason])
        except CAError as e:
            raise Problem("alreadyRevoked" if "already" in str(e) else "malformed", str(e)) from None
        log.info("revoked %s (%s) on request of account %s", serial, REASONS[reason], account)
        return 200, None, {}


def eab_keys(root):
    f = Path(root) / "acme" / "eab.json"
    return json.loads(f.read_text()) if f.exists() else {}


def create_eab(root, note=""):
    """A new external account binding key: give the key id and the HMAC key to one ACME client."""
    kid, key = "kid-" + secrets.token_hex(6), b64u(secrets.token_bytes(32))
    with locked(root):
        keys = eab_keys(root)
        keys[kid] = {"hmac": key, "note": note, "created": _iso(now()), "used": None}
        write(Path(root) / "acme" / "eab.json", json.dumps(keys, indent=1).encode(), secret=True)
    return kid, key


def serve(service, listen, tls_cert=None, tls_key=None):
    """An HTTP(S) server for the ACME service; TLS uses Python's ssl module, so give it a certificate ACME clients accept."""
    class Handler(BaseHTTPRequestHandler):
        timeout = HTTP_IDLE
        server_version = f"{NAME}-acme/{__version__}"

        def respond(self, status, body, headers):
            if isinstance(body, (dict, list)):
                data, ctype = json.dumps(body).encode(), "application/json"
            else:
                data, ctype = body or b"", headers.pop("Content-Type", "application/json")
            self.send_response(status)
            if data or status != 204:
                self.send_header("Content-Type", headers.pop("Content-Type", ctype))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Replay-Nonce", service.nonce())
            self.send_header("Cache-Control", "no-store")
            self.send_header("Link", f'<{service.url("directory")}>;rel="index"')
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def route(self):
            n = content_length(self.headers)
            if n is None or n > 1 << 16:
                return self.respond(400 if n is None else 413, {"type": ERR + "malformed", "detail": "bad Content-Length" if n is None else
                                                                "request too large"}, {"Content-Type": "application/problem+json"})
            body = self.rfile.read(n) if n else b""
            try:
                self.respond(*service.handle(self.command, self.path.split("?")[0], body))
            except Problem as p:
                self.respond(p.status, {"type": ERR + p.kind, "detail": p.detail, "status": p.status}, {"Content-Type": "application/problem+json"})
            except Exception:
                log.exception("%s %s failed", self.command, self.path.replace("\r", "").replace("\n", ""))
                self.respond(500, {"type": ERR + "serverInternal", "detail": "internal error; see the server's log", "status": 500},
                             {"Content-Type": "application/problem+json"})

        do_GET = do_POST = do_HEAD = route

        def log_message(self, fmt, *args):
            log.debug(fmt, *args)

    from ..tls import hostport
    httpd = ThreadingHTTPServer(hostport(listen, "127.0.0.1"), Handler)
    httpd.service = service
    if tls_cert:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(tls_cert, tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def make_csr(names, out, algorithm="ML-DSA-65", passphrase=None):
    """An ML-DSA key and CSR for ACME clients that take a CSR file (certbot --csr)."""
    from . import general_names, generate, key_pem
    key = generate(algorithm)
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, names[0])]))
           .add_extension(x509.SubjectAlternativeName(general_names(names)), critical=False).sign(key, None))
    out = Path(out)
    if (out / "key.pem").exists():
        raise CAError(f"{out} already holds a key; choose another --out, so that key and whatever certificate uses it are kept")
    write(out / "key.pem", key_pem(key, passphrase), secret=True)
    write(out / "csr.pem", csr.public_bytes(serialization.Encoding.PEM))
    write(out / "csr.der", csr.public_bytes(serialization.Encoding.DER))
    return out
