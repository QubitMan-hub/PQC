"""ctypes bridge to OpenSSL 3.5+ libssl.

Python's ssl module cannot choose TLS 1.3 key-exchange groups or report which one was negotiated, so the handshake goes
through libssl directly. Sockets run non-blocking under OpenSSL and every operation has a deadline.
"""
import ctypes
import hashlib
import ipaddress
import os
import platform
import re
import select
import tempfile
import time
from pathlib import Path

MIN_VERSION = 0x30500000
TLS1_3_VERSION = 0x0304
CTRL_MODE, MODE_NO_AUTO_CHAIN = 33, 0x8
OP_CIPHER_SERVER_PREFERENCE = 1 << 22
CTRL_SET_GROUPS_LIST, CTRL_SET_SIGALGS_LIST, CTRL_SET_TLSEXT_HOSTNAME = 92, 98, 55
CTRL_SET_MIN_PROTO_VERSION, CTRL_SET_MAX_PROTO_VERSION = 123, 124
VERIFY_NONE, VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT = 0, 1, 2
X509_PURPOSE_ANY = 7
WANT_READ, WANT_WRITE, ERROR_SYSCALL, ZERO_RETURN = 2, 3, 5, 6

# Public-CA fallback first for clients offering both kinds; strict clients still select ML-DSA.
FALLBACK_SIGALGS = (
    'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ed25519:ed448:'
    'ecdsa_brainpoolP256r1tls13_sha256:ecdsa_brainpoolP384r1tls13_sha384:ecdsa_brainpoolP512r1tls13_sha512:'
    'rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:'
    'rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:mldsa87:mldsa65:mldsa44'
)

P, I, L, S, B = ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_char_p, ctypes.c_char_p
PROTOTYPES = {
    "crypto": [
        ("ERR_get_error", [], ctypes.c_ulong), ("ERR_error_string_n", [ctypes.c_ulong, P, ctypes.c_size_t], None), ("ERR_clear_error", [], None),
        ("BIO_new_mem_buf", [B, I], P), ("BIO_free", [P], I),
        ("PEM_read_bio_PrivateKey", [P, P, P, B], P), ("EVP_PKEY_free", [P], None),
        ("i2d_X509", [P, ctypes.POINTER(P)], I), ("X509_free", [P], None),
        ("X509_verify_cert_error_string", [L], S), ("X509_VERIFY_PARAM_set1_ip_asc", [P, S], I),
        ("OPENSSL_sk_num", [P], I), ("OPENSSL_sk_value", [P, I], P),
        ("BIO_new", [P], P), ("BIO_s_mem", [], P), ("BIO_ctrl", [P, I, L, P], L), ("EVP_aes_256_cbc", [], P),
        ("PEM_write_bio_PKCS8PrivateKey", [P, P, P, B, I, P, P], I), ("EVP_PKEY_get0_type_name", [P], S),
        ("EVP_PKEY_CTX_new_from_name", [P, S, S], P), ("EVP_PKEY_CTX_free", [P], None), ("EVP_PKEY_keygen_init", [P], I),
        ("EVP_PKEY_generate", [P, ctypes.POINTER(P)], I), ("i2d_PUBKEY", [P, ctypes.POINTER(P)], I), ("d2i_PUBKEY", [P, ctypes.POINTER(P), L], P),
        ("EVP_MD_CTX_new", [], P), ("EVP_MD_CTX_free", [P], None), ("EVP_DigestSignInit_ex", [P, P, S, P, S, P, P], I),
        ("EVP_DigestSign", [P, P, ctypes.POINTER(ctypes.c_size_t), B, ctypes.c_size_t], I),
        ("EVP_DigestVerifyInit_ex", [P, P, S, P, S, P, P], I), ("EVP_DigestVerify", [P, B, ctypes.c_size_t, B, ctypes.c_size_t], I),
    ],
    "ssl": [
        ("TLS_server_method", [], P), ("TLS_client_method", [], P),
        ("SSL_CTX_new", [P], P), ("SSL_CTX_free", [P], None), ("SSL_CTX_ctrl", [P, I, L, P], L),
        ("SSL_CTX_set_options", [P, ctypes.c_uint64], ctypes.c_uint64),
        ("SSL_CTX_set_ciphersuites", [P, S], I), ("SSL_CTX_use_certificate_chain_file", [P, S], I),
        ("SSL_CTX_use_PrivateKey", [P, P], I), ("SSL_CTX_check_private_key", [P], I),
        ("SSL_CTX_load_verify_locations", [P, S, S], I), ("SSL_CTX_set_verify", [P, I, P], None), ("SSL_CTX_set_purpose", [P, I], I),
        ("SSL_CTX_set_session_id_context", [P, B, ctypes.c_uint], I), ("SSL_get1_session", [P], P), ("SSL_set_session", [P, P], I),
        ("SSL_SESSION_free", [P], None), ("SSL_session_reused", [P], I),
        ("SSL_new", [P], P), ("SSL_free", [P], None), ("SSL_set_fd", [P, I], I), ("SSL_ctrl", [P, I, L, P], L),
        ("SSL_set_accept_state", [P], None), ("SSL_set_connect_state", [P], None), ("SSL_do_handshake", [P], I),
        ("SSL_read", [P, P, I], I), ("SSL_write", [P, B, I], I), ("SSL_pending", [P], I), ("SSL_shutdown", [P], I),
        ("SSL_get_error", [P, I], I), ("SSL_get_version", [P], S), ("SSL_get_current_cipher", [P], P),
        ("SSL_CIPHER_get_name", [P], S), ("SSL_get0_group_name", [P], S), ("SSL_get_verify_result", [P], L),
        ("SSL_get1_peer_certificate", [P], P), ("SSL_get0_verified_chain", [P], P), ("SSL_set1_host", [P, S], I), ("SSL_get0_param", [P], P),
        ("SSL_export_keying_material", [P, P, ctypes.c_size_t, S, ctypes.c_size_t, B, ctypes.c_size_t, I], I),
    ],
}


# Calls on the data path that never block (the sockets are non-blocking) and take microseconds. They keep the GIL:
# releasing and re-taking it around each one costs more than the call once many connections share the process.
# Handshakes and key operations still release it, so they run on several cores at once.
KEEP_GIL = {"ERR_clear_error", "ERR_get_error", "SSL_read", "SSL_write", "SSL_pending", "SSL_get_error", "SSL_shutdown"}


def _self_signed(pem):
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    try:
        c = x509.load_pem_x509_certificate(pem)
        if c.subject != c.issuer:
            return False
        c.verify_directly_issued_by(c)
        return True
    except UnsupportedAlgorithm:
        from ..pki import signed_by
        return signed_by(c, c.tbs_certificate_bytes, c.signature)
    except InvalidSignature:
        return False
    except ValueError:
        return False


class TLSError(Exception):
    pass


class OpenSSLUnavailable(TLSError):
    pass


EASIEST = ("Easiest: use the container image, which has it (docker run --rm ghcr.io/qubitman-hub/pqc, then your command), "
           "or Debian 13 or Ubuntu 25.04+, whose OpenSSL is new enough.")


def _names(stem):
    """Prefer the supported OpenSSL 3 ABI. PQC_OPENSSL selects an installation before standard folders and PATH."""
    system = platform.system()
    folders = [os.environ["PQC_OPENSSL"]] if os.environ.get("PQC_OPENSSL") else []
    if system == "Windows":
        program_files = os.environ.get('ProgramFiles')
        if program_files and ctypes.sizeof(ctypes.c_void_p) == 8:
            folders.append(os.path.join(program_files, 'OpenSSL-Win64', 'bin'))
        rx = re.compile(rf"^lib{stem}-(\d+)(?:-x64)?\.dll$", re.I)
        found = []
        for folder in folders + os.environ.get("PATH", "").split(os.pathsep):
            if os.path.isdir(folder):
                matches = [(int(m.group(1)), os.path.join(folder, f)) for f in os.listdir(folder) if (m := rx.match(f))]
                found.extend(f for _, f in sorted(matches, key=lambda item: (item[0] != 3, -item[0])))
        return found
    name = f"lib{stem}.3.dylib" if system == "Darwin" else f"lib{stem}.so.3"
    return [os.path.join(f, name) for f in folders] + [name]


def _load(stem, names=None):
    names = _names(stem) if names is None else names
    for n in names:
        try:
            return ctypes.CDLL(n, mode=getattr(ctypes, "RTLD_GLOBAL", 0))
        except OSError:
            continue
    raise OpenSSLUnavailable(f"OpenSSL 3.5+ was not found (tried {', '.join(names) or 'nothing on PATH'}). {EASIEST} "
                             "Or install OpenSSL 3.5+ and set PQC_OPENSSL to the folder that holds it.")


def _windows_libraries():
    """Use SSL and crypto DLLs of the same major version from the same directory."""
    for ssl_name in _names('ssl'):
        crypto_name = str(Path(ssl_name).with_name(re.sub('^libssl', 'libcrypto', Path(ssl_name).name, flags=re.I)))
        if not Path(crypto_name).is_file():
            continue
        try:
            crypto = _load('crypto', [crypto_name])
            crypto.OpenSSL_version_num.restype = ctypes.c_ulong
            if crypto.OpenSSL_version_num() < MIN_VERSION:
                continue
            return crypto, _load('ssl', [ssl_name])
        except OpenSSLUnavailable:
            continue
    raise OpenSSLUnavailable('No matching OpenSSL 3.5+ SSL and crypto DLLs were found. '
                             'Install 64-bit OpenSSL 3.5+ and set PQC_OPENSSL to its bin folder, then run pqc doctor.')


class _Lib:
    def __init__(self):
        crypto, ssl = _windows_libraries() if platform.system() == 'Windows' else (_load('crypto'), None)
        crypto.OpenSSL_version.argtypes, crypto.OpenSSL_version.restype = [I], S
        crypto.OpenSSL_version_num.restype = ctypes.c_ulong
        self.version = crypto.OpenSSL_version(0).decode()
        if crypto.OpenSSL_version_num() < MIN_VERSION:
            hint = (" Or, with OpenSSL 3.5+ installed elsewhere, start pqc with LD_LIBRARY_PATH set to its lib folder "
                    "(PQC_OPENSSL cannot help here: this process has already loaded the system OpenSSL).") if platform.system() == "Linux" else \
                   " Or install OpenSSL 3.5+ and set PQC_OPENSSL to the folder that holds it."
            raise OpenSSLUnavailable(f"this machine's {self.version} is too old: post-quantum TLS needs OpenSSL 3.5 or newer. {EASIEST}{hint}")
        if ssl is None:
            ssl = _load("ssl")
        for lib_, table in ((crypto, PROTOTYPES["crypto"]), (ssl, PROTOTYPES["ssl"])):
            held = ctypes.PyDLL(lib_._name, handle=lib_._handle)
            for name, args, res in table:
                fn = getattr(held if name in KEEP_GIL else lib_, name)
                fn.argtypes, fn.restype = args, res
                setattr(self, name, fn)


_lib = None


def lib():
    global _lib
    if _lib is None:
        _lib = _Lib()
    return _lib


PLAIN = {"no start line": "not the expected kind of PEM file (certificate and key swapped?)", "no such file": "file not found",
         "No such file or directory": "file not found", "bad decrypt": "wrong passphrase",
         "key values mismatch": "this key does not belong to this certificate"}


def errors(default="unknown OpenSSL error"):
    """Drain OpenSSL's error queue into one readable message, in plain words where the reason is a common one."""
    L_, out, buf = lib(), [], ctypes.create_string_buffer(256)
    while code := L_.ERR_get_error():
        L_.ERR_error_string_n(code, buf, len(buf))
        reason = buf.value.decode(errors="replace").split(":", 4)[-1]
        if not reason.endswith(" lib"):
            out.append(PLAIN.get(reason, reason))
    return "; ".join(dict.fromkeys(out)) or default


def _certificate(x):
    from cryptography import x509
    L_ = lib()
    n = L_.i2d_X509(x, None)
    if n <= 0:
        raise TLSError(f"cannot encode the peer certificate: {errors()}")
    buf = ctypes.create_string_buffer(n)
    if L_.i2d_X509(x, ctypes.byref(ctypes.c_void_p(ctypes.addressof(buf)))) != n:
        raise TLSError("the peer certificate changed length between two encodings")
    return x509.load_der_x509_certificate(buf.raw)


def is_ip(name):
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


class Context:
    """A TLS 1.3-only SSL_CTX. `groups` and `sigalgs` are OpenSSL list strings, e.g. "X25519MLKEM768" and "mldsa65".
    `fallback` is (cert, key[, passphrase]) of a classical certificate. With default signature algorithms it is preferred
    for dual-capability clients; clients offering only ML-DSA still get the primary certificate."""

    def __init__(self, server, groups, sigalgs=None, ciphersuites=None, cert=None, key=None, key_passphrase=None,
                 ca=None, verify=True, require_client_cert=False, request_client_cert=False, any_purpose=False, fallback=None):
        if fallback and not sigalgs:
            sigalgs = FALLBACK_SIGALGS
        L_ = lib()
        L_.ERR_clear_error()
        self.server = server
        self.ptr = L_.SSL_CTX_new(L_.TLS_server_method() if server else L_.TLS_client_method())
        if not self.ptr:
            raise TLSError(errors())
        try:
            self._check(L_.SSL_CTX_ctrl(self.ptr, CTRL_SET_MIN_PROTO_VERSION, TLS1_3_VERSION, None), "set TLS 1.3")
            self._check(L_.SSL_CTX_ctrl(self.ptr, CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, None), "set TLS 1.3")
            self._check(L_.SSL_CTX_ctrl(self.ptr, CTRL_SET_GROUPS_LIST, 0, groups.encode()), f"use groups {groups}")
            if sigalgs:
                self._check(L_.SSL_CTX_ctrl(self.ptr, CTRL_SET_SIGALGS_LIST, 0, sigalgs.encode()), f"use signature algorithms {sigalgs}")
            if ciphersuites:
                self._check(L_.SSL_CTX_set_ciphersuites(self.ptr, ciphersuites.encode()), f"use cipher suites {ciphersuites}")
            if cert:
                self._use_chain(cert)
                # send the chain as given: with a CA file loaded, OpenSSL would otherwise rebuild it and add the root back
                L_.SSL_CTX_ctrl(self.ptr, CTRL_MODE, MODE_NO_AUTO_CHAIN, None)
            if key:
                self._use_key(key, key_passphrase)
            if fallback:
                self._use_chain(fallback[0])
                self._use_key(fallback[1], fallback[2] if len(fallback) > 2 else None)
                L_.SSL_CTX_set_options(self.ptr, OP_CIPHER_SERVER_PREFERENCE)
            if ca:
                self._check(L_.SSL_CTX_load_verify_locations(self.ptr, os.fsencode(ca), None), f"load CA {ca}")
            mode = VERIFY_NONE
            if verify and (not server or require_client_cert or request_client_cert):
                mode = VERIFY_PEER | (VERIFY_FAIL_IF_NO_PEER_CERT if server and require_client_cert else 0)
            L_.SSL_CTX_set_verify(self.ptr, mode, None)
            if server:
                # Without it OpenSSL fails every resumed session ("session id context uninitialized") once client
                # certificates are checked, and clients resume automatically. Derived from what the server trusts, so a
                # session from an edge that trusted other clients, or another policy, is never resumed here.
                sid = hashlib.sha256(b"|".join([groups.encode(), str(sigalgs).encode(), str(mode).encode(),
                                                Path(ca).read_bytes() if ca else b""])).digest()[:32]
                self._check(L_.SSL_CTX_set_session_id_context(self.ptr, sid, len(sid)), "set the session id context")
            if any_purpose:
                self._check(L_.SSL_CTX_set_purpose(self.ptr, X509_PURPOSE_ANY), "accept certificates of any purpose")
        except Exception:
            self.close()
            raise

    def _check(self, result, what):
        if result != 1:
            raise TLSError(f"cannot {what}: {errors('not supported by this OpenSSL')}")

    def _use_chain(self, path):
        """Load a certificate chain, leaving out a self-signed root after the first certificate: the peer has the root
        already, and an ML-DSA root is 7 KB that pushes the handshake past TCP's initial window, an extra round trip on
        every new connection. The file itself is not changed."""
        load = lambda p: self._check(lib().SSL_CTX_use_certificate_chain_file(self.ptr, os.fsencode(p)), f"load certificate {path}")
        try:
            blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\s*", Path(path).read_bytes(), re.S)
        except OSError:
            return load(path)  # OpenSSL's error names the problem
        keep = blocks[:1] + [b for b in blocks[1:] if not _self_signed(b)]
        if len(keep) == len(blocks):
            return load(path)
        fd, tmp = tempfile.mkstemp(suffix=".pem")
        try:
            os.write(fd, b"".join(keep))
            os.close(fd)
            load(tmp)
        finally:
            os.unlink(tmp)

    def _use_key(self, path, passphrase):
        L_ = lib()
        with open(path, "rb") as f:
            data = f.read()
        bio = L_.BIO_new_mem_buf(data, len(data))
        if not bio:
            raise TLSError(f"cannot allocate a private-key BIO: {errors()}")
        try:
            pkey = L_.PEM_read_bio_PrivateKey(bio, None, None, passphrase or b"")
        finally:
            L_.BIO_free(bio)
        if not pkey:
            raise TLSError(f"cannot read private key {path}: {errors()}" + ("" if passphrase else " (if it is encrypted, give its passphrase)"))
        try:
            self._check(L_.SSL_CTX_use_PrivateKey(self.ptr, pkey), f"use private key {path}")
            self._check(L_.SSL_CTX_check_private_key(self.ptr), f"match private key {path} to its certificate")
        finally:
            L_.EVP_PKEY_free(pkey)

    def wrap(self, sock, server_name=None, timeout=10.0):
        """Run the handshake on a connected socket and return a Connection. The socket is owned by the Connection from here on."""
        try:
            conn = Connection(self, sock, timeout)
        except Exception:
            sock.close()
            raise
        try:
            conn.handshake(server_name)
        except Exception:
            conn.close()
            raise
        return conn

    def close(self):
        if getattr(self, "ptr", None) and _lib:
            _lib.SSL_CTX_free(self.ptr)
        self.ptr = None

    __del__ = close


class Connection:
    def __init__(self, ctx, sock, timeout):
        L_ = lib()
        if not ctx.ptr:
            raise TLSError('TLS context is closed')
        self.ctx, self.sock, self.timeout = ctx, sock, timeout
        sock.setblocking(False)
        self.closed = False
        self._ssl = L_.SSL_new(ctx.ptr)
        if not self._ssl or L_.SSL_set_fd(self._ssl, sock.fileno()) != 1:
            msg = errors()
            if self._ssl:
                L_.SSL_free(self._ssl)
            self._ssl = None
            raise TLSError(msg)
        (L_.SSL_set_accept_state if ctx.server else L_.SSL_set_connect_state)(self.ssl)

    @property
    def ssl(self):
        if self.closed or not self._ssl:
            raise TLSError('TLS connection is closed')
        return self._ssl

    def handshake(self, server_name=None):
        L_ = lib()
        if server_name and not self.ctx.server:
            L_.SSL_ctrl(self.ssl, CTRL_SET_TLSEXT_HOSTNAME, 0, server_name.encode())
            if is_ip(server_name):
                ok = L_.X509_VERIFY_PARAM_set1_ip_asc(L_.SSL_get0_param(self.ssl), server_name.encode())
            else:
                ok = L_.SSL_set1_host(self.ssl, server_name.encode())
            if ok != 1:
                raise TLSError(f"cannot check the certificate against {server_name}: {errors()}")
        try:
            self._io(lambda: L_.SSL_do_handshake(self.ssl), "handshake")
        except TLSError as e:
            result = L_.SSL_get_verify_result(self.ssl)
            if result:
                hint = " (the certificate names another host: connect by that name, or give it as the server name)" if result in (62, 64) else ""
                raise TLSError(f"certificate rejected: {L_.X509_verify_cert_error_string(result).decode()}{hint}") from None
            hint = " (is this port speaking TLS?)" if any(x in str(e) for x in ("packet length too long", "wrong version number")) else ""
            raise TLSError(f"handshake failed: {e}{hint}") from None

    def _io(self, op, what, deadline=None, wait=True):
        L_ = lib()
        deadline = deadline or time.monotonic() + self.timeout
        while True:
            L_.ERR_clear_error()
            r = op()
            if r > 0:
                return r
            err = L_.SSL_get_error(self.ssl, r)
            if err == ZERO_RETURN:
                return 0
            if err == WANT_READ and not wait:
                return None
            if err in (WANT_READ, WANT_WRITE):
                left = deadline - time.monotonic()
                if left <= 0 or not self._wait(err == WANT_READ, left):
                    raise TLSError(f"{what} timed out after {self.timeout:g}s")
                continue
            if err == ERROR_SYSCALL and what == "read":
                return 0
            raise TLSError(errors(f"{what} failed (peer closed the connection)"))

    def _wait(self, readable, seconds):
        if hasattr(select, "poll"):  # one syscall, where a selector would create and close an epoll object every time
            p = select.poll()
            p.register(self.sock, select.POLLIN if readable else select.POLLOUT)
            return bool(p.poll(seconds * 1000))
        r, w, _ = select.select([self.sock] if readable else [], [] if readable else [self.sock], [], seconds)
        return bool(r or w)

    def recv(self, size=65536, timeout=None, wait=True):
        """Up to `size` bytes; b"" once the peer has closed. With wait=False, None when no application data is ready yet
        (a record such as a session ticket can make the socket readable without carrying any)."""
        buf = ctypes.create_string_buffer(size)
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        n = self._io(lambda: lib().SSL_read(self.ssl, buf, size), "read", deadline, wait)
        return None if n is None else ctypes.string_at(buf, n)

    def sendall(self, data):
        for i in range(0, len(data), 1 << 20):
            chunk = bytes(data[i:i + (1 << 20)])
            self._io(lambda: lib().SSL_write(self.ssl, chunk, len(chunk)), "write")

    def pending(self):
        return lib().SSL_pending(self.ssl) > 0

    def fileno(self):
        return self.sock.fileno()

    @property
    def version(self):
        return lib().SSL_get_version(self.ssl).decode()

    @property
    def cipher(self):
        c = lib().SSL_get_current_cipher(self.ssl)
        return lib().SSL_CIPHER_get_name(c).decode() if c else None

    @property
    def group(self):
        g = lib().SSL_get0_group_name(self.ssl)
        return g.decode() if g else None

    def peer_certificate(self):
        """The peer's certificate as a cryptography x509.Certificate, or None."""
        L_ = lib()
        x = L_.SSL_get1_peer_certificate(self.ssl)
        if not x:
            return None
        try:
            return _certificate(x)
        finally:
            L_.X509_free(x)

    def peer_chain(self):
        """The chain OpenSSL verified, leaf first, up to the trust anchor; empty when the peer was not verified."""
        L_ = lib()
        sk = L_.SSL_get0_verified_chain(self.ssl)
        return [_certificate(L_.OPENSSL_sk_value(sk, i)) for i in range(L_.OPENSSL_sk_num(sk))] if sk else []

    def export(self, label, context, length=32):
        """Keying material from this session (RFC 8446 section 7.5): both peers get the same bytes, nobody else can."""
        out = ctypes.create_string_buffer(length)
        label = label.encode()
        if lib().SSL_export_keying_material(self.ssl, out, length, label, len(label), context, len(context), 1) != 1:
            raise TLSError(f"cannot export keying material: {errors()}")
        return out.raw

    def info(self):
        from ..pki import algorithm_of
        cert = self.peer_certificate()
        return {"version": self.version, "cipher": self.cipher, "group": self.group,
                "peer": cert.subject.rfc4514_string() if cert else None,
                "peer_key": (algorithm_of(cert.public_key()) or cert.public_key_algorithm_oid.dotted_string) if cert else None,
                "peer_serial": f"{cert.serial_number:x}" if cert else None,
                "peer_expires": cert.not_valid_after_utc.date().isoformat() if cert else None}

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self._ssl:
                try:
                    self._shutdown()
                except OSError:
                    pass  # closing is best effort if the peer or socket has already gone
                finally:
                    lib().SSL_free(self._ssl)
        finally:
            self._ssl = None
            self.sock.close()

    def _shutdown(self):
        """Send close_notify, waiting up to 5 s for room when the peer has not read everything yet: without it, the peer cannot
        tell the end of the data from a cut connection ("unexpected eof")."""
        L_, deadline = lib(), time.monotonic() + min(self.timeout, 5)
        while True:
            L_.ERR_clear_error()
            r = L_.SSL_shutdown(self._ssl)
            if r >= 0 or L_.SSL_get_error(self._ssl, r) != WANT_WRITE:
                break
            left = deadline - time.monotonic()
            if left <= 0 or not self._wait(False, left):
                break
        L_.ERR_clear_error()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

