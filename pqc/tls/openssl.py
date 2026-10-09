"""ctypes bridge to OpenSSL 3.5+ libssl.

Python's ssl module cannot choose TLS 1.3 key-exchange groups or report which one was negotiated, so the handshake goes
through libssl directly. Sockets run non-blocking under OpenSSL and every operation has a deadline.
"""
import ctypes
import ipaddress
import os
import platform
import re
import select
import time

MIN_VERSION = 0x30500000
TLS1_3_VERSION = 0x0304
CTRL_SET_GROUPS_LIST, CTRL_SET_SIGALGS_LIST, CTRL_SET_TLSEXT_HOSTNAME = 92, 98, 55
CTRL_SET_MIN_PROTO_VERSION, CTRL_SET_MAX_PROTO_VERSION = 123, 124
VERIFY_NONE, VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT = 0, 1, 2
X509_PURPOSE_ANY = 7
WANT_READ, WANT_WRITE, ERROR_SYSCALL, ZERO_RETURN = 2, 3, 5, 6

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
        ("SSL_CTX_set_ciphersuites", [P, S], I), ("SSL_CTX_use_certificate_chain_file", [P, S], I),
        ("SSL_CTX_use_PrivateKey", [P, P], I), ("SSL_CTX_check_private_key", [P], I),
        ("SSL_CTX_load_verify_locations", [P, S, S], I), ("SSL_CTX_set_verify", [P, I, P], None), ("SSL_CTX_set_purpose", [P, I], I),
        ("SSL_new", [P], P), ("SSL_free", [P], None), ("SSL_set_fd", [P, I], I), ("SSL_ctrl", [P, I, L, P], L),
        ("SSL_set_accept_state", [P], None), ("SSL_set_connect_state", [P], None), ("SSL_do_handshake", [P], I),
        ("SSL_read", [P, P, I], I), ("SSL_write", [P, B, I], I), ("SSL_pending", [P], I), ("SSL_shutdown", [P], I),
        ("SSL_get_error", [P, I], I), ("SSL_get_version", [P], S), ("SSL_get_current_cipher", [P], P),
        ("SSL_CIPHER_get_name", [P], S), ("SSL_get0_group_name", [P], S), ("SSL_get_verify_result", [P], L),
        ("SSL_get1_peer_certificate", [P], P), ("SSL_get0_verified_chain", [P], P), ("SSL_set1_host", [P, S], I), ("SSL_get0_param", [P], P),
        ("SSL_export_keying_material", [P, P, ctypes.c_size_t, S, ctypes.c_size_t, B, ctypes.c_size_t, I], I),
    ],
}


class TLSError(Exception):
    pass


class OpenSSLUnavailable(TLSError):
    pass


EASIEST = ("Easiest: use the container image, which has it (docker run --rm ghcr.io/qubitman-hub/pqc, then your command), "
           "or Debian 13 or Ubuntu 25.04+, whose OpenSSL is new enough.")


def _names(stem):
    """Library file names to try, newest first. PQC_OPENSSL points at a directory holding a specific build."""
    system = platform.system()
    folders = [os.environ["PQC_OPENSSL"]] if os.environ.get("PQC_OPENSSL") else []
    if system == "Windows":
        rx = re.compile(rf"^lib{stem}-(\d+)(?:-x64)?\.dll$", re.I)
        found = []
        for folder in folders + os.environ.get("PATH", "").split(os.pathsep):
            if os.path.isdir(folder):
                found += [(int(m.group(1)), os.path.join(folder, f)) for f in os.listdir(folder) if (m := rx.match(f))]
        return [f for _, f in sorted(found, reverse=True)]
    name = f"lib{stem}.3.dylib" if system == "Darwin" else f"lib{stem}.so.3"
    return [os.path.join(f, name) for f in folders] + [name]


def _load(stem):
    names = _names(stem)
    for n in names:
        try:
            return ctypes.CDLL(n, mode=getattr(ctypes, "RTLD_GLOBAL", 0))
        except OSError:
            continue
    raise OpenSSLUnavailable(f"OpenSSL 3.5+ was not found (tried {', '.join(names) or 'nothing on PATH'}). {EASIEST} "
                             "Or install OpenSSL 3.5+ and set PQC_OPENSSL to the folder that holds it.")


class _Lib:
    def __init__(self):
        crypto = _load("crypto")
        crypto.OpenSSL_version.argtypes, crypto.OpenSSL_version.restype = [I], S
        crypto.OpenSSL_version_num.restype = ctypes.c_ulong
        self.version = crypto.OpenSSL_version(0).decode()
        if crypto.OpenSSL_version_num() < MIN_VERSION:
            hint = (" Or, with OpenSSL 3.5+ installed elsewhere, start pqc with LD_LIBRARY_PATH set to its lib folder "
                    "(PQC_OPENSSL cannot help here: this process has already loaded the system OpenSSL).") if platform.system() == "Linux" else \
                   " Or install OpenSSL 3.5+ and set PQC_OPENSSL to the folder that holds it."
            raise OpenSSLUnavailable(f"this machine's {self.version} is too old: post-quantum TLS needs OpenSSL 3.5 or newer. {EASIEST}{hint}")
        ssl = _load("ssl")
        for lib_, table in ((crypto, PROTOTYPES["crypto"]), (ssl, PROTOTYPES["ssl"])):
            for name, args, res in table:
                fn = getattr(lib_, name)
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
    `fallback` is (cert, key[, passphrase]) of a classical certificate that OpenSSL sends to clients that cannot verify ML-DSA."""

    def __init__(self, server, groups, sigalgs=None, ciphersuites=None, cert=None, key=None, key_passphrase=None,
                 ca=None, verify=True, require_client_cert=False, request_client_cert=False, any_purpose=False, fallback=None):
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
                self._check(L_.SSL_CTX_use_certificate_chain_file(self.ptr, os.fsencode(cert)), f"load certificate {cert}")
            if key:
                self._use_key(key, key_passphrase)
            if fallback:
                self._check(L_.SSL_CTX_use_certificate_chain_file(self.ptr, os.fsencode(fallback[0])), f"load certificate {fallback[0]}")
                self._use_key(fallback[1], fallback[2] if len(fallback) > 2 else None)
            if ca:
                self._check(L_.SSL_CTX_load_verify_locations(self.ptr, os.fsencode(ca), None), f"load CA {ca}")
            mode = VERIFY_NONE
            if verify and (not server or require_client_cert or request_client_cert):
                mode = VERIFY_PEER | (VERIFY_FAIL_IF_NO_PEER_CERT if server and require_client_cert else 0)
            L_.SSL_CTX_set_verify(self.ptr, mode, None)
            if any_purpose:
                self._check(L_.SSL_CTX_set_purpose(self.ptr, X509_PURPOSE_ANY), "accept certificates of any purpose")
        except Exception:
            self.close()
            raise

    def _check(self, result, what):
        if result != 1:
            raise TLSError(f"cannot {what}: {errors('not supported by this OpenSSL')}")

    def _use_key(self, path, passphrase):
        L_ = lib()
        with open(path, "rb") as f:
            data = f.read()
        bio = L_.BIO_new_mem_buf(data, len(data))
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
        self.ctx, self.sock, self.timeout = ctx, sock, timeout
        sock.setblocking(False)
        self.closed = False
        self.ssl = L_.SSL_new(ctx.ptr)
        if not self.ssl or L_.SSL_set_fd(self.ssl, sock.fileno()) != 1:
            msg = errors()
            if self.ssl:
                L_.SSL_free(self.ssl)
            self.ssl = None
            raise TLSError(msg)
        (L_.SSL_set_accept_state if ctx.server else L_.SSL_set_connect_state)(self.ssl)

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
        return None if n is None else buf.raw[:n]

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
        if lib().SSL_export_keying_material(self.ssl, out, length, label.encode(), len(label), context, len(context), 1) != 1:
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
            if self.ssl:
                self._shutdown()
                lib().SSL_free(self.ssl)
        finally:
            self.ssl = None
            self.sock.close()

    def _shutdown(self):
        """Send close_notify, waiting up to 5 s for room when the peer has not read everything yet: without it, the peer cannot
        tell the end of the data from a cut connection ("unexpected eof")."""
        L_, deadline = lib(), time.monotonic() + min(self.timeout, 5)
        while True:
            L_.ERR_clear_error()
            r = L_.SSL_shutdown(self.ssl)
            if r >= 0 or L_.SSL_get_error(self.ssl, r) != WANT_WRITE:
                break
            left = deadline - time.monotonic()
            if left <= 0 or not self._wait(False, left):
                break
        L_.ERR_clear_error()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
