import socket
import subprocess
import sys
from unittest import mock

import pytest
from cryptography.exceptions import InvalidSignature

from pqc import tls
from pqc.pki import generate, key_pem, signers
from pqc.tls.openssl import Connection, _names, _self_signed
from tests.helpers import REASON


@pytest.fixture
def connection():
    if REASON:
        pytest.skip(REASON)
    ctx = tls.client_context(verify=False)
    raw, peer = socket.socketpair()
    conn = Connection(ctx, raw, 1)
    try:
        yield conn
    finally:
        conn.close()
        peer.close()
        ctx.close()


@pytest.mark.skipif(REASON, reason=REASON or '')
@pytest.mark.parametrize('operation', [
    'conn.pending()', 'conn.version', 'conn.cipher', 'conn.group', 'conn.peer_certificate()',
    'conn.peer_chain()', 'conn.export("test", b"")', 'conn.recv()', 'conn.sendall(b"test")', 'conn.handshake()',
])
def test_closed_connection_operations_raise_instead_of_crashing(operation):
    code = '''
import socket
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
except ImportError:
    pass
from pqc import tls
from pqc.tls.openssl import Connection
ctx = tls.client_context(verify=False)
raw, peer = socket.socketpair()
conn = Connection(ctx, raw, 1)
conn.close()
peer.close()
try:
    OPERATION
except tls.TLSError:
    pass
else:
    raise AssertionError('closed connection was accepted')
'''.replace('OPERATION', operation)
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode(errors='replace')


def test_close_frees_ssl_even_when_shutdown_fails(connection):
    lib = tls.lib()
    with mock.patch.object(connection, '_shutdown', side_effect=OSError('socket closed')):
        with mock.patch.object(lib, 'SSL_free', wraps=lib.SSL_free) as free:
            connection.close()
            free.assert_called_once()
            connection.close()
            free.assert_called_once()
    assert connection.sock.fileno() == -1


def test_closed_context_rejects_new_connections(connection):
    connection.ctx.close()
    raw, peer = socket.socketpair()
    try:
        with pytest.raises(tls.TLSError, match='closed'):
            connection.ctx.wrap(raw)
        assert raw.fileno() == -1
    finally:
        raw.close()
        peer.close()


def test_windows_loader_prefers_the_configured_directory(tmp_path, monkeypatch):
    pinned, other = tmp_path / 'pinned', tmp_path / 'zpath'
    pinned.mkdir()
    other.mkdir()
    for folder in (pinned, other):
        (folder / 'libssl-3-x64.dll').touch()
    (other / 'libssl-4-x64.dll').touch()
    monkeypatch.setenv('PQC_OPENSSL', str(pinned))
    monkeypatch.setenv('PATH', str(other))
    with mock.patch('pqc.tls.openssl.platform.system', return_value='Windows'):
        assert _names('ssl')[0] == str(pinned / 'libssl-3-x64.dll')


def test_exporter_uses_the_encoded_label_length(connection):
    with mock.patch.object(tls.lib(), 'SSL_export_keying_material', return_value=1) as export:
        connection.export('é', b'context')
    assert export.call_args.args[3:5] == ('é'.encode(), len('é'.encode()))


def test_self_issued_rollover_certificate_is_not_removed_as_a_root(tmp_path):
    from pqc.pki import CA, cert_pem
    root = CA.init(tmp_path / 'root', 'Same Name')
    rollover = CA.init(tmp_path / 'rollover', 'Same Name', parent=root)
    assert rollover.cert.subject == rollover.cert.issuer
    with pytest.raises(InvalidSignature):
        rollover.cert.verify_directly_issued_by(rollover.cert)
    assert not _self_signed(cert_pem(rollover.cert))
    assert _self_signed(cert_pem(root.cert))


def test_private_key_bio_allocation_failure_never_reaches_the_parser(connection, tmp_path):
    path = tmp_path / 'key.pem'
    path.write_bytes(key_pem(generate('ML-DSA-65')))
    lib = tls.lib()
    with mock.patch.object(lib, 'BIO_new_mem_buf', return_value=None):
        with mock.patch.object(lib, 'PEM_read_bio_PrivateKey', side_effect=AssertionError('NULL BIO reached parser')):
            with pytest.raises(tls.TLSError, match='allocat'):
                connection.ctx._use_key(path, None)


@pytest.mark.skipif(REASON, reason=REASON or '')
@pytest.mark.parametrize('operation', ['sign', 'verify'])
def test_signer_digest_allocation_failure_never_reaches_initialization(operation):
    lib = tls.lib()
    signer = signers.OpenSSLSigner(key_pem(generate('ML-DSA-65')))
    with mock.patch.object(lib, 'EVP_MD_CTX_new', return_value=None):
        if operation == 'sign':
            with mock.patch.object(lib, 'EVP_DigestSignInit_ex', side_effect=AssertionError('NULL digest reached signing')):
                with pytest.raises(signers.SignerError, match='allocat'):
                    signer.sign(b'data')
        else:
            with mock.patch.object(lib, 'EVP_DigestVerifyInit_ex', side_effect=AssertionError('NULL digest reached verification')):
                assert not signers.verify(signer.spki, b'data', b'signature')


@pytest.mark.skipif(REASON, reason=REASON or '')
def test_self_issued_rollover_chain_connects_to_the_original_root(tmp_path):
    from pqc.pki import CA
    from pqc.tls.server import Server
    root = CA.init(tmp_path / 'root', 'Same Name')
    rollover = CA.init(tmp_path / 'rollover', 'Same Name', parent=root)
    folder, _ = rollover.issue('localhost', 'server')
    make = lambda: tls.server_context(folder / 'chain.pem', folder / 'key.pem')
    server = Server(('127.0.0.1', 0), make, lambda conn, addr: conn.sendall(b'rollover'))
    server.start()
    try:
        with tls.connect('127.0.0.1', server.port, tls.client_context(root.anchor), 'localhost') as conn:
            assert conn.recv() == b'rollover'
            assert len(conn.peer_chain()) == 3
    finally:
        server.stop(1)


@pytest.mark.skipif(REASON, reason=REASON or '')
@pytest.mark.parametrize('operation', ['load', 'generate'])
def test_signer_bio_allocation_failure_never_reaches_the_parser(operation):
    lib = tls.lib()
    if operation == 'load':
        with mock.patch.object(lib, 'BIO_new_mem_buf', return_value=None):
            with mock.patch.object(lib, 'PEM_read_bio_PrivateKey', side_effect=AssertionError('NULL BIO reached parser')):
                with pytest.raises(signers.SignerError, match='allocat'):
                    signers.OpenSSLSigner(key_pem(generate('ML-DSA-65')))
    else:
        with mock.patch.object(lib, 'BIO_new', return_value=None):
            with mock.patch.object(lib, 'PEM_write_bio_PKCS8PrivateKey', side_effect=AssertionError('NULL BIO reached writer')):
                with pytest.raises(signers.SignerError, match='allocat'):
                    signers.OpenSSLSigner.generate('ML-DSA-65')
