import datetime as dt
import io
import socket
import ssl
import threading
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pqc.pki import CA, CAError, cert_pem, check_revocation, fetch_crl, now
from pqc.pki.acme import Problem, Service, _iso, b64u, make_csr, serve
from tests.helpers import wait


def test_same_second_crl_replay_cannot_restore_a_revoked_certificate(tmp_path):
    with mock.patch('pqc.pki.now', return_value=now()):
        ca = CA.init(tmp_path / 'pki', 'Root')
        old = (ca.root / 'crl.pem').read_bytes()
        _, rec = ca.issue('alice', 'client')
        current = ca.revoke(rec.serial)
    dest = tmp_path / 'download' / 'crl.pem'
    with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(current)):
        assert fetch_crl('http://ca.test/crl.pem', dest, ca.cert)
    with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(old)):
        with pytest.raises(CAError, match='older|replay'):
            fetch_crl('http://ca.test/crl.pem', dest, ca.cert)
    assert dest.read_bytes() == current
    with pytest.raises(CAError, match='revoked'):
        check_revocation(int(rec.serial, 16), dest.read_bytes(), ca.cert)


def test_crl_numbers_increase_after_reopening_the_ca_and_losing_the_crl(tmp_path):
    ca = CA.init(tmp_path / 'pki', 'Root')
    first = x509.load_pem_x509_crl(ca.crl()).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    (ca.root / 'crl.pem').unlink()
    second = x509.load_pem_x509_crl(CA(ca.root).crl()).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    assert second > first


def test_a_damaged_crl_can_be_repaired_without_reusing_its_number(tmp_path):
    ca = CA.init(tmp_path / 'pki', 'Root')
    first = x509.load_pem_x509_crl(ca.crl()).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    (ca.root / 'crl.pem').write_bytes(b'damaged')
    second = x509.load_pem_x509_crl(ca.crl()).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    assert second > first


def legacy_crl(ca, serials, date):
    builder = x509.CertificateRevocationListBuilder().issuer_name(ca.cert.subject).last_update(date).next_update(date + dt.timedelta(days=7))
    for serial in serials:
        builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(date).build())
    return builder.sign(ca.signer.key, None).public_bytes(serialization.Encoding.PEM)


def test_legacy_crl_updates_keep_same_second_revocations_and_upgrade_safely(tmp_path):
    ca = CA.init(tmp_path / 'pki', 'Root')
    _, rec = ca.issue('alice', 'client')
    date = now()
    old = legacy_crl(ca, [], date)
    current = legacy_crl(ca, [int(rec.serial, 16)], date)
    dest = tmp_path / 'edge-crl.pem'
    dest.write_bytes(old)
    with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(current)):
        assert fetch_crl('http://ca.test/crl.pem', dest, ca.cert)
    with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(old)):
        with pytest.raises(CAError, match='older|replay'):
            fetch_crl('http://ca.test/crl.pem', dest, ca.cert)
    numbered = ca.revoke(rec.serial)
    with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(numbered)):
        assert fetch_crl('http://ca.test/crl.pem', dest, ca.cert)
    with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(legacy_crl(ca, [], date + dt.timedelta(seconds=1)))):
        with pytest.raises(CAError, match='older|replay'):
            fetch_crl('http://ca.test/crl.pem', dest, ca.cert)


@pytest.mark.parametrize('state', ['valid', 'deactivated', 'expired', 'pending'])
def test_acme_finalization_rechecks_authorization(tmp_path, state):
    ca = CA.init(tmp_path / 'pki', 'Root')
    svc = Service(ca, 'http://ca.test')
    _, _, headers = svc.new_order({'identifiers': [{'type': 'dns', 'value': 'localhost'}]}, 'owner')
    oid = headers['Location'].rsplit('/', 1)[1]
    aid = svc.state['orders'][oid]['authorizations'][0]
    auth = svc.state['authz'][aid]
    auth['status'] = 'valid'
    svc.order(oid, None, 'owner')
    if state == 'deactivated':
        svc.authz(aid, {'status': 'deactivated'}, 'owner')
    elif state == 'expired':
        auth['expires'] = _iso(now())
    else:
        auth['status'] = state
    csr = (make_csr(['localhost'], tmp_path / 'csr') / 'csr.der').read_bytes()
    if state == 'valid':
        assert svc.finalize(oid, {'csr': b64u(csr)}, 'owner')[1]['status'] == 'valid'
        assert len(ca.records()) == 1
    else:
        with pytest.raises(Problem, match='order is'):
            svc.finalize(oid, {'csr': b64u(csr)}, 'owner')
        assert ca.records() == []


def test_acme_validation_cannot_reactivate_a_deactivated_authorization(tmp_path):
    svc = Service(CA.init(tmp_path / 'pki', 'Root'), 'http://ca.test', allow_local=True)
    svc.state['accounts']['owner'] = {'thumbprint': 'tp'}
    _, _, headers = svc.new_order({'identifiers': [{'type': 'dns', 'value': 'localhost'}]}, 'owner')
    oid = headers['Location'].rsplit('/', 1)[1]
    aid = svc.state['orders'][oid]['authorizations'][0]
    auth = svc.state['authz'][aid]
    auth['challenge_status'] = 'processing'

    class Response(io.BytesIO):
        def read(self, *args):
            svc.authz(aid, {'status': 'deactivated'}, 'owner')
            return super().read(*args)

    with mock.patch('pqc.pki.acme.FETCH.open', return_value=Response(f"{auth['token']}.tp".encode())):
        svc.validate(aid, f"{auth['token']}.tp")
    assert auth['status'] == 'deactivated'


def https_server(tmp_path, **limits):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'localhost')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now() - dt.timedelta(minutes=1)).not_valid_after(now() + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False).sign(key, hashes.SHA256()))
    (tmp_path / 'c.pem').write_bytes(cert_pem(cert))
    (tmp_path / 'k.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    httpd = serve(Service(CA.init(tmp_path / 'pki', 'Root'), 'https://localhost'), '127.0.0.1:0', str(tmp_path / 'c.pem'), str(tmp_path / 'k.pem'), **limits)
    return httpd, ssl.create_default_context(cafile=str(tmp_path / 'c.pem'))


def test_acme_https_stalled_handshake_does_not_block_other_clients(tmp_path):
    httpd, ctx = https_server(tmp_path)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    # Wait until accept has consumed the first socket before starting the legitimate client.
    accepted = threading.Event()
    original = httpd.get_request

    def get_request():
        accepted.set()
        return original()

    httpd.get_request = get_request
    silent = socket.create_connection(httpd.server_address, timeout=2)
    try:
        assert accepted.wait(2)
        with socket.create_connection(httpd.server_address, timeout=2) as raw, ctx.wrap_socket(raw, server_hostname='localhost') as conn:
            conn.sendall(b'GET /directory HTTP/1.0\r\n\r\n')
            assert conn.recv(100).startswith(b'HTTP/1.0 200')
    finally:
        silent.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(2)
    assert wait(lambda: not thread.is_alive())


def test_acme_https_limits_workers_and_releases_timed_out_handshakes(tmp_path):
    httpd, ctx = https_server(tmp_path, handshake_timeout=0.5, max_connections=1)
    handshaking = threading.Event()
    original = httpd.context.wrap_socket

    def wrap_socket(*args, **kwargs):
        handshaking.set()
        return original(*args, **kwargs)

    httpd.context.wrap_socket = wrap_socket
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    silent = socket.create_connection(httpd.server_address, timeout=2)
    try:
        assert handshaking.wait(2)
        with socket.create_connection(httpd.server_address, timeout=2) as extra:
            assert extra.recv(1) == b''
        assert silent.recv(1) == b''

        def request_succeeds():
            try:
                with socket.create_connection(httpd.server_address, timeout=2) as raw, ctx.wrap_socket(raw, server_hostname='localhost') as conn:
                    conn.sendall(b'GET /directory HTTP/1.0\r\n\r\n')
                    return conn.recv(100).startswith(b'HTTP/1.0 200')
            except OSError:
                return False

        assert wait(request_succeeds)
    finally:
        silent.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(2)
