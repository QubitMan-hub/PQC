import io
from unittest import mock

import pytest

from pqc.cli import main
from pqc.pki import CA, encrypted


def run_menu(answers, *flags):
    with mock.patch('sys.stdin.isatty', return_value=True), mock.patch('builtins.input', side_effect=answers):
        with pytest.raises(SystemExit) as result:
            main(['start', *flags])
    return result.value.code


def test_menu_checks_installation_and_retries_invalid_choices(capsys):
    with mock.patch('pqc.cli.start.cmd_doctor', return_value=3) as doctor:
        assert run_menu(['bad', '1']) == 3
    doctor.assert_called_once()
    output = capsys.readouterr().out
    assert 'Choose 1, 2, 3 or Q' in output


def test_menu_does_not_create_a_ca_without_agreement(tmp_path):
    root = tmp_path / 'authority'
    assert run_menu(['3', 'n'], '--ca', str(root)) == 0
    assert not root.exists()


def test_menu_creates_an_encrypted_ca_and_passes_password_in_memory(tmp_path, monkeypatch, capsys):
    root = tmp_path / 'authority'
    monkeypatch.delenv('PQC_CA_PASSPHRASE', raising=False)
    with mock.patch('getpass.getpass', side_effect=['secret-password', 'secret-password']), \
            mock.patch('pqc.cli.console.cmd_console', return_value=0) as console:
        assert run_menu(['3', 'y', 'Customer Root'], '--ca', str(root)) == 0
    assert encrypted(root / 'ca.key')
    assert CA(root, b'secret-password').cert.subject.rfc4514_string() == 'CN=Customer Root'
    assert console.call_args.args[0].passphrase == b'secret-password'
    assert 'secret-password' not in capsys.readouterr().out


def test_menu_preserves_an_existing_ca(tmp_path):
    root = tmp_path / 'authority'
    CA.init(root, 'Existing Root', passphrase=b'password')
    original = (root / 'ca.crt').read_bytes()
    with mock.patch('pqc.cli.console.cmd_console', return_value=0):
        assert run_menu(['3'], '--ca', str(root)) == 0
    assert (root / 'ca.crt').read_bytes() == original


def test_menu_requires_a_terminal(capsys):
    with mock.patch('sys.stdin', io.StringIO('')):
        with pytest.raises(SystemExit) as result:
            main(['start'])
    assert result.value.code == 1
    assert 'terminal' in capsys.readouterr().err


def test_menu_rejects_an_empty_password_without_creating_a_ca(tmp_path, monkeypatch, capsys):
    root = tmp_path / 'authority'
    monkeypatch.delenv('PQC_CA_PASSPHRASE', raising=False)
    with mock.patch('getpass.getpass', side_effect=['', '']), mock.patch('pqc.cli.console.cmd_console', return_value=0):
        assert run_menu(['3', 'y', 'Customer Root'], '--ca', str(root)) == 1
    assert not root.exists()
    assert 'empty' in capsys.readouterr().err


def test_missing_console_ca_suggests_a_complete_command(tmp_path, capsys):
    with pytest.raises(SystemExit) as result:
        main(['console', '--ca', str(tmp_path / 'missing'), '--no-browser'])
    assert result.value.code == 1
    assert '--name "My Root"' in capsys.readouterr().err

