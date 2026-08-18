"""Comprehensive unit tests for core/killchain/ssh_helpers.py."""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import core.killchain.ssh_helpers as ssh_helpers


@pytest.mark.unit
def test_safe_connection_error():
    assert ssh_helpers._safe_connection_error("secret error", "secret") == "[REDACTED] error"
    assert ssh_helpers._safe_connection_error("plain error", "") == "plain error"


@pytest.mark.unit
def test_is_port_open():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock
        assert ssh_helpers._is_port_open("127.0.0.1", 22)

        mock_sock.connect_ex.return_value = 1
        assert not ssh_helpers._is_port_open("127.0.0.1", 22)

        mock_sock.connect_ex.side_effect = Exception("err")
        assert not ssh_helpers._is_port_open("127.0.0.1", 22)


@pytest.mark.unit
def test_ssh_connect_paramiko_none():
    with patch.object(ssh_helpers, "paramiko", None):
        client, err = ssh_helpers._ssh_connect("10.0.0.1", "user", "pass")
        assert client is None
        assert "paramiko not installed" in str(err)


@pytest.mark.unit
def test_ssh_connect_key_auth(tmp_path: Path):
    fake_key = tmp_path / "id_rsa"
    fake_key.write_text("fake_key")

    mock_client = MagicMock()
    mock_rsa = MagicMock()

    with patch.object(ssh_helpers.os.path, "expanduser", return_value=str(fake_key)):
        with patch.object(ssh_helpers.paramiko, "SSHClient", return_value=mock_client):
            with patch.object(ssh_helpers.paramiko.RSAKey, "from_private_key_file", return_value=mock_rsa):
                client, err = ssh_helpers._ssh_connect("10.0.0.1", "user", "__KEY_AUTH__")
                assert client is mock_client
                assert err is None

                # Test failure in connect
                mock_client.connect.side_effect = Exception("conn error")
                client2, err2 = ssh_helpers._ssh_connect("10.0.0.1", "user", "__KEY_AUTH__")
                assert client2 is None
                assert "Key auth failed" in str(err2)

    # Missing key path
    with patch.object(ssh_helpers.os.path, "expanduser", return_value=str(tmp_path / "missing")):
        client3, err3 = ssh_helpers._ssh_connect("10.0.0.1", "user", "__KEY_AUTH__")
        assert client3 is None
        assert "No SSH key found" in str(err3)


@pytest.mark.unit
def test_ssh_connect_password_auth(tmp_path: Path):
    mock_client = MagicMock()

    with patch.object(ssh_helpers.paramiko, "SSHClient", side_effect=lambda: mock_client):
        # 1. Success
        client, err = ssh_helpers._ssh_connect("10.0.0.1", "user", "secret")
        assert client is mock_client
        assert err is None

        # 2. AuthException with fallback to root key
        fake_key = tmp_path / "id_rsa"
        fake_key.write_text("fake_key")
        mock_client.connect.side_effect = ssh_helpers.paramiko.AuthenticationException("auth fail")

        with patch.object(ssh_helpers.os.path, "expanduser", return_value=str(fake_key)):
            with patch.object(ssh_helpers.paramiko.RSAKey, "from_private_key_file"):
                # Make client2 succeed
                mock_client2 = MagicMock()
                with patch.object(ssh_helpers.paramiko, "SSHClient", side_effect=[mock_client, mock_client2]):
                    client_root, err_root = ssh_helpers._ssh_connect("10.0.0.1", "root", "wrong")
                    assert client_root is not None
                    assert err_root is None

                # Non-root user with auth fail
                client_user, err_user = ssh_helpers._ssh_connect("10.0.0.1", "regular", "wrong")
                assert client_user is None
                assert "Auth failed" in str(err_user)

        # 3. General Exception
        mock_client.connect.side_effect = RuntimeError("general error")
        client_err, err_msg = ssh_helpers._ssh_connect("10.0.0.1", "user", "secret")
        assert client_err is None
        assert "general error" in str(err_msg)


@pytest.mark.unit
def test_ssh_exec():
    # Inactive transport
    mock_client = MagicMock()
    mock_client.get_transport.return_value = None
    assert "SSH transport is closed" in ssh_helpers._ssh_exec(mock_client, "id")

    # Active transport normal execution
    mock_transport = MagicMock()
    mock_transport.is_active.return_value = True
    mock_channel = MagicMock()
    mock_channel.exit_status_ready.side_effect = [False, True]
    mock_channel.recv_ready.side_effect = [True, False, False]
    mock_channel.recv_stderr_ready.side_effect = [False, False]
    mock_channel.recv.return_value = b"uid=0(root)\n"
    mock_channel.recv_stderr.return_value = b""
    mock_channel.recv_exit_status.return_value = 0
    mock_transport.open_session.return_value = mock_channel
    mock_client.get_transport.return_value = mock_transport

    res = ssh_helpers._ssh_exec(mock_client, "id")
    assert "uid=0(root)" in res

    # Socket timeout
    mock_channel.exec_command.side_effect = socket.timeout()
    timeout_res = ssh_helpers._ssh_exec(mock_client, "sleep 100")
    assert "timed out" in timeout_res

    # Binary data filtering
    mock_channel2 = MagicMock()
    mock_channel2.exit_status_ready.side_effect = [False, True]
    mock_channel2.recv_ready.side_effect = [True, False, False]
    mock_channel2.recv_stderr_ready.side_effect = [False, False]
    mock_channel2.recv.return_value = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08" * 50
    mock_channel2.recv_exit_status.return_value = 0
    mock_transport.open_session.return_value = mock_channel2

    res_bin = ssh_helpers._ssh_exec(mock_client, "cat /dev/urandom")
    assert "BINARY DATA" in res_bin

    # Non-zero exit code with empty output
    mock_channel3 = MagicMock()
    mock_channel3.exit_status_ready.side_effect = [False, True]
    mock_channel3.recv_ready.side_effect = [False, False]
    mock_channel3.recv_stderr_ready.side_effect = [False, False]
    mock_channel3.recv.return_value = b""
    mock_channel3.recv_stderr.return_value = b""
    mock_channel3.recv_exit_status.return_value = 127
    mock_transport.open_session.return_value = mock_channel3

    res_exit = ssh_helpers._ssh_exec(mock_client, "nonexistent")
    assert "exited with code 127" in res_exit

    # Wall-clock timeout
    mock_channel4 = MagicMock()
    mock_channel4.exit_status_ready.return_value = False
    mock_transport.open_session.return_value = mock_channel4
    with patch("time.time", side_effect=[100.0, 200.0]):
        res_force_kill = ssh_helpers._ssh_exec(mock_client, "sleep 100", timeout=5)
        assert "timed out after 5s" in res_force_kill

    # Stderr recv and line filtering
    mock_channel5 = MagicMock()
    mock_channel5.exit_status_ready.side_effect = [False, True]
    mock_channel5.recv_ready.side_effect = [True, False, False]
    mock_channel5.recv_stderr_ready.side_effect = [True, False, False]
    mock_channel5.recv.return_value = b"normal line\n" + b"bad \x00\x01\x02 line with binary chars\n"
    mock_channel5.recv_stderr.return_value = b"stderr error line\n"
    mock_channel5.recv_exit_status.return_value = 0
    mock_transport.open_session.return_value = mock_channel5

    res_mixed = ssh_helpers._ssh_exec(mock_client, "mixed_output")
    assert "normal line" in res_mixed
    assert "stderr error line" in res_mixed
