"""Comprehensive unit tests for core/killchain/exfil.py."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import core.killchain.exfil as exfil


@pytest.mark.unit
def test_data_exfil_ssh_fail():
    with patch("core.killchain.exfil._ssh_connect", return_value=(None, "Auth failed")):
        res = exfil.data_exfil("10.0.0.1", "user", "pass")
        assert "SSH connection failed" in res


@pytest.mark.unit
def test_data_exfil_success(tmp_path: Path):
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if "id" in cmd and "whoami" not in cmd:
            return "uid=0(root) gid=0(root)"
        if "find / -name 'wp-config.php'" in cmd:
            return "/var/www/html/wp-config.php\n"
        if "find /var/www /opt /home -name '.env'" in cmd:
            return "/var/www/.env\n"
        if "find / -name id_rsa" in cmd:
            return "/home/user/.ssh/id_rsa\n"
        if "find / -name '*.sql'" in cmd:
            return "/var/backups/dump.sql\n"
        if "shadow" in cmd:
            return (
                "root:$6$hash:18000:0:99999:7:::\n"
                "user1:$5$hash:18000:0:99999:7:::\n"
                "user2:$1$hash:18000:0:99999:7:::\n"
                "user3:$y$hash:18000:0:99999:7:::\n"
                "user4:$2b$hash:18000:0:99999:7:::\n"
            )
        if "id_rsa" in cmd:
            return "-----BEGIN OPENSSH PRIVATE KEY-----\nkey data\n"
        if "wp-config.php" in cmd or ".env" in cmd:
            return "DB_PASSWORD=secret_pass_123\n"
        if "cat" in cmd:
            return "sample file content"
        return ""

    with patch.object(exfil.os.path, "expanduser", return_value=str(tmp_path)):
        with patch("core.killchain.exfil._ssh_connect", return_value=(mock_client, None)):
            with patch("core.killchain.exfil._ssh_exec", side_effect=fake_exec):
                with patch("shutil.which", return_value="/usr/bin/john"):
                    with patch("core.killchain.orchestrator._generate_target_report"):
                        res = exfil.data_exfil("10.0.0.1", "root", "pass")
                        assert "DATA EXFILTRATION" in res
                        assert "Files exfiltrated" in res
                        assert "SHA-512" in res
                        assert "SHA-256" in res
                        assert "MD5" in res
                        assert "yescrypt" in res
                        assert "bcrypt" in res


@pytest.mark.unit
def test_data_exfil_sudo_fallback(tmp_path: Path):
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if "id" in cmd:
            return "uid=1000(user) gid=1000(user)"
        if "sudo -n -l" in cmd:
            return "(ALL) NOPASSWD: ALL"
        if "sudo cat" in cmd:
            return "root:$6$hash:18000:0:99999:7:::\n"
        if "cat /etc/shadow" in cmd:
            return "cat: /etc/shadow: Permission denied"
        if "cat" in cmd:
            return "sample content"
        return ""

    with patch.object(exfil.os.path, "expanduser", return_value=str(tmp_path)):
        with patch("core.killchain.exfil._ssh_connect", return_value=(mock_client, None)):
            with patch("core.killchain.exfil._ssh_exec", side_effect=fake_exec):
                res = exfil.data_exfil("10.0.0.1", "user", "pass")
                assert "via sudo" in res or "EXFIL" in res
