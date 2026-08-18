"""Comprehensive unit tests for core/killchain/persistence.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

import core.killchain.persistence as persistence


@pytest.mark.unit
def test_persistence_ssh_connection_failed():
    with patch("core.killchain.persistence._ssh_connect", return_value=(None, "Auth failed")):
        res = persistence.plant_persistence("10.0.0.1", "user", "pass", callback_host="10.0.0.2")
        assert "SSH connection failed" in res


@pytest.mark.unit
def test_plant_persistence_root_all_methods(tmp_path: Path):
    mock_client = MagicMock()
    bashrc_calls = 0

    def fake_exec(client, cmd, timeout=None):
        nonlocal bashrc_calls
        if "whoami" in cmd:
            return "root"
        if "id" in cmd:
            return "uid=0(root) gid=0(root)"
        if "grep octopus" in cmd:
            return "octopus-persistence"
        if "grep -F" in cmd and "crontab" in cmd:
            return "octopus-persistence"
        if "grep -F" in cmd and "bashrc" in cmd:
            bashrc_calls += 1
            return "octopus-persistence" if bashrc_calls > 1 else ""
        if "cat /etc/passwd" in cmd:
            return "root:x:0:0:root:/root:/bin/bash\n"
        if "ls -la" in cmd:
            return "-rwsr-xr-x 1 root root 1000 /usr/local/share/.mtr_shell"
        return ""

    with patch("core.killchain.persistence._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.persistence._ssh_exec", side_effect=fake_exec):
            with patch("os.path.isfile", side_effect=lambda p: True if "pub" in p else False):
                with patch("subprocess.run"):
                    with patch("builtins.open", mock_open(read_data="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n")):
                        with patch("core.opsec.artifact_mgr.ArtifactManager"):
                            res = persistence.plant_persistence("10.0.0.1", "root", "pass", callback_host="10.0.0.2")
                            assert "SSH KEY INJECTED" in res
                            assert "CRONTAB persistence set" in res
                            assert "HIDDEN SUID SHELL" in res
                            assert ".bashrc backdoor" in res


@pytest.mark.unit
def test_plant_persistence_keygen_paramiko_fallback(tmp_path: Path):
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if "whoami" in cmd:
            return "user"
        if "id" in cmd:
            return "uid=1000(user) gid=1000(user)"
        if "crontab -l" in cmd:
            return "octopus-persistence"
        return ""

    mock_key = MagicMock()
    mock_key.get_base64.return_value = "AAAAC3NzaC1lZDI1NTE5AAAA"

    mock_paramiko = MagicMock()
    mock_paramiko.Ed25519Key.generate.return_value = mock_key

    with patch("core.killchain.persistence._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.persistence._ssh_exec", side_effect=fake_exec):
            with patch("core.killchain.persistence.paramiko", mock_paramiko):
                with patch("subprocess.run", side_effect=Exception("ssh-keygen not found")):
                    with patch("os.path.isfile", side_effect=[False, True]):
                        with patch("builtins.open", mock_open(read_data="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n")):
                            with patch("core.opsec.artifact_mgr.ArtifactManager"):
                                res = persistence.plant_persistence(
                                    "10.0.0.1", "user", "pass", callback_host="10.0.0.2"
                                )
                                assert "Crontab persistence already exists" in res
