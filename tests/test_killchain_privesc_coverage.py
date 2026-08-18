"""Comprehensive unit tests for core/killchain/privesc.py."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, mock_open, patch

import pytest

import core.killchain.privesc as privesc


@pytest.mark.unit
def test_privesc_ssh_connection_failed():
    with patch("core.killchain.privesc._ssh_connect", return_value=(None, "Auth failed")):
        res = privesc.run_privesc("10.0.0.1", "user", "pass")
        assert "SSH connection failed" in res


@pytest.mark.unit
def test_privesc_already_root():
    mock_client = MagicMock()
    with patch("core.killchain.privesc._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.privesc._ssh_exec", return_value="uid=0(root) gid=0(root)"):
            res = privesc.run_privesc("10.0.0.1", "root", "pass")
            assert "ALREADY ROOT" in res


@pytest.mark.unit
def test_run_linpeas():
    mock_client = MagicMock()

    def fake_lp_exec(client, cmd, timeout=None):
        if "curl" in cmd or "wget" in cmd:
            return "DL_OK"
        if "wc -c" in cmd:
            return "15000"
        if "nohup bash" in cmd:
            return "12345"
        if "kill -0" in cmd:
            return "DONE"
        if "head -c" in cmd or ".lp.out" in cmd:
            return "LinPEAS Report\nCVE-2021-4034 vulnerable\n" * 10
        return ""

    with patch("core.killchain.privesc._ssh_exec", side_effect=fake_lp_exec):
        with patch("time.sleep"):
            out, cves = privesc._run_linpeas(mock_client)
            assert "LinPEAS" in out


@pytest.mark.unit
def test_harvest_credentials(tmp_path: Path):
    mock_client = MagicMock()
    res = privesc._harvest_credentials(mock_client, "10.0.0.1")
    assert "CREDENTIAL BOUNDARY" in res
    assert "disabled" in res


@pytest.mark.unit
def test_run_privesc_suid_vectors():
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if cmd == "id":
            return "uid=1000(test) gid=1000(test)"
        if "sudo" in cmd:
            return "Sorry, user test may not run sudo"
        if "find / -perm -4000" in cmd or "find" in cmd:
            return "/usr/bin/python\n/usr/bin/find\n/usr/bin/vim\n/usr/bin/env\n"
        if "python" in cmd:
            return "uid=0(root) gid=0(root)"
        if "find /dev/null" in cmd:
            return "uid=0(root) gid=0(root)"
        if "env /bin/bash" in cmd:
            return "uid=0(root) gid=0(root)"
        return ""

    with patch("core.killchain.privesc._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.privesc._run_linpeas", return_value=("[LinPEAS output]", [])):
            with patch("core.killchain.privesc._ssh_exec", side_effect=fake_exec):
                with patch("core.killchain.privesc.get_privesc_exploits", return_value=[]):
                    with patch("time.sleep"):
                        res = privesc.run_privesc("10.0.0.1", "test", "pass")
                        assert "PRIVESC" in res


@pytest.mark.unit
def test_run_privesc_suid_pkexec():
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if cmd == "id":
            return "uid=1000(test) gid=1000(test)"
        if "find / -perm -4000" in cmd:
            return "/usr/bin/pkexec\n"
        if "which gcc" in cmd:
            return "gcc"
        if "rootbash" in cmd:
            return "uid=0(root) gid=0(root)"
        if "cat /etc/shadow" in cmd:
            return "root:$6$hash:18000:0:99999:7:::\n"
        return ""

    with patch("core.killchain.privesc._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.privesc._run_linpeas", return_value=("[LinPEAS output]", [])):
            with patch("core.killchain.privesc._ssh_exec", side_effect=fake_exec):
                with patch("core.killchain.privesc.get_privesc_exploits", return_value=[]):
                    with patch("time.sleep"):
                        res = privesc.run_privesc("10.0.0.1", "test", "pass")
                        assert "PWNKIT" in res


@pytest.mark.unit
def test_run_privesc_suid_pkexec_download_fallback(tmp_path: Path):
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if cmd == "id":
            return "uid=1000(test) gid=1000(test)"
        if "find / -perm -4000" in cmd:
            return "/usr/bin/pkexec\n"
        if "which gcc" in cmd:
            return ""  # No gcc on target
        if "curl" in cmd or "wget" in cmd:
            return "DL_OK"
        if "wc -c" in cmd:
            return "5000"
        if "pk id" in cmd or "pk_path" in cmd or "rootbash" in cmd or "root" in cmd:
            return "uid=0(root) gid=0(root)"
        if "cat /etc/shadow" in cmd:
            return "root:$6$hash:18000:0:99999:7:::\n"
        if "chpasswd" in cmd:
            return "CHPASSWD_FAIL"
        return ""

    with patch("core.killchain.privesc._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.privesc._run_linpeas", return_value=("[LinPEAS output]", [])):
            with patch("core.killchain.privesc._ssh_exec", side_effect=fake_exec):
                with patch("core.killchain.privesc.get_privesc_exploits", return_value=[]):
                    with patch("core.credentials.register_credential"):
                        with patch("builtins.open", mock_open(read_data="ssh-rsa AAAAB3...")):
                            with patch("os.path.isfile", return_value=True):
                                with patch("os.makedirs"):
                                    with patch("time.sleep"):
                                        res = privesc.run_privesc("10.0.0.1", "test", "pass")
                                        assert (
                                            "PWNKIT BINARY PRIVESC SUCCESSFUL" in res or "ROOT ACCESS CONFIRMED" in res
                                        )


@pytest.mark.unit
def test_run_privesc_suid_bash():
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if cmd == "id":
            return "uid=1000(test) gid=1000(test)"
        if "find / -perm -4000" in cmd:
            return "/bin/bash\n"
        if "bash -p" in cmd:
            return "uid=0(root) gid=0(root)"
        return ""

    with patch("core.killchain.privesc._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.privesc._run_linpeas", return_value=("[LinPEAS output]", [])):
            with patch("core.killchain.privesc._ssh_exec", side_effect=fake_exec):
                with patch("core.killchain.privesc.get_privesc_exploits", return_value=[]):
                    with patch("time.sleep"):
                        res = privesc.run_privesc("10.0.0.1", "test", "pass")
                        assert "SUID BASH" in res


@pytest.mark.unit
def test_run_privesc_sudo_nopasswd():
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if cmd == "id":
            return "uid=1000(test) gid=1000(test)"
        if "sudo -l" in cmd or "sudo -n -l" in cmd:
            return "User test may run the following commands on host:\n(ALL) NOPASSWD: ALL"
        if "sudo -n id" in cmd:
            return "uid=0(root) gid=0(root)"
        return ""

    with patch("core.killchain.privesc._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.privesc._run_linpeas", return_value=("[LinPEAS output]", [])):
            with patch("core.killchain.privesc._ssh_exec", side_effect=fake_exec):
                with patch("core.killchain.privesc.get_privesc_exploits", return_value=[]):
                    with patch("time.sleep"):
                        res = privesc.run_privesc("10.0.0.1", "test", "pass")
                        assert "PRIVESC SUCCESSFUL via sudo" in res


@pytest.mark.unit
def test_run_privesc_docker_vector():
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if cmd == "id":
            return "uid=1000(test) gid=1000(test) groups=1000(test),999(docker)"
        if "id | grep docker" in cmd:
            return "docker"
        if "docker run" in cmd:
            return "root:$6$hash:18000:0:99999:7:::\n"
        return ""

    with patch("core.killchain.privesc._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.privesc._run_linpeas", return_value=("[LinPEAS output]", [])):
            with patch("core.killchain.privesc._ssh_exec", side_effect=fake_exec):
                with patch("core.killchain.privesc.get_privesc_exploits", return_value=[]):
                    with patch("time.sleep"):
                        res = privesc.run_privesc("10.0.0.1", "test", "pass")
                        assert "DOCKER PRIVESC SUCCESSFUL" in res


@pytest.mark.unit
def test_run_privesc_writable_passwd_vector():
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if cmd == "id":
            return "uid=1000(test) gid=1000(test)"
        if "ls -la /etc/passwd" in cmd:
            return "-rw-rw-rw- 1 root root 1000 /etc/passwd"
        if "grep mtr0n /etc/passwd" in cmd:
            return "mtr0n:$1$octopus$hash:0:0::/root:/bin/bash"
        return ""

    with patch("core.killchain.privesc._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.privesc._run_linpeas", return_value=("[LinPEAS output]", [])):
            with patch("core.killchain.privesc._ssh_exec", side_effect=fake_exec):
                with patch("core.killchain.privesc.get_privesc_exploits", return_value=[]):
                    with patch("time.sleep"):
                        res = privesc.run_privesc("10.0.0.1", "test", "pass")
                        assert "WRITABLE PASSWD" in res


@pytest.mark.unit
def test_run_privesc_writable_shadow_vector():
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if cmd == "id":
            return "uid=1000(test) gid=1000(test)"
        if "ls -la /etc/shadow" in cmd:
            return "-rw-rw-rw- 1 root shadow 1000 /etc/shadow"
        if "su -c 'id' root" in cmd:
            return "uid=0(root) gid=0(root)"
        return ""

    with patch("core.killchain.privesc._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.privesc._run_linpeas", return_value=("[LinPEAS output]", [])):
            with patch("core.killchain.privesc._ssh_exec", side_effect=fake_exec):
                with patch("core.killchain.privesc.get_privesc_exploits", return_value=[]):
                    with patch("core.credentials.register_credential"):
                        with patch("time.sleep"):
                            res = privesc.run_privesc("10.0.0.1", "test", "pass")
                            assert "WRITABLE SHADOW" in res


@pytest.mark.unit
def test_run_privesc_kernel_adapters_fallback():
    mock_client = MagicMock()

    def fake_exec(client, cmd, timeout=None):
        if cmd == "id":
            return "uid=1000(test) gid=1000(test)"
        if "sudo" in cmd:
            return "Sorry, user test may not run sudo"
        if "uname -r" in cmd:
            return "3.10.0-123.el7.x86_64"
        return ""

    mock_exploit = MagicMock()
    mock_exploit.name = "MockExploit"
    mock_exploit.cve = "CVE-2021-4034"
    mock_exploit.normalize_check_result.return_value = SimpleNamespace(success=True, evidence="vuln", output="")
    mock_exploit.normalize_run_result.return_value = SimpleNamespace(as_tuple=lambda: (True, "EXPLOIT SUCCESS uid=0"))

    with patch("core.killchain.privesc._ssh_connect", return_value=(mock_client, None)):
        with patch("core.killchain.privesc._run_linpeas", return_value=("[LinPEAS output]", ["CVE-2021-4034"])):
            with patch("core.killchain.privesc._ssh_exec", side_effect=fake_exec):
                with patch("core.killchain.privesc.get_privesc_exploits", return_value=[mock_exploit]):
                    with patch("time.sleep"):
                        res = privesc.run_privesc("10.0.0.1", "test", "pass")
                        assert "EXPLOIT SUCCESS" in res
