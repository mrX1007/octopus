"""Comprehensive unit tests for core/killchain/ad/lateral.py."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import core.killchain.ad.lateral as lat_mod


@pytest.mark.unit
def test_psexec_missing_creds():
    assert "Credentials required" in lat_mod.psexec("10.0.0.1", {})


@pytest.mark.unit
def test_psexec_impacket_success():
    class FakePSEXEC:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            return "NT AUTHORITY\\SYSTEM"

    with patch.dict("sys.modules", {"impacket.examples.psexec": SimpleNamespace(PSEXEC=FakePSEXEC)}):
        res = lat_mod.psexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
        assert "PsExec successful" in res


@pytest.mark.unit
def test_psexec_impacket_error():
    class FailingPSEXEC:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            raise Exception("PsExec denied")

    with patch.dict("sys.modules", {"impacket.examples.psexec": SimpleNamespace(PSEXEC=FailingPSEXEC)}):
        res = lat_mod.psexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
        assert "impacket error" in res


@pytest.mark.unit
def test_psexec_fallbacks():
    with patch.dict("sys.modules", {"impacket.examples.psexec": None}):
        with patch("shutil.which", return_value="/bin/psexec.py"):
            res = lat_mod.psexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
            assert "PsExec CLI fallback is disabled" in res

        with patch("shutil.which", return_value=None):
            res = lat_mod.psexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
            assert "No impacket psexec available" in res


@pytest.mark.unit
def test_wmiexec_missing_creds():
    assert "Credentials required" in lat_mod.wmiexec("10.0.0.1", {})


@pytest.mark.unit
def test_wmiexec_impacket_success():
    class FakeWMIEXEC:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            return "CORP\\admin"

    with patch.dict("sys.modules", {"impacket.examples.wmiexec": SimpleNamespace(WMIEXEC=FakeWMIEXEC)}):
        res = lat_mod.wmiexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
        assert "WMIExec successful" in res


@pytest.mark.unit
def test_wmiexec_impacket_error():
    class FailingWMIEXEC:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            raise Exception("WMIExec denied")

    with patch.dict("sys.modules", {"impacket.examples.wmiexec": SimpleNamespace(WMIEXEC=FailingWMIEXEC)}):
        res = lat_mod.wmiexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
        assert "impacket error" in res


@pytest.mark.unit
def test_wmiexec_fallbacks():
    with patch.dict("sys.modules", {"impacket.examples.wmiexec": None}):
        with patch("shutil.which", return_value="/bin/wmiexec.py"):
            res = lat_mod.wmiexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
            assert "WMIExec CLI fallback is disabled" in res

        with patch("shutil.which", return_value=None):
            res = lat_mod.wmiexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
            assert "No impacket wmiexec available" in res


@pytest.mark.unit
def test_smbexec_missing_creds():
    assert "Credentials required" in lat_mod.smbexec("10.0.0.1", {})


@pytest.mark.unit
def test_smbexec_impacket_success():
    class FakeSMBEXEC:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            return "CORP\\admin"

    with patch.dict("sys.modules", {"impacket.examples.smbexec": SimpleNamespace(SMBEXEC=FakeSMBEXEC)}):
        res = lat_mod.smbexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
        assert "SMBExec successful" in res


@pytest.mark.unit
def test_smbexec_impacket_error():
    class FailingSMBEXEC:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args, **kwargs):
            raise Exception("SMBExec denied")

    with patch.dict("sys.modules", {"impacket.examples.smbexec": SimpleNamespace(SMBEXEC=FailingSMBEXEC)}):
        res = lat_mod.smbexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
        assert "impacket error" in res


@pytest.mark.unit
def test_smbexec_fallbacks():
    with patch.dict("sys.modules", {"impacket.examples.smbexec": None}):
        with patch("shutil.which", return_value="/bin/smbexec.py"):
            res = lat_mod.smbexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
            assert "SMBExec CLI fallback is disabled" in res

        with patch("shutil.which", return_value=None):
            res = lat_mod.smbexec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
            assert "No impacket smbexec available" in res


@pytest.mark.unit
def test_winrm_exec_missing_creds():
    assert "Credentials required" in lat_mod.winrm_exec("10.0.0.1", {})


@pytest.mark.unit
def test_winrm_exec_pywinrm_success():
    class FakeResponse:
        status_code = 0
        std_out = b"whoami output"
        std_err = b""

    class FakeProtocol:
        def get_command_output(self, shell_id, command_id):
            return b"whoami output", b"", 0

        def cleanup_command(self, shell_id, command_id):
            pass

        def close_shell(self, shell_id):
            pass

    class FakeSession:
        protocol = FakeProtocol()

        def __init__(self, *args, **kwargs):
            pass

        def run_cmd(self, command, args=()):
            return FakeResponse()

    with patch.dict("sys.modules", {"winrm": SimpleNamespace(Session=FakeSession)}):
        res = lat_mod.winrm_exec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
        assert "WinRM successful" in res

    # All connections fail
    class FailingSession:
        def __init__(self, *args, **kwargs):
            raise Exception("connection refused")

    with patch.dict("sys.modules", {"winrm": SimpleNamespace(Session=FailingSession)}):
        res_fail = lat_mod.winrm_exec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
        assert "WinRM connection failed on both HTTP and HTTPS" in res_fail


@pytest.mark.unit
def test_winrm_exec_fallbacks():
    with patch.dict("sys.modules", {"winrm": None}):
        with patch("shutil.which", return_value="/bin/evil-winrm"):
            res = lat_mod.winrm_exec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
            assert "Credential-bearing evil-winrm CLI fallback is disabled" in res

        with patch("shutil.which", return_value=None):
            res = lat_mod.winrm_exec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
            assert "No WinRM client available" in res


@pytest.mark.unit
def test_dcom_exec_missing_creds():
    assert "Credentials required" in lat_mod.dcom_exec("10.0.0.1", {})


@pytest.mark.unit
def test_dcom_exec_impacket_success():
    class FakeDCOMEXEC:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target, target_ip):
            return "CORP\\admin"

    with patch.dict("sys.modules", {"impacket.examples.dcomexec": SimpleNamespace(DCOMEXEC=FakeDCOMEXEC)}):
        res = lat_mod.dcom_exec(
            "10.0.0.1",
            {"user": "admin", "password": "p", "domain": "CORP", "nthash": "31d6cfe0d16ae931b73c59d7e0c089c0"},
        )
        assert "DCOM exec successful" in res

    # All DCOM objects fail
    class FailingDCOM:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target, target_ip):
            raise Exception("DCOM error")

    with patch.dict("sys.modules", {"impacket.examples.dcomexec": SimpleNamespace(DCOMEXEC=FailingDCOM)}):
        res_fail = lat_mod.dcom_exec(
            "10.0.0.1",
            {"user": "admin", "password": "p", "domain": "CORP"},
        )
        assert "All DCOM objects failed" in res_fail


@pytest.mark.unit
def test_dcom_exec_fallbacks():
    with patch.dict("sys.modules", {"impacket.examples.dcomexec": None}):
        with patch("shutil.which", return_value="/bin/dcomexec.py"):
            res = lat_mod.dcom_exec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
            assert "Credential-bearing DCOM CLI fallback is disabled" in res

        with patch("shutil.which", return_value=None):
            res = lat_mod.dcom_exec("10.0.0.1", {"user": "admin", "password": "p", "domain": "CORP"})
            assert "No impacket dcomexec available" in res
