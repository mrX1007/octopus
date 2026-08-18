"""Comprehensive unit tests for core/killchain/ad/credential.py."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import core.killchain.ad.credential as cred_mod


@pytest.mark.unit
def test_normalize_creds():
    # Empty
    assert cred_mod._normalize_creds({}) == {
        "user": "",
        "password": "",
        "domain": "",
        "nthash": "",
    }

    # With full creds
    full = {
        "user": "admin",
        "password": "secret",
        "domain": "corp.local",
        "nthash": "31d6cfe0d16ae931b73c59d7e0c089c0",
    }
    norm = cred_mod._normalize_creds(full)
    assert norm["user"] == "admin"
    assert norm["password"] == "secret"
    assert norm["nthash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"


@pytest.mark.unit
def test_loot_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cred_mod, "DEFAULT_LOOT_BASE", str(tmp_path))
    d = cred_mod._loot_dir("10.0.0.1")
    assert "10_0_0_1" in d
    assert os.path.isdir(d)


@pytest.mark.unit
def test_run_cli():
    with patch("subprocess.run", return_value=SimpleNamespace(stdout="ok\n", stderr="")):
        out = cred_mod._run_cli(["echo", "test"])
        assert out == "ok"

    with patch("subprocess.run", side_effect=Exception("command failed")):
        out_err = cred_mod._run_cli(["echo", "test"])
        assert "command failed" in out_err or "Command error" in out_err


@pytest.mark.unit
def test_impacket_auth_string():
    auth = cred_mod._impacket_auth_string(
        {
            "user": "admin",
            "password": "pwd",
            "domain": "corp.local",
            "nthash": "31d6cfe0d16ae931b73c59d7e0c089c0",
        },
    )
    assert "corp.local/admin:pwd" in auth

    auth_no_dom = cred_mod._impacket_auth_string(
        {
            "user": "admin",
            "password": "pwd",
            "domain": "",
            "nthash": "",
        },
    )
    assert auth_no_dom == "admin:pwd"


@pytest.mark.unit
def test_dcsync_missing_creds():
    assert "Domain credentials required" in cred_mod.dcsync("10.0.0.1", {})


@pytest.mark.unit
def test_dcsync_impacket_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cred_mod, "DEFAULT_LOOT_BASE", str(tmp_path))
    loot = cred_mod._loot_dir("10.0.0.1")
    dump_file = os.path.join(loot, "dcsync_hashes.txt")

    with open(dump_file + ".ntds", "w") as f:
        f.write("Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n")

    class FakeDumpSecrets:
        def __init__(self, options):
            pass

        def dump(self):
            pass

    with patch.dict("sys.modules", {"impacket.examples.secretsdump": SimpleNamespace(DumpSecrets=FakeDumpSecrets)}):
        res = cred_mod.dcsync("10.0.0.1", {"user": "admin", "password": "pass", "domain": "CORP"})
        assert "DCSync successful" in res


@pytest.mark.unit
def test_dcsync_impacket_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cred_mod, "DEFAULT_LOOT_BASE", str(tmp_path))

    class FailingDumpSecrets:
        def __init__(self, options):
            pass

        def dump(self):
            raise Exception("DCSync denied")

    with patch.dict("sys.modules", {"impacket.examples.secretsdump": SimpleNamespace(DumpSecrets=FailingDumpSecrets)}):
        res = cred_mod.dcsync("10.0.0.1", {"user": "admin", "password": "pass", "domain": "CORP"})
        assert "impacket error" in res


@pytest.mark.unit
def test_dcsync_fallbacks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cred_mod, "DEFAULT_LOOT_BASE", str(tmp_path))

    # Empty output
    class EmptyDumpSecrets:
        def __init__(self, options):
            pass

        def dump(self):
            pass

    with patch.dict("sys.modules", {"impacket.examples.secretsdump": SimpleNamespace(DumpSecrets=EmptyDumpSecrets)}):
        res_empty = cred_mod.dcsync("10.0.0.1", {"user": "admin", "password": "pass", "domain": "CORP"})
        assert "produced no output" in res_empty

    # ImportError path
    with patch.dict("sys.modules", {"impacket.examples.secretsdump": None}):
        with patch("shutil.which", return_value="/bin/secretsdump.py"):
            res = cred_mod.dcsync("10.0.0.1", {"user": "admin", "password": "pass", "domain": "CORP"})
            assert "Credential-bearing CLI fallback is disabled" in res

        with patch("shutil.which", return_value=None):
            res = cred_mod.dcsync("10.0.0.1", {"user": "admin", "password": "pass", "domain": "CORP"})
            assert "No impacket secretsdump available" in res


@pytest.mark.unit
def test_pass_the_hash():
    assert "unsafe_provider_contract_not_mounted" in cred_mod.pass_the_hash("10.0.0.1")


@pytest.mark.unit
def test_pass_the_ticket(tmp_path: Path):
    # Ticket file not found
    assert "Ticket file not found" in cred_mod.pass_the_ticket("10.0.0.1", str(tmp_path / "missing.ccache"))

    # Valid ticket file
    ticket = tmp_path / "test.ccache"
    ticket.write_bytes(b"dummy ticket")

    class FakeCCache:
        principal = "admin@CORP.LOCAL"

        @classmethod
        def loadFile(cls, path):
            return cls()

    with patch.dict("sys.modules", {"impacket.krb5.ccache": SimpleNamespace(CCache=FakeCCache)}):
        with patch("shutil.which", return_value="/bin/smbexec.py"):
            res = cred_mod.pass_the_ticket("10.0.0.1", str(ticket))
            assert "Ticket principal: admin@CORP.LOCAL" in res
            assert "Ticket-bearing CLI fallback is disabled" in res


@pytest.mark.unit
def test_dump_lsass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cred_mod, "DEFAULT_LOOT_BASE", str(tmp_path))

    # Missing user
    assert "Credentials required" in cred_mod.dump_lsass("10.0.0.1", {})

    class FakeSMBConnection:
        def __init__(self, *args, **kwargs):
            pass

        def login(self, *args, **kwargs):
            pass

        def getFile(self, share, path, callback):
            callback(b"dmp bytes")

        def deleteFile(self, share, path):
            pass

        def logoff(self):
            pass

    class FakeWMIEXEC:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target, smb):
            pass

    class FakeParsedSession:
        username = "admin"
        domain = "CORP"
        lm_hash = "aad3b435b51404ee"
        nt_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
        password = "secret"

    class FakePypykatz:
        @classmethod
        def parse_minidump_file(cls, path):
            return SimpleNamespace(logon_sessions={1: FakeParsedSession()})

    with patch.dict(
        "sys.modules",
        {
            "impacket.smbconnection": SimpleNamespace(SMBConnection=FakeSMBConnection),
            "impacket.examples.wmiexec": SimpleNamespace(WMIEXEC=FakeWMIEXEC),
            "pypykatz": FakePypykatz,
        },
    ):
        res = cred_mod.dump_lsass("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
        assert "Credentials extracted from LSASS" in res or "EXTRACTED CREDENTIALS" in res

    # pypykatz parse error
    class ErrorPypykatz:
        @classmethod
        def parse_minidump_file(cls, path):
            raise RuntimeError("Corrupt minidump")

    with patch.dict(
        "sys.modules",
        {
            "impacket.smbconnection": SimpleNamespace(SMBConnection=FakeSMBConnection),
            "impacket.examples.wmiexec": SimpleNamespace(WMIEXEC=FakeWMIEXEC),
            "pypykatz": ErrorPypykatz,
        },
    ):
        res_parse_err = cred_mod.dump_lsass("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
        assert "pypykatz parsing failed" in res_parse_err

    # pypykatz ImportError
    with patch.dict(
        "sys.modules",
        {
            "impacket.smbconnection": SimpleNamespace(SMBConnection=FakeSMBConnection),
            "impacket.examples.wmiexec": SimpleNamespace(WMIEXEC=FakeWMIEXEC),
            "pypykatz": None,
        },
    ):
        res_no_katz = cred_mod.dump_lsass("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
        assert "pypykatz not installed" in res_no_katz

    # getFile exception
    class ErrorSMBConnection:
        def __init__(self, *args, **kwargs):
            pass

        def login(self, *args, **kwargs):
            pass

        def getFile(self, share, path, callback):
            raise RuntimeError("Access denied to share")

        def logoff(self):
            pass

    with patch.dict(
        "sys.modules",
        {
            "impacket.smbconnection": SimpleNamespace(SMBConnection=ErrorSMBConnection),
            "impacket.examples.wmiexec": SimpleNamespace(WMIEXEC=FakeWMIEXEC),
        },
    ):
        res_dl_err = cred_mod.dump_lsass("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
        assert "Failed to download dump" in res_dl_err

    # Fallback paths
    with patch.dict("sys.modules", {"impacket.smbconnection": None}):
        with patch("shutil.which", return_value="/bin/secretsdump.py"):
            res2 = cred_mod.dump_lsass("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
            assert "Credential-bearing CLI fallback is disabled" in res2

        with patch("shutil.which", return_value=None):
            res3 = cred_mod.dump_lsass("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
            assert "No LSASS dump method available" in res3


@pytest.mark.unit
def test_sam_dump(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cred_mod, "DEFAULT_LOOT_BASE", str(tmp_path))

    # Missing user
    assert "Credentials required" in cred_mod.sam_dump("10.0.0.1", {})

    loot = cred_mod._loot_dir("10.0.0.1")
    sam_file = os.path.join(loot, "sam_dump.sam")
    with open(sam_file, "w") as f:
        f.write("Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n")

    class FakeDumpSecrets:
        def __init__(self, options):
            pass

        def dump(self):
            pass

    with patch.dict("sys.modules", {"impacket.examples.secretsdump": SimpleNamespace(DumpSecrets=FakeDumpSecrets)}):
        res = cred_mod.sam_dump("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
        assert "SAM dump successful" in res

    # Remove sam_file for empty output test
    if os.path.exists(sam_file):
        os.remove(sam_file)

    # Empty output
    class EmptyDumpSecrets:
        def __init__(self, options):
            pass

        def dump(self):
            pass

    with patch.dict("sys.modules", {"impacket.examples.secretsdump": SimpleNamespace(DumpSecrets=EmptyDumpSecrets)}):
        res_empty = cred_mod.sam_dump("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
        assert "produced no output" in res_empty

    # Error path
    class FailingDumpSecrets:
        def __init__(self, options):
            pass

        def dump(self):
            raise Exception("SAM access denied")

    with patch.dict("sys.modules", {"impacket.examples.secretsdump": SimpleNamespace(DumpSecrets=FailingDumpSecrets)}):
        res_err = cred_mod.sam_dump("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
        assert "impacket error" in res_err

    # Fallback paths
    with patch.dict("sys.modules", {"impacket.examples.secretsdump": None}):
        with patch("shutil.which", return_value="/bin/secretsdump.py"):
            res2 = cred_mod.sam_dump("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
            assert "Credential-bearing CLI fallback is disabled" in res2

        with patch("shutil.which", return_value=None):
            res3 = cred_mod.sam_dump("10.0.0.1", {"user": "admin", "password": "pwd", "domain": "CORP"})
            assert "No impacket secretsdump available" in res3
