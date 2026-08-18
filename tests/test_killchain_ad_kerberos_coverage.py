"""Comprehensive unit tests for core/killchain/ad/kerberos.py."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import core.killchain.ad.kerberos as krb_mod


@pytest.mark.unit
def test_asrep_roast_missing_creds():
    assert "Domain name required" in krb_mod.asrep_roast("10.0.0.1", userlist=None, creds={})


@pytest.mark.unit
def test_asrep_roast_impacket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(krb_mod, "DEFAULT_LOOT_BASE", str(tmp_path))

    class FakeGetNPUsers:
        def __init__(self, args):
            self.args = args

        def run(self):
            with open(self.args.outputfile, "w") as f:
                f.write("$krb5asrep$23$user1@CORP.LOCAL:hash\n")

    krb5_const_mod = SimpleNamespace(PrincipalNameType=SimpleNamespace(NT_PRINCIPAL=SimpleNamespace(value=1)))
    krb5_v5_mod = SimpleNamespace(getKerberosTGT=MagicMock())
    get_np_mod = SimpleNamespace(GetNPUsers=FakeGetNPUsers)
    krb5_mod = SimpleNamespace(constants=krb5_const_mod, kerberosv5=krb5_v5_mod)
    impacket_mod = SimpleNamespace(krb5=krb5_mod, examples=SimpleNamespace(GetNPUsers=get_np_mod))

    with patch.dict(
        "sys.modules",
        {
            "impacket": impacket_mod,
            "impacket.krb5": krb5_mod,
            "impacket.krb5.constants": krb5_const_mod,
            "impacket.krb5.kerberosv5": krb5_v5_mod,
            "impacket.examples.GetNPUsers": get_np_mod,
        },
    ):
        res = krb_mod.asrep_roast(
            "10.0.0.1", userlist=["user1"], creds={"user": "admin", "domain": "corp.local", "password": "pwd"}
        )
        assert "AS-REP hash(es) extracted" in res or "krb5asrep" in res


@pytest.mark.unit
def test_asrep_roast_fallbacks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(krb_mod, "DEFAULT_LOOT_BASE", str(tmp_path))

    class FailingGetNPUsers:
        def __init__(self, args):
            pass

        def run(self):
            raise Exception("impacket error")

    krb5_const_mod = SimpleNamespace(PrincipalNameType=SimpleNamespace(NT_PRINCIPAL=SimpleNamespace(value=1)))
    krb5_v5_mod = SimpleNamespace(getKerberosTGT=MagicMock())
    get_np_mod = SimpleNamespace(GetNPUsers=FailingGetNPUsers)
    krb5_mod = SimpleNamespace(constants=krb5_const_mod, kerberosv5=krb5_v5_mod)
    impacket_mod = SimpleNamespace(krb5=krb5_mod, examples=SimpleNamespace(GetNPUsers=get_np_mod))

    with patch.dict(
        "sys.modules",
        {
            "impacket": impacket_mod,
            "impacket.krb5": krb5_mod,
            "impacket.krb5.constants": krb5_const_mod,
            "impacket.krb5.kerberosv5": krb5_v5_mod,
            "impacket.examples.GetNPUsers": get_np_mod,
        },
    ):
        res = krb_mod.asrep_roast(
            "10.0.0.1", userlist=["user1"], creds={"user": "admin", "domain": "corp.local", "password": "pwd"}
        )
        assert "impacket error" in res


@pytest.mark.unit
def test_kerberoast_missing_creds():
    assert "domain credentials required" in krb_mod.kerberoast("10.0.0.1", creds={}).lower()


@pytest.mark.unit
def test_kerberoast_impacket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(krb_mod, "DEFAULT_LOOT_BASE", str(tmp_path))

    class FakeGetUserSPNs:
        def __init__(self, args):
            self.args = args

        def run(self):
            with open(self.args.outputfile, "w") as f:
                f.write("$krb5tgs$23$*HTTP/server*$hash\n")

    get_spn_mod = SimpleNamespace(GetUserSPNs=FakeGetUserSPNs)
    impacket_mod = SimpleNamespace(examples=SimpleNamespace(GetUserSPNs=get_spn_mod))

    with patch.dict(
        "sys.modules",
        {
            "impacket": impacket_mod,
            "impacket.examples.GetUserSPNs": get_spn_mod,
        },
    ):
        res = krb_mod.kerberoast("10.0.0.1", creds={"user": "admin", "password": "pwd", "domain": "corp.local"})
        assert "Kerberoast hash(es) extracted" in res


@pytest.mark.unit
def test_kerberoast_fallbacks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(krb_mod, "DEFAULT_LOOT_BASE", str(tmp_path))

    class FailingGetUserSPNs:
        def __init__(self, args):
            pass

        def run(self):
            raise Exception("impacket error")

    get_spn_mod = SimpleNamespace(GetUserSPNs=FailingGetUserSPNs)
    impacket_mod = SimpleNamespace(examples=SimpleNamespace(GetUserSPNs=get_spn_mod))

    with patch.dict(
        "sys.modules",
        {
            "impacket": impacket_mod,
            "impacket.examples.GetUserSPNs": get_spn_mod,
        },
    ):
        res = krb_mod.kerberoast("10.0.0.1", creds={"user": "admin", "password": "pwd", "domain": "corp.local"})
        assert "impacket error" in res


@pytest.mark.unit
def test_extract_tickets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(krb_mod, "DEFAULT_LOOT_BASE", str(tmp_path))

    # Missing creds
    assert "Domain credentials required" in krb_mod.extract_tickets("10.0.0.1", {})

    class FakePrincipal:
        def __init__(self, *args, **kwargs):
            pass

    class FakeCCache:
        def fromTGT(self, tgt, old_key, session_key):
            pass

        def saveFile(self, path):
            with open(path, "wb") as f:
                f.write(b"ccache")

    fake_cipher = SimpleNamespace(enctype=18)

    krb5_const_mod = SimpleNamespace(PrincipalNameType=SimpleNamespace(NT_PRINCIPAL=SimpleNamespace(value=1)))
    krb5_v5_mod = SimpleNamespace(getKerberosTGT=MagicMock(return_value=("tgt", fake_cipher, b"old", b"session")))
    types_mod = SimpleNamespace(Principal=FakePrincipal)
    ccache_mod = SimpleNamespace(CCache=FakeCCache)
    krb5_mod = SimpleNamespace(constants=krb5_const_mod, kerberosv5=krb5_v5_mod, types=types_mod, ccache=ccache_mod)
    impacket_mod = SimpleNamespace(krb5=krb5_mod)
    with patch.dict(
        "sys.modules",
        {
            "impacket": impacket_mod,
            "impacket.krb5": krb5_mod,
            "impacket.krb5.constants": krb5_const_mod,
            "impacket.krb5.kerberosv5": krb5_v5_mod,
            "impacket.krb5.types": types_mod,
            "impacket.krb5.ccache": ccache_mod,
        },
    ):
        res = krb_mod.extract_tickets(
            "10.0.0.1",
            creds={
                "user": "svc",
                "password": "p",
                "domain": "corp.local",
                "nthash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            },
        )
        assert "TGT obtained and saved" in res

    # Fallback paths
    with patch.dict("sys.modules", {"impacket.krb5.kerberosv5": None}):
        with patch("shutil.which", return_value="/bin/getTGT.py"):
            res2 = krb_mod.extract_tickets(
                "10.0.0.1",
                creds={"user": "svc", "password": "p", "domain": "corp.local"},
            )
            assert "getTGT CLI fallback is disabled" in res2

        with patch("shutil.which", return_value=None):
            res3 = krb_mod.extract_tickets(
                "10.0.0.1",
                creds={"user": "svc", "password": "p", "domain": "corp.local"},
            )
            assert "No impacket getTGT available" in res3


@pytest.mark.unit
def test_crack_tickets(tmp_path: Path):
    # Missing ticket file
    assert "Ticket file not found" in krb_mod.crack_tickets(str(tmp_path / "missing.txt"))

    ticket_file = tmp_path / "tickets.txt"
    ticket_file.write_text("ticket hash")

    # Missing wordlist
    assert "No wordlist found" in krb_mod.crack_tickets(str(ticket_file), wordlist=str(tmp_path / "missing_wl.txt"))

    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("password123\n")

    # Hashcat path
    with patch("shutil.which", side_effect=lambda x: "/bin/hashcat" if x == "hashcat" else None):
        with patch.object(krb_mod, "_run_cli", side_effect=["hashcat started", "hash:password123"]):
            res = krb_mod.crack_tickets(str(ticket_file), wordlist=str(wordlist), mode="kerberoast")
            assert "CRACKED HASHES" in res

    # John the Ripper path
    with patch("shutil.which", side_effect=lambda x: "/bin/john" if "john" in x else None):
        with patch.object(krb_mod, "_run_cli", side_effect=["john started", "password123 (user)"]):
            res = krb_mod.crack_tickets(str(ticket_file), wordlist=str(wordlist), mode="asrep")
            assert "CRACKED" in res

    # Neither found
    with patch("shutil.which", return_value=None):
        res = krb_mod.crack_tickets(str(ticket_file), wordlist=str(wordlist))
        assert "Neither hashcat nor john found in PATH" in res
