"""Comprehensive unit tests for core/killchain/ad/enumeration.py."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import core.killchain.ad.enumeration as enum_mod


@pytest.mark.unit
def test_ldap_search_impacket_and_ldap3():
    target = "10.0.0.1"
    creds = {"user": "admin", "password": "pwd", "domain": "corp.local", "nthash": ""}

    class FakeSearchResultEntry:
        def __getitem__(self, item):
            if item == "objectName":
                return "CN=admin,DC=corp,DC=local"
            if item == "attributes":
                return [{"type": "sAMAccountName", "vals": ["admin"]}]
            return None

    class FakeLDAPConnection:
        def __init__(self, *args, **kwargs):
            pass

        def login(self, *args, **kwargs):
            pass

        def search(self, *args, **kwargs):
            return [FakeSearchResultEntry()]

    ldap_mod = SimpleNamespace(
        LDAPConnection=FakeLDAPConnection,
        SimplePagedResultsControl=lambda size: None,
    )
    asn1_mod = SimpleNamespace(SearchResultEntry=FakeSearchResultEntry)

    with patch.dict(
        "sys.modules",
        {
            "impacket.ldap": SimpleNamespace(ldap=ldap_mod, ldapasn1=asn1_mod),
            "impacket.ldap.ldap": ldap_mod,
            "impacket.ldap.ldapasn1": asn1_mod,
        },
    ):
        res = enum_mod._ldap_search_impacket(target, "DC=corp,DC=local", "(objectClass=*)", ["sAMAccountName"], creds)
        assert res is not None
        assert res[0]["sAMAccountName"] == "admin"

    # Mock ldap3 connection
    class FakeLdap3Server:
        def __init__(self, *args, **kwargs):
            pass

    class FakeAttr:
        value = "ldap3_admin"

    class FakeEntry:
        entry_dn = "CN=ldap3_admin,DC=corp,DC=local"

        def __getitem__(self, item):
            return FakeAttr()

    class FakeLdap3Connection:
        def __init__(self, *args, **kwargs):
            self.entries = [FakeEntry()]

        def bind(self):
            return True

        def search(self, *args, **kwargs):
            return True

        def unbind(self):
            pass

    class FakeExceptions:
        class LDAPKeyError(Exception):
            pass

    with patch.dict(
        "sys.modules",
        {
            "ldap3": SimpleNamespace(
                Server=FakeLdap3Server,
                Connection=FakeLdap3Connection,
                ALL=True,
                NTLM="NTLM",
                SIMPLE="SIMPLE",
                SUBTREE="SUBTREE",
                core=SimpleNamespace(exceptions=FakeExceptions),
            )
        },
    ):
        res_ldap3 = enum_mod._ldap_search_ldap3(
            target, "DC=corp,DC=local", "(objectClass=*)", ["sAMAccountName"], creds
        )
        assert res_ldap3 is not None
        assert res_ldap3[0]["sAMAccountName"] == "ldap3_admin"


@pytest.mark.unit
def test_ldap_search_cli_and_fallbacks():
    target = "10.0.0.1"
    creds = {"user": "admin", "password": "pwd", "domain": "corp.local", "nthash": ""}

    with patch("shutil.which", return_value="/bin/ldapsearch"):
        res = enum_mod._ldap_search_cli(target, "DC=corp,DC=local", "(objectClass=*)", ["sAMAccountName"], creds)
        assert "Credential-bearing ldapsearch CLI fallback is disabled" in res

    with patch("shutil.which", return_value=None):
        res_none = enum_mod._ldap_search_cli(target, "DC=corp,DC=local", "(objectClass=*)", ["sAMAccountName"], creds)
        assert "ldapsearch not found in PATH" in res_none

    with patch("core.killchain.ad.enumeration._ldap_search_impacket", return_value=None):
        with patch("core.killchain.ad.enumeration._ldap_search_ldap3", return_value=None):
            with patch("core.killchain.ad.enumeration._ldap_search_cli", return_value="cli fallback data"):
                u_out = enum_mod.enumerate_users(target, creds)
                assert "ldapsearch CLI" in u_out
                assert "cli fallback data" in u_out

                g_out = enum_mod.enumerate_groups(target, creds)
                assert "ldapsearch CLI" in g_out

                c_out = enum_mod.enumerate_computers(target, creds)
                assert "ldapsearch CLI" in c_out


@pytest.mark.unit
def test_bloodhound_ingest(tmp_path: Path):
    target = "10.0.0.1"
    creds = {"user": "admin", "password": "pwd", "domain": "corp.local", "nthash": ""}

    # bloodhound python module
    class FakeAD:
        def __init__(self, **kwargs):
            pass

        def dns_resolve(self, domain):
            pass

    class FakeBloodhound:
        def __init__(self, ad):
            pass

        def connect(self, user, pwd, dom):
            pass

        def run(self, collect, output_directory):
            Path(output_directory).mkdir(parents=True, exist_ok=True)
            (Path(output_directory) / "test.json").write_text("{}")

    loot_dir = tmp_path / "loot"
    with patch("os.path.expanduser", return_value=str(loot_dir)):
        with patch.dict(
            "sys.modules",
            {
                "bloodhound": SimpleNamespace(BloodHound=FakeBloodhound),
                "bloodhound.ad": SimpleNamespace(domain=SimpleNamespace(AD=FakeAD)),
                "bloodhound.ad.domain": SimpleNamespace(AD=FakeAD),
            },
        ):
            res = enum_mod.bloodhound_ingest(target, creds)
            assert "BloodHound data collected" in res

        # CLI fallback
        with patch.dict("sys.modules", {"bloodhound": None}):
            with patch("shutil.which", return_value="/bin/bloodhound-python"):
                res2 = enum_mod.bloodhound_ingest(target, creds)
                assert "BloodHound CLI fallback is disabled" in res2

            with patch("shutil.which", return_value=None):
                res3 = enum_mod.bloodhound_ingest(target, creds)
                assert "No BloodHound ingestor available" in res3
