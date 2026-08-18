"""Comprehensive unit tests for core/killchain/orchestrator.py."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import core.killchain.orchestrator as orch
from core.credentials import CredentialRef


class FakeContextManager:
    def __init__(self, username="admin", password="pwd"):
        self.username = username
        self.password = password

    def __enter__(self):
        return SimpleNamespace(username=self.username, password=self.password)

    def __exit__(self, *args):
        pass


@pytest.mark.unit
def test_sanitize_credential_text():
    assert orch.sanitize_credential_text("plain text", "") == "plain text"
    assert orch.sanitize_credential_text("my secret password", "secret") == "my [REDACTED] password"


@pytest.mark.unit
def test_resolve_killchain_credential():
    ref = CredentialRef(
        handle="credential://default/ssh/10.0.0.1/admin",
        service="ssh",
        target="10.0.0.1",
        username="admin",
        port=22,
    )

    with patch("core.killchain.orchestrator.resolve_credential_handle", return_value=ref):
        resolved, err = orch._resolve_killchain_credential(
            "10.0.0.1",
            user=None,
            password=None,
            credential="credential://default/ssh/10.0.0.1/admin",
            port=22,
        )
        assert resolved == ref
        assert err == ""

    # Ambiguous inputs
    _, err_ambig = orch._resolve_killchain_credential(
        "10.0.0.1",
        user="admin",
        password="pwd",
        credential="credential://default/ssh/10.0.0.1/admin",
        port=22,
    )
    assert "Plaintext credential arguments are prohibited" in err_ambig or "Ambiguous" in err_ambig


@pytest.mark.unit
def test_ssh_connect_under_revealed_lease():
    ref = CredentialRef(
        handle="credential://default/ssh/10.0.0.1/admin",
        service="ssh",
        target="10.0.0.1",
        username="admin",
        port=22,
    )

    mock_client = MagicMock()
    with patch(
        "core.killchain.orchestrator.credential_material_for_execution",
        return_value=FakeContextManager(username="admin", password="pwd"),
    ):
        with patch("core.killchain.orchestrator._ssh_connect", return_value=(mock_client, "")):
            client, err = orch._connect_with_credential("10.0.0.1", ref, 22)
            assert client is mock_client
            assert err == ""

        with patch("core.killchain.orchestrator._ssh_connect", side_effect=Exception("Connection refused")):
            client, err = orch._connect_with_credential("10.0.0.1", ref, 22)
            assert client is None
            assert "Exception" in err


@pytest.mark.unit
def test_run_full_killchain_no_creds():
    with patch("core.killchain.orchestrator.vuln_assess", return_value="[VULN ASSESS]"):
        with patch("core.killchain.orchestrator.auto_exploit", return_value="[EXPLOIT]"):
            res = orch.run_full_killchain("10.0.0.1", credential=None, callback_host="10.0.0.2")
            assert "[VULN ASSESS]" in res
            assert "[EXPLOIT]" in res
            assert "No SSH credentials available" in res


@pytest.mark.unit
def test_run_full_killchain_with_credential(tmp_path: Path):
    ref = CredentialRef(
        handle="credential://default/ssh/10.0.0.1/admin",
        service="ssh",
        target="10.0.0.1",
        username="admin",
        port=22,
    )
    root_ref = CredentialRef(
        handle="credential://default/ssh/10.0.0.1/root",
        service="ssh",
        target="10.0.0.1",
        username="root",
        port=22,
    )

    with (
        patch("core.killchain.orchestrator.resolve_credential_handle", return_value=ref),
        patch(
            "core.killchain.orchestrator.call_credential_provider",
            side_effect=lambda cred, fn: fn(SimpleNamespace(username=cred.username, password="pwd")),
        ),
        patch("core.killchain.orchestrator.run_privesc", return_value="ROOT ACCESS CONFIRMED uid=0(root)"),
    ):
        with patch("core.killchain.orchestrator.get_best_credential_ref", return_value=root_ref):
            with patch("core.killchain.orchestrator._connect_with_credential", return_value=(MagicMock(), "")):
                with patch("core.killchain.orchestrator.plant_persistence", return_value="[PERSISTENCE]"):
                    with patch("core.killchain.orchestrator.lateral_move", return_value="[LATERAL]"):
                        with patch("core.killchain.orchestrator.data_exfil", return_value="[EXFIL]"):
                            with patch("core.killchain.orchestrator.stealth_cleanup", return_value="[CLEANUP]"):
                                with patch.object(orch.os.path, "expanduser", return_value=str(tmp_path)):
                                    res = orch.run_full_killchain(
                                        "10.0.0.1",
                                        credential=ref.handle,
                                        callback_host="10.0.0.2",
                                    )
                                    assert "Re-authenticated as root" in res
                                    assert "[PERSISTENCE]" in res
                                    assert "[LATERAL]" in res
                                    assert "[EXFIL]" in res
                                    assert "[CLEANUP]" in res


@pytest.mark.unit
def test_generate_target_report(tmp_path: Path):
    loot_dir = tmp_path / "loot"
    loot_dir.mkdir(parents=True)

    full_output = """
    CVE-2021-4034 vulnerable!
    CVE-2022-0847 vulnerable!
    SSH PRIVATE KEY found: /root/.ssh/id_rsa
    shadow file contents:
    root: $6$hashvalue$1234567890:18000:0:99999:7:::
    Internal subnet: 192.168.1.0/24
    DISCOVERED INTERNAL HOSTS: 3
    → 192.168.1.50
    PRIVILEGE ESCALATION: 1
    Persistence methods planted: 2
    Hosts compromised: 1
    Files exfiltrated: 5
    """

    exfil_files = [{"remote": "/etc/passwd", "local": str(loot_dir / "passwd"), "size": 1234}]

    orch._generate_target_report(
        "10.0.0.1",
        "admin",
        str(loot_dir),
        exfil_files,
        full_output,
    )

    report_path = loot_dir / "10_0_0_1_report.txt"
    assert report_path.exists()
    content = report_path.read_text()
    assert "OCTOPUS TARGET INTELLIGENCE REPORT" in content
    assert "/root/.ssh/id_rsa" in content
    assert "192.168.1.0/24" in content
    assert "Data Exfiltration: 5" in content
