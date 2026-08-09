"""Defensive contracts for privilege-escalation checks and adapter discovery."""

from __future__ import annotations

import importlib
from types import ModuleType
from unittest.mock import Mock

import pytest

registry = importlib.import_module("core.killchain.exploits")
base = importlib.import_module("core.killchain.exploits.base")
baron_samedit = importlib.import_module("core.killchain.exploits.baron_samedit")
dirtycow = importlib.import_module("core.killchain.exploits.dirtycow")
dirtypipe = importlib.import_module("core.killchain.exploits.dirtypipe")
pwnkit = importlib.import_module("core.killchain.exploits.pwnkit")
privesc = importlib.import_module("core.killchain.privesc")

ExploitBase = base.ExploitBase
ExploitResult = base.ExploitResult

pytestmark = [pytest.mark.unit, pytest.mark.security]


class _SafeExploit(ExploitBase):
    name = "Safe applicability check"
    cve = "CVE-2099-0001"

    def __init__(self) -> None:
        self.run_calls = 0

    def check_vulnerable(self, _client) -> tuple[bool, str]:
        return False, "not applicable"

    def run(self, _client) -> tuple[bool, str]:
        self.run_calls += 1
        raise AssertionError("a negative applicability check must never execute")


class _Client:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


def test_exploit_result_tuple_uses_bounded_precedence() -> None:
    assert ExploitResult(success=True, output="output", evidence="evidence", error="error").as_tuple() == (
        True,
        "output",
    )
    assert ExploitResult(evidence="evidence", error="error").as_tuple() == (False, "evidence")
    assert ExploitResult(error="error").as_tuple() == (False, "error")


def test_check_result_normalization_accepts_legacy_shapes_without_execution() -> None:
    exploit = _SafeExploit()
    existing = ExploitResult(success=False, evidence="existing")

    assert exploit.normalize_check_result(existing) is existing

    vulnerable = exploit.normalize_check_result((True, "matched safely"))
    assert vulnerable.success is True
    assert vulnerable.status == "vulnerable"
    assert vulnerable.output == "matched safely"
    assert {fact["type"] for fact in vulnerable.facts} == {"vulnerability", "exploit_success"}

    empty_tuple = exploit.normalize_check_result(())
    assert empty_tuple.success is False
    assert empty_tuple.status == "not_vulnerable"
    assert empty_tuple.evidence == ""

    mapping = exploit.normalize_check_result(
        {
            "vulnerable": False,
            "status": "inconclusive",
            "name": "mapped check",
            "cve": "CVE-2099-0002",
            "details": "insufficient evidence",
            "output": "bounded output",
            "facts": [{"type": "service_status", "value": "unavailable"}],
            "artifacts": ["temporary-artifact"],
            "error": "dependency unavailable",
        }
    )
    assert mapping.status == "inconclusive"
    assert mapping.name == "mapped check"
    assert mapping.evidence == "insufficient evidence"
    assert mapping.output == "bounded output"
    assert mapping.facts == [{"type": "service_status", "value": "unavailable"}]
    assert mapping.artifacts == ["temporary-artifact"]
    assert mapping.credentials == []
    assert mapping.error == "dependency unavailable"

    unsupported = exploit.normalize_check_result(None)
    assert unsupported.success is False
    assert unsupported.evidence == "None"
    assert unsupported.output == "None"


def test_run_result_normalization_changes_status_but_never_invokes_adapter() -> None:
    exploit = _SafeExploit()

    success = exploit.normalize_run_result((True, "verified result"))
    failure = exploit.normalize_run_result((False, "denied result"))

    assert success.status == "success"
    assert any(fact["type"] == "exploit_success" for fact in success.facts)
    assert failure.status == "failed"
    assert any(fact["type"] == "potential_vulnerability" for fact in failure.facts)
    assert exploit.run_calls == 0


def test_fact_projection_handles_unknown_identifier_and_bounded_evidence() -> None:
    exploit = _SafeExploit()
    negative = exploit._facts_from_status(False, "x" * 200)

    assert negative[0] == {
        "type": "potential_vulnerability",
        "value": exploit.cve,
        "confidence": 60,
    }
    assert negative[1]["type"] == "service_status"
    assert len(negative[1]["value"].split(":", 1)[1]) == 120

    class UnknownExploit(_SafeExploit):
        cve = "CVE-Unknown"

    assert UnknownExploit()._facts_from_status(False, "") == []
    assert UnknownExploit()._facts_from_status(True, "") == [
        {
            "type": "exploit_success",
            "value": "CVE-Unknown:Safe applicability check",
            "confidence": 95,
        }
    ]


def test_registry_orders_modules_and_ignores_packages_and_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        registry.pkgutil,
        "iter_modules",
        lambda _paths: [
            (None, "zeta", False),
            (None, "dirtycow", False),
            (None, "base", False),
            (None, "nested", True),
            (None, "pwnkit", False),
        ],
    )

    assert registry._module_names() == ["pwnkit", "dirtycow", "zeta"]


def test_registry_skips_import_failures_foreign_classes_and_non_adapters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qualified_name = "core.killchain.exploits.valid"
    module = ModuleType(qualified_name)
    valid_class = type("ValidExploit", (_SafeExploit,), {"__module__": qualified_name})
    foreign_class = type("ForeignExploit", (_SafeExploit,), {"__module__": "another.module"})
    plain_class = type("PlainClass", (), {"__module__": qualified_name})
    module.ValidExploit = valid_class  # type: ignore[attr-defined]
    module.ForeignExploit = foreign_class  # type: ignore[attr-defined]
    module.PlainClass = plain_class  # type: ignore[attr-defined]
    module.ExploitBase = ExploitBase  # type: ignore[attr-defined]
    monkeypatch.setattr(registry, "_module_names", lambda: ["missing", "valid"])

    def import_module(name: str) -> ModuleType:
        if name.endswith(".missing"):
            raise ImportError("optional module unavailable")
        assert name == qualified_name
        return module

    monkeypatch.setattr(registry.importlib, "import_module", import_module)

    assert list(registry.iter_exploit_classes()) == [valid_class]


def test_registry_contains_adapter_initialization_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    class GoodExploit(_SafeExploit):
        pass

    class BrokenExploit(_SafeExploit):
        def __init__(self) -> None:
            raise RuntimeError("initialization rejected")

    monkeypatch.setattr(registry, "iter_exploit_classes", lambda: iter((GoodExploit, BrokenExploit)))

    loaded = registry.get_privesc_exploits()

    assert len(loaded) == 1
    assert isinstance(loaded[0], GoodExploit)


@pytest.mark.parametrize(
    ("responses", "expected_success", "expected_evidence"),
    [
        ([""], False, "Cannot determine sudo version"),
        (["sudo release unknown"], False, "Cannot parse sudo version"),
        (["Sudo version 2.0.0", "normal response"], False, "not vulnerable"),
        (["Sudo version 1.9.5p1", "normal response"], True, "vulnerable range"),
        (["Sudo version 2.0.0", "usage: denied"], True, "Possibly vulnerable"),
        (["Sudo version 2.0.0", "Segmentation fault"], True, "CONFIRMED VULNERABLE"),
    ],
)
def test_baron_samedit_check_classifies_only_mocked_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[str],
    expected_success: bool,
    expected_evidence: str,
) -> None:
    ssh_exec = Mock(side_effect=responses)
    monkeypatch.setattr(baron_samedit, "_ssh_exec", ssh_exec)

    success, evidence = baron_samedit.BaronSameditExploit().check_vulnerable(object())

    assert success is expected_success
    assert expected_evidence in evidence
    assert ssh_exec.call_count == len(responses)


@pytest.mark.parametrize(
    ("kernel", "expected_success", "expected_evidence"),
    [
        ("", False, "Could not determine kernel version"),
        ("3.10.0-test", True, "appears vulnerable"),
        ("6.8.0-current", False, "does not appear vulnerable"),
    ],
)
def test_dirtycow_check_uses_mocked_kernel_only(
    monkeypatch: pytest.MonkeyPatch,
    kernel: str,
    expected_success: bool,
    expected_evidence: str,
) -> None:
    ssh_exec = Mock(return_value=kernel)
    monkeypatch.setattr(dirtycow, "_ssh_exec", ssh_exec)

    success, evidence = dirtycow.DirtyCowExploit().check_vulnerable(object())

    assert success is expected_success
    assert expected_evidence in evidence
    ssh_exec.assert_called_once()


@pytest.mark.parametrize(
    ("kernel", "expected_success", "expected_evidence"),
    [
        ("", False, "Could not determine kernel version"),
        ("unparseable", False, "Cannot parse kernel version"),
        ("5.8.0", True, "appears vulnerable"),
        ("5.10.101", True, "appears vulnerable"),
        ("5.10.102", False, "does not appear vulnerable"),
        ("5.15.24", True, "appears vulnerable"),
        ("5.15.25", False, "does not appear vulnerable"),
        ("5.16.10", True, "appears vulnerable"),
        ("5.16.11", False, "does not appear vulnerable"),
        ("5.17.0", False, "does not appear vulnerable"),
        ("4.19.0", False, "does not appear vulnerable"),
    ],
)
def test_dirtypipe_version_parser_covers_fixed_and_affected_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    kernel: str,
    expected_success: bool,
    expected_evidence: str,
) -> None:
    ssh_exec = Mock(return_value=kernel)
    monkeypatch.setattr(dirtypipe, "_ssh_exec", ssh_exec)

    success, evidence = dirtypipe.DirtyPipeExploit().check_vulnerable(object())

    assert success is expected_success
    assert expected_evidence in evidence
    ssh_exec.assert_called_once()


@pytest.mark.parametrize(
    ("responses", "expected_success", "expected_evidence"),
    [
        ([""], False, "pkexec is not installed"),
        (["/usr/bin/pkexec", "pkexec 0.105", ""], False, "NOT SUID root"),
        (["/usr/bin/pkexec", "pkexec 0.105", "/usr/bin/pkexec"], True, "SUID root"),
    ],
)
def test_pwnkit_check_stops_on_missing_or_non_suid_binary(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[str],
    expected_success: bool,
    expected_evidence: str,
) -> None:
    ssh_exec = Mock(side_effect=responses)
    monkeypatch.setattr(pwnkit, "_ssh_exec", ssh_exec)

    success, evidence = pwnkit.PwnKitExploit().check_vulnerable(object())

    assert success is expected_success
    assert expected_evidence in evidence
    assert ssh_exec.call_count == len(responses)


@pytest.mark.parametrize(
    ("module", "exploit_class"),
    [
        (baron_samedit, baron_samedit.BaronSameditExploit),
        (pwnkit, pwnkit.PwnKitExploit),
    ],
    ids=["baron-samedit", "pwnkit"],
)
def test_run_entrypoints_stop_after_negative_applicability_check(
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    exploit_class: type[ExploitBase],
) -> None:
    exploit = exploit_class()
    check = Mock(return_value=(False, "not applicable"))
    ssh_exec = Mock(side_effect=AssertionError("execution must not begin"))
    monkeypatch.setattr(exploit, "check_vulnerable", check)
    monkeypatch.setattr(module, "_ssh_exec", ssh_exec)

    success, output = exploit.run(object())

    assert success is False
    assert "not applicable" in output
    check.assert_called_once()
    ssh_exec.assert_not_called()


def test_privesc_closes_client_when_identity_inventory_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _Client()
    monkeypatch.setattr(privesc, "_ssh_connect", lambda *_args: (client, ""))
    monkeypatch.setattr(privesc, "_ssh_exec", Mock(side_effect=RuntimeError("identity unavailable")))

    with pytest.raises(RuntimeError, match="identity unavailable"):
        privesc.run_privesc("host.example", "tester", "")

    assert client.close_calls == 1


@pytest.mark.parametrize("with_adapter", [False, True], ids=["missing-adapters", "negative-adapter"])
def test_privesc_no_vector_path_blocks_credential_replay_and_closes(
    monkeypatch: pytest.MonkeyPatch,
    with_adapter: bool,
) -> None:
    client = _Client()
    adapter = _SafeExploit()
    fake_paramiko = ModuleType("paramiko")
    fake_paramiko.SSHClient = Mock(side_effect=AssertionError("authentication must not start"))  # type: ignore[attr-defined]
    fake_paramiko.AutoAddPolicy = Mock(side_effect=AssertionError("authentication must not start"))  # type: ignore[attr-defined]
    fake_paramiko.AuthenticationException = RuntimeError  # type: ignore[attr-defined]
    monkeypatch.setattr(privesc, "paramiko", fake_paramiko)
    monkeypatch.setattr(privesc, "_ssh_connect", lambda *_args: (client, ""))
    monkeypatch.setattr(privesc, "_run_linpeas", lambda *_args, **_kwargs: ("[!] unavailable\n", []))
    monkeypatch.setattr(privesc, "_PRIVESC_CHECKS", [])
    monkeypatch.setattr(privesc, "get_privesc_exploits", lambda: (adapter,) if with_adapter else ())

    def ssh_exec(_client: object, command: str, **_kwargs: object) -> str:
        if command == "id":
            return "uid=1000(tester) gid=1000(tester)"
        if command.startswith("cat /etc/passwd"):
            return ""
        if command.startswith("uname -r"):
            return "6.8.0-current"
        raise AssertionError(f"unexpected diagnostic command: {command}")

    monkeypatch.setattr(privesc, "_ssh_exec", ssh_exec)

    output = privesc.run_privesc("host.example", "tester", "")

    assert "No obvious privesc vectors found" in output
    assert "Cross-account password testing is disabled" in output
    assert "Section timeout (25s)" not in output
    assert "No root obtained" in output
    if with_adapter:
        assert "Loaded kernel exploit adapters" in output
    else:
        assert "Kernel exploit adapters are not enabled" in output
    assert adapter.run_calls == 0
    assert client.close_calls == 1
