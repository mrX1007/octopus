"""Coverage contracts for small package-level public APIs."""

from __future__ import annotations

import types
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit


def test_benchmark_package_rejects_unknown_exports_and_lists_public_names() -> None:
    import core.benchmarks as benchmarks

    with pytest.raises(AttributeError, match="has no attribute 'unknown_export'"):
        _ = benchmarks.unknown_export

    assert "BenchmarkHarness" in benchmarks.__dir__()


def test_action_catalog_reports_registry_mismatches(monkeypatch: pytest.MonkeyPatch) -> None:
    import core.actions as actions

    monkeypatch.setattr(actions, "register_tool_adapters", lambda *_args: None)

    with pytest.raises(RuntimeError) as exc_info:
        actions.build_action_catalog(
            lambda _command, _context: None,
            tool_defs=[SimpleNamespace(name="Expected Tool")],
        )

    assert "missing=expected tool; unexpected=none" in str(exc_info.value)


def test_pipeline_mixin_missing_attributes_fail_normally() -> None:
    from core.ai.pipeline_types import PipelineMixinBase

    with pytest.raises(AttributeError, match="missing_collaborator"):
        _ = PipelineMixinBase().missing_collaborator


def test_c2_channels_package_exports_dns_channel() -> None:
    from core.c2.channels import DNSChannel
    from core.c2.channels.dns import DNSChannel as ConcreteDNSChannel

    assert DNSChannel is ConcreteDNSChannel


def test_exploit_registry_skips_imports_and_filters_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import core.killchain.exploits as registry

    class GoodExploit(registry.ExploitBase):
        def check_vulnerable(self, client):
            return False, ""

        def run(self, client):
            return False, ""

    class ForeignExploit(GoodExploit):
        pass

    class Unrelated:
        pass

    GoodExploit.__module__ = f"{registry.__name__}.mixed"
    Unrelated.__module__ = GoodExploit.__module__
    module = types.SimpleNamespace(__name__=GoodExploit.__module__)

    def import_module(name: str):
        if name.endswith(".missing"):
            raise ImportError("optional adapter unavailable")
        return module

    monkeypatch.setattr(registry, "_module_names", lambda: ["missing", "mixed"])
    monkeypatch.setattr(registry.importlib, "import_module", import_module)
    monkeypatch.setattr(
        registry.inspect,
        "getmembers",
        lambda *_args, **_kwargs: [
            ("base", registry.ExploitBase),
            ("foreign", ForeignExploit),
            ("unrelated", Unrelated),
            ("valid", GoodExploit),
        ],
    )

    assert list(registry.iter_exploit_classes()) == [GoodExploit]


def test_exploit_registry_skips_classes_that_fail_to_initialize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import core.killchain.exploits as registry

    class WorkingExploit(registry.ExploitBase):
        def check_vulnerable(self, client):
            return False, ""

        def run(self, client):
            return False, ""

    class BrokenExploit(WorkingExploit):
        def __init__(self) -> None:
            raise RuntimeError("broken adapter")

    monkeypatch.setattr(
        registry,
        "iter_exploit_classes",
        lambda: iter((BrokenExploit, WorkingExploit)),
    )

    exploits = registry.get_privesc_exploits()

    assert len(exploits) == 1
    assert isinstance(exploits[0], WorkingExploit)
