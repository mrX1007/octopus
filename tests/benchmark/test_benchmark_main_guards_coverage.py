"""Hermetic execution contracts for benchmark and lab ``__main__`` guards."""

from __future__ import annotations

import http.server
import runpy
import sys
from pathlib import Path
from typing import Any

import pytest

from core.benchmarks.v3 import fixture as v3_fixture

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

ROOT = Path(__file__).parents[2]
LAB_V1_APP = ROOT / "benchmarks" / "competitors" / "lab" / "app.py"
LAB_V2_APP = ROOT / "benchmarks" / "competitors" / "labs" / "discovery-lab-v2" / "app.py"
LAB_V3 = ROOT / "benchmarks" / "competitors" / "labs" / "discovery-lab-v3"


def test_core_v3_server_main_guard_rejects_missing_controller_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OCTOBENCH_V3_PRIVATE_MANIFEST", raising=False)
    monkeypatch.delenv("OCTOBENCH_V3_LEDGER_PATH", raising=False)
    monkeypatch.delitem(sys.modules, "core.benchmarks.v3.server", raising=False)

    with pytest.raises(
        SystemExit,
        match="private manifest and controller ledger paths are required",
    ):
        runpy.run_module("core.benchmarks.v3.server", run_name="__main__")


def test_v3_generate_and_reveal_main_guards_delegate_to_fixture_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[Any, ...]] = []
    family = v3_fixture.SCENARIO_FAMILIES[0]
    private_path = tmp_path / "private.json"
    reveal_path = tmp_path / "reveal.json"

    class Variant:
        def write_private_manifest(self, path: Path) -> None:
            calls.append(("write-private", path))

        def write_reveal_manifest(self, path: Path, *, campaign_closed: bool) -> None:
            calls.append(("write-reveal", path, campaign_closed))

    variant = Variant()

    def generate_fixture_variant(
        selected_family: str,
        *,
        matched_fixture_seed: int,
    ) -> Variant:
        calls.append(("generate", selected_family, matched_fixture_seed))
        return variant

    def load_private_fixture(path: Path) -> Variant:
        calls.append(("load-private", path))
        return variant

    monkeypatch.setattr(v3_fixture, "generate_fixture_variant", generate_fixture_variant)
    monkeypatch.setattr(v3_fixture, "load_private_fixture", load_private_fixture)
    monkeypatch.setattr(
        sys,
        "argv",
        ["generate.py", family, "73", str(private_path)],
    )
    runpy.run_path(str(LAB_V3 / "generate.py"), run_name="__main__")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reveal.py",
            str(private_path),
            str(reveal_path),
            "--campaign-closed",
        ],
    )
    runpy.run_path(str(LAB_V3 / "reveal.py"), run_name="__main__")

    assert calls == [
        ("generate", family, 73),
        ("write-private", private_path),
        ("load-private", private_path),
        ("write-reveal", reveal_path, True),
    ]


@pytest.mark.parametrize(
    ("app_path", "scenario_id"),
    [
        pytest.param(LAB_V1_APP, None, id="discovery-lab-v1"),
        pytest.param(
            LAB_V2_APP,
            "authorized-linked-navigation-small-model-v2",
            id="discovery-lab-v2",
        ),
    ],
)
def test_stateless_lab_main_guards_use_in_process_server_boundary(
    monkeypatch: pytest.MonkeyPatch,
    app_path: Path,
    scenario_id: str | None,
) -> None:
    instances: list[FakeHTTPServer] = []

    class FakeHTTPServer:
        def __init__(self, address: tuple[str, int], handler: type[Any]) -> None:
            self.address = address
            self.handler = handler
            self.poll_intervals: list[float] = []
            instances.append(self)

        def serve_forever(self, *, poll_interval: float) -> None:
            self.poll_intervals.append(poll_interval)

    monkeypatch.setattr(http.server, "ThreadingHTTPServer", FakeHTTPServer)
    monkeypatch.setenv("OCTOBENCH_LAB_HOST", "127.0.0.7")
    monkeypatch.setenv("OCTOBENCH_LAB_INTERNAL_PORT", "18080")
    if scenario_id is None:
        monkeypatch.delenv("OCTOBENCH_LAB_SCENARIO_ID", raising=False)
    else:
        monkeypatch.setenv("OCTOBENCH_LAB_SCENARIO_ID", scenario_id)

    runpy.run_path(str(app_path), run_name="__main__")

    assert len(instances) == 1
    server = instances[0]
    assert server.address == ("127.0.0.7", 18080)
    assert server.poll_intervals == [0.2]
    if scenario_id is not None:
        assert server.scenario_id == scenario_id


def test_v3_lab_main_guard_delegates_to_packaged_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.benchmarks.v3 import server

    calls: list[str] = []
    monkeypatch.setattr(server, "main", lambda: calls.append("main"))

    runpy.run_path(str(LAB_V3 / "app.py"), run_name="__main__")

    assert calls == ["main"]
