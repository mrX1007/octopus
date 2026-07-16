"""Release-cleanup contracts for removed duplicates and production simulations."""

from __future__ import annotations

import asyncio

import pytest

from core.exploits.exploit_mapper import ExploitIntelligenceEngine
from core.recon.recon_engine import ReconEngine
from core.tools.base import ToolResult
from core.tools.exploit_tools import ToolResult as LegacyToolResult

pytestmark = [pytest.mark.contract, pytest.mark.security]


def test_legacy_tool_result_import_is_canonical_alias():
    result = LegacyToolResult(
        tool_name="fixture",
        command="fixture --safe",
        stdout="ok",
    )

    assert LegacyToolResult is ToolResult
    assert str(result) == "ok"
    assert result == "ok"
    assert result.timestamp


def test_payload_adapter_requires_explicit_bounded_template(tmp_path):
    template = tmp_path / "template.txt"
    template.write_text("destination=__LHOST__:__LPORT__\n", encoding="utf-8")
    engine = ExploitIntelligenceEngine(str(tmp_path / "intel.db"))

    rendered = engine.adapt_payload(str(template), "127.0.0.1", 4444)

    assert rendered == "destination=127.0.0.1:4444\n"
    assert "__LHOST__" not in rendered
    assert "__LPORT__" not in rendered


def test_payload_adapter_rejects_missing_template_placeholders(tmp_path):
    template = tmp_path / "template.txt"
    template.write_text("no substitution markers", encoding="utf-8")
    engine = ExploitIntelligenceEngine(str(tmp_path / "intel.db"))

    with pytest.raises(ValueError, match="payload_template_missing_placeholders"):
        engine.adapt_payload(str(template), "127.0.0.1", 4444)

    with pytest.raises(ValueError, match="invalid_lport"):
        engine.adapt_payload(str(template), "127.0.0.1", 0)


def test_recon_probe_closes_connection_after_partial_failure(monkeypatch):
    class Writer:
        closed = False
        waited = False

        def write(self, _data):
            return None

        async def drain(self):
            raise asyncio.TimeoutError

        def close(self):
            self.closed = True

        async def wait_closed(self):
            self.waited = True

    writer = Writer()

    async def open_connection(_target, _port):
        return object(), writer

    monkeypatch.setattr(asyncio, "open_connection", open_connection)

    async def run_probe():
        engine = ReconEngine(concurrency=1)
        await engine._grab_banner("127.0.0.1", 443)

    asyncio.run(run_probe())

    assert writer.closed is True
    assert writer.waited is True
