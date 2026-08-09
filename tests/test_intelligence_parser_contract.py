"""Passive search output remains reference evidence, never a finding."""

from __future__ import annotations

import pytest

from core.ai.evidence import OutputParser
from core.ai.parsers import IntelligenceParser, ParserFamilyPipeline

pytestmark = [pytest.mark.contract, pytest.mark.security]


def _pairs(facts: list[dict[str, object]]) -> set[tuple[object, object]]:
    return {(item["type"], item["value"]) for item in facts}


def test_intelligence_parser_is_exact_bounded_and_low_authority() -> None:
    output = (
        "[1] Advisory\n"
        "URL: https://example.test/advisory/CVE-2024-12345).\n"
        "Mirror: https://example.test/advisory/CVE-2024-12345\n"
        "CVE-2024-12345 CVE-2024-12345"
    )

    facts = IntelligenceParser().parse("search_cve", output, "session")

    assert _pairs(facts) == {
        ("external_reference", "https://example.test/advisory/CVE-2024-12345"),
        ("external_cve_reference", "CVE-2024-12345"),
    }
    assert all(int(item["confidence"]) <= 50 for item in facts)
    assert IntelligenceParser().parse("not_web_search", output, "session") == []


def test_family_and_output_pipeline_do_not_promote_search_text_to_vulnerability() -> None:
    output = "CVE-2025-54321\nURL: https://security.example.test/CVE-2025-54321"

    family_facts = ParserFamilyPipeline().parse("web_search", output, "session")
    output_facts = OutputParser().parse_tool_output("cve_lookup CVE-2025-54321", output)

    for facts in (family_facts, output_facts):
        types = {item["type"] for item in facts}
        assert "external_reference" in types
        assert "external_cve_reference" in types
        assert "potential_vulnerability" not in types
        assert "vulnerability" not in types
