#!/usr/bin/env python3
"""AST Inventory gate enforcing legacy descriptor.provider and provider_mounted usage restrictions."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Allowed files for V1 legacy provider field reads
REVIEWED_V1_ALLOWLIST: set[str] = {
    "core/actions/catalog.py",
    "core/actions/legacy_descriptor_decoder.py",
    "core/actions/models.py",
    "core/actions/base.py",
    "core/actions/adapters.py",
    "core/actions/adapters_ad_credential.py",
    "core/actions/adapters_ad_lateral.py",
    "core/actions/adapters_c2.py",
    "core/actions/adapters_evasion.py",
    "core/actions/adapters_kerberos.py",
    "core/actions/adapters_pivot.py",
    "core/ai/capability_assessment.py",
    "core/ai/runtime.py",
    "core/ai/tool_registry.py",
    "core/actions/selection.py",
    "core/tools/registry.py",
    "tests/test_capability_assessment.py",
    "tests/test_action_catalog.py",
    "tests/test_action_catalog_coverage.py",
    "tests/test_action_provider_contracts.py",
    "tests/test_action_adapters_new.py",
    "tests/test_action_base_coverage.py",
    "tests/test_architecture_ratchet.py",
    "tests/test_high_risk_action_contracts.py",
    "tests/test_runtime_plugin_catalog_contract.py",
    "tests/test_unified_tool_runtime_contract.py",
    "tests/test_provider_legacy_field_inventory.py",
}


class LegacyFieldVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.v1_reads: list[tuple[int, str]] = []
        self.v2_constructor_keywords: list[tuple[int, str]] = []

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in ("provider", "provider_mounted"):
            self.v1_reads.append((node.lineno, node.attr))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name == "ActionDescriptorV2":
            for keyword in node.keywords:
                if keyword.arg in ("provider", "provider_mounted"):
                    self.v2_constructor_keywords.append((keyword.lineno, keyword.arg or ""))
        self.generic_visit(node)


def audit_repository() -> tuple[list[str], list[str]]:
    unallowed_v1_reads: list[str] = []
    v2_keyword_violations: list[str] = []

    python_files = (
        list(PROJECT_ROOT.glob("core/**/*.py"))
        + list(PROJECT_ROOT.glob("tests/**/*.py"))
        + list(PROJECT_ROOT.glob("scripts/**/*.py"))
    )

    for path in python_files:
        rel_path = path.relative_to(PROJECT_ROOT).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel_path)
        except Exception:
            continue

        visitor = LegacyFieldVisitor(rel_path)
        visitor.visit(tree)

        if visitor.v2_constructor_keywords:
            for lineno, kw in visitor.v2_constructor_keywords:
                v2_keyword_violations.append(f"{rel_path}:{lineno} ActionDescriptorV2 cannot accept '{kw}' keyword")

        if visitor.v1_reads and rel_path not in REVIEWED_V1_ALLOWLIST:
            for lineno, attr in visitor.v1_reads:
                unallowed_v1_reads.append(f"{rel_path}:{lineno} Read legacy field '{attr}' in non-allowlisted module")

    return unallowed_v1_reads, v2_keyword_violations


def main() -> int:
    unallowed_reads, v2_violations = audit_repository()

    if v2_violations:
        print("ERROR: ActionDescriptorV2 constructor keyword violations detected:", file=sys.stderr)
        for v in v2_violations:
            print(f"  {v}", file=sys.stderr)

    if unallowed_reads:
        print("ERROR: Legacy descriptor provider field reads outside allowlist detected:", file=sys.stderr)
        for r in unallowed_reads:
            print(f"  {r}", file=sys.stderr)

    if v2_violations or unallowed_reads:
        return 1

    print("Legacy provider field inventory gate: OK (all reads inside reviewed V1 allowlist, 0 V2 violations)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
