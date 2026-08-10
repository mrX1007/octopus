"""Machine-readable legacy-retirement inventory contracts."""

import ast
from pathlib import Path

import pytest
import yaml

from scripts.quality.docs_gate import validate_deprecations

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "deprecations.yaml"
REQUIRED_FIELDS = {
    "symbol_or_path",
    "current_owner",
    "replacement",
    "internal_callers",
    "public_compatibility_status",
    "warning_introduced_version",
    "planned_removal_version",
}


def test_deprecation_manifest_is_versioned_and_complete() -> None:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "1.0"
    entries = payload["entries"]
    assert entries
    assert len({entry["symbol_or_path"] for entry in entries}) == len(entries)
    for entry in entries:
        assert entry.keys() >= REQUIRED_FIELDS
        assert all(str(entry[field]).strip() for field in REQUIRED_FIELDS - {"internal_callers"})
        assert isinstance(entry["internal_callers"], list)


def test_published_benchmark_bundles_are_explicitly_retained() -> None:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    retained = {item["symbol_or_path"] for item in payload["retained_without_removal_date"]}

    assert {
        "benchmarks/competitors/results/linux-blackbox-small-model-v1-20260721t134205z",
        "benchmarks/competitors/results/linux-blackbox-small-model-v2-20260721t202413z",
    } <= retained


def test_deprecation_targets_symbols_and_declared_callers_are_current() -> None:
    assert validate_deprecations(ROOT) == len(yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["entries"])


def test_removed_plaintext_credential_cache_is_not_still_scheduled() -> None:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))

    assert all("_KNOWN_CREDS" not in entry["symbol_or_path"] for entry in payload["entries"])


def test_c2_evasion_is_an_exported_production_c2_module() -> None:
    package_tree = ast.parse((ROOT / "core" / "c2" / "__init__.py").read_text(encoding="utf-8"))
    exported_names = {
        value.value
        for node in package_tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and target.id == "__all__"
        if isinstance(node.value, (ast.List, ast.Tuple))
        for value in node.value.elts
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    }
    assert "evasion" in exported_names
    assert "aes_encrypt_payload" in exported_names
    assert "xor_encode" in exported_names



def test_readme_tooling_inventory_matches_code_owned_registries() -> None:
    import core.tools
    from core.ai.tool_registry import ToolRegistry
    from core.tools.registry import get_tool

    definitions = tuple(get_tool(name) for name in core.tools.BUILTIN_TOOL_NAMES)
    assert all(definition is not None for definition in definitions)
    registry = ToolRegistry()
    registered_count = len(definitions)
    alias_count = sum(len(definition.aliases) for definition in definitions)
    enabled_count = sum(bool(definition.enabled) for definition in definitions)
    disabled_count = registered_count - enabled_count
    leaf_providers = {provider for task in registry.task_map for provider in registry._tool_names_for_task(task)}
    normalized_readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())

    assert f"covered/registered: {registered_count}/{registered_count}" in normalized_readme
    assert (
        f"decorator inventory contains {registered_count} canonical names and {alias_count} unique aliases"
    ) in normalized_readme
    assert f"{enabled_count} are enabled and {disabled_count} are explicitly quarantined" in normalized_readme
    assert f"task map contains {len(leaf_providers)} enabled leaf providers" in normalized_readme
    assert f"all {len(registry.task_map)} conceptual task-map keys" in normalized_readme
    assert "one individual `PluginActionAdapter` per discovered class plugin" in normalized_readme
    assert "Registry coverage is a classification invariant, not a planner-reachability metric" in normalized_readme
