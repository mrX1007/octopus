"""Machine-readable legacy-retirement inventory contracts."""

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
    retained = {
        item["symbol_or_path"] for item in payload["retained_without_removal_date"]
    }

    assert {
        "benchmarks/competitors/results/linux-blackbox-small-model-v1-20260721t134205z",
        "benchmarks/competitors/results/linux-blackbox-small-model-v2-20260721t202413z",
    } <= retained


def test_deprecation_targets_symbols_and_declared_callers_are_current() -> None:
    assert validate_deprecations(ROOT) == len(
        yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["entries"]
    )


def test_removed_plaintext_credential_cache_is_not_still_scheduled() -> None:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))

    assert all(
        "_KNOWN_CREDS" not in entry["symbol_or_path"]
        for entry in payload["entries"]
    )
