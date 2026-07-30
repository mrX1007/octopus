"""Focused edge-case coverage for the mission-store codec layer."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from core.ai.mission_store_codecs import MissionStoreCodecMixin
from core.ai.mission_store_models import (
    _MAX_OUTCOME_BYTES,
    _MAX_RETRY_COMMAND_KEYS,
    BackoffStrategy,
    MissionStoreError,
    RetryErrorClass,
    TaskBackoff,
    TaskRetryNotAllowed,
)
from core.ai.outcomes import TaskOutcome
from core.knowledge.identity import canonical_asset

pytestmark = pytest.mark.unit


class _Codec(MissionStoreCodecMixin):
    def __init__(self, redactor=None):
        self.redactor = redactor


class _MissingRow(dict):
    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError as exc:
            raise IndexError(key) from exc


def _outcome(**overrides):
    values = {
        "agent": "agent",
        "task": "task",
        "status": "completed",
        "reason": "done",
        "new_facts": 1,
        "parsed_facts": 1,
        "commands": ({"command": "probe"},),
        "duration": 1.0,
    }
    values.update(overrides)
    return TaskOutcome(**values)


def test_scope_coercion_covers_mapping_sequence_and_invalid_shapes():
    codec = _Codec()
    entity_id = canonical_asset("192.0.2.1").entity_id

    from_string = codec._coerce_task_scope({"entity_ids": entity_id})
    from_sequence = codec._coerce_task_scope({"canonical_entity_ids": [entity_id]})
    legacy_mapping = codec._coerce_task_scope({"display": "legacy"})
    top_level_sequence = codec._coerce_task_scope([entity_id])

    assert from_string.entity_ids == (entity_id,)
    assert from_sequence.entity_ids == (entity_id,)
    assert json.loads(legacy_mapping.legacy_scope) == {"display": "legacy"}
    assert top_level_sequence.entity_ids == (entity_id,)
    with pytest.raises(MissionStoreError, match="entity_ids"):
        codec._coerce_task_scope({"entity_ids": object()})
    with pytest.raises(MissionStoreError, match="TaskScope"):
        codec._coerce_task_scope(object())


@pytest.mark.parametrize("encoded", ["[]", '{"entity_ids":"bad"}', "{"])
def test_decode_scope_rejects_corrupt_payloads(encoded):
    with pytest.raises(MissionStoreError, match="persisted task scope"):
        _Codec._decode_task_scope(encoded)


def test_decode_scope_supplies_missing_entity_list():
    assert _Codec._decode_task_scope("{}").entity_ids == ()


def test_capability_version_and_timestamp_validation():
    canonical = "capability:v2:" + "A" * 16

    assert _Codec._capability_id(canonical) == canonical.casefold()
    assert _Codec._capability_id("Network Discovery").startswith("capability:v1:")
    assert _Codec._not_before("1.5") == 1.5
    with pytest.raises(MissionStoreError, match="capability_id"):
        _Codec._capability_id(" ")
    with pytest.raises(MissionStoreError, match="definition version"):
        _Codec._task_definition_version("bad version")
    for value in (True, object(), -1, float("nan")):
        with pytest.raises(MissionStoreError, match="not_before"):
            _Codec._not_before(value)


def test_requested_time_participates_in_retry_gate():
    none = TaskBackoff()
    fixed = TaskBackoff(strategy=BackoffStrategy.FIXED, base_delay_seconds=5)

    assert _Codec._retry_not_before(10, 1, none, None) is None
    assert _Codec._retry_not_before(10, 1, none, 12) == 12
    assert _Codec._retry_not_before(10, 1, fixed, 20) == 20


@pytest.mark.parametrize("encoded", ["[]", '{"strategy":"unknown"}', "{"])
def test_decode_backoff_rejects_corrupt_payloads(encoded):
    with pytest.raises(MissionStoreError, match="persisted task backoff"):
        _Codec._decode_backoff(encoded)


def test_stable_key_requires_keyed_redactor_store():
    with pytest.raises(MissionStoreError, match="keyed identity"):
        _Codec(SimpleNamespace())._stable_key("kind", "value")


def test_redactor_compatibility_fallbacks_and_absent_redactor():
    class LegacyRedactor:
        def redact_text(self, text, **kwargs):
            if kwargs:
                raise TypeError("legacy signature")
            return f"safe:{text}"

        def redact_data(self, value, **kwargs):
            if kwargs:
                raise TypeError("legacy signature")
            return [*value, {"legacy": True}]

    legacy = _Codec(LegacyRedactor())

    assert legacy._safe_text("value", "kind", 100) == "safe:value"
    assert legacy._safe_data([{"a": 1}])[-1] == {"legacy": True}
    assert _Codec()._safe_text("value", "kind", 100) == "value"
    marker = object()
    assert _Codec()._safe_data(marker) is marker


def test_retry_keys_and_fact_ids_reject_invalid_values():
    codec = _Codec()
    too_many = tuple(f"key-{index}" for index in range(_MAX_RETRY_COMMAND_KEYS + 1))

    with pytest.raises(MissionStoreError, match="allowlist"):
        codec._safe_retry_command_keys(too_many)
    with pytest.raises(MissionStoreError, match="integers"):
        codec._safe_fact_ids((object(),))
    with pytest.raises(MissionStoreError, match="positive"):
        codec._safe_fact_ids((0,))


def test_safe_outcome_requires_redacted_commands_to_remain_a_list():
    redactor = SimpleNamespace(
        redact_data=lambda _value, **_kwargs: {"not": "a list"},
        redact_text=lambda value, **_kwargs: value,
    )

    with pytest.raises(MissionStoreError, match="remain a list"):
        _Codec(redactor)._safe_outcome(_outcome(), agent="agent", task="task")


def test_encode_outcome_rejects_oversized_payload():
    oversized = _outcome(reason="x" * (_MAX_OUTCOME_BYTES + 1))

    with pytest.raises(MissionStoreError, match="durable payload limit"):
        _Codec._encode_outcome(oversized)


@pytest.mark.parametrize("encoded", ["{", "[]"])
def test_decode_outcome_rejects_corrupt_payload(encoded):
    with pytest.raises(MissionStoreError, match="corrupt persisted"):
        _Codec._decode_outcome(encoded)


def test_tuple_loaders_tolerate_legacy_corruption():
    assert _Codec._load_string_tuple("{") == ()
    assert _Codec._load_string_tuple("{}") == ()
    assert _Codec._load_int_tuple("{") == ()
    assert _Codec._load_int_tuple("{}") == ()
    assert _Codec._load_int_tuple('[1,"bad",2]') == (1, 2)


@pytest.mark.parametrize("encoded", ["{", "{}", '["", "ok"]'])
def test_state_replan_signature_loader_rejects_corruption(encoded):
    with pytest.raises(MissionStoreError, match="state replan signatures"):
        _Codec._load_state_replan_signatures(encoded)


def test_state_replan_row_compatibility_and_bounds():
    assert _Codec._state_replan_count_from_row(_MissingRow()) == 0
    assert _Codec._state_replan_signatures_from_row(_MissingRow()) == ()
    with pytest.raises(MissionStoreError, match="state replan count"):
        _Codec._state_replan_count_from_row(_MissingRow(state_replan_count=-1))


def test_retry_error_class_and_loader_reject_unknown_values():
    assert _Codec._retry_error_class(RetryErrorClass.TIMEOUT) is RetryErrorClass.TIMEOUT
    with pytest.raises(TaskRetryNotAllowed, match="unsupported"):
        _Codec._retry_error_class("unknown")
    for encoded in ("{}", '["unknown"]', "{"):
        with pytest.raises(MissionStoreError, match="retry error classes"):
            _Codec._load_retry_error_classes(encoded)
