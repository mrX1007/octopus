"""Unit tests for target_extraction.py."""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from core.actions.input_contracts import (
    C2CleanupInputV2,
    C2CleanupReason,
    C2DeploymentProfileId,
    C2EnrollmentIssueInput,
    DNSC2ChannelInputV2,
    SSHChainHopInputV2,
    SSHChainInputV2,
)
from core.actions.target_extraction import (
    ActionTargetExtractorRegistry,
    get_action_target_extractor_registry,
)
from core.c2.transport_catalog import DNSChannelConfig, DNSRecordType

pytestmark = pytest.mark.unit


def test_target_extractor_registry_errors():
    reg = ActionTargetExtractorRegistry()

    extractor = MagicMock()
    reg.register(
        action_id="act-1",
        input_schema_id="schema-1",
        input_type=dict,
        extractor=extractor,
    )

    # Duplicate registration
    with pytest.raises(ValueError, match="duplicate target extractor registration"):
        reg.register(
            action_id="act-1",
            input_schema_id="schema-1",
            input_type=dict,
            extractor=extractor,
        )

    # Unknown registration
    with pytest.raises(ValueError, match="no target extractor registered"):
        reg.extract_checked(
            action_id="act-unknown",
            input_schema_id="schema-unknown",
            decoded_input={},
            reference_snapshots=(),
        )

    # Runtime type mismatch
    with pytest.raises(TypeError, match="target extractor runtime type mismatch"):
        reg.extract_checked(
            action_id="act-1",
            input_schema_id="schema-1",
            decoded_input="not_a_dict",
            reference_snapshots=(),
        )


def test_default_registry_c2_and_ssh_extractors():
    reg = get_action_target_extractor_registry()

    # SSH chain
    ssh_in = SSHChainInputV2(
        hops=(SSHChainHopInputV2(target="10.0.0.2", port=22, credential_ref="cred://1"),),
    )
    ssh_targets = reg.extract_checked(
        action_id="killchain:pivot_ssh_chain",
        input_schema_id="octopus:input:pivot_ssh_chain:2.0",
        decoded_input=ssh_in,
        reference_snapshots=(),
    )
    assert len(ssh_targets) == 2

    # DNS C2 channel
    dns_in = DNSC2ChannelInputV2(
        target="10.0.0.3",
        config=DNSChannelConfig(
            domain="c2.example.com",
            record_type=DNSRecordType.TXT,
            listen_address="127.0.0.1",
            listen_port=53,
        ),
    )
    dns_targets = reg.extract_checked(
        action_id="c2:dns_c2_channel",
        input_schema_id="octopus:input:dns_c2_channel:2.0",
        decoded_input=dns_in,
        reference_snapshots=(),
    )
    assert len(dns_targets) == 2

    # C2 enroll
    enroll_in = C2EnrollmentIssueInput(
        channel_ref="c2://1",
        target="10.0.0.5",
        profile_id=C2DeploymentProfileId.PYTHON_AGENT,
        agent_protocol_version="12.0",
        ttl_seconds=3600,
    )
    enroll_targets = reg.extract_checked(
        action_id="c2:c2_enroll",
        input_schema_id="octopus:input:c2_enroll:2.0",
        decoded_input=enroll_in,
        reference_snapshots=(),
    )
    assert len(enroll_targets) == 2

    # C2 cleanup
    clean_in = C2CleanupInputV2(
        resource_ref="c2://1",
        reason=C2CleanupReason.OPERATOR_REQUEST,
    )
    clean_targets = reg.extract_checked(
        action_id="c2:c2_cleanup",
        input_schema_id="octopus:input:c2_cleanup:2.0",
        decoded_input=clean_in,
        reference_snapshots=(),
    )
    assert len(clean_targets) == 1
