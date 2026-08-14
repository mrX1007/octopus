"""Tests for the closed remote-execution operation catalog."""

from __future__ import annotations

import pytest

from core.actions.operation_catalog import RemoteExecOperationCatalog, RemoteExecOperationId, RemoteExecService
from core.c2.build_models import (
    BuildTemplateSource,
    C2DeploymentSource,
    PrebuiltArtifactSource,
    deployment_source_kind,
)
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.task_catalog import (
    C2TaskOperationId,
    HostInventoryTaskPayload,
    IdentityTaskPayload,
    TaskOperationCatalog,
    operation_for_payload,
)

pytestmark = pytest.mark.unit


def test_remote_exec_service_enum_exact_values_and_single_owner() -> None:
    assert tuple(item.value for item in RemoteExecService) == ("smb", "winrm", "dcom")


def test_operation_catalog_accepts_only_closed_ids() -> None:
    catalog = RemoteExecOperationCatalog()
    assert tuple(item.operation_id for item in catalog.entries()) == tuple(RemoteExecOperationId)
    assert catalog.require(RemoteExecOperationId.IDENTITY).output_schema_id.endswith("identity:1.0")
    with pytest.raises(ValueError, match="RemoteExecOperationId"):
        catalog.require("whoami")  # type: ignore[arg-type]


def test_unknown_operation_id_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported C2 task operation"):
        TaskOperationCatalog().require_payload_type("c2-operation://identity")  # type: ignore[arg-type]


def test_wrong_task_payload_variant_rejected() -> None:
    with pytest.raises(ValueError, match="payload variant mismatch"):
        TaskOperationCatalog().validate(
            C2TaskOperationId.IDENTITY,
            HostInventoryTaskPayload(
                include_processes=False,
                include_services=False,
                max_items=1,
            ),
        )


def test_deployment_source_union_is_closed() -> None:
    prebuilt = PrebuiltArtifactSource("artifact://one", "rebind://one")
    template = BuildTemplateSource(
        "template://one",
        C2TargetOS.LINUX,
        C2TargetArch.AMD64,
    )
    assert deployment_source_kind(prebuilt) == "prebuilt_artifact"
    assert deployment_source_kind(template) == "build_template"


def test_unknown_deployment_source_rejected() -> None:
    with pytest.raises(AssertionError, match="unreachable"):
        deployment_source_kind(object())  # type: ignore[arg-type]


def test_closed_unions_are_exhaustive() -> None:
    assert operation_for_payload(IdentityTaskPayload()) is C2TaskOperationId.IDENTITY
    assert (
        deployment_source_kind(
            BuildTemplateSource(
                "template://one",
                C2TargetOS.LINUX,
                C2TargetArch.AMD64,
            )
        )
        == "build_template"
    )
    assert C2DeploymentSource is not object
