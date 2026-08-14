"""C2 deployment attempt records, states and probes (§16.6A)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal


class DeploymentAttemptState(str, Enum):
    RESERVED = "reserved"
    UPLOADING = "uploading"
    START_DISPATCHING = "start_dispatching"
    STARTED = "started"
    UNKNOWN_EFFECT = "unknown_effect"
    FAILED_NO_EFFECT = "failed_no_effect"
    RECONCILING = "reconciling"


class DeploymentProbeOutcome(str, Enum):
    NOT_STARTED = "not_started"
    STARTED = "started"
    FAILED_NO_EFFECT = "failed_no_effect"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DeploymentAttemptRecord:
    transaction_id: str
    deployment_attempt_id: str
    deployment_ref: str
    request_digest: str
    state: DeploymentAttemptState
    backend_probe_token: str | None
    revision: int


@dataclass(frozen=True)
class DeploymentStartReceipt:
    schema_version: Literal["1.0"]
    deployment_attempt_id: str
    deployment_ref: str
    state: Literal[DeploymentAttemptState.STARTED]
    backend_probe_token: str
    remote_effect_ref: str
    started_at: float
    receipt_digest: str


@dataclass(frozen=True)
class DeploymentAttemptProbe:
    schema_version: Literal["1.0"]
    deployment_attempt_id: str
    deployment_ref: str
    outcome: DeploymentProbeOutcome
    backend_probe_token: str | None
    remote_effect_ref: str | None
    observed_at: float
