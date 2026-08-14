"""Ingress session models."""

from __future__ import annotations

import math
from dataclasses import dataclass

from core.auth.types import (
    AuthenticationMethod,
    IngressChannelBinding,
    IngressKind,
    Principal,
    SubjectType,
)


@dataclass(frozen=True)
class IngressSession:
    session_id: str
    principal: Principal
    channel_binding: IngressChannelBinding
    revision: int = 1
    revoked: bool = False


@dataclass(frozen=True)
class IngressSessionAuthorizationSnapshot:
    schema_version: str
    ingress_session_ref: str
    revision: int
    principal_ref: str
    subject_id: str
    subject_type: SubjectType
    authentication_method: AuthenticationMethod
    ingress_kind: IngressKind
    authenticated_peer_id: str
    transport_binding_digest: str
    issued_at: float
    expires_at: float
    revoked_at: float | None

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("ingress snapshot schema version is unsupported")
        for name in (
            "ingress_session_ref",
            "principal_ref",
            "subject_id",
            "authenticated_peer_id",
            "transport_binding_digest",
        ):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("ingress snapshot revision must be positive")
        if (
            type(self.subject_type) is not SubjectType
            or type(self.authentication_method) is not AuthenticationMethod
            or type(self.ingress_kind) is not IngressKind
        ):
            raise ValueError("ingress snapshot enums must be canonical")
        if not math.isfinite(self.issued_at) or not math.isfinite(self.expires_at) or self.expires_at <= self.issued_at:
            raise ValueError("ingress snapshot lifetime is invalid")
        if self.revoked_at is not None and (not math.isfinite(self.revoked_at) or self.revoked_at < self.issued_at):
            raise ValueError("ingress revocation timestamp is invalid")


__all__ = [
    "IngressSession",
    "IngressSessionAuthorizationSnapshot",
]
