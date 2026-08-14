"""Authentication and authorization types for Ingress leases and Principals."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class PrincipalRole(str, Enum):
    OPERATOR = "operator"
    SYSTEM = "system"
    ANONYMOUS = "anonymous"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    name: str
    role: PrincipalRole
    revision: int = 1


@dataclass(frozen=True)
class IngressChannelBinding:
    peer_uid: int
    peer_gid: int
    peer_pid: int
    transport_instance: str
    channel_binding: str


class IngressKind(str, Enum):
    INTERACTIVE_CLI = "interactive_cli"
    HTTP_API = "http_api"
    C2_CONTROL = "c2_control"
    INTERNAL_SERVICE = "internal_service"


class SubjectType(str, Enum):
    OPERATOR = "operator"
    SERVICE = "service"


class AuthenticationMethod(str, Enum):
    PASSWORD = "password"
    API_KEY = "api_key"
    MTLS = "mtls"
    OS_PEER_API_KEY = "os_peer_api_key"
    INTERNAL_ATTESTATION = "internal_attestation"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"


__all__ = [
    "ApprovalStatus",
    "AuthenticationMethod",
    "IngressChannelBinding",
    "IngressKind",
    "Principal",
    "PrincipalRole",
    "SubjectType",
]
