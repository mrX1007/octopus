#!/usr/bin/env python3

import time
from dataclasses import dataclass, field
from enum import Enum

from core.secrets import get_redactor, is_secret_ref

from .identity import (
    ENTITY_NORMALIZATION_VERSION,
    canonical_asset,
    canonical_credential,
    canonical_endpoint,
    canonical_identity,
    canonical_service,
    canonical_session,
    canonical_vulnerability,
)

# NODE & EDGE TYPES

class NodeType(Enum):
    ASSET = "asset"
    IDENTITY = "identity"
    CREDENTIAL = "credential"
    ENDPOINT = "endpoint"
    SERVICE = "service"
    SESSION = "session"
    VULNERABILITY = "vulnerability"
    CAMPAIGN = "campaign"


class EdgeType(Enum):
    RUNS_SERVICE = "runs_service"           # Asset → Service
    HAS_CREDENTIAL = "has_credential"       # Identity → Credential
    CAN_ACCESS = "can_access"               # Credential → Asset
    TRUSTS = "trusts"                       # Asset → Asset
    VULNERABLE_TO = "vulnerable_to"         # Service → Vulnerability
    MEMBER_OF = "member_of"                 # Asset → Campaign
    ACTIVE_SESSION = "active_session"       # Identity → Session
    SESSION_TO = "session_to"               # Session → Asset
    EXPLOITED_BY = "exploited_by"           # Vulnerability → Exploit name
    DISCOVERED_BY = "discovered_by"         # Any → Tool name
    HAS_IDENTITY = "has_identity"           # Asset → Identity (local users)
    PIVOTS_TO = "pivots_to"                 # Asset → Asset (lateral movement)
    EXPOSES_ENDPOINT = "exposes_endpoint"   # Service → Endpoint
    HAS_VULNERABILITY = "has_vulnerability" # Asset → Vulnerability
    DISCOVERED_ASSET = "discovered_asset"   # Asset → Asset


# NODE MODELS

@dataclass
class Asset:
    """A host or IP address in the target environment."""
    ip: str
    hostname: str = ""
    os: str = ""
    ports: list[int] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    rooted: bool = False
    first_seen: float = field(default_factory=time.time)

    @property
    def node_id(self) -> str:
        return canonical_asset(self.ip).entity_id

    @property
    def legacy_node_ids(self) -> tuple[str, ...]:
        return canonical_asset(self.ip).aliases

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "hostname": self.hostname, "os": self.os,
            "ports": self.ports, "tags": self.tags, "rooted": self.rooted,
            "first_seen": self.first_seen,
            "canonical_id": self.node_id,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
        }


@dataclass
class Identity:
    """A user account (local, domain, or service)."""
    username: str
    domain: str = ""
    identity_type: str = "local"
    uid: int = -1
    shell: str = ""
    groups: list[str] = field(default_factory=list)
    host: str = ""

    @property
    def node_id(self) -> str:
        return canonical_identity(
            self.username,
            domain=self.domain,
            identity_type=self.identity_type,
            host=self.host,
        ).entity_id

    @property
    def legacy_node_ids(self) -> tuple[str, ...]:
        return canonical_identity(
            self.username,
            domain=self.domain,
            identity_type=self.identity_type,
            host=self.host,
        ).aliases

    def to_dict(self) -> dict:
        return {
            "username": self.username, "domain": self.domain,
            "identity_type": self.identity_type, "uid": self.uid,
            "shell": self.shell, "groups": self.groups, "host": self.host,
            "canonical_id": self.node_id,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
        }


@dataclass
class Credential:
    """A credential pair (username + secret)."""
    username: str
    secret: str
    secret_type: str = "password"
    source: str = ""
    verified: bool = False
    service: str = ""
    host: str = ""

    def __post_init__(self) -> None:
        if self.secret and not is_secret_ref(self.secret):
            self.secret = get_redactor().protect(self.secret, kind=self.secret_type or "credential")

    @property
    def node_id(self) -> str:
        return canonical_credential(
            self.username,
            self.secret,
            service=self.service,
            host=self.host,
            secret_type=self.secret_type,
        ).entity_id

    @property
    def legacy_node_ids(self) -> tuple[str, ...]:
        return canonical_credential(
            self.username,
            self.secret,
            service=self.service,
            host=self.host,
            secret_type=self.secret_type,
        ).aliases

    def to_dict(self) -> dict:
        return {
            "username": self.username, "secret": self.secret,
            "secret_type": self.secret_type, "source": self.source,
            "verified": self.verified, "service": self.service,
            "host": self.host,
            "canonical_id": self.node_id,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
        }


@dataclass
class Service:
    """A network service running on a host."""
    host: str
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    version: str = ""
    banner: str = ""
    state: str = "open"
    web_app: str = ""

    @property
    def node_id(self) -> str:
        return canonical_service(self.host, self.port, self.protocol).entity_id

    @property
    def legacy_node_ids(self) -> tuple[str, ...]:
        return canonical_service(self.host, self.port, self.protocol).aliases

    def to_dict(self) -> dict:
        return {
            "host": self.host, "port": self.port, "protocol": self.protocol,
            "service_name": self.service_name, "version": self.version,
            "banner": self.banner, "state": self.state, "web_app": self.web_app,
            "canonical_id": self.node_id,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
        }


@dataclass
class Endpoint:
    """A canonical HTTP(S) endpoint exposed by a service."""

    url: str
    service: str = ""
    status: str = ""
    title: str = ""

    @property
    def node_id(self) -> str:
        return canonical_endpoint(self.url).entity_id

    @property
    def legacy_node_ids(self) -> tuple[str, ...]:
        return canonical_endpoint(self.url).aliases

    def to_dict(self) -> dict:
        identity = canonical_endpoint(self.url)
        return {
            **dict(identity.components),
            "service": self.service,
            "status": self.status,
            "title": self.title,
            "canonical_id": self.node_id,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
        }


@dataclass
class Session:
    """An active connection to a target."""
    session_id: str
    session_type: str = "ssh"
    username: str = ""
    host: str = ""
    active: bool = True
    opened_at: float = field(default_factory=time.time)

    @property
    def node_id(self) -> str:
        return canonical_session(
            self.session_id,
            session_type=self.session_type,
            username=self.username,
            host=self.host,
        ).entity_id

    @property
    def legacy_node_ids(self) -> tuple[str, ...]:
        return canonical_session(
            self.session_id,
            session_type=self.session_type,
            username=self.username,
            host=self.host,
        ).aliases

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id, "session_type": self.session_type,
            "username": self.username, "host": self.host,
            "active": self.active, "opened_at": self.opened_at,
            "canonical_id": self.node_id,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
        }


@dataclass
class Vulnerability:
    """A confirmed or suspected vulnerability."""
    vuln_id: str
    name: str = ""
    cvss: float = 0.0
    severity: str = "medium"
    service: str = ""
    confirmed: bool = False
    exploit_available: bool = False
    description: str = ""

    @property
    def node_id(self) -> str:
        return canonical_vulnerability(self.vuln_id).entity_id

    @property
    def legacy_node_ids(self) -> tuple[str, ...]:
        return canonical_vulnerability(self.vuln_id).aliases

    def to_dict(self) -> dict:
        return {
            "vuln_id": self.vuln_id, "name": self.name, "cvss": self.cvss,
            "severity": self.severity, "service": self.service,
            "confirmed": self.confirmed, "exploit_available": self.exploit_available,
            "description": self.description,
            "canonical_id": self.node_id,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
        }


@dataclass
class Campaign:
    """An offensive operation grouping targets and findings."""
    name: str
    objective: str = ""
    started_at: float = field(default_factory=time.time)
    targets: list[str] = field(default_factory=list)
    status: str = "active"

    @property
    def node_id(self) -> str:
        return f"campaign:{self.name}"

    def to_dict(self) -> dict:
        return {
            "name": self.name, "objective": self.objective,
            "started_at": self.started_at, "targets": self.targets,
            "status": self.status,
        }
