#!/usr/bin/env python3

import time
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict


# ═══════════════════════════════════════════════
# NODE & EDGE TYPES
# ═══════════════════════════════════════════════

class NodeType(Enum):
    ASSET = "asset"
    IDENTITY = "identity"
    CREDENTIAL = "credential"
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


# ═══════════════════════════════════════════════
# NODE MODELS
# ═══════════════════════════════════════════════

@dataclass
class Asset:
    """A host or IP address in the target environment."""
    ip: str
    hostname: str = ""
    os: str = ""
    ports: List[int] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    rooted: bool = False
    first_seen: float = field(default_factory=time.time)

    @property
    def node_id(self) -> str:
        return f"asset:{self.ip}"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "hostname": self.hostname, "os": self.os,
            "ports": self.ports, "tags": self.tags, "rooted": self.rooted,
            "first_seen": self.first_seen,
        }


@dataclass
class Identity:
    """A user account (local, domain, or service)."""
    username: str
    domain: str = ""
    identity_type: str = "local"
    uid: int = -1
    shell: str = ""
    groups: List[str] = field(default_factory=list)

    @property
    def node_id(self) -> str:
        prefix = f"{self.domain}\\\\" if self.domain else ""
        return f"identity:{prefix}{self.username}"

    def to_dict(self) -> dict:
        return {
            "username": self.username, "domain": self.domain,
            "identity_type": self.identity_type, "uid": self.uid,
            "shell": self.shell, "groups": self.groups,
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

    @property
    def node_id(self) -> str:
        import hashlib
        secret_hash = hashlib.sha256(self.secret.encode()).hexdigest()[:8]
        return f"cred:{self.username}:{secret_hash}"

    def to_dict(self) -> dict:
        return {
            "username": self.username, "secret": self.secret,
            "secret_type": self.secret_type, "source": self.source,
            "verified": self.verified, "service": self.service,
            "host": self.host,
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
        return f"svc:{self.host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "host": self.host, "port": self.port, "protocol": self.protocol,
            "service_name": self.service_name, "version": self.version,
            "banner": self.banner, "state": self.state, "web_app": self.web_app,
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
        return f"sess:{self.session_id}"

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id, "session_type": self.session_type,
            "username": self.username, "host": self.host,
            "active": self.active, "opened_at": self.opened_at,
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
        return f"vuln:{self.vuln_id}"

    def to_dict(self) -> dict:
        return {
            "vuln_id": self.vuln_id, "name": self.name, "cvss": self.cvss,
            "severity": self.severity, "service": self.service,
            "confirmed": self.confirmed, "exploit_available": self.exploit_available,
            "description": self.description,
        }


@dataclass
class Campaign:
    """An offensive operation grouping targets and findings."""
    name: str
    objective: str = ""
    started_at: float = field(default_factory=time.time)
    targets: List[str] = field(default_factory=list)
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
