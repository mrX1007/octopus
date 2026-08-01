"""Typed fact predicates and durable observation-trust helpers.

This module deliberately keeps decision predicates separate from free-form
fact rendering.  State transitions must be based on an exact fact type and a
fully parsed value, never on a substring that target-controlled text can
accidentally (or deliberately) contain.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

TRUSTED = "trusted"
TARGET_CONTROLLED = "target_controlled"
UNTRUSTED = "untrusted"

FACT_TRUST_LEVELS = frozenset({TRUSTED, TARGET_CONTROLLED, UNTRUSTED})
NON_DECISION_TRUST_LEVELS = frozenset({TARGET_CONTROLLED, UNTRUSTED})

_TRUST_ALIASES = {
    "trusted": TRUSTED,
    "verified": TRUSTED,
    "authoritative": TRUSTED,
    "target_controlled": TARGET_CONTROLLED,
    "target_controlled_stdout": TARGET_CONTROLLED,
    "untrusted": UNTRUSTED,
    "untrusted_stdout": UNTRUSTED,
    "llm_extracted": UNTRUSTED,
}

_METHOD_TRUST = {
    "target_controlled": TARGET_CONTROLLED,
    "target_controlled_stdout": TARGET_CONTROLLED,
    "untrusted": UNTRUSTED,
    "untrusted_stdout": UNTRUSTED,
    "llm_extracted": UNTRUSTED,
}

_WEB_FACT_TYPES = frozenset(
    {
        "browser_rendered",
        "web_title",
        "web_surface",
        "web_input",
        "web_endpoint",
        "web_link",
        "web_server",
        "web_redirect",
        "web_powered_by",
    }
)
_VULNERABILITY_FACT_TYPES = frozenset(
    {
        "nuclei_finding",
        "vulnerability",
        "vulnerability_claim",
        "potential_vulnerability",
        "verified_vulnerability",
        "vulnerability_candidate",
        "vulnerability_endpoint",
        "exploit_success",
    }
)
_SECURITY_FINDING_FACT_TYPES = frozenset(
    {
        "ad_acl_issue",
        "ad_adcs_issue",
        "ad_attack_path",
        "ad_delegation",
        "ad_gpo_issue",
        "ad_high_value_object",
        "ad_local_admin_path",
        "api_security_note",
        "cloud_finding",
        "code_finding",
        "misconfiguration",
        "proxy_finding",
        "secret_finding",
        "web_security_note",
    }
)
_DECISION_MODEL_FACT_TYPES = frozenset(
    {
        "active_command",
        "ad_domain",
        "ad_computers",
        "ad_enumeration",
        "ad_graph_data",
        "ad_groups",
        "ad_object",
        "ad_password_policy",
        "ad_users",
        "api_endpoint",
        "app_manifest",
        "app_stack",
        "asset_domain",
        "asset_ip",
        "asset_service",
        "asset_url",
        "candidate",
        "check_result",
        "config_candidate",
        "container_runtime",
        "cve_candidate",
        "database_inventory",
        "dns_record",
        "domain",
        "endpoint",
        "exploit_attempted",
        "exploit_candidate",
        "exploit_reference",
        "finding",
        "host",
        "hostname",
        "http_status",
        "internal_host",
        "internal_service",
        "internal_subnet",
        "js_route",
        "jwt_metadata",
        "kernel_version",
        "local_listening_port",
        "msf_module",
        "network_edge",
        "network_node",
        "os_version",
        "privesc_vector",
        "privilege_context",
        "scheduled_task_surface",
        "service_version",
        "smb_status",
        "subdomain",
        "technology",
        "verification_command",
        "version_match",
        "vulnerability_hypothesis",
        "web_path",
        "web_root",
    }
)
_CREDENTIAL_FACT_TYPES = frozenset(
    {
        "credential",
        "credential_material",
    }
)
_AUTHORITY_FACT_TYPES = frozenset(
    {
        "application_access",
        "domain_hash_dump",
        "hash_material",
        "inferred_claim",
        "kerberos_hashes",
        "lateral_access",
        "remote_execution",
        "system_access",
        "verified_access",
        "verified_claim",
    }
)
_WEB_SERVICES = frozenset(
    {
        "http",
        "https",
        "ssl/http",
        "http-alt",
        "http-proxy",
        "https-alt",
        "cpanel",
        "whm",
        "tomcat",
    }
)
_WEB_PORTS = frozenset(
    {
        80,
        443,
        2082,
        2083,
        2086,
        2087,
        8000,
        8008,
        8080,
        8081,
        8443,
        8888,
        9000,
    }
)

_PORT_VALUE_RE = re.compile(
    r"^(?:(?P<host>\S+):)?"
    r"(?P<port>\d{1,5})/(?P<protocol>tcp|udp)"
    r"(?:\s+(?:\((?P<parenthesized>[^()\r\n]+)\)|"
    r"(?P<bare>[a-z0-9][a-z0-9+./_-]*)))?"
    r"(?:\s+\[[^\[\]\r\n]*\])?$",
    re.IGNORECASE,
)
_ROOT_SSH_LOGIN_RE = re.compile(r"^ssh_login_success:root@[^\s@]+$", re.IGNORECASE)
_SYSTEM_EXPLOIT_RE = re.compile(
    r"^(?:cve-\d{4}-\d+\s+)?"
    r"(?:pwnkit|dirty\s*pipe|dirtycow|baron\s+samedit)\s+"
    r"(?:root\s+access|root\s+shell|uid=0|local\s+privilege\s+escalation)$",
    re.IGNORECASE,
)
_FILES_EXFILTRATED_RE = re.compile(r"^files_exfiltrated:(\d+)$", re.IGNORECASE)
_COMPLETED_ARTIFACT_RE = re.compile(r"^completed:[^\s].*$", re.IGNORECASE)


def _token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().casefold()).strip("_")


def canonical_trust_level(
    value: Any,
    *,
    observation_method: Any = "",
    default: str = TRUSTED,
) -> str:
    """Return one closed-set trust level; unknown explicit labels fail closed.

    Missing trust remains trusted only for compatibility with direct internal
    ``FactStore.add_fact`` callers.  A known target-controlled observation
    method always supplies an explicit lower default for ingestion paths that
    cannot yet pass a dedicated trust argument.
    """

    explicit = _token(value)
    if explicit:
        return _TRUST_ALIASES.get(explicit, UNTRUSTED)
    method = _token(observation_method)
    if method in _METHOD_TRUST:
        return _METHOD_TRUST[method]
    normalized_default = _TRUST_ALIASES.get(_token(default))
    return normalized_default or UNTRUSTED


def aggregate_observation_trust(
    observations: Iterable[Mapping[str, Any]],
    *,
    default: str = TRUSTED,
) -> str:
    """Aggregate observation trust without allowing untrusted corroboration.

    One trusted observation is enough to keep a real fact usable, preventing a
    later target-controlled duplicate from downgrading it.  With no trusted
    observation the aggregate remains fail-closed.
    """

    levels = tuple(
        canonical_trust_level(
            observation.get("trust_level"),
            observation_method=observation.get("observation_method"),
            default=default,
        )
        for observation in observations
        if isinstance(observation, Mapping)
    )
    if not levels:
        return canonical_trust_level(None, default=default)
    if TRUSTED in levels:
        return TRUSTED
    if TARGET_CONTROLLED in levels:
        return TARGET_CONTROLLED
    return UNTRUSTED


def fact_trust_level(fact: Mapping[str, Any]) -> str:
    """Resolve a fact's trust from durable observations when available."""

    observations = tuple(
        item
        for item in (fact.get("observations") or ())
        if isinstance(item, Mapping)
    )
    if observations:
        return aggregate_observation_trust(observations)
    return canonical_trust_level(
        fact.get("trust_level"),
        observation_method=fact.get("observation_method"),
        default=TRUSTED,
    )


def fact_type(fact: Mapping[str, Any]) -> str:
    return str(fact.get("type") or "").strip().casefold()


def fact_value(fact: Mapping[str, Any]) -> str:
    return str(fact.get("value") or "").strip().casefold()


@dataclass(frozen=True)
class PortObservation:
    """A fully parsed ``port_open`` value."""

    port: int
    protocol: str
    service: str
    rendered: str

    @property
    def is_web(self) -> bool:
        return self.port in _WEB_PORTS or self.service in _WEB_SERVICES

    @property
    def is_ssh(self) -> bool:
        return self.port == 22 or self.service == "ssh"


def parse_port_open(fact: Mapping[str, Any]) -> PortObservation | None:
    """Parse an exact ``port_open`` fact; embedded port substrings do not count."""

    if fact_type(fact) != "port_open":
        return None
    rendered = fact_value(fact)
    match = _PORT_VALUE_RE.fullmatch(rendered)
    if match is None:
        return None
    port = int(match.group("port"))
    if not 1 <= port <= 65535:
        return None
    service = str(match.group("parenthesized") or match.group("bare") or "").casefold()
    return PortObservation(
        port=port,
        protocol=match.group("protocol").casefold(),
        service=service,
        rendered=rendered,
    )


def is_web_fact(fact: Mapping[str, Any]) -> bool:
    return fact_type(fact) in _WEB_FACT_TYPES


def web_fact_port(fact: Mapping[str, Any]) -> PortObservation | None:
    """Return the actual/default URL port for a typed web fact, if present."""

    if not is_web_fact(fact):
        return None
    raw_value = str(fact.get("value") or "").strip()
    if not raw_value:
        return None
    candidate: Any = raw_value
    try:
        decoded = json.loads(raw_value)
    except (TypeError, ValueError, json.JSONDecodeError):
        decoded = None
    if isinstance(decoded, Mapping):
        candidate = decoded.get("url") or ""
        scheme = str(decoded.get("scheme") or "").strip().casefold()
        raw_port = decoded.get("port")
        try:
            explicit_port = int(str(raw_port)) if raw_port is not None else None
        except (TypeError, ValueError):
            explicit_port = None
        if explicit_port is not None and 1 <= explicit_port <= 65535:
            service = "https" if scheme == "https" else "http" if scheme == "http" else ""
            rendered = (
                f"{explicit_port}/tcp ({service})"
                if service
                else f"{explicit_port}/tcp"
            )
            return PortObservation(explicit_port, "tcp", service, rendered)
    if not isinstance(candidate, str):
        return None
    try:
        parsed = urlsplit(candidate)
        explicit_port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return None
    port = explicit_port or (443 if scheme == "https" else 80)
    return PortObservation(port, "tcp", scheme, f"{port}/tcp ({scheme})")


def is_vulnerability_fact(fact: Mapping[str, Any]) -> bool:
    return fact_type(fact) in _VULNERABILITY_FACT_TYPES


def confirms_credentials(fact: Mapping[str, Any]) -> bool:
    return fact_type(fact) in _CREDENTIAL_FACT_TYPES and bool(fact_value(fact))


def confirms_root(fact: Mapping[str, Any]) -> bool:
    current_type = fact_type(fact)
    current_value = fact_value(fact)
    if current_type == "system_access":
        return current_value in {"uid=0", "root_access_confirmed"}
    return current_type == "credential" and _ROOT_SSH_LOGIN_RE.fullmatch(current_value) is not None


def confirms_system_access_exploit(value: Any) -> bool:
    return _SYSTEM_EXPLOIT_RE.fullmatch(str(value or "").strip()) is not None


def confirms_persistence(fact: Mapping[str, Any]) -> bool:
    return fact_type(fact) == "persistence" and fact_value(fact) in {
        "mechanism_planted",
        "ssh_key_injected",
    }


def confirms_cleanup(fact: Mapping[str, Any]) -> bool:
    return fact_type(fact) in {
        "cleanup",
        "cleanup_action",
        "cleanup_outcome",
        "cleanup_status",
    } and fact_value(fact) in {
        "success",
        "partial",
        "completed",
    }


def confirms_exfiltration(fact: Mapping[str, Any]) -> bool:
    current_type = fact_type(fact)
    current_value = fact_value(fact)
    if current_type == "post_exploit_stage":
        return current_value == "data_exfiltration_completed"
    if current_type not in {"data_exfiltration", "data_exfiltration_status"}:
        return False
    if current_value in {"completed", "complete", "loot_collected"}:
        return True
    match = _FILES_EXFILTRATED_RE.fullmatch(current_value)
    if match is not None:
        return int(match.group(1)) > 0
    return _COMPLETED_ARTIFACT_RE.fullmatch(current_value) is not None


def fact_is_decision_critical(fact: Mapping[str, Any]) -> bool:
    """Return whether this exact fact shape can advance a decision gate."""

    current_type = fact_type(fact)
    current_value = fact_value(fact)
    if current_type in _AUTHORITY_FACT_TYPES:
        return True
    if current_type in _SECURITY_FINDING_FACT_TYPES:
        return True
    if current_type in _DECISION_MODEL_FACT_TYPES:
        return True
    if parse_port_open(fact) is not None or is_web_fact(fact):
        return True
    if is_vulnerability_fact(fact) or confirms_credentials(fact) or confirms_root(fact):
        return True
    if confirms_persistence(fact) or confirms_exfiltration(fact) or confirms_cleanup(fact):
        return True
    if current_type == "internal_network":
        return True
    if current_type == "post_exploit_stage":
        return current_value in {
            "post_access_inventory_completed",
            "internal_network_recon_completed",
            "data_exfiltration_completed",
        }
    if current_type in {"service_status", "stage_status"}:
        # Status facts affect coverage, scheduling, negative evidence and stage
        # selection throughout the pipeline.  Treat the whole typed family as
        # decision-critical; individual producers still need a tool-bound
        # schema before ingestion marks one trusted.
        return bool(current_value)
    return False


__all__ = [
    "FACT_TRUST_LEVELS",
    "NON_DECISION_TRUST_LEVELS",
    "TARGET_CONTROLLED",
    "TRUSTED",
    "UNTRUSTED",
    "PortObservation",
    "aggregate_observation_trust",
    "canonical_trust_level",
    "confirms_cleanup",
    "confirms_credentials",
    "confirms_exfiltration",
    "confirms_persistence",
    "confirms_root",
    "confirms_system_access_exploit",
    "fact_is_decision_critical",
    "fact_trust_level",
    "fact_type",
    "fact_value",
    "is_vulnerability_fact",
    "is_web_fact",
    "parse_port_open",
    "web_fact_port",
]
