#!/usr/bin/env python3
"""Deterministic evidence adapters for native reconnaissance providers."""

from __future__ import annotations

import json
import re
import shlex
from collections import Counter
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from .common import BaseParser, Fact, check_result_fact, fact, tool_identity

_TLS_PROTOCOL = re.compile(r"(?im)^\s*(SSLv2|SSLv3|TLSv1(?:\.0|\.1|\.2|\.3)?)\s+(enabled|disabled)\s*$")
_TLS_CIPHER = re.compile(r"(?im)^\s*(Preferred|Accepted)\s+(SSLv\d|TLSv\d(?:\.\d)?)\s+(\d+)\s+bits\s+(\S+)")
_SMB_SHARE = re.compile(r"^\s*(\S(?:.*?\S)?)\s{2,}(Disk|IPC|Printer|Device)\s*(.*?)\s*$", re.IGNORECASE)


def _clean(value: Any, limit: int = 160) -> str:
    return " ".join(str(value or "").split())[:limit]


def _identity(tool_name: str) -> str:
    return tool_identity(tool_name)


def _arguments(tool_name: str) -> list[str]:
    try:
        return shlex.split(str(tool_name or ""))[1:]
    except ValueError:
        return str(tool_name or "").split()[1:]


def _target_argument(tool_name: str) -> str:
    for argument in _arguments(tool_name):
        if not argument.startswith("-"):
            return _clean(argument, 300)
    return ""


def _host_scope(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return "unknown"
    try:
        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        return (parsed.hostname or candidate).strip().lower()[:255]
    except ValueError:
        return candidate.lower()[:255]


def _canonical_url(value: str, *, default_scheme: str = "http") -> str:
    candidate = str(value or "").strip().strip("'\"").rstrip(".,);]")
    if not candidate or len(candidate) > 2_048:
        return ""
    if not re.match(r"^https?://", candidate, re.IGNORECASE):
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", candidate):
            return ""
        candidate = f"{default_scheme}://{candidate}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    netloc = parsed.hostname.casefold()
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def _same_authority(left: str, right: str) -> bool:
    try:
        left_parsed = urlsplit(left)
        right_parsed = urlsplit(right)
        left_port = left_parsed.port or (443 if left_parsed.scheme == "https" else 80)
        right_port = right_parsed.port or (443 if right_parsed.scheme == "https" else 80)
    except ValueError:
        return False
    return left_parsed.hostname == right_parsed.hostname and left_port == right_port


def _endpoint_value(url: str, status: str = "") -> str:
    canonical = _canonical_url(url)
    if not canonical:
        return ""
    parsed = urlsplit(canonical)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    encoded = json.dumps(
        {
            "host": parsed.hostname or "",
            "path": parsed.path or "/",
            "port": str(port),
            "scheme": parsed.scheme,
            "service": "",
            "status": str(status),
            "title": "",
            "url": canonical,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return encoded if len(encoded) <= 500 else ""


def _line_value(raw_output: str, labels: tuple[str, ...]) -> str:
    label_pattern = "|".join(re.escape(label) for label in labels)
    match = re.search(rf"(?im)^\s*(?:{label_pattern})\s*:\s*(.+?)\s*$", raw_output or "")
    return _clean(match.group(1), 180) if match else ""


class ReconEvidenceParser(BaseParser):
    """Parse formats emitted by the registry's native reconnaissance tools."""

    family = "recon_evidence"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        tool = _identity(tool_name)
        if tool == "waf_detect":
            return self._parse_waf(tool_name, raw_output, session_id)
        if tool == "sslscan":
            return self._parse_sslscan(tool_name, raw_output, session_id)
        if tool == "whois":
            return self._parse_whois(tool_name, raw_output, session_id)
        if tool == "smbclient":
            return self._parse_smbclient(tool_name, raw_output, session_id)
        if tool in {"gobuster", "dirb"}:
            return self._parse_web_discovery(tool, tool_name, raw_output, session_id)
        return []

    def _parse_waf(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        if not re.search(r"(?im)^\[WAF DETECTION\s*[—-]", raw_output or ""):
            return []
        detected_match = re.search(r"(?im)^WAF Detected:\s*(true|false)\s*$", raw_output or "")
        if not detected_match:
            return []
        detected = detected_match.group(1).casefold() == "true"
        product = _line_value(raw_output, ("WAF Type",)) or "unknown"
        target = _host_scope(_target_argument(tool_name))
        summary = {"detected": detected, "product": product[:80] if detected else "none"}
        return [
            check_result_fact(
                "waf_detect",
                "firewall_detection",
                "host",
                target,
                session_id,
                summary=summary,
            ),
            fact(
                "waf_detection",
                json.dumps(summary, separators=(",", ":"), sort_keys=True),
                90,
                session_id,
            ),
        ]

    def _parse_sslscan(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        raw = raw_output or ""
        if "Testing SSL server" not in raw and "SSL/TLS Protocols:" not in raw:
            return []

        protocols: list[tuple[str, str]] = []
        for match in _TLS_PROTOCOL.finditer(raw):
            item = (match.group(1), match.group(2).casefold())
            if item not in protocols:
                protocols.append(item)

        ciphers: list[dict[str, Any]] = []
        for match in _TLS_CIPHER.finditer(raw):
            cipher = {
                "bits": int(match.group(3)),
                "cipher": _clean(match.group(4), 100),
                "preference": match.group(1).casefold(),
                "protocol": match.group(2),
            }
            if cipher not in ciphers:
                ciphers.append(cipher)
            if len(ciphers) >= 64:
                break

        certificate = {
            key: value
            for key, value in {
                "issuer": _line_value(raw, ("Issuer",)),
                "not_after": _line_value(raw, ("Not valid after",)),
                "subject": _line_value(raw, ("Subject",)),
            }.items()
            if value
        }
        if not protocols and not ciphers and not certificate:
            return []
        enabled = [name for name, state in protocols if state == "enabled"]
        disabled = [name for name, state in protocols if state == "disabled"]
        target = _target_argument(tool_name) or "unknown"
        summary: dict[str, Any] = {
            "accepted_cipher_count": len(ciphers),
            "disabled_protocols": disabled[:8],
            "enabled_protocols": enabled[:8],
        }
        if certificate:
            summary["certificate"] = certificate

        facts: list[Fact] = [
            check_result_fact(
                "sslscan",
                "transport_security_assessment",
                "host",
                _host_scope(target),
                session_id,
                summary=summary,
            )
        ]
        facts.extend(fact("tls_protocol", f"{name}:{state}", 90, session_id) for name, state in protocols)
        for cipher in ciphers:
            facts.append(
                fact(
                    "tls_cipher",
                    json.dumps(cipher, separators=(",", ":"), sort_keys=True),
                    85,
                    session_id,
                )
            )
        if certificate:
            facts.extend(
                fact("tls_certificate", f"{key}:{value}", 85, session_id) for key, value in certificate.items()
            )
        return facts

    def _parse_whois(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        raw = raw_output or ""
        target = _host_scope(_target_argument(tool_name))
        no_match = bool(re.search(r"(?im)^(?:No match for|NOT FOUND|No entries found)", raw))
        field_labels: tuple[tuple[str, tuple[str, ...]], ...] = (
            ("domain", ("Domain Name",)),
            ("registrar", ("Registrar",)),
            ("creation_date", ("Creation Date", "Created On")),
            ("expiry_date", ("Registry Expiry Date", "Expiration Date", "Expiry Date")),
            ("updated_date", ("Updated Date", "Last Updated On")),
            ("dnssec", ("DNSSEC",)),
            ("net_range", ("NetRange",)),
            ("cidr", ("CIDR",)),
            ("net_name", ("NetName",)),
            ("organization", ("OrgName", "Organization")),
            ("country", ("Country",)),
        )
        record: dict[str, Any] = {key: value for key, labels in field_labels if (value := _line_value(raw, labels))}
        nameservers: list[str] = []
        for match in re.finditer(r"(?im)^\s*Name Server\s*:\s*(\S+)", raw):
            nameserver = _clean(match.group(1).rstrip("."), 255).casefold()
            if nameserver and nameserver not in nameservers:
                nameservers.append(nameserver)
            if len(nameservers) >= 8:
                break
        if nameservers:
            record["name_servers"] = nameservers
        if not record and not no_match:
            return []

        summary = dict(record)
        summary["found"] = not no_match
        facts: list[Fact] = [
            check_result_fact(
                "whois",
                "external_intelligence",
                "host",
                target,
                session_id,
                summary=summary,
                confidence=85,
            )
        ]
        if record:
            facts.extend(
                fact("whois_record", f"{key}:{value}", 80, session_id)
                for key, value in record.items()
                if key != "name_servers"
            )
            facts.extend(
                fact("whois_record", f"name_server:{value}", 80, session_id) for value in record.get("name_servers", [])
            )
        return facts

    def _parse_smbclient(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        raw = raw_output or ""
        if not re.search(r"(?im)^\s*Sharename\s+Type\s+Comment\s*$", raw):
            return []
        shares: list[dict[str, str]] = []
        for line in raw.splitlines():
            match = _SMB_SHARE.match(line)
            if not match:
                continue
            name = _clean(match.group(1), 120)
            if name.casefold() in {"sharename", "---------"}:
                continue
            item = {
                "comment": _clean(match.group(3), 160),
                "name": name,
                "type": match.group(2).casefold(),
            }
            if item not in shares:
                shares.append(item)
            if len(shares) >= 64:
                break
        target = _host_scope(_target_argument(tool_name))
        summary = {
            "share_count": len(shares),
            "shares": [{"name": item["name"][:48], "type": item["type"]} for item in shares[:6]],
        }
        facts: list[Fact] = [
            check_result_fact(
                "smbclient",
                "smb_enumeration",
                "host",
                target,
                session_id,
                summary=summary,
            )
        ]
        facts.extend(
            fact(
                "smb_share",
                json.dumps(item, separators=(",", ":"), sort_keys=True),
                85,
                session_id,
            )
            for item in shares
        )
        return facts

    def _parse_web_discovery(
        self,
        tool: str,
        tool_name: str,
        raw_output: str,
        session_id: str,
    ) -> list[Fact]:
        raw = raw_output or ""
        command_base = _canonical_url(_target_argument(tool_name))
        output_base = ""
        if tool == "gobuster":
            base_match = re.search(r"(?im)^\[\+\]\s*Url:\s*(https?://\S+)", raw)
        else:
            base_match = re.search(r"(?im)^URL_BASE:\s*(https?://\S+)", raw)
        if base_match:
            output_base = _canonical_url(base_match.group(1))
        base = output_base or command_base
        if command_base and output_base and not _same_authority(command_base, output_base):
            return []
        if not base:
            return []

        discoveries: list[tuple[str, str, str]] = []
        if tool == "gobuster":
            for match in re.finditer(r"(?im)^\s*(/\S*)\s+\(Status:\s*(\d{3})\)", raw):
                candidate = _canonical_url(urljoin(base, match.group(1)))
                if candidate and _same_authority(candidate, base):
                    endpoint = _endpoint_value(candidate, match.group(2))
                    if not endpoint:
                        continue
                    item = (candidate, match.group(2), endpoint)
                    if item not in discoveries:
                        discoveries.append(item)
        else:
            for match in re.finditer(r"(?im)^\+\s+(https?://\S+)\s+\(CODE:(\d{3})\|", raw):
                candidate = _canonical_url(match.group(1))
                if candidate and _same_authority(candidate, base):
                    endpoint = _endpoint_value(candidate, match.group(2))
                    if not endpoint:
                        continue
                    item = (candidate, match.group(2), endpoint)
                    if item not in discoveries:
                        discoveries.append(item)

        facts: list[Fact] = []
        for _url, _status, endpoint in discoveries[:256]:
            facts.append(fact("web_endpoint", endpoint, 85, session_id))

        completed = (tool == "gobuster" and "Gobuster v" in raw and bool(re.search(r"(?im)^Finished\s*$", raw))) or (
            tool == "dirb" and "DIRB v" in raw and "END_TIME:" in raw
        )
        if completed:
            statuses = Counter(status for _url, status, _endpoint in discoveries)
            facts.insert(
                0,
                check_result_fact(
                    tool,
                    "web_content_discovery",
                    "endpoint",
                    base.rstrip("/"),
                    session_id,
                    summary={
                        "discovered_count": len(discoveries),
                        "statuses": dict(sorted(statuses.items())),
                    },
                ),
            )
        return facts


__all__ = ["ReconEvidenceParser"]
