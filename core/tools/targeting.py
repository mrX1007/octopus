#!/usr/bin/env python3
"""Shared target and web-surface normalization helpers for tool runners."""

import fnmatch
import ipaddress
import json
import re
from urllib.parse import urlparse, urlunparse

HTTPS_PORTS = {"443", "8443", "1443", "2083", "2087", "2096", "9443"}


def ensure_url(target: str, scheme: str = "http") -> str:
    target = (target or "").strip().rstrip("/")
    if target.startswith(("http://", "https://")):
        return target
    return f"{scheme}://{target}"


def url_candidates(target: str) -> list[str]:
    target = (target or "").strip().rstrip("/")
    if target.startswith(("http://", "https://")):
        return [target]
    return [f"http://{target}", f"https://{target}"]


def split_host_port(target: str, default_port: int) -> tuple[str, int]:
    """Parse host[:port] without treating URL paths as part of the host."""
    raw = (target or "").strip()
    raw = raw.replace("http://", "").replace("https://", "")
    raw = raw.split("/", 1)[0]
    host = raw
    port = default_port
    if raw.count(":") == 1:
        maybe_host, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            host = maybe_host
            port = int(maybe_port)
    return host.strip(), int(port)


def coerce_port(port, default_port: int) -> int:
    try:
        return int(port)
    except (TypeError, ValueError):
        return int(default_port)


def target_host(target: str) -> str:
    return (target or "").strip().split("://")[-1].split("/", 1)[0].split(":", 1)[0]


def target_looks_domain(target: str) -> bool:
    host = target_host(target)
    return bool(re.search(r"[A-Za-z]", host) and "." in host)


def as_url(target: str) -> str:
    if (target or "").startswith(("http://", "https://")):
        return target.rstrip("/")
    return f"http://{target.strip().rstrip('/')}"


def nmap_service_looks_web(service: str, banner: str = "") -> bool:
    text = f"{service or ''} {banner or ''}".lower()
    web_markers = (
        "http", "httpd", "web server", "nginx", "apache", "cowboy",
        "golang net/http", "node.js", "express", "php", "wordpress",
        "tomcat", "jetty", "gunicorn", "uwsgi", "werkzeug", "flask",
        "django", "rails", "sinatra", "grafana", "kibana", "prometheus",
        "cpanel", "whm",
    )
    return any(marker in text for marker in web_markers)


def detect_web_ports_from_nmap(nmap_output: str) -> list[str]:
    """Return open HTTP-like ports from nmap output, preserving scan order."""
    web_ports = []
    for line in (nmap_output or "").splitlines():
        match = re.match(
            r"\s*(?:\[[^\]]+\]\s*)?(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        port, service, banner = match.groups()
        if nmap_service_looks_web(service, banner) and port not in web_ports:
            web_ports.append(port)
    return web_ports


def nmap_has_any_open_port(nmap_output: str, ports: set[str]) -> bool:
    for line in (nmap_output or "").splitlines():
        match = re.match(r"\s*(?:\[[^\]]+\]\s*)?(\d+)/tcp\s+open\b", line, re.IGNORECASE)
        if match and match.group(1) in ports:
            return True
    return False


def web_urls_from_ports(target: str, ports: list[str]) -> list[str]:
    urls = []
    for port in ports or ["80"]:
        proto = "https" if port in HTTPS_PORTS else "http"
        url = f"{proto}://{target}:{port}" if port not in {"80", "443"} else f"{proto}://{target}"
        if url not in urls:
            urls.append(url)
    return urls


def canonical_check_url(url: str) -> str:
    """Normalize the URL identity used by command/check-result records."""
    parsed = urlparse((url or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return (url or "").strip().rstrip("/")
    port = parsed.port
    netloc = parsed.hostname.lower()
    if port and not (
        (parsed.scheme.lower() == "http" and port == 80)
        or (parsed.scheme.lower() == "https" and port == 443)
    ):
        netloc = f"{netloc}:{port}"
    return urlunparse(
        (parsed.scheme.lower(), netloc, parsed.path or "/", "", parsed.query, "")
    ).rstrip("/")


def canonical_endpoint_value(url: str, service: str = "", port: str = "") -> str:
    """Return the pipeline's canonical JSON representation of a web endpoint."""
    raw = (url or "").strip()
    if not raw:
        return ""
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    parsed_port = parsed.port
    if parsed_port is None:
        parsed_port = 443 if parsed.scheme.lower() == "https" else 80
    path = parsed.path or "/"
    netloc = parsed.hostname.lower()
    if not (
        (parsed.scheme.lower() == "http" and parsed_port == 80)
        or (parsed.scheme.lower() == "https" and parsed_port == 443)
    ):
        netloc = f"{netloc}:{parsed_port}"
    canonical_url = urlunparse(
        (parsed.scheme.lower(), netloc, path, "", parsed.query, "")
    )
    return json.dumps(
        {
            "url": canonical_url,
            "scheme": parsed.scheme.lower(),
            "host": parsed.hostname.lower(),
            "port": str(port or parsed_port),
            "path": path,
            "service": service or "",
            "status": "",
            "title": "",
        },
        sort_keys=True,
    )


def endpoint_url_from_value(value: str) -> str:
    """Read a URL from a canonical endpoint value or a legacy URL string."""
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return value if re.match(r"^https?://", value or "", re.IGNORECASE) else ""
    url = str(parsed.get("url", "")).strip()
    return url if re.match(r"^https?://", url, re.IGNORECASE) else ""


def display_endpoint_url(endpoint: str) -> str:
    """Normalize an endpoint for display and command expansion."""
    parsed = urlparse(endpoint or "")
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    if (parsed.path or "") in {"", "/"} and not parsed.query:
        netloc = parsed.netloc.lower()
        return f"{parsed.scheme.lower()}://{netloc}"
    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            "",
            parsed.query,
            "",
        )
    )


def endpoint_in_target_scope(endpoint: str, target: str) -> bool:
    """Match an endpoint to the exact target host or one of its subdomains."""
    parsed = urlparse(endpoint or "")
    endpoint_host = (parsed.hostname or "").lower()
    normalized_target_host = target_host(target).lower()
    if not endpoint_host or not normalized_target_host:
        return False
    if endpoint_host == normalized_target_host:
        return True
    try:
        ipaddress.ip_address(normalized_target_host)
        ipaddress.ip_address(endpoint_host)
        return False
    except ValueError:
        pass
    return endpoint_host.endswith(f".{normalized_target_host}")


def internal_service_scope_value(value: str) -> str:
    """Normalize a compact IPv4 service scope while retaining legacy parsing."""
    match = re.match(
        r"((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})/(tcp|udp)",
        value or "",
        re.IGNORECASE,
    )
    if not match:
        return ""
    host, port, proto = match.groups()
    return f"{host.lower()}:{int(port)}/{proto.lower()}"


def internal_service_scopes_from_compact_state(cmd: str) -> list[str]:
    """Extract ordered, de-duplicated service scopes from compact-state JSON."""
    scopes: list[str] = []
    seen: set[str] = set()
    decoder = json.JSONDecoder()
    for match in re.finditer(
        r"compact_state\s*(?:->|:)\s*", cmd or "", re.IGNORECASE
    ):
        payload = (cmd or "")[match.end():].lstrip()
        try:
            parsed, _end = decoder.raw_decode(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(parsed, dict):
            continue
        for service in parsed.get("internal_services") or []:
            if not isinstance(service, dict):
                continue
            host = str(service.get("host") or "").strip().lower()
            port = service.get("port")
            proto = str(service.get("proto") or "tcp").strip().lower()
            if not host or port in {None, ""}:
                continue
            try:
                scope = f"{host}:{int(str(port))}/{proto}"
            except (TypeError, ValueError):
                continue
            if scope not in seen:
                seen.add(scope)
                scopes.append(scope)
    return scopes


def target_in_authorized_scope(target: str, scopes: list[str]) -> bool:
    """Apply the pipeline's legacy wildcard and CIDR authorization matching."""
    if not scopes:
        return False
    host = target_host(target)
    for scope in scopes:
        scope = str(scope or "").strip()
        if not scope:
            continue
        if scope in {"*", "all"}:
            return True
        if fnmatch.fnmatch(host, scope):
            return True
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(scope, strict=False):
                return True
        except ValueError:
            continue
    return False


def service_fact_looks_tls(value: str = "") -> bool:
    """Return whether service evidence uses one of the pipeline's TLS markers."""
    text = (value or "").lower()
    return any(
        marker in text
        for marker in ("ssl/http", "https", "tls", "ssl ", "cpanel", "whm")
    )
