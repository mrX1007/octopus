#!/usr/bin/env python3
"""Shared target and web-surface normalization helpers for tool runners."""

import re

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
