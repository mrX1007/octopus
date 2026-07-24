"""Web-path and discovered-link follow-up helpers for the AI pipeline."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from core.ai.pipeline_types import PipelineMixinBase


class PipelineWebLinksMixin(PipelineMixinBase):
    """Normalize discovered links and build bounded web follow-up commands."""

    def _web_path_action_commands(self, scan_id: str, target: str, facts: list[dict[str, Any]]) -> list[str]:
        endpoints = self._web_endpoints_from_facts(scan_id, target)
        if not endpoints:
            host = (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
            endpoints = [f"http://{host}"]
        base = endpoints[0].rstrip("/")
        commands = []
        for fact in facts:
            if fact.get("type") != "web_path":
                continue
            value = str(fact.get("value", ""))
            path, _, status = value.partition(":")
            path = "/" + path.strip().lstrip("/")
            if path in {"/", ""}:
                continue
            is_interesting = status in {"200", "301", "302", "401", "403"} or any(
                word in path.lower() for word in self._interesting_web_words()
            )
            if not is_interesting:
                continue
            url = f"{base}{path}"
            commands.append(f"curl_headers {url}")
            commands.append(f"scrapling {url}")
            path_limit = self._strategy_limit("web_path_followup_commands", None)
            if path_limit is not None and len(commands) >= path_limit:
                break
        return commands

    def _web_link_action_commands(self, scan_id: str, target: str, facts: list[dict[str, Any]]) -> list[str]:
        urls = self._normalized_web_link_urls(scan_id, target, facts)
        commands = []
        limit = self._web_link_followup_command_limit()
        for url in urls:
            if self._url_looks_javascript_asset(url):
                commands.append(f"js_route_extract {url}")
                if limit is not None and len(commands) >= limit:
                    break
                continue
            commands.append(f"curl_headers {url}")
            if limit is not None and len(commands) >= limit:
                break
            commands.append(f"scrapling {url}")
            if limit is not None and len(commands) >= limit:
                break
            if self._url_looks_openapi_spec(url):
                commands.append(f"openapi_import {url}")
                if limit is not None and len(commands) >= limit:
                    break
            if self._url_looks_graphql_endpoint(url):
                commands.append(f"graphql_check {url}")
                if limit is not None and len(commands) >= limit:
                    break
        return commands

    def _normalized_web_link_urls(self, scan_id: str, target: str, facts: list[dict[str, Any]]) -> list[str]:
        endpoints = self._web_endpoints_from_facts(scan_id, target)
        if not endpoints:
            host = self._target_host(target)
            endpoints = [f"http://{host}"] if host else []
        if not endpoints:
            return []

        allowed_hosts = {
            parsed.hostname.lower() for parsed in (urlparse(endpoint) for endpoint in endpoints) if parsed.hostname
        }
        target_host = self._target_host(target)
        if target_host:
            allowed_hosts.add(target_host.lower())

        urls = []
        seen = set()
        for fact in facts:
            if str(fact.get("type", "")).lower() != "web_link":
                continue
            raw_link = str(fact.get("value", "")).strip()
            if not self._web_link_looks_interesting(raw_link):
                continue
            candidate_urls = []
            if re.match(r"^https?://", raw_link, re.IGNORECASE) or raw_link.startswith("//"):
                candidate_urls.append(self._normalize_web_link_url(raw_link, endpoints[0], allowed_hosts))
            else:
                for endpoint in endpoints:
                    candidate_urls.append(self._normalize_web_link_url(raw_link, endpoint, allowed_hosts))

            for url in candidate_urls:
                if not url or url in seen:
                    continue
                seen.add(url)
                urls.append(url)
                url_limit = self._strategy_limit("web_link_url_limit", None)
                if url_limit is not None and len(urls) >= url_limit:
                    return urls
        return urls

    def _normalize_web_link_url(self, raw_link: str, base: str, allowed_hosts: set) -> str:
        link = (raw_link or "").strip().strip("\"'<>")
        link = re.sub(r"[\s)\],;]+$", "", link)
        if not link:
            return ""
        if link.startswith("#"):
            return ""
        if re.match(r"^(?:javascript|mailto|tel|data):", link, re.IGNORECASE):
            return ""

        base_url = base.rstrip("/") + "/"
        if link.startswith("//"):
            base_scheme = urlparse(base_url).scheme or "http"
            url = f"{base_scheme}:{link}"
        elif re.match(r"^https?://", link, re.IGNORECASE):
            url = link
        else:
            url = urljoin(base_url, link)

        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.hostname.lower() not in allowed_hosts:
            return ""

        path = parsed.path or "/"
        if path == "/" and not parsed.query:
            return ""
        if self._web_path_is_static(path) and not path.lower().endswith((".js", ".mjs")):
            return ""

        return urlunparse(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                path,
                "",
                parsed.query,
                "",
            )
        )

    def _web_link_looks_interesting(self, raw_link: str) -> bool:
        link = (raw_link or "").strip().strip("\"'<>").lower()
        if not link or link.startswith("#"):
            return False
        if re.match(r"^(?:javascript|mailto|tel|data):", link):
            return False
        path = urlparse(link).path if re.match(r"^https?://", link) else link.split("?", 1)[0].split("#", 1)[0]
        if path.lower().endswith((".js", ".mjs")):
            return True
        if self._web_path_is_static(path):
            return False
        if any(word in link for word in self._interesting_web_words()):
            return True
        return path not in {"", "/", "./", "../"}

    def _web_path_is_static(self, path: str) -> bool:
        return (
            (path or "")
            .lower()
            .endswith(
                (
                    ".css",
                    ".js",
                    ".mjs",
                    ".map",
                    ".png",
                    ".jpg",
                    ".jpeg",
                    ".gif",
                    ".svg",
                    ".ico",
                    ".webp",
                    ".woff",
                    ".woff2",
                    ".ttf",
                    ".eot",
                    ".mp4",
                    ".mp3",
                    ".avi",
                    ".mov",
                )
            )
        )

    def _interesting_web_words(self) -> tuple:
        return (
            "admin",
            "login",
            "signin",
            "auth",
            "account",
            "report",
            "_reports",
            "api",
            "dashboard",
            "cpanel",
            "whm",
            "wp-admin",
            "phpmyadmin",
            "grafana",
            "metrics",
            "health",
            "status",
            "config",
            "setup",
            "install",
            "swagger",
            "openapi",
            "api-docs",
            "graphql",
        )

    def _url_looks_openapi_spec(self, url: str) -> bool:
        path = (urlparse(url or "").path or "").lower()
        return any(
            marker in path
            for marker in (
                "swagger.json",
                "openapi.json",
                "openapi.yaml",
                "openapi.yml",
                "api-docs",
                "swagger/v1",
                "swagger/v2",
                "swagger/v3",
            )
        )

    def _url_looks_graphql_endpoint(self, url: str) -> bool:
        return (urlparse(url or "").path or "").lower().rstrip("/") == "/graphql"

    def _url_looks_javascript_asset(self, url: str) -> bool:
        return (urlparse(url or "").path or "").lower().endswith((".js", ".mjs"))

    def _web_link_followup_command_limit(self):
        return self._strategy_limit("web_link_followup_commands", None)


__all__ = ["PipelineWebLinksMixin"]
