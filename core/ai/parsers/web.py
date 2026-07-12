#!/usr/bin/env python3

import json
import re
from urllib.parse import urlparse, urlunparse

from .common import BaseParser, Fact, fact, tool_lower


class WebParser(BaseParser):
    family = "web"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        tool = tool_lower(tool_name)
        raw = raw_output or ""
        lower = raw.lower()
        facts: list[Fact] = []
        if any(marker in tool for marker in ("scrapling", "browser_surface", "katana")):
            for url in re.findall(r"\bhttps?://[^\s\"'<>]+", raw):
                endpoint = self._endpoint(url)
                if endpoint:
                    facts.append(fact("web_endpoint", endpoint, 85, session_id))
        if any(marker in tool for marker in ("curl_headers", "security_headers", "cors_check", "scrapling", "browser_surface", "katana", "js_route")):
            title = re.search(r"(?im)^(?:Page title|Title):\s*(.+)$", raw)
            if title:
                facts.append(fact("web_title", title.group(1).strip()[:180], 85, session_id))
            forms = re.search(r"(?im)^Forms(?:\s*\((\d+)\)|:\s*(\d+))", raw)
            if forms:
                facts.append(fact("web_surface", f"forms:{forms.group(1) or forms.group(2)}", 85, session_id))
            if "no http(s) response" in lower:
                facts.append(fact("service_status", "web_content_discovery_skipped:no_http_response", 90, session_id))
            if "not installed" in lower or "tool not found" in lower:
                facts.append(fact("tool_unavailable", f"{tool.split()[0] or 'web_tool'}", 80, session_id))

        if "security_headers" in tool or "curl_headers" in tool:
            headers = {m.group(1).lower(): m.group(2).strip() for m in re.finditer(r"(?im)^([A-Za-z0-9-]+):\s*(.+)$", raw)}
            if headers:
                for header, fact_type in (("server", "web_server"), ("location", "web_redirect"), ("x-powered-by", "web_powered_by")):
                    if headers.get(header):
                        facts.append(fact(fact_type, headers[header][:160], 80, session_id))
                for header, note in {
                    "strict-transport-security": "missing_hsts",
                    "content-security-policy": "missing_csp",
                    "x-frame-options": "missing_x_frame_options",
                    "x-content-type-options": "missing_x_content_type_options",
                    "referrer-policy": "missing_referrer_policy",
                }.items():
                    if header not in headers:
                        facts.append(fact("web_security_note", note, 65, session_id))
                csp = headers.get("content-security-policy", "")
                if csp and ("'unsafe-inline'" in csp or "*" in csp):
                    facts.append(fact("web_security_note", "weak_csp_policy", 70, session_id))
                for cookie in re.findall(r"(?im)^set-cookie:\s*(.+)$", raw):
                    cookie_l = cookie.lower()
                    cookie_name = cookie.split("=", 1)[0][:80]
                    if "httponly" not in cookie_l:
                        facts.append(fact("web_security_note", f"cookie_missing_httponly:{cookie_name}", 75, session_id))
                    if "secure" not in cookie_l:
                        facts.append(fact("web_security_note", f"cookie_missing_secure:{cookie_name}", 75, session_id))
                    if "samesite" not in cookie_l:
                        facts.append(fact("web_security_note", f"cookie_missing_samesite:{cookie_name}", 75, session_id))

        if "cors_check" in tool:
            origin = re.search(r"(?im)^origin:\s*(.+)$", raw)
            acao = re.search(r"(?im)^access-control-allow-origin:\s*(.+)$", raw)
            acac = re.search(r"(?im)^access-control-allow-credentials:\s*(.+)$", raw)
            if acao:
                allow_origin = acao.group(1).strip()
                facts.append(fact("web_security_note", f"cors_allow_origin:{allow_origin[:120]}", 75, session_id))
                if allow_origin == "*" or (origin and allow_origin == origin.group(1).strip()):
                    facts.append(fact("web_security_note", "cors_reflective_or_wildcard_origin", 80, session_id))
            if acac and acac.group(1).strip().lower() == "true":
                facts.append(fact("web_security_note", "cors_credentials_allowed", 80, session_id))

        if "session_profile_import" in tool or "session_import" in tool:
            header_count = re.search(r"(?im)^Headers:\s*(\d+)", raw)
            cookie_count = re.search(r"(?im)^Cookies:\s*(\d+)", raw)
            if header_count or cookie_count:
                facts.append(fact("web_session", f"profile_imported:headers={header_count.group(1) if header_count else 0}:cookies={cookie_count.group(1) if cookie_count else 0}", 85, session_id))
        if "authenticated_crawl" in tool or "[authenticated crawl" in lower:
            status = re.search(r"(?im)^Status:\s*(\d{3})", raw)
            if status:
                facts.append(fact("web_session", f"authenticated_crawl_status:{status.group(1)}", 85, session_id))
            title = re.search(r"(?im)^Title:\s*(.+)$", raw)
            if title:
                facts.append(fact("web_title", title.group(1).strip()[:180], 85, session_id))
            forms = re.search(r"(?im)^Forms:\s*(\d+)\s*$", raw)
            if forms:
                facts.append(fact("web_surface", f"forms:{forms.group(1)}", 85, session_id))
            csrf = re.search(r"(?im)^CSRF token observed:\s*(yes|no)", raw)
            if csrf:
                value = "csrf_token_observed" if csrf.group(1).lower() == "yes" else "csrf_token_not_observed_authenticated"
                facts.append(fact("web_security_note", value, 70, session_id))
            for link in re.findall(r"(?im)^LINK\s+(https?://\S+)", raw):
                facts.append(fact("web_link", link[:300], 75, session_id))
        if "jwt_analyze" in tool or "[jwt analyze" in lower:
            alg = re.search(r"(?im)^alg:\s*(\S+)", raw)
            kid = re.search(r"(?im)^kid:\s*(\S+)", raw)
            claims = re.search(r"(?im)^claims:\s*(.+)$", raw)
            if alg:
                value = alg.group(1).strip()
                facts.append(fact("jwt_metadata", f"alg:{value}", 85, session_id))
                if value.lower() in {"none", "hs256"}:
                    facts.append(fact("web_security_note", f"jwt_review_required_alg:{value}", 70, session_id))
            if kid and kid.group(1).strip():
                facts.append(fact("jwt_metadata", f"kid:{kid.group(1).strip()[:120]}", 80, session_id))
            if claims:
                facts.append(fact("jwt_metadata", f"claims:{claims.group(1).strip()[:220]}", 80, session_id))
        if "js_route_extract" in tool or "[js route extract" in lower:
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("[") or line.startswith("Routes:"):
                    continue
                if line.startswith(("http://", "https://", "/")):
                    facts.append(fact("js_route", line[:300], 75, session_id))
                    if any(marker in line.lower() for marker in ("/api/", "/graphql", "/admin", "/user", "/account")):
                        facts.append(fact("api_endpoint", f"UNKNOWN:{line}:source=js", 65, session_id))
                    if re.search(r"(?:^|[/?&])(id|user_id|account_id|tenant_id|order_id)=", line, re.IGNORECASE) or re.search(r"\{[^}]*id[^}]*\}", line, re.IGNORECASE):
                        facts.append(fact("api_security_note", f"idor_candidate:UNKNOWN:{line[:160]}", 60, session_id))
        if "burp_import" in tool or "zap_import" in tool or "[burp import" in lower or "[zap import" in lower:
            for match in re.finditer(r"^(?:URL)\s+(https?://\S+)", raw, re.MULTILINE):
                url = match.group(1).rstrip("/")
                facts.append(fact("asset_url", url, 85, session_id))
                endpoint = self._endpoint(url)
                if endpoint:
                    facts.append(fact("web_endpoint", endpoint, 80, session_id))
            for match in re.finditer(r"^(?:ISSUE|ALERT)\s+(.+)$", raw, re.MULTILINE):
                issue = match.group(1).strip()
                facts.append(fact("proxy_finding", issue[:300], 80, session_id))
                if re.search(r"(?i)(cors|csrf|idor|jwt|cookie|clickjack|x-frame|content security|csp)", issue):
                    facts.append(fact("web_security_note", f"proxy:{issue[:220]}", 75, session_id))
        return facts

    def _endpoint(self, url: str) -> str:
        parsed = urlparse((url or "").strip().rstrip(".,);]"))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        netloc = parsed.hostname.lower()
        if not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
            netloc = f"{netloc}:{port}"
        path = parsed.path or "/"
        canonical = urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))
        return json.dumps({
            "url": canonical,
            "scheme": parsed.scheme.lower(),
            "host": parsed.hostname.lower(),
            "port": str(port),
            "path": path,
            "service": "",
            "status": "",
            "title": "",
        }, sort_keys=True)
