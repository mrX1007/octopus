#!/usr/bin/env python3
"""Execution bounds, scope, dependency, and ranking contracts."""

import pytest

pytestmark = [pytest.mark.contract, pytest.mark.security]

def test_tooldef_python_dependency_gate():
    from core.tools.registry import ToolDef

    assert ToolDef(name="ok", requires=["python:sys"]).is_available()
    assert not ToolDef(name="missing", requires=["python:octopus_missing_module"]).is_available()
    assert ToolDef(name="any-ok", requires=["any:python:octopus_missing_module,python:sys"]).is_available()
    assert not ToolDef(name="any-missing", requires=["any:python:octopus_missing_a,python:octopus_missing_b"]).is_available()


def test_pipeline_runtime_zero_means_unlimited():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_runtime_limit.db")

    assert pipeline._runtime_limit(0) is None
    assert pipeline._runtime_limit("unlimited") is None
    assert pipeline._runtime_limit(7) == 7


def test_x_mode_runs_exhaustive_applicable_coverage_without_real_tools():
    import builtins
    import sys
    import types

    import core.tools.post_tools
    import core.tools.recon_tools  # noqa: F401 - registers recon/deep tools
    import core.tools.runner as runner
    from core.tools.registry import get_tool

    old_input = builtins.input
    old_default_recon = runner.run_default_recon
    old_killchain = sys.modules.get("core.killchain")
    patched_tools = {}
    calls = []

    def fake_default_recon(_target):
        return {
            "nmap": "80/tcp open http nginx\n",
            "curl_headers": "HTTP/1.1 200 OK\nServer: nginx\n",
            "whatweb": "nginx",
        }

    def fake_tool(name):
        def _run(target, *args, **kwargs):
            calls.append((name, target))
            return f"{name} ok {target}"
        return _run

    try:
        builtins.input = lambda _prompt="": "x"
        runner.run_default_recon = fake_default_recon
        fake_killchain = types.ModuleType("core.killchain")
        fake_killchain.vuln_assess = lambda target, recon_blob: f"vuln_assess ok {target}"
        sys.modules["core.killchain"] = fake_killchain

        for tool_name in (
            "httpx_probe", "naabu", "tlsx", "whatweb", "curl_headers",
            "security_headers_check", "cors_check", "scrapling",
            "scrapling_crawl", "browser_surface_analysis", "nuclei_safe",
            "katana_crawl", "wpscan", "sqlmap", "nikto", "openapi_import",
            "graphql_check", "api_auth_check",
        ):
            tool_def = get_tool(tool_name)
            patched_tools[tool_name] = (tool_def.func, list(tool_def.requires))
            tool_def.requires = []
            tool_def.func = fake_tool(tool_name)

        output = runner.interactive_tool_run("10.0.0.5")
    finally:
        builtins.input = old_input
        runner.run_default_recon = old_default_recon
        if old_killchain is None:
            sys.modules.pop("core.killchain", None)
        else:
            sys.modules["core.killchain"] = old_killchain
        for tool_name, (old_func, old_requires) in patched_tools.items():
            tool_def = get_tool(tool_name)
            tool_def.func = old_func
            tool_def.requires = old_requires

    called_tools = {name for name, _target in calls}

    assert "[X MODE PLAN]" in output
    assert "gated killchain_exfil" in output
    assert "vuln_assess ok 10.0.0.5" in output
    assert {"httpx_probe", "naabu", "tlsx", "nuclei_safe", "katana_crawl", "nikto", "api_auth_check"}.issubset(called_tools)
    assert "wpscan" not in called_tools
    assert "sqlmap" not in called_tools
    assert "skip wpscan_http_10_0_0_5: not_applicable:no_wordpress_signal" in output
    assert "skip sqlmap_http_10_0_0_5: not_applicable:no_input_surface" in output
    assert ("security_headers_check", "http://10.0.0.5") in calls
    assert ("api_auth_check", "http://10.0.0.5/api") in calls


def test_x_mode_dedupes_default_heavy_web_scanners_without_dropping_distinct_ports():
    import builtins
    import sys
    import types

    import core.tools.post_tools
    import core.tools.recon_tools  # noqa: F401 - registers recon/deep tools
    import core.tools.runner as runner
    from core.tools.registry import get_tool

    old_input = builtins.input
    old_default_recon = runner.run_default_recon
    old_killchain = sys.modules.get("core.killchain")
    patched_tools = {}
    calls = []

    def fake_default_recon(_target):
        return {
            "nmap": (
                "80/tcp open http nginx\n"
                "443/tcp open ssl/http nginx\n"
                "9001/tcp open http Cowboy httpd\n"
            ),
            "curl_headers": "HTTP/1.1 200 OK\nServer: nginx\n",
            "whatweb": "nginx",
        }

    def fake_tool(name):
        def _run(target, *args, **kwargs):
            calls.append((name, target))
            if name == "curl_headers":
                server = "Cowboy" if str(target).endswith(":9001") else "nginx"
                return f"HTTP/1.1 200 OK\nServer: {server}\n"
            if name == "whatweb":
                server = "Cowboy" if str(target).endswith(":9001") else "nginx"
                return f"{target} [200 OK] HTTPServer[{server}]"
            return f"{name} ok {target}"
        return _run

    try:
        builtins.input = lambda _prompt="": "x"
        runner.run_default_recon = fake_default_recon
        fake_killchain = types.ModuleType("core.killchain")
        fake_killchain.vuln_assess = lambda target, recon_blob: f"vuln_assess ok {target}"
        sys.modules["core.killchain"] = fake_killchain

        for tool_name in (
            "httpx_probe", "naabu", "tlsx", "whatweb", "curl_headers",
            "security_headers_check", "cors_check", "scrapling",
            "scrapling_crawl", "browser_surface_analysis", "nuclei_safe",
            "katana_crawl", "wpscan", "sqlmap", "nikto", "openapi_import",
            "graphql_check", "api_auth_check",
        ):
            tool_def = get_tool(tool_name)
            patched_tools[tool_name] = (tool_def.func, list(tool_def.requires))
            tool_def.requires = []
            tool_def.func = fake_tool(tool_name)

        output = runner.interactive_tool_run("10.0.0.5")
    finally:
        builtins.input = old_input
        runner.run_default_recon = old_default_recon
        if old_killchain is None:
            sys.modules.pop("core.killchain", None)
        else:
            sys.modules["core.killchain"] = old_killchain
        for tool_name, (old_func, old_requires) in patched_tools.items():
            tool_def = get_tool(tool_name)
            tool_def.func = old_func
            tool_def.requires = old_requires

    nuclei_targets = [target for name, target in calls if name == "nuclei_safe"]
    nikto_targets = [target for name, target in calls if name == "nikto"]

    assert set(nuclei_targets) == {"https://10.0.0.5", "http://10.0.0.5:9001"}
    assert set(nikto_targets) == {"https://10.0.0.5", "http://10.0.0.5:9001"}
    assert len(nuclei_targets) == 2
    assert len(nikto_targets) == 2
    assert ("security_headers_check", "http://10.0.0.5") in calls
    assert ("security_headers_check", "https://10.0.0.5") in calls
    assert ("security_headers_check", "http://10.0.0.5:9001") in calls
    assert "skip nuclei_safe_http_10_0_0_5: duplicate_surface covered_by=https://10.0.0.5" in output
    assert "web_contextual_targets: https://10.0.0.5, http://10.0.0.5:9001" in output


def test_web_endpoint_followups_stay_in_target_scope():
    import json
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_scope_endpoints_{uuid.uuid4().hex}.db")
    scan_id = "scan-scope-endpoints"
    target = "83.166.242.55"
    for endpoint in (
        {"url": "http://83.166.242.55/", "scheme": "http", "host": "83.166.242.55", "port": "80", "path": "/"},
        {"url": "http://nginx.org/", "scheme": "http", "host": "nginx.org", "port": "80", "path": "/"},
        {"url": "https://octopus.invalid/", "scheme": "https", "host": "octopus.invalid", "port": "443", "path": "/"},
    ):
        pipeline.fact_store.add_fact(scan_id, target, "web_endpoint", json.dumps(endpoint, sort_keys=True), "test")

    endpoints = pipeline._web_endpoints_from_facts(scan_id, target)

    assert endpoints == ["http://83.166.242.55"]


def test_pipeline_stores_offscope_browser_urls_as_external_not_web_endpoint():
    import json
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_store_scope_{uuid.uuid4().hex}.db")
    scan_id = "scan-store-scope"
    target = "83.166.242.55"

    pipeline._store_fact(
        scan_id,
        target,
        {
            "type": "web_endpoint",
            "value": json.dumps({
                "url": "http://nginx.org/",
                "scheme": "http",
                "host": "nginx.org",
                "port": "80",
                "path": "/",
            }, sort_keys=True),
            "confidence": 90,
        },
        "browser_surface_analysis",
    )
    pipeline._store_fact(
        scan_id,
        target,
        {
            "type": "web_endpoint",
            "value": json.dumps({
                "url": "http://83.166.242.55/",
                "scheme": "http",
                "host": "83.166.242.55",
                "port": "80",
                "path": "/",
            }, sort_keys=True),
            "confidence": 90,
        },
        "browser_surface_analysis",
    )

    facts = pipeline.fact_store.get_facts(scan_id, target)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("external_url", "http://nginx.org/") in pairs
    assert not any(ftype == "web_endpoint" and "nginx.org" in value for ftype, value in pairs)
    assert pipeline._web_endpoints_from_facts(scan_id, target) == ["http://83.166.242.55"]


def test_domain_target_allows_subdomain_but_not_external_endpoint_followups():
    import json
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_scope_domain_{uuid.uuid4().hex}.db")
    scan_id = "scan-scope-domain"
    target = "example.com"
    for endpoint in (
        {"url": "https://app.example.com/admin", "scheme": "https", "host": "app.example.com", "port": "443", "path": "/admin"},
        {"url": "https://cdn.other.net/app.js", "scheme": "https", "host": "cdn.other.net", "port": "443", "path": "/app.js"},
    ):
        pipeline.fact_store.add_fact(scan_id, target, "web_endpoint", json.dumps(endpoint, sort_keys=True), "test")

    endpoints = pipeline._web_endpoints_from_facts(scan_id, target)

    assert endpoints == ["https://app.example.com/admin"]


def test_ssh_exec_blocks_arbitrary_commands_by_default():
    from core.tools.post_tools import ai_ssh_exec

    output = ai_ssh_exec("10.0.0.5", "support", "secret", "cat /etc/passwd")

    assert "ssh_exec blocked" in output
    assert "outside controlled ssh_exec inventory allowlist" in output


def test_tool_ranking_prefers_short_safe_checks_before_long_active_work():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_ranked_tasks.db")
    context = {
        "host": "10.0.0.5",
        "services": ["http"],
        "target_model": {
            "endpoints": [{"url": "http://10.0.0.5/", "scheme": "http"}],
            "surface_states": {"web": "confirmed_present"},
        },
    }

    ranked = pipeline._rank_candidate_tasks(
        ["template_verification", "web_vulnerability_testing", "web_app_deep_testing", "web_application_mapping"],
        context,
    )

    assert ranked == [
        "web_application_mapping",
        "web_app_deep_testing",
        "template_verification",
        "web_vulnerability_testing",
    ]
