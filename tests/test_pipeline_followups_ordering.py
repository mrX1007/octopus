"""Characterization contracts for typed service and web/API follow-ups."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from core.ai.followups import (
    FollowupProposal,
    FollowupRuleFamilies,
    ServiceFollowupRules,
    WebAPIFollowupRules,
)

pytestmark = pytest.mark.contract


def test_legacy_followup_groups_keep_exact_composite_order_and_first_seen_dedupe():
    families = FollowupRuleFamilies()
    ssh = ["ssh_inventory 10.0.0.5"]
    cpanel = ["plugin cpanel_auth_bypass 10.0.0.5 scan"]
    intelligence = [
        "exploit_select 10.0.0.5",
        "searchsploit nginx 1.24",
    ]
    protocol = [
        "ftp_anonymous_check 10.0.0.5 21",
        "smtp_probe 10.0.0.5 25",
    ]
    paths = ["curl_headers http://10.0.0.5/admin"]
    links = [
        "scrapling http://10.0.0.5/admin",
        "openapi_import http://10.0.0.5/openapi.json",
    ]
    surface = [
        "browser_surface_analysis http://10.0.0.5",
        "curl_headers http://10.0.0.5/admin",  # first path proposal wins
        "nuclei_safe http://10.0.0.5",
    ]

    proposals = families.from_legacy_groups(
        ssh_inventory_commands=ssh,
        cpanel_commands=cpanel,
        service_intelligence_commands=intelligence,
        protocol_service_commands=protocol,
        web_path_commands=paths,
        web_link_api_commands=links,
        web_surface_commands=surface,
    )

    assert [proposal.command for proposal in proposals] == [
        "ssh_inventory 10.0.0.5",
        "plugin cpanel_auth_bypass 10.0.0.5 scan",
        "exploit_select 10.0.0.5",
        "searchsploit nginx 1.24",
        "ftp_anonymous_check 10.0.0.5 21",
        "smtp_probe 10.0.0.5 25",
        "curl_headers http://10.0.0.5/admin",
        "scrapling http://10.0.0.5/admin",
        "openapi_import http://10.0.0.5/openapi.json",
        "browser_surface_analysis http://10.0.0.5",
        "nuclei_safe http://10.0.0.5",
    ]
    assert [(proposal.family, proposal.rule_id) for proposal in proposals] == [
        ("post_access", "post_access.ssh_inventory"),
        ("service", "service.cpanel"),
        ("service", "service.intelligence"),
        ("service", "service.intelligence"),
        ("service", "service.protocol"),
        ("service", "service.protocol"),
        ("web_api", "web_api.path"),
        ("web_api", "web_api.link_api"),
        ("web_api", "web_api.link_api"),
        ("web_api", "web_api.surface"),
        ("web_api", "web_api.surface"),
    ]
    assert all(isinstance(proposal, FollowupProposal) for proposal in proposals)


def test_service_and_web_rules_are_bounded_without_mutating_command_groups():
    service = ServiceFollowupRules()
    web = WebAPIFollowupRules()
    cpanel = ["cpanel-1"]
    intelligence = ["intel-1", "intel-2"]
    protocol = ["protocol-1"]
    paths = ["path-1", "path-2"]
    links = ["link-1"]
    surface = ["surface-1"]
    before = tuple(tuple(group) for group in (cpanel, intelligence, protocol, paths, links, surface))

    service_proposals = service.propose(
        cpanel_commands=cpanel,
        intelligence_commands=intelligence,
        protocol_commands=protocol,
        limit=2,
    )
    web_proposals = web.propose(
        path_commands=paths,
        link_api_commands=links,
        surface_commands=surface,
        limit=3,
    )

    assert [proposal.command for proposal in service_proposals] == ["cpanel-1", "intel-1"]
    assert [proposal.command for proposal in web_proposals] == ["path-1", "path-2", "link-1"]
    assert tuple(tuple(group) for group in (cpanel, intelligence, protocol, paths, links, surface)) == before
    assert service.propose(cpanel_commands=cpanel, limit=0) == []
    assert web.propose(path_commands=paths, limit=0) == []


def test_composite_limit_applies_after_legacy_ordering_without_executing_commands():
    runner_calls = []
    commands = ["ssh_inventory host", "plugin cpanel host scan", "exploit_select host"]

    proposals = FollowupRuleFamilies().from_legacy_groups(
        ssh_inventory_commands=commands[:1],
        cpanel_commands=commands[1:2],
        service_intelligence_commands=commands[2:],
        limit=2,
    )

    assert [proposal.command for proposal in proposals] == commands[:2]
    assert runner_calls == []
    assert commands == ["ssh_inventory host", "plugin cpanel host scan", "exploit_select host"]


def test_followup_proposal_is_frozen():
    proposal = FollowupProposal("nuclei_safe http://example.test", "web_api", "web_api.surface")

    with pytest.raises(FrozenInstanceError):
        proposal.command = "changed"  # type: ignore[misc]

