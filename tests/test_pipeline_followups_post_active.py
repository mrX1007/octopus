"""Characterization contracts for post-access and active-promotion proposals."""

from __future__ import annotations

import pytest

from core.ai.followups import ActivePromotionFollowupRules, PostAccessFollowupRules

pytestmark = pytest.mark.contract


def test_post_access_prefers_confirmed_access_and_does_not_mutate_inputs():
    rules = PostAccessFollowupRules()
    facts = [
        {"type": "credential", "value": "support:secret://cached (cached)"},
        {"type": "credential", "value": "ssh_login_success:support@10.0.0.5"},
        {"type": "credential", "value": "cpanel_session:cpsess123"},
    ]
    executed = {"unrelated command"}
    facts_before = [dict(fact) for fact in facts]
    executed_before = set(executed)

    proposals = rules.propose(
        "10.0.0.5",
        facts,
        enabled=True,
        inventory_seen=False,
        already_executed=executed,
    )

    assert [proposal.command for proposal in proposals] == ["ssh_inventory 10.0.0.5"]
    assert proposals[0].family == "post_access"
    assert proposals[0].rule_id == "post_access.confirmed_ssh_access"
    assert proposals[0].evidence_key == "ssh_login_success:support@10.0.0.5"
    assert facts == facts_before
    assert executed == executed_before


def test_post_access_cached_credentials_are_explicitly_gated_and_repeat_safe():
    rules = PostAccessFollowupRules()
    facts = [{"type": "credential", "value": "root:secret://key-ref (cached)"}]

    proposed = rules.propose(
        "host.example",
        facts,
        enabled=True,
        inventory_seen=False,
        allow_cached_credentials=True,
    )

    assert proposed[0].rule_id == "post_access.cached_ssh_credential"
    assert rules.propose(
        "host.example",
        facts,
        enabled=True,
        inventory_seen=False,
        allow_cached_credentials=False,
    ) == []
    assert rules.propose(
        "host.example",
        facts,
        enabled=True,
        inventory_seen=False,
        already_executed={"ssh_inventory host.example"},
    ) == []
    assert rules.propose(
        "host.example",
        facts,
        enabled=False,
        inventory_seen=False,
    ) == []
    assert rules.propose(
        "host.example",
        facts,
        enabled=True,
        inventory_seen=True,
    ) == []
    assert rules.propose(
        "host.example",
        facts,
        enabled=True,
        inventory_seen=False,
        limit=0,
    ) == []


def test_post_access_does_not_promote_application_sessions_or_unrelated_facts():
    proposals = PostAccessFollowupRules().propose(
        "10.0.0.5",
        [
            {"type": "credential", "value": "whm_session:session-id"},
            {"type": "credential", "value": "cpanel_session:session-id"},
            {"type": "service_status", "value": "web_authenticated"},
        ],
        enabled=True,
        inventory_seen=False,
    )

    assert proposals == []


def test_active_promotion_requires_authorization_and_exact_positive_module_match():
    rules = ActivePromotionFollowupRules()
    matched = "msf_run 10.0.0.5 exploit/linux/http/matched RPORT=80"
    unmatched = "msf_run 10.0.0.5 exploit/linux/http/unmatched RPORT=8080"
    facts = [
        {"type": "vulnerability", "value": "msf_check_positive:exploit/linux/http/matched"},
        {"type": "potential_vulnerability", "value": "msf_check_positive:exploit/linux/http/unmatched"},
    ]

    assert rules.propose(
        [matched, unmatched],
        facts,
        authorization_granted=False,
        max_runs=2,
    ) == []

    proposals = rules.propose(
        [matched, unmatched],
        facts,
        authorization_granted=True,
        max_runs=2,
    )

    assert [proposal.command for proposal in proposals] == [matched]
    assert proposals[0].family == "active_promotion"
    assert proposals[0].rule_id == "active_promotion.positive_msf_check"
    assert proposals[0].evidence_key == "msf_check_positive:exploit/linux/http/matched"


def test_active_promotion_preserves_candidate_order_repeat_snapshot_and_run_cap():
    rules = ActivePromotionFollowupRules()
    commands = [
        f"msf_run host exploit/test/module_{index} RPORT={8000 + index}"
        for index in range(1, 5)
    ]
    facts = [
        {"type": "vulnerability", "value": f"msf_check_positive:exploit/test/module_{index}"}
        for index in range(1, 5)
    ]
    executed = {commands[0]}
    executed_before = set(executed)

    proposals = rules.propose(
        commands,
        facts,
        authorization_granted=True,
        max_runs=3,
        already_executed=executed,
    )

    # The legacy candidate collector exposes only its first three unique entries.
    assert [proposal.command for proposal in proposals] == commands[1:3]
    assert executed == executed_before

    one = rules.propose(
        commands,
        facts,
        authorization_granted=True,
        max_runs=4,
        candidate_limit=None,
        limit=1,
    )
    assert [proposal.command for proposal in one] == commands[:1]


def test_active_promotion_dedupes_candidates_before_applying_candidate_cap():
    rules = ActivePromotionFollowupRules()
    first = "msf_run host exploit/test/first RPORT=80"
    second = "msf_run host exploit/test/second RPORT=81"
    third = "msf_run host exploit/test/third RPORT=82"
    facts = [
        {"type": "vulnerability", "value": "msf_check_positive:exploit/test/first"},
        {"type": "vulnerability", "value": "msf_check_positive:exploit/test/second"},
        {"type": "vulnerability", "value": "msf_check_positive:exploit/test/third"},
    ]

    proposals = rules.propose(
        [first, first, second, third],
        facts,
        authorization_granted=True,
        max_runs=3,
        candidate_limit=2,
    )

    assert [proposal.command for proposal in proposals] == [first, second]

