"""Boundary coverage for pure follow-up proposal rules."""

from __future__ import annotations

import pytest

from core.ai.followups import (
    ActivePromotionFollowupRules,
    FollowupProposal,
    PostAccessFollowupRules,
    _bounded_limit,
    _dedupe_and_bound,
)

pytestmark = pytest.mark.contract


def test_invalid_limit_and_zero_bound_fail_closed():
    assert _bounded_limit(object()) == 0
    assert _dedupe_and_bound([FollowupProposal("one", "family", "rule")], limit=0) == []


def test_dedupe_skips_empty_and_repeated_commands():
    proposals = [
        FollowupProposal("", "family", "empty"),
        FollowupProposal("one", "family", "first"),
        FollowupProposal("one", "family", "duplicate"),
        FollowupProposal("two", "family", "second"),
    ]

    assert [item.command for item in _dedupe_and_bound(proposals)] == ["one", "two"]


def test_post_access_requires_a_nonempty_target():
    assert (
        PostAccessFollowupRules().propose(
            "  ",
            [{"type": "service_status", "value": "ssh_authenticated"}],
            enabled=True,
            inventory_seen=False,
        )
        == []
    )


def test_active_promotion_zero_caps_and_exhausted_total_budget():
    rules = ActivePromotionFollowupRules()
    candidate = "msf_run host exploit/test/module RPORT=80"

    assert (
        rules.propose(
            [candidate],
            [],
            authorization_granted=True,
            max_runs=0,
        )
        == []
    )
    assert (
        rules.propose(
            [candidate],
            [],
            authorization_granted=True,
            max_runs=1,
            already_executed={"unrelated"},
        )
        == []
    )


def test_active_promotion_ignores_negative_vulnerability_facts():
    candidate = "msf_run host exploit/test/module RPORT=80"

    assert (
        ActivePromotionFollowupRules().propose(
            [candidate],
            [
                {"type": "vulnerability", "value": "verification_negative"},
                {
                    "type": "vulnerability",
                    "value": "msf_check_positive:exploit/test/other",
                },
            ],
            authorization_granted=True,
            max_runs=1,
        )
        == []
    )
