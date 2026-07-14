#!/usr/bin/env python3
"""Pure, typed follow-up proposal rules for the AI pipeline.

The objects in this module describe possible commands.  They deliberately do
not execute commands, consult the scheduler, authorize active work, or mutate
the pipeline's orchestration/deduplication sets.  ``AIPipeline`` remains the
compatibility facade and the existing runtime remains the execution boundary.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FollowupProposal:
    """A deterministic command proposal emitted by one bounded rule family."""

    command: str
    family: str
    rule_id: str
    evidence_key: str = ""


def _bounded_limit(limit: int | None) -> int | None:
    if limit is None:
        return None
    try:
        return max(0, int(limit))
    except (TypeError, ValueError):
        return 0


def _proposals_from_groups(
    family: str,
    groups: Sequence[tuple[str, Iterable[str]]],
    *,
    limit: int | None = None,
) -> list[FollowupProposal]:
    """Wrap ordered legacy command groups without changing their first-seen order."""

    bounded = _bounded_limit(limit)
    if bounded == 0:
        return []

    proposals: list[FollowupProposal] = []
    seen: set[str] = set()
    for rule_id, commands in groups:
        for raw_command in tuple(commands or ()):
            command = str(raw_command or "").strip()
            if not command or command in seen:
                continue
            seen.add(command)
            proposals.append(FollowupProposal(command, family, rule_id))
            if bounded is not None and len(proposals) >= bounded:
                return proposals
    return proposals


def _dedupe_and_bound(
    proposals: Iterable[FollowupProposal],
    *,
    limit: int | None = None,
) -> list[FollowupProposal]:
    bounded = _bounded_limit(limit)
    if bounded == 0:
        return []

    result: list[FollowupProposal] = []
    seen: set[str] = set()
    for proposal in tuple(proposals or ()):
        if not proposal.command or proposal.command in seen:
            continue
        seen.add(proposal.command)
        result.append(proposal)
        if bounded is not None and len(result) >= bounded:
            break
    return result


class ServiceFollowupRules:
    """Typed facade over the existing ordered service rule groups."""

    FAMILY = "service"

    def propose(
        self,
        *,
        cpanel_commands: Sequence[str] = (),
        intelligence_commands: Sequence[str] = (),
        protocol_commands: Sequence[str] = (),
        limit: int | None = None,
    ) -> list[FollowupProposal]:
        return _proposals_from_groups(
            self.FAMILY,
            (
                ("service.cpanel", cpanel_commands),
                ("service.intelligence", intelligence_commands),
                ("service.protocol", protocol_commands),
            ),
            limit=limit,
        )


class WebAPIFollowupRules:
    """Typed facade over the existing ordered web/API rule groups."""

    FAMILY = "web_api"

    def propose(
        self,
        *,
        path_commands: Sequence[str] = (),
        link_api_commands: Sequence[str] = (),
        surface_commands: Sequence[str] = (),
        limit: int | None = None,
    ) -> list[FollowupProposal]:
        return _proposals_from_groups(
            self.FAMILY,
            (
                ("web_api.path", path_commands),
                ("web_api.link_api", link_api_commands),
                ("web_api.surface", surface_commands),
            ),
            limit=limit,
        )


class PostAccessFollowupRules:
    """Propose controlled SSH inventory from explicit credential/access facts."""

    FAMILY = "post_access"
    _CACHED_CREDENTIAL = re.compile(r"[^:\s]+:[^\s]+\s+\(cached\)")

    def from_commands(
        self,
        commands: Sequence[str],
        *,
        limit: int | None = None,
    ) -> list[FollowupProposal]:
        """Wrap already-characterized post-access commands during migration."""

        return _proposals_from_groups(
            self.FAMILY,
            (("post_access.ssh_inventory", commands),),
            limit=limit,
        )

    def propose(
        self,
        target: str,
        facts: Sequence[Mapping[str, Any]],
        *,
        enabled: bool,
        inventory_seen: bool,
        already_executed: Collection[str] = (),
        allow_cached_credentials: bool = True,
        limit: int | None = None,
    ) -> list[FollowupProposal]:
        """Return at most one read-only inventory proposal without side effects."""

        if not enabled or inventory_seen or _bounded_limit(limit) == 0:
            return []
        normalized_target = str(target or "").strip()
        if not normalized_target:
            return []

        confirmed_evidence = ""
        cached_evidence = ""
        for fact in tuple(facts or ()):
            fact_type = str(fact.get("type", "")).strip().lower()
            value = str(fact.get("value", "")).strip()
            lowered = value.lower()
            if (
                fact_type == "credential" and lowered.startswith("ssh_login_success:")
            ) or (fact_type == "service_status" and lowered == "ssh_authenticated"):
                confirmed_evidence = confirmed_evidence or value
            elif fact_type == "credential" and (
                lowered.startswith("ssh_key_available:")
                or self._CACHED_CREDENTIAL.fullmatch(value) is not None
            ):
                cached_evidence = cached_evidence or value

        if confirmed_evidence:
            rule_id = "post_access.confirmed_ssh_access"
            evidence_key = confirmed_evidence
        elif allow_cached_credentials and cached_evidence:
            rule_id = "post_access.cached_ssh_credential"
            evidence_key = cached_evidence
        else:
            return []

        command = f"ssh_inventory {normalized_target}"
        if command in frozenset(already_executed or ()):
            return []
        return [FollowupProposal(command, self.FAMILY, rule_id, evidence_key)]


class ActivePromotionFollowupRules:
    """Promote verified MSF candidates after an external authorization decision."""

    FAMILY = "active_promotion"

    def propose(
        self,
        candidates: Sequence[str],
        verification_facts: Sequence[Mapping[str, Any]],
        *,
        authorization_granted: bool,
        max_runs: int,
        already_executed: Collection[str] = (),
        candidate_limit: int | None = 3,
        limit: int | None = None,
    ) -> list[FollowupProposal]:
        """Return module-matched proposals; never authorize or execute them here."""

        if not authorization_granted:
            return []
        total_cap = _bounded_limit(max_runs)
        family_cap = _bounded_limit(limit)
        candidate_cap = _bounded_limit(candidate_limit)
        if total_cap == 0 or family_cap == 0 or candidate_cap == 0:
            return []

        executed_snapshot = frozenset(already_executed or ())
        remaining = max(0, int(total_cap or 0) - len(executed_snapshot))
        if remaining == 0:
            return []
        if family_cap is not None:
            remaining = min(remaining, family_cap)

        positive_modules: set[str] = set()
        for fact in tuple(verification_facts or ()):
            if str(fact.get("type", "")).strip().lower() != "vulnerability":
                continue
            value = str(fact.get("value", "")).strip()
            if value.startswith("msf_check_positive:"):
                positive_modules.add(value.split(":", 1)[1])

        unique_candidates: list[str] = []
        seen: set[str] = set()
        for raw_command in tuple(candidates or ()):
            command = str(raw_command or "").strip()
            if not command.startswith("msf_run ") or command in seen:
                continue
            seen.add(command)
            unique_candidates.append(command)
            if candidate_cap is not None and len(unique_candidates) >= candidate_cap:
                break

        proposals: list[FollowupProposal] = []
        for command in unique_candidates:
            parts = command.split()
            module = parts[2] if len(parts) >= 3 else ""
            if not module or module not in positive_modules or command in executed_snapshot:
                continue
            proposals.append(
                FollowupProposal(
                    command,
                    self.FAMILY,
                    "active_promotion.positive_msf_check",
                    f"msf_check_positive:{module}",
                )
            )
            if len(proposals) >= remaining:
                break
        return proposals


class FollowupRuleFamilies:
    """Composition facade preserving the characterized legacy family order."""

    def __init__(self) -> None:
        self.service = ServiceFollowupRules()
        self.web_api = WebAPIFollowupRules()
        self.post_access = PostAccessFollowupRules()
        self.active_promotion = ActivePromotionFollowupRules()

    def from_legacy_groups(
        self,
        *,
        ssh_inventory_commands: Sequence[str] = (),
        cpanel_commands: Sequence[str] = (),
        service_intelligence_commands: Sequence[str] = (),
        protocol_service_commands: Sequence[str] = (),
        web_path_commands: Sequence[str] = (),
        web_link_api_commands: Sequence[str] = (),
        web_surface_commands: Sequence[str] = (),
        limit: int | None = None,
    ) -> list[FollowupProposal]:
        """Wrap legacy groups in their existing composite first-seen order."""

        post_access = self.post_access.from_commands(ssh_inventory_commands)
        service = self.service.propose(
            cpanel_commands=cpanel_commands,
            intelligence_commands=service_intelligence_commands,
            protocol_commands=protocol_service_commands,
        )
        web_api = self.web_api.propose(
            path_commands=web_path_commands,
            link_api_commands=web_link_api_commands,
            surface_commands=web_surface_commands,
        )
        return _dedupe_and_bound((*post_access, *service, *web_api), limit=limit)
