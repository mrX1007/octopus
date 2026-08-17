"""Mission-scoped, non-destructive in-memory C2 result service.

The concrete store is intentionally non-operational: it stores only the public
summary DTOs and access metadata needed to validate the PR-14 control contract.
It never stores raw task output or agent-wire acknowledgements.
"""

from __future__ import annotations

import math
import time
from bisect import bisect_right
from collections.abc import Callable
from dataclasses import dataclass, replace
from threading import RLock
from typing import Protocol, TypeVar, runtime_checkable

from core.c2.control_auth import AuthenticatedControlPrincipal
from core.c2.control_commands import C2ControlAction
from core.c2.control_rbac import ControlRBACPolicy
from core.c2.result_models import (
    AgentPageV1,
    AgentSummaryV1,
    PurgeResultV1,
    ResultAckBatchV1,
    ResultAcknowledgementRecordV1,
    ResultAckRequestV1,
    ResultPageV1,
    ResultRecordStatusV1,
    ResultSummaryV1,
)

_MAX_PAGE_SIZE = 100
_MAX_ACL_SUBJECTS = 100
_MAX_REFERENCE_LENGTH = 512
_PageItemT = TypeVar("_PageItemT")


@dataclass(frozen=True)
class _ResourceAccess:
    owner_subject_id: str | None
    permitted_subject_ids: frozenset[str]


@dataclass(frozen=True)
class _AgentRow:
    summary: AgentSummaryV1
    access: _ResourceAccess


@dataclass(frozen=True)
class _ResultRow:
    summary: ResultSummaryV1
    access: _ResourceAccess


@runtime_checkable
class C2ControlResultServiceV1(Protocol):
    def list_agents(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        *,
        cursor: str | None,
        limit: int,
    ) -> AgentPageV1: ...

    def list_results(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        agent_ref: str,
        *,
        cursor: str | None,
        limit: int,
    ) -> ResultPageV1: ...

    def ack_results(
        self,
        principal: AuthenticatedControlPrincipal,
        request: ResultAckRequestV1,
    ) -> ResultAckBatchV1: ...

    def purge_results(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        *,
        before: float,
        limit: int,
    ) -> PurgeResultV1: ...


class C2ResultServiceV1:
    """Thread-safe reference implementation of the result-control contract."""

    __slots__ = (
        "_acknowledgement_revisions",
        "_acknowledgements",
        "_agents",
        "_clock",
        "_lock",
        "_policy",
        "_results",
    )

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        policy: ControlRBACPolicy | None = None,
    ) -> None:
        self._clock = clock
        self._policy = policy or ControlRBACPolicy(clock=clock)
        self._lock = RLock()
        self._agents: dict[str, _AgentRow] = {}
        self._results: dict[str, _ResultRow] = {}
        self._acknowledgements: dict[tuple[str, str], ResultAcknowledgementRecordV1] = {}
        self._acknowledgement_revisions: dict[str, int] = {}

    def register_agent(
        self,
        agent: AgentSummaryV1,
        *,
        owner_subject_id: str | None,
        permitted_subject_ids: tuple[str, ...] = (),
    ) -> None:
        """Seed an in-memory agent summary with explicit ownership and ACL.

        ``owner_subject_id=None`` represents an unassigned migrated row. Such a
        row is intentionally invisible to every role, including ADMIN.
        """

        if type(agent) is not AgentSummaryV1:
            raise TypeError("agent must be AgentSummaryV1")
        access = self._make_access(owner_subject_id, permitted_subject_ids)
        row = _AgentRow(summary=agent, access=access)
        with self._lock:
            existing = self._agents.get(agent.agent_ref)
            if existing == row:
                return
            if existing is not None and agent.revision <= existing.summary.revision:
                raise ValueError("agent revision must increase monotonically")
            self._agents[agent.agent_ref] = row

    def store_result(
        self,
        result: ResultSummaryV1,
        *,
        owner_subject_id: str | None,
        permitted_subject_ids: tuple[str, ...] = (),
    ) -> None:
        """Seed one result summary; acknowledgements can only use ``ack_results``."""

        if type(result) is not ResultSummaryV1:
            raise TypeError("result must be ResultSummaryV1")
        if result.acknowledged:
            raise ValueError("result acknowledgements must use ack_results")
        access = self._make_access(owner_subject_id, permitted_subject_ids)
        row = _ResultRow(summary=result, access=access)
        with self._lock:
            agent = self._agents.get(result.agent_ref)
            if agent is None or agent.summary.mission_id != result.mission_id:
                raise ValueError("result must reference an agent in the same mission")
            existing = self._results.get(result.result_ref)
            if existing == row:
                return
            if existing is not None and result.revision <= existing.summary.revision:
                raise ValueError("result revision must increase monotonically")
            self._results[result.result_ref] = row

    def list_agents(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        *,
        cursor: str | None,
        limit: int,
    ) -> AgentPageV1:
        checked_at = self._checked_now()
        self._policy.require(
            principal,
            C2ControlAction.LIST_AGENTS,
            mission_id=mission_id,
            now=checked_at,
        )
        self._validate_page(cursor, limit)

        with self._lock:
            visible = sorted(
                (
                    row.summary
                    for row in self._agents.values()
                    if row.summary.mission_id == mission_id and self._can_access(row.access, principal.subject_id)
                ),
                key=lambda item: item.agent_ref,
            )
            page, next_cursor = self._page_by_reference(
                visible,
                cursor=cursor,
                limit=limit,
                reference=lambda item: item.agent_ref,
            )
            return AgentPageV1(items=page, next_cursor=next_cursor)

    def list_results(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        agent_ref: str,
        *,
        cursor: str | None,
        limit: int,
    ) -> ResultPageV1:
        checked_at = self._checked_now()
        self._policy.require(
            principal,
            C2ControlAction.LIST_RESULTS,
            agent_ref,
            mission_id=mission_id,
            now=checked_at,
        )
        self._validate_reference(agent_ref, "agent_ref")
        self._validate_page(cursor, limit)

        with self._lock:
            agent = self._agents.get(agent_ref)
            if not self._agent_accessible(agent, principal.subject_id, mission_id):
                return ResultPageV1(items=(), next_cursor=None)

            visible: list[ResultSummaryV1] = []
            for row in self._results.values():
                summary = row.summary
                if (
                    summary.mission_id != mission_id
                    or summary.agent_ref != agent_ref
                    or summary.status is ResultRecordStatusV1.LEGACY_UNASSIGNED
                    or not self._can_access(row.access, principal.subject_id)
                ):
                    continue
                visible.append(
                    replace(
                        summary,
                        acknowledged=self._is_acknowledged(summary.result_ref),
                    )
                )
            visible.sort(key=lambda item: item.result_ref)
            page, next_cursor = self._page_by_reference(
                visible,
                cursor=cursor,
                limit=limit,
                reference=lambda item: item.result_ref,
            )
            return ResultPageV1(items=page, next_cursor=next_cursor)

    def ack_results(
        self,
        principal: AuthenticatedControlPrincipal,
        request: ResultAckRequestV1,
    ) -> ResultAckBatchV1:
        if type(request) is not ResultAckRequestV1:
            raise TypeError("request must be ResultAckRequestV1")
        checked_at = self._checked_now()
        self._policy.require(
            principal,
            C2ControlAction.ACK_RESULTS,
            request.agent_ref,
            mission_id=request.mission_id,
            now=checked_at,
        )

        acknowledgements: list[ResultAcknowledgementRecordV1] = []
        rejected_refs: list[str] = []
        seen_refs: set[str] = set()
        with self._lock:
            agent = self._agents.get(request.agent_ref)
            agent_accessible = self._agent_accessible(agent, principal.subject_id, request.mission_id)
            for selection in request.selections:
                if selection.result_ref in seen_refs:
                    rejected_refs.append(selection.result_ref)
                    continue
                seen_refs.add(selection.result_ref)
                row = self._results.get(selection.result_ref)
                if not agent_accessible or not self._ack_target_accessible(
                    row,
                    principal.subject_id,
                    request.mission_id,
                    request.agent_ref,
                    selection.expected_revision,
                ):
                    rejected_refs.append(selection.result_ref)
                    continue

                assert row is not None
                key = (selection.result_ref, principal.subject_id)
                existing = self._acknowledgements.get(key)
                if existing is not None and existing.result_revision == row.summary.revision:
                    acknowledgements.append(existing)
                    continue

                acknowledgement_revision = self._acknowledgement_revisions.get(selection.result_ref, 0) + 1
                record = ResultAcknowledgementRecordV1(
                    result_ref=selection.result_ref,
                    result_revision=row.summary.revision,
                    acknowledged_by_subject_id=principal.subject_id,
                    acknowledged_at=checked_at,
                    acknowledgement_revision=acknowledgement_revision,
                )
                self._acknowledgements[key] = record
                self._acknowledgement_revisions[selection.result_ref] = acknowledgement_revision
                acknowledgements.append(record)

        return ResultAckBatchV1(
            acknowledgements=tuple(acknowledgements),
            rejected_refs=tuple(rejected_refs),
        )

    def purge_results(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        *,
        before: float,
        limit: int,
    ) -> PurgeResultV1:
        checked_at = self._checked_now()
        self._policy.require(
            principal,
            C2ControlAction.PURGE_RESULTS,
            mission_id=mission_id,
            now=checked_at,
        )
        if type(before) not in (int, float) or not math.isfinite(float(before)) or before < 0:
            raise ValueError("before must be a finite non-negative timestamp")
        self._validate_limit(limit)

        with self._lock:
            candidates = sorted(
                (
                    row
                    for row in self._results.values()
                    if row.summary.mission_id == mission_id
                    and row.summary.completed_at < before
                    and row.summary.status is not ResultRecordStatusV1.LEGACY_UNASSIGNED
                    and self._can_access(row.access, principal.subject_id)
                    and self._agent_accessible(
                        self._agents.get(row.summary.agent_ref),
                        principal.subject_id,
                        mission_id,
                    )
                    and self._is_acknowledged(row.summary.result_ref)
                ),
                key=lambda row: (row.summary.completed_at, row.summary.result_ref),
            )
            selected = candidates[:limit]
            for row in selected:
                result_ref = row.summary.result_ref
                del self._results[result_ref]
                self._acknowledgement_revisions.pop(result_ref, None)
                for key in tuple(self._acknowledgements):
                    if key[0] == result_ref:
                        del self._acknowledgements[key]
            next_cursor = candidates[limit].summary.result_ref if len(candidates) > limit else None
            return PurgeResultV1(
                purged_count=len(selected),
                next_cursor=next_cursor,
            )

    def _checked_now(self) -> float:
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(float(now)) or now < 0:
            raise RuntimeError("control clock is invalid")
        return float(now)

    @staticmethod
    def _make_access(owner_subject_id: str | None, permitted_subject_ids: tuple[str, ...]) -> _ResourceAccess:
        if owner_subject_id is not None:
            C2ResultServiceV1._validate_reference(owner_subject_id, "owner_subject_id")
        if type(permitted_subject_ids) is not tuple:
            raise TypeError("permitted_subject_ids must be a tuple")
        if len(permitted_subject_ids) > _MAX_ACL_SUBJECTS:
            raise ValueError("resource ACL exceeds its bounded size")
        for subject_id in permitted_subject_ids:
            C2ResultServiceV1._validate_reference(subject_id, "permitted subject")
        if len(set(permitted_subject_ids)) != len(permitted_subject_ids):
            raise ValueError("resource ACL contains duplicate subjects")
        return _ResourceAccess(
            owner_subject_id=owner_subject_id,
            permitted_subject_ids=frozenset(permitted_subject_ids),
        )

    @staticmethod
    def _can_access(access: _ResourceAccess, subject_id: str) -> bool:
        return access.owner_subject_id is not None and (
            subject_id == access.owner_subject_id or subject_id in access.permitted_subject_ids
        )

    @classmethod
    def _agent_accessible(
        cls,
        row: _AgentRow | None,
        subject_id: str,
        mission_id: str,
    ) -> bool:
        return row is not None and row.summary.mission_id == mission_id and cls._can_access(row.access, subject_id)

    @classmethod
    def _ack_target_accessible(
        cls,
        row: _ResultRow | None,
        subject_id: str,
        mission_id: str,
        agent_ref: str,
        expected_revision: int,
    ) -> bool:
        return (
            row is not None
            and row.summary.mission_id == mission_id
            and row.summary.agent_ref == agent_ref
            and row.summary.revision == expected_revision
            and row.summary.status is not ResultRecordStatusV1.LEGACY_UNASSIGNED
            and cls._can_access(row.access, subject_id)
        )

    def _is_acknowledged(self, result_ref: str) -> bool:
        return any(key[0] == result_ref for key in self._acknowledgements)

    @staticmethod
    def _validate_reference(value: object, field_name: str) -> None:
        if type(value) is not str or not value or len(value) > _MAX_REFERENCE_LENGTH:
            raise ValueError(f"{field_name} must be a non-empty bounded string")

    @classmethod
    def _validate_page(cls, cursor: str | None, limit: int) -> None:
        if cursor is not None:
            cls._validate_reference(cursor, "cursor")
        cls._validate_limit(limit)

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if type(limit) is not int or not 1 <= limit <= _MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {_MAX_PAGE_SIZE}")

    @staticmethod
    def _page_by_reference(
        values: list[_PageItemT],
        *,
        cursor: str | None,
        limit: int,
        reference: Callable[[_PageItemT], str],
    ) -> tuple[tuple[_PageItemT, ...], str | None]:
        references = [reference(value) for value in values]
        start = 0 if cursor is None else bisect_right(references, cursor)
        selected = values[start : start + limit]
        next_cursor = reference(selected[-1]) if selected and start + len(selected) < len(values) else None
        return tuple(selected), next_cursor


__all__ = ["C2ControlResultServiceV1", "C2ResultServiceV1"]
