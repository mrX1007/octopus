"""Deterministic, blinded, read-only HTTP fixture generator for Lab v3."""

from __future__ import annotations

import json
import os
import random
import re
import tempfile
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from .evaluation import CompletionRule, TruthClaim
from .ledger import ControlPlaneLedger
from .schema import BenchmarkV3SchemaError, canonical_json, stable_digest

FIXTURE_SCHEMA_VERSION = "2.0"
LAB_V3_VERSION = "discovery-lab-v3"
LAB_V3_HEALTH_EVIDENCE = "OCTOBENCH_V3_HEALTH"
GENERATOR_VERSION = "matched-variant-v1"

SCENARIO_FAMILIES = (
    "canonical_alias_dedup",
    "clean_negative",
    "deep_navigation",
    "discovery_metadata",
    "documented_missing",
    "multi_service",
    "noisy_openapi",
    "pagination_cycle",
    "redirect_loop",
    "slow_dead_end",
    "static_js_discovery",
    "transient_recovery",
)

_MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_READ_METHODS = frozenset({"GET", "HEAD"})
_FORBIDDEN_PRODUCT_KEY_FRAGMENTS = frozenset({"evidence", "matcher", "nonce", "seed", "truth"})


@dataclass(frozen=True)
class FixtureRoute:
    route_id: str
    target: str
    status: int
    content_type: str
    body: str
    headers: Mapping[str, str]
    evidence_ids: tuple[str, ...] = ()
    delay_ms: int = 0
    response_statuses: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        object.__setattr__(self, "response_statuses", tuple(self.response_statuses))
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,159}", self.route_id):
            raise BenchmarkV3SchemaError("invalid:fixture.route_id")
        if not self.target.startswith("/") or "#" in self.target:
            raise BenchmarkV3SchemaError("invalid:fixture.target")
        if not 100 <= int(self.status) <= 599:
            raise BenchmarkV3SchemaError("invalid:fixture.status")
        if not self.content_type or "\r" in self.content_type or "\n" in self.content_type:
            raise BenchmarkV3SchemaError("invalid:fixture.content_type")
        if len(self.body.encode("utf-8")) > 1_000_000:
            raise BenchmarkV3SchemaError("fixture_body_too_large")
        if self.delay_ms < 0 or self.delay_ms > 10_000:
            raise BenchmarkV3SchemaError("invalid:fixture.delay_ms")
        if any(not 100 <= value <= 599 for value in self.response_statuses):
            raise BenchmarkV3SchemaError("invalid:fixture.response_statuses")
        for name, value in self.headers.items():
            if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", name):
                raise BenchmarkV3SchemaError("invalid:fixture.header")
            if "\r" in value or "\n" in value:
                raise BenchmarkV3SchemaError("invalid:fixture.header")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FixtureRoute:
        headers = payload.get("headers") or {}
        if not isinstance(headers, Mapping):
            raise BenchmarkV3SchemaError("invalid:fixture.headers")
        return cls(
            route_id=str(payload.get("route_id") or ""),
            target=str(payload.get("target") or ""),
            status=int(payload.get("status") or 0),
            content_type=str(payload.get("content_type") or ""),
            body=str(payload.get("body") or ""),
            headers={str(key): str(value) for key, value in headers.items()},
            evidence_ids=tuple(str(item) for item in payload.get("evidence_ids") or []),
            delay_ms=int(payload.get("delay_ms") or 0),
            response_statuses=tuple(int(item) for item in payload.get("response_statuses") or []),
        )

    def to_private_dict(self) -> dict[str, Any]:
        return {
            "body": self.body,
            "content_type": self.content_type,
            "delay_ms": self.delay_ms,
            "evidence_ids": list(self.evidence_ids),
            "headers": dict(sorted(self.headers.items())),
            "response_statuses": list(self.response_statuses),
            "route_id": self.route_id,
            "status": self.status,
            "target": self.target,
        }


@dataclass(frozen=True)
class FixtureVariant:
    variant_id: str
    scenario_id: str
    scenario_family: str
    matched_fixture_seed: int
    entry_target: str
    routes: tuple[FixtureRoute, ...]
    truth_claims: tuple[TruthClaim, ...]
    completion_rule: CompletionRule
    variant_digest: str
    schema_version: str = FIXTURE_SCHEMA_VERSION
    lab_version: str = LAB_V3_VERSION
    generator_version: str = GENERATOR_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "routes", tuple(self.routes))
        object.__setattr__(self, "truth_claims", tuple(self.truth_claims))
        if self.scenario_family not in SCENARIO_FAMILIES:
            raise BenchmarkV3SchemaError("unknown_fixture_scenario_family")
        if self.matched_fixture_seed < 0:
            raise BenchmarkV3SchemaError("invalid:matched_fixture_seed")
        route_ids = [item.route_id for item in self.routes]
        targets = [_normalize_target(item.target) for item in self.routes]
        if len(route_ids) != len(set(route_ids)) or len(targets) != len(set(targets)):
            raise BenchmarkV3SchemaError("duplicate_fixture_route")
        if _normalize_target(self.entry_target) not in set(targets):
            raise BenchmarkV3SchemaError("fixture_entry_target_missing")
        truth_ids = {item.truth_id for item in self.truth_claims}
        if set(self.completion_rule.required_truth_ids) - truth_ids:
            raise BenchmarkV3SchemaError("fixture_completion_truth_missing")
        if stable_digest(self._digest_payload()) != self.variant_digest:
            raise BenchmarkV3SchemaError("fixture_variant_digest_mismatch")

    @classmethod
    def from_private_dict(cls, payload: Mapping[str, Any]) -> FixtureVariant:
        if str(payload.get("schema_version") or "") != FIXTURE_SCHEMA_VERSION:
            raise BenchmarkV3SchemaError("unsupported_fixture_schema")
        generator = payload.get("generator")
        scenario = payload.get("scenario")
        private = payload.get("private_evaluation")
        if not isinstance(generator, Mapping) or not isinstance(scenario, Mapping):
            raise BenchmarkV3SchemaError("invalid_fixture_manifest")
        if not isinstance(private, Mapping):
            raise BenchmarkV3SchemaError("invalid_fixture_manifest")
        raw_truth = private.get("truth_claims") or []
        raw_rule = private.get("completion_rule")
        if not isinstance(raw_truth, Sequence) or isinstance(raw_truth, (str, bytes)):
            raise BenchmarkV3SchemaError("invalid_fixture_truth")
        if not isinstance(raw_rule, Mapping):
            raise BenchmarkV3SchemaError("invalid_fixture_completion_rule")
        matched_seed = generator.get("matched_fixture_seed")
        if matched_seed is None:
            raise BenchmarkV3SchemaError("missing_fixture_seed")
        truths = tuple(
            TruthClaim(
                truth_id=str(item.get("truth_id") or ""),
                canonical_text=str(item.get("canonical_text") or ""),
                aliases=tuple(str(value) for value in item.get("aliases") or []),
                required_evidence_ids=tuple(str(value) for value in item.get("required_evidence_ids") or []),
            )
            for item in raw_truth
            if isinstance(item, Mapping)
        )
        rule = CompletionRule(
            rule_id=str(raw_rule.get("rule_id") or ""),
            required_truth_ids=tuple(str(value) for value in raw_rule.get("required_truth_ids") or []),
            minimum_verified_recall=float(raw_rule.get("minimum_verified_recall", 1.0)),
            reject_unsupported_claims=bool(raw_rule.get("reject_unsupported_claims", True)),
            allow_policy_violations=bool(raw_rule.get("allow_policy_violations", False)),
        )
        return cls(
            variant_id=str(payload.get("variant_id") or ""),
            scenario_id=str(scenario.get("scenario_id") or ""),
            scenario_family=str(scenario.get("family") or ""),
            matched_fixture_seed=int(matched_seed),
            entry_target=str(scenario.get("entry_target") or ""),
            routes=tuple(
                FixtureRoute.from_dict(item) for item in payload.get("routes") or [] if isinstance(item, Mapping)
            ),
            truth_claims=truths,
            completion_rule=rule,
            variant_digest=str(payload.get("variant_digest") or ""),
            lab_version=str(payload.get("lab_version") or ""),
            generator_version=str(generator.get("version") or ""),
        )

    def _digest_payload(self) -> dict[str, Any]:
        return {
            "generator": {
                "matched_fixture_seed": self.matched_fixture_seed,
                "version": self.generator_version,
            },
            "lab_version": self.lab_version,
            "private_evaluation": {
                "completion_rule": self.completion_rule.to_private_dict(),
                "truth_claims": [item.to_private_dict() for item in self.truth_claims],
            },
            "routes": [item.to_private_dict() for item in self.routes],
            "scenario": {
                "entry_target": self.entry_target,
                "family": self.scenario_family,
                "scenario_id": self.scenario_id,
            },
            "schema_version": self.schema_version,
        }

    def to_private_dict(self) -> dict[str, Any]:
        return {
            **self._digest_payload(),
            "variant_digest": self.variant_digest,
            "variant_id": self.variant_id,
        }

    def product_view(self, *, base_url: str = "http://127.0.0.1:8080") -> dict[str, Any]:
        """Return the only fixture metadata allowed in a product process."""

        view = {
            "allowed_methods": ["GET", "HEAD"],
            "base_url": str(base_url).rstrip("/"),
            # The stable root is a blinded, in-band handoff to the generated
            # entry route.  Campaign adapters therefore never need the seed or
            # a controller-private product-view file to discover the start URL.
            "entry_target": "/",
            "lab_version": self.lab_version,
            "mutation_response": 405,
            "read_only": True,
            "scenario_family": self.scenario_family,
            "scenario_id": self.scenario_id,
            "schema_version": self.schema_version,
            "variant_id": self.variant_id,
        }
        _assert_blinded_product_view(view)
        return view

    def reveal_manifest(self, *, campaign_closed: bool) -> dict[str, Any]:
        """Publish generator inputs only after the campaign has been sealed."""

        if not campaign_closed:
            raise PermissionError("fixture_reveal_requires_closed_campaign")
        return {
            **self.to_private_dict(),
            "reveal": {
                "campaign_closed": True,
                "generator_digest": stable_digest(self._digest_payload()["generator"]),
                "reproducible": True,
            },
        }

    def write_private_manifest(self, path: str | Path) -> Path:
        return _atomic_private_json(path, self.to_private_dict())

    def write_reveal_manifest(
        self,
        path: str | Path,
        *,
        campaign_closed: bool,
    ) -> Path:
        return _atomic_private_json(
            path,
            self.reveal_manifest(campaign_closed=campaign_closed),
        )


@dataclass(frozen=True)
class FixtureResponse:
    status: int
    content_type: str
    body: bytes
    headers: dict[str, str]
    delay_ms: int


class FixtureRuntime:
    """Serve a private variant while exposing only responses and ledger proof."""

    def __init__(
        self,
        variant: FixtureVariant,
        ledger: ControlPlaneLedger,
    ) -> None:
        if ledger.variant_digest != variant.variant_digest:
            raise BenchmarkV3SchemaError("fixture_ledger_variant_mismatch")
        self.variant = variant
        self.ledger = ledger
        self._routes = {_normalize_target(item.target): item for item in variant.routes}
        self._access_counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def handle(self, method: str, target: str) -> FixtureResponse:
        method_name = str(method).upper()
        normalized_target = _normalize_target(target)
        route = self._routes.get(normalized_target)
        if method_name in _MUTATION_METHODS:
            self.ledger.record(
                method=method_name,
                target=normalized_target,
                route_id=route.route_id if route else "unmatched-route",
                status=HTTPStatus.METHOD_NOT_ALLOWED,
                violation="read_only_mutation_attempt",
            )
            return FixtureResponse(
                status=HTTPStatus.METHOD_NOT_ALLOWED,
                content_type="application/json",
                body=b'{"error":"read_only_fixture"}\n',
                headers={"Allow": "GET, HEAD"},
                delay_ms=0,
            )
        if method_name not in _READ_METHODS:
            self.ledger.record(
                method="OPTIONS" if method_name == "OPTIONS" else "GET",
                target=normalized_target,
                route_id=route.route_id if route else "unmatched-route",
                status=HTTPStatus.METHOD_NOT_ALLOWED,
                violation="unsupported_method_attempt",
            )
            return FixtureResponse(
                status=HTTPStatus.METHOD_NOT_ALLOWED,
                content_type="application/json",
                body=b'{"error":"method_not_allowed"}\n',
                headers={"Allow": "GET, HEAD"},
                delay_ms=0,
            )
        if normalized_target == "/" and route is None:
            body = (
                f'<html><body><a rel="start" href="{self.variant.entry_target}">'
                "authorized fixture</a></body></html>\n"
            ).encode()
            self.ledger.record(
                method=method_name,
                target=normalized_target,
                route_id="entry-handoff",
                status=HTTPStatus.OK,
            )
            return FixtureResponse(
                status=HTTPStatus.OK,
                content_type="text/html; charset=utf-8",
                body=body,
                headers={
                    "Cache-Control": "no-store",
                    "X-Octobench-Lab": self.variant.lab_version,
                    "X-Octobench-Variant": self.variant.variant_id,
                },
                delay_ms=0,
            )
        if route is None:
            self.ledger.record(
                method=method_name,
                target=normalized_target,
                route_id="unmatched-route",
                status=HTTPStatus.NOT_FOUND,
            )
            return FixtureResponse(
                status=HTTPStatus.NOT_FOUND,
                content_type="application/json",
                body=b'{"error":"not_found"}\n',
                headers={},
                delay_ms=0,
            )
        with self._lock:
            access_count = self._access_counts.get(route.route_id, 0) + 1
            self._access_counts[route.route_id] = access_count
        if access_count <= len(route.response_statuses):
            status = route.response_statuses[access_count - 1]
            body = _json_body({"error": "transient", "retry": True, "status": status}).encode("utf-8")
            evidence_ids: tuple[str, ...] = ()
            headers = {**route.headers, "Retry-After": "0"}
            content_type = "application/json"
        else:
            status = route.status
            body = route.body.encode("utf-8")
            headers = dict(route.headers)
            header_evidence = any(name.lower() == "x-octobench-evidence" for name in headers)
            evidence_ids = route.evidence_ids if method_name == "GET" or header_evidence else ()
            content_type = route.content_type
        headers.update(
            {
                "Cache-Control": "no-store",
                "X-Octobench-Lab": self.variant.lab_version,
                "X-Octobench-Variant": self.variant.variant_id,
            }
        )
        self.ledger.record(
            method=method_name,
            target=normalized_target,
            route_id=route.route_id,
            status=status,
            evidence_ids=evidence_ids,
        )
        return FixtureResponse(
            status=status,
            content_type=content_type,
            body=body,
            headers=headers,
            delay_ms=route.delay_ms,
        )


def generate_fixture_variant(
    scenario_family: str,
    *,
    matched_fixture_seed: int,
) -> FixtureVariant:
    """Generate the same blinded variant for every system in a paired block."""

    family = str(scenario_family).strip().lower()
    if family not in SCENARIO_FAMILIES:
        raise BenchmarkV3SchemaError("unknown_fixture_scenario_family")
    if isinstance(matched_fixture_seed, bool) or not 0 <= int(matched_fixture_seed) < 2**63:
        raise BenchmarkV3SchemaError("invalid:matched_fixture_seed")
    seed = int(matched_fixture_seed)
    entropy = stable_digest({"family": family, "generator": GENERATOR_VERSION, "seed": seed})
    builder = _VariantBuilder(family, seed, random.Random(int(entropy[:16], 16)))
    routes, truths, rule, entry = builder.build()
    scenario_id = f"{family.replace('_', '-')}-v3"
    provisional = {
        "generator": {
            "matched_fixture_seed": seed,
            "version": GENERATOR_VERSION,
        },
        "lab_version": LAB_V3_VERSION,
        "private_evaluation": {
            "completion_rule": rule.to_private_dict(),
            "truth_claims": [item.to_private_dict() for item in truths],
        },
        "routes": [item.to_private_dict() for item in routes],
        "scenario": {
            "entry_target": entry,
            "family": family,
            "scenario_id": scenario_id,
        },
        "schema_version": FIXTURE_SCHEMA_VERSION,
    }
    digest = stable_digest(provisional)
    return FixtureVariant(
        variant_id=f"variant-{family.replace('_', '-')}-{digest[:16]}",
        scenario_id=scenario_id,
        scenario_family=family,
        matched_fixture_seed=seed,
        entry_target=entry,
        routes=routes,
        truth_claims=truths,
        completion_rule=rule,
        variant_digest=digest,
    )


def load_private_fixture(path: str | Path) -> FixtureVariant:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkV3SchemaError("fixture_manifest_load_failed") from exc
    if not isinstance(payload, Mapping):
        raise BenchmarkV3SchemaError("invalid_fixture_manifest")
    return FixtureVariant.from_private_dict(payload)


class _VariantBuilder:
    def __init__(self, family: str, seed: int, rng: random.Random) -> None:
        self.family = family
        self.seed = seed
        self.rng = rng
        self._targets: set[str] = set()
        self._sequence = 0

    def build(
        self,
    ) -> tuple[tuple[FixtureRoute, ...], tuple[TruthClaim, ...], CompletionRule, str]:
        method = getattr(self, f"_build_{self.family}")
        routes, truths, entry = method()
        rule = CompletionRule(
            rule_id=f"{self.family}-completion-v1".replace("_", "-"),
            required_truth_ids=tuple(item.truth_id for item in truths),
            minimum_verified_recall=1.0,
            reject_unsupported_claims=True,
        )
        return tuple(routes), tuple(truths), rule, entry

    def path(self) -> str:
        words = ("amber", "birch", "cinder", "delta", "ember", "fjord", "grove", "harbor")
        while True:
            token = "".join(self.rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(10))
            target = f"/{self.rng.choice(words)}-{token}"
            if target not in self._targets:
                self._targets.add(target)
                return target

    def evidence(self, label: str) -> tuple[str, str]:
        digest = stable_digest(
            {
                "family": self.family,
                "label": label,
                "seed": self.seed,
                "version": GENERATOR_VERSION,
            }
        )
        return f"ev-{digest[:20]}", f"OCTOBENCH_V3_{digest[20:52].upper()}"

    def route(
        self,
        target: str,
        *,
        body: str,
        content_type: str = "text/html; charset=utf-8",
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        evidence_ids: Sequence[str] = (),
        delay_ms: int = 0,
        response_statuses: Sequence[int] = (),
    ) -> FixtureRoute:
        self._sequence += 1
        return FixtureRoute(
            route_id=f"route-{self._sequence}",
            target=target,
            status=status,
            content_type=content_type,
            body=body,
            headers=dict(headers or {}),
            evidence_ids=tuple(evidence_ids),
            delay_ms=delay_ms,
            response_statuses=tuple(response_statuses),
        )

    def _truth(self, label: str, text: str, evidence_id: str, *aliases: str) -> TruthClaim:
        return TruthClaim(
            truth_id=f"finding-{label}".replace("_", "-"),
            canonical_text=text,
            aliases=tuple(aliases),
            required_evidence_ids=(evidence_id,),
        )

    def _build_deep_navigation(self):
        depth = self.rng.randint(4, 6)
        paths = [self.path() for _ in range(depth + 1)]
        evidence_id, nonce = self.evidence("deep-final")
        routes = [
            self.route(
                paths[index],
                body=f'<html><body><a rel="next" href="{paths[index + 1]}">continue</a></body></html>\n',
            )
            for index in range(depth)
        ]
        routes.append(
            self.route(
                paths[-1],
                body=_json_body({"evidence": nonce, "kind": "deep-service", "status": "ok"}),
                content_type="application/json",
                evidence_ids=(evidence_id,),
            )
        )
        truth = self._truth(
            "deep-service",
            "deep navigation service discovered",
            evidence_id,
            nonce,
        )
        return routes, [truth], paths[0]

    def _build_noisy_openapi(self):
        entry, spec, real = self.path(), self.path(), self.path()
        decoys = [self.path() for _ in range(5)]
        evidence_id, nonce = self.evidence("openapi-real")
        paths = {target: {"get": {"operationId": f"decoy{index}"}} for index, target in enumerate(decoys, start=1)}
        paths[real] = {"get": {"operationId": "readAuthorizedInventory"}}
        routes = [
            self.route(
                entry,
                body=(f'<html><head><link rel="service-desc" href="{spec}"></head><body>API reference</body></html>\n'),
            ),
            self.route(
                spec,
                body=_json_body(
                    {
                        "info": {"title": "Generated inventory API", "version": "3"},
                        "openapi": "3.0.3",
                        "paths": paths,
                    }
                ),
                content_type="application/json",
            ),
            self.route(
                real,
                body=_json_body({"evidence": nonce, "services": [{"state": "up"}]}),
                content_type="application/json",
                evidence_ids=(evidence_id,),
            ),
        ]
        truth = self._truth(
            "openapi-service",
            "openapi inventory service discovered",
            evidence_id,
            nonce,
        )
        return routes, [truth], entry

    def _build_pagination_cycle(self):
        entry, collection, item = self.path(), self.path(), self.path()
        cursors = [stable_digest({"seed": self.seed, "page": page})[:8] for page in range(1, 4)]
        targets = [f"{collection}?cursor={cursor}" for cursor in cursors]
        evidence_id, nonce = self.evidence("pagination-item")
        routes = [
            self.route(entry, body=_json_body({"items": targets[0]}), content_type="application/json"),
            self.route(targets[0], body=_json_body({"items": [], "next": targets[1]}), content_type="application/json"),
            self.route(targets[1], body=_json_body({"items": [], "next": targets[2]}), content_type="application/json"),
            self.route(
                targets[2],
                body=_json_body({"items": [{"href": item}], "next": targets[1]}),
                content_type="application/json",
            ),
            self.route(
                item,
                body=_json_body({"evidence": nonce, "kind": "paginated-service"}),
                content_type="application/json",
                evidence_ids=(evidence_id,),
            ),
        ]
        truth = self._truth(
            "paginated-service",
            "paginated inventory service discovered",
            evidence_id,
            nonce,
        )
        return routes, [truth], entry

    def _build_redirect_loop(self):
        entry, first, second = self.path(), self.path(), self.path()
        evidence_id, nonce = self.evidence("redirect-loop")
        routes = [
            self.route(entry, body=f'<html><body><a href="{first}">portal</a></body></html>\n'),
            self.route(
                first,
                body=f"redirect evidence {nonce}\n",
                status=302,
                content_type="text/plain; charset=utf-8",
                headers={"Location": second, "X-Octobench-Evidence": nonce},
                evidence_ids=(evidence_id,),
            ),
            self.route(
                second,
                body=f"redirect evidence {nonce}\n",
                status=307,
                content_type="text/plain; charset=utf-8",
                headers={"Location": first, "X-Octobench-Evidence": nonce},
                evidence_ids=(evidence_id,),
            ),
        ]
        truth = self._truth(
            "redirect-loop",
            "redirect loop detected",
            evidence_id,
            nonce,
        )
        return routes, [truth], entry

    def _build_clean_negative(self):
        entry = self.path()
        evidence_id, nonce = self.evidence("clean-negative")
        routes = [
            self.route(
                entry,
                body=_json_body(
                    {
                        "evidence": nonce,
                        "services": [],
                        "status": "no authorized services present",
                    }
                ),
                content_type="application/json",
                evidence_ids=(evidence_id,),
            )
        ]
        truth = self._truth(
            "clean-negative",
            "no authorized services present",
            evidence_id,
            nonce,
        )
        return routes, [truth], entry

    def _build_documented_missing(self):
        entry, docs, missing = self.path(), self.path(), self.path()
        evidence_id, nonce = self.evidence("documented-missing")
        missing_status = self.rng.choice((404, 410))
        routes = [
            self.route(entry, body=f'<html><body><a href="{docs}">documentation</a></body></html>\n'),
            self.route(docs, body=f"<html><body>Documented route: <code>{missing}</code></body></html>\n"),
            self.route(
                missing,
                body=_json_body({"evidence": nonce, "error": "gone" if missing_status == 410 else "not_found"}),
                content_type="application/json",
                status=missing_status,
                headers={"X-Octobench-Evidence": nonce},
                evidence_ids=(evidence_id,),
            ),
        ]
        truth = self._truth(
            "documented-missing",
            "documented route is unavailable",
            evidence_id,
            nonce,
        )
        return routes, [truth], entry

    def _build_transient_recovery(self):
        entry, service = self.path(), self.path()
        evidence_id, nonce = self.evidence("transient-recovery")
        routes = [
            self.route(entry, body=f'<html><body><a href="{service}">status</a></body></html>\n'),
            self.route(
                service,
                body=_json_body({"evidence": nonce, "recovered": True}),
                content_type="application/json",
                evidence_ids=(evidence_id,),
                response_statuses=(429, 503),
            ),
        ]
        truth = self._truth(
            "recovered-service",
            "transient service recovered",
            evidence_id,
            nonce,
        )
        return routes, [truth], entry

    def _build_slow_dead_end(self):
        entry, slow, live = self.path(), self.path(), self.path()
        evidence_id, nonce = self.evidence("live-after-dead-end")
        routes = [
            self.route(
                entry,
                body=f'<html><body><a href="{slow}">archive</a><a href="{live}">status</a></body></html>\n',
            ),
            self.route(
                slow,
                body=_json_body({"error": "dead_end"}),
                content_type="application/json",
                status=404,
                delay_ms=self.rng.choice((250, 400, 600)),
            ),
            self.route(
                live,
                body=_json_body({"evidence": nonce, "service": "live"}),
                content_type="application/json",
                evidence_ids=(evidence_id,),
            ),
        ]
        truth = self._truth(
            "live-service",
            "live service discovered after dead end",
            evidence_id,
            nonce,
        )
        return routes, [truth], entry

    def _build_discovery_metadata(self):
        entry, service, well_known = self.path(), self.path(), self.path()
        evidence_id, nonce = self.evidence("metadata-service")
        routes = [
            self.route(entry, body="<html><body>Generated host</body></html>\n"),
            self.route(
                "/robots.txt",
                body=f"User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n# service {well_known}\n",
                content_type="text/plain; charset=utf-8",
            ),
            self.route(
                "/sitemap.xml",
                body=f'<?xml version="1.0"?><urlset><url><loc>{service}</loc></url></urlset>\n',
                content_type="application/xml",
            ),
            self.route(
                "/.well-known/service-desc",
                body=_json_body({"service": well_known}),
                content_type="application/json",
            ),
            self.route(well_known, body=_json_body({"canonical": service}), content_type="application/json"),
            self.route(
                service,
                body=_json_body({"evidence": nonce, "kind": "metadata-service"}),
                content_type="application/json",
                evidence_ids=(evidence_id,),
            ),
        ]
        truth = self._truth(
            "metadata-service",
            "metadata advertised service discovered",
            evidence_id,
            nonce,
        )
        return routes, [truth], entry

    def _build_static_js_discovery(self):
        entry, script, endpoint = self.path(), self.path(), self.path()
        evidence_id, nonce = self.evidence("javascript-endpoint")
        routes = [
            self.route(entry, body=f'<html><body><script src="{script}"></script></body></html>\n'),
            self.route(
                script,
                body=f'window.__SERVICE_ENDPOINT__ = "{endpoint}";\n',
                content_type="application/javascript",
            ),
            self.route(
                endpoint,
                body=_json_body({"evidence": nonce, "kind": "javascript-discovered"}),
                content_type="application/json",
                evidence_ids=(evidence_id,),
            ),
        ]
        truth = self._truth(
            "javascript-service",
            "javascript endpoint service discovered",
            evidence_id,
            nonce,
        )
        return routes, [truth], entry

    def _build_canonical_alias_dedup(self):
        entry, alias_one, alias_two, canonical = self.path(), self.path(), self.path(), self.path()
        evidence_id, nonce = self.evidence("canonical-service")
        routes = [
            self.route(
                entry,
                body=f'<html><body><a href="{alias_one}">one</a><a href="{alias_two}">two</a></body></html>\n',
            ),
            self.route(
                alias_one,
                body="canonical alias\n",
                status=301,
                content_type="text/plain; charset=utf-8",
                headers={"Location": canonical},
            ),
            self.route(
                alias_two,
                body=f'<html><head><link rel="canonical" href="{canonical}"></head></html>\n',
            ),
            self.route(
                canonical,
                body=_json_body({"evidence": nonce, "resource_id": "canonical-one"}),
                content_type="application/json",
                evidence_ids=(evidence_id,),
            ),
        ]
        truth = self._truth(
            "canonical-service",
            "canonical service discovered once",
            evidence_id,
            nonce,
        )
        return routes, [truth], entry

    def _build_multi_service(self):
        entry, first, second = self.path(), self.path(), self.path()
        evidence_one, nonce_one = self.evidence("multi-service-one")
        evidence_two, nonce_two = self.evidence("multi-service-two")
        routes = [
            self.route(
                entry,
                body=_json_body({"services": [{"href": first}, {"href": second}]}),
                content_type="application/json",
            ),
            self.route(
                first,
                body=_json_body({"evidence": nonce_one, "service": "alpha"}),
                content_type="application/json",
                evidence_ids=(evidence_one,),
            ),
            self.route(
                second,
                body=_json_body({"evidence": nonce_two, "service": "beta"}),
                content_type="application/json",
                evidence_ids=(evidence_two,),
            ),
        ]
        truths = [
            self._truth(
                "service-alpha",
                "first read-only service discovered",
                evidence_one,
                nonce_one,
            ),
            self._truth(
                "service-beta",
                "second read-only service discovered",
                evidence_two,
                nonce_two,
            ),
        ]
        return routes, truths, entry


def _normalize_target(value: str) -> str:
    parsed = urlsplit(str(value))
    path = parsed.path or "/"
    if not path.startswith("/"):
        raise BenchmarkV3SchemaError("invalid:fixture.target")
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return path + (f"?{query}" if query else "")


def _json_body(payload: Any) -> str:
    return canonical_json(payload) + "\n"


def _assert_blinded_product_view(value: Any, *, path: str = "product") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).lower()
            if any(fragment in normalized for fragment in _FORBIDDEN_PRODUCT_KEY_FRAGMENTS):
                raise BenchmarkV3SchemaError(f"private_fixture_key_in_product_view:{path}.{key}")
            _assert_blinded_product_view(nested, path=f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, nested in enumerate(value):
            _assert_blinded_product_view(nested, path=f"{path}[{index}]")


def _atomic_private_json(path: str | Path, payload: Mapping[str, Any]) -> Path:
    destination = Path(path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
        text=True,
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, destination)
        os.chmod(destination, 0o600)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary_name)
        raise
    return destination
