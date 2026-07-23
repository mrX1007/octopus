"""Adapters over existing tool, exploit, Metasploit, plugin, and killchain APIs."""

from __future__ import annotations

import re
import shlex
import shutil
from collections.abc import Callable, Iterable, Mapping
from typing import Any, ClassVar

from core.execution import ExecutionContext, ExecutionResult
from core.execution.policy import registered_tool_requires_approval

from .base import ActionAdapter
from .models import (
    ActionCheckResult,
    ActionCleanupResult,
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
    ApplicabilityResult,
)

ActionDispatch = Callable[[str, ExecutionContext], Any]
MetasploitRunner = Callable[..., Any]

_ASSESSMENT_FACT_TYPES = {
    "inferred_claim",
    "potential_vulnerability",
    "verified_claim",
    "vulnerability",
    "vulnerability_candidate",
    "vulnerability_endpoint",
}


def canonical_assessment_applicability(
    facts: Iterable[Mapping[str, Any]],
    aliases: Iterable[str] = (),
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Gate only matching canonical evidence; unrelated facts have no effect.

    This pure boundary is shared by lifecycle adapters and the legacy command
    facade while that facade remains a production compatibility path.
    """

    normalized_aliases = {
        str(alias or "").strip().casefold()
        for alias in aliases
        if str(alias or "").strip()
    }
    relevant: list[dict[str, Any]] = []
    for fact in facts or ():
        fact_type = str(fact.get("type") or "").strip().casefold()
        if fact_type not in _ASSESSMENT_FACT_TYPES:
            continue
        value = str(fact.get("value") or "").casefold()
        if normalized_aliases and not any(
            alias in value for alias in normalized_aliases
        ):
            continue
        relevant.append(dict(fact))
    if not relevant:
        return (), ()

    usable = [
        fact
        for fact in relevant
        if str(fact.get("assessment_status") or "observed").casefold()
        != "contradicted"
        and str(fact.get("freshness_status") or "unknown").casefold() != "stale"
        and str(fact.get("coverage_status") or "unknown").casefold() != "degraded"
    ]
    if usable:
        status_order = {"verified": 0, "inferred": 1, "observed": 2}
        statuses = {
            str(fact.get("assessment_status") or "observed").casefold()
            for fact in usable
        }
        best = min(statuses, key=lambda status: status_order.get(status, 99))
        return (f"canonical_assessment:{best}",), ()

    missing: list[str] = []
    if any(
        str(fact.get("assessment_status") or "").casefold() == "contradicted"
        for fact in relevant
    ):
        missing.append("assessment:contradicted")
    if any(
        str(fact.get("freshness_status") or "").casefold() == "stale"
        for fact in relevant
    ):
        missing.append("assessment:stale")
    if any(
        str(fact.get("coverage_status") or "").casefold() == "degraded"
        for fact in relevant
    ):
        missing.append("assessment:degraded_coverage")
    return (), tuple(missing or ("assessment:no_usable_evidence",))


class RegisteredToolAdapter(ActionAdapter):
    def __init__(self, tool_def: Any, dispatch: ActionDispatch):
        self.tool_def = tool_def
        self.dispatch = dispatch
        name = str(tool_def.name)
        is_killchain = name.startswith("killchain_")
        kind = ActionKind.KILLCHAIN if is_killchain else ActionKind.REGISTERED_TOOL
        active = registered_tool_requires_approval(name, (name,))
        action_id = f"killchain:{name}" if is_killchain else f"tool:{name}"
        self.descriptor = ActionDescriptor(
            action_id=action_id,
            name=name,
            kind=kind,
            provider="core.tools.registry",
            category=str(getattr(tool_def, "category", "")),
            description=str(getattr(tool_def, "description", "")),
            aliases=tuple(str(item) for item in getattr(tool_def, "aliases", ()) or ()),
            requirements=ActionRequirements(
                system_dependencies=tuple(
                    str(item) for item in getattr(tool_def, "requires", ()) or ()
                ),
                target_required=bool(getattr(tool_def, "needs_target", True)),
                active=active,
            ),
        )

    def applicability(self, request: ActionRequest) -> ApplicabilityResult:
        missing = []
        if self.descriptor.requirements.target_required and not request.target.strip():
            missing.append("target")
        if not bool(getattr(self.tool_def, "enabled", True)):
            missing.append("provider_disabled")
        if not self.tool_def.is_available():
            missing.extend(
                f"dependency:{item}"
                for item in self.descriptor.requirements.system_dependencies
            )
            if not self.descriptor.requirements.system_dependencies:
                missing.append("provider_unavailable")
        return ApplicabilityResult(
            applicable=not missing,
            reasons=("registered_tool_available",) if not missing else (),
            missing_requirements=tuple(dict.fromkeys(missing)),
        )

    def _command(self, request: ActionRequest) -> str:
        allowed_names = {
            self.descriptor.name.casefold(),
            *(alias.casefold() for alias in self.descriptor.aliases),
        }
        provider_command = request.provider_command_for(self.descriptor.action_id)
        if not provider_command:
            provider_command = request.provider_command_for(self.descriptor.name)
        command = provider_command or request.command
        if command:
            try:
                parts = shlex.split(command, posix=True)
            except ValueError as exc:
                raise ValueError("invalid_action_command_quoting") from exc
            if not parts or parts[0].casefold() not in allowed_names:
                raise ValueError("action_command_does_not_match_descriptor")
            return command
        parts = [self.descriptor.name]
        if request.target and self.descriptor.requirements.target_required:
            parts.append(request.target)
        parts.extend(str(item) for item in request.arguments)
        return shlex.join(parts)

    def active_risk_class(
        self,
        request: ActionRequest,
        phase: str = "execute",
    ) -> ActiveRiskClass:
        try:
            invocation = self.invocation(request, phase)
        except (TypeError, ValueError):
            return super().active_risk_class(request, phase)
        return (
            ActiveRiskClass.ACTIVE
            if registered_tool_requires_approval(
                invocation.registered_name or invocation.executable,
                invocation.argv,
            )
            else ActiveRiskClass.READ_ONLY
        )

    def invocation(self, request: ActionRequest, phase: str):
        return self.registered_invocation(
            self._command(request),
            self.descriptor.name,
        )

    def execute(self, request: ActionRequest) -> Any:
        return self.dispatch(self._command(request), request.execution_context)


class KillchainActionAdapter(RegisteredToolAdapter):
    """Named compatibility adapter for existing killchain registry tools."""

    def __init__(self, tool_def: Any, dispatch: ActionDispatch):
        super().__init__(tool_def, dispatch)
        if self.descriptor.kind is not ActionKind.KILLCHAIN:
            raise ValueError("KillchainActionAdapter requires a killchain_* tool")


class ExploitBaseAdapter(ActionAdapter):
    def __init__(self, exploit: Any):
        self.exploit = exploit
        name = str(getattr(exploit, "name", type(exploit).__name__))
        cve = str(getattr(exploit, "cve", ""))
        slug = re.sub(r"[^a-z0-9]+", "-", cve or name, flags=re.IGNORECASE).strip("-").lower()
        self.descriptor = ActionDescriptor(
            action_id=f"exploit:{slug}",
            name=name,
            kind=ActionKind.EXPLOIT,
            provider=f"{type(exploit).__module__}.{type(exploit).__name__}",
            category="privilege_escalation",
            description=str(getattr(exploit, "description", "")),
            aliases=tuple(item for item in (cve,) if item),
            requirements=ActionRequirements(
                active=True,
                supports_check=True,
                positive_check_required=True,
            ),
        )

    def applicability(self, request: ActionRequest) -> ApplicabilityResult:
        base = super().applicability(request)
        missing = list(base.missing_requirements)
        if request.handle is None:
            missing.append("provider_handle")
        target_os = str(request.parameters.get("target_os") or "").lower()
        supported = [
            str(item).lower()
            for item in getattr(self.exploit, "supported_os", ()) or ()
        ]
        if target_os and supported and target_os not in supported:
            missing.append(f"supported_os:{','.join(supported)}")
        assessment_reasons, assessment_missing = self._assessment_applicability(
            request.facts
        )
        missing.extend(assessment_missing)
        return ApplicabilityResult(
            applicable=not missing,
            reasons=(
                ("exploit_contract_applicable", *assessment_reasons)
                if not missing
                else ()
            ),
            missing_requirements=tuple(dict.fromkeys(missing)),
        )

    def _assessment_applicability(
        self,
        facts: tuple[dict[str, Any], ...],
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Consume canonical fact judgements without turning candidates into proof."""

        aliases = {
            str(item or "").strip().casefold()
            for item in (
                *self.descriptor.aliases,
                getattr(self.exploit, "cve", ""),
            )
            if str(item or "").strip()
        }
        return canonical_assessment_applicability(facts, aliases)

    def invocation(self, request: ActionRequest, phase: str):
        policy_name = "killchain_vuln_assess" if phase == "check" else "killchain_privesc"
        command = shlex.join((policy_name, request.target))
        return self.registered_invocation(command, policy_name)

    def check(self, request: ActionRequest) -> ActionCheckResult:
        normalized = self.exploit.normalize_check_result(
            self.exploit.check_vulnerable(request.handle)
        )
        return ActionCheckResult(
            result=normalized,
            applicable=bool(normalized.success),
            reason=str(normalized.evidence or normalized.output or normalized.status),
        )

    def execute(self, request: ActionRequest) -> Any:
        return self.exploit.normalize_run_result(self.exploit.run(request.handle))


class MetasploitActionAdapter(ActionAdapter):
    _MODULE_RE = re.compile(r"^(?:auxiliary|exploit|post)/[a-z0-9_./-]+$", re.IGNORECASE)

    def __init__(
        self,
        module: str,
        runner: MetasploitRunner | None = None,
        dependency_check: Callable[[str], bool] | None = None,
    ):
        module = str(module or "").strip().strip("'\"")
        if not self._MODULE_RE.fullmatch(module):
            raise ValueError("Invalid Metasploit module identifier")
        self.module = module.lower()
        self.runner = runner or self._default_runner
        self.dependency_check = dependency_check or (lambda name: shutil.which(name) is not None)
        self.descriptor = ActionDescriptor(
            action_id=f"metasploit:{self.module}",
            name=self.module,
            kind=ActionKind.METASPLOIT,
            provider="msf.run_msf_module",
            category=self.module.split("/", 1)[0],
            description=f"Metasploit module {self.module}",
            aliases=(f"msf:{self.module}",),
            requirements=ActionRequirements(
                system_dependencies=("msfconsole",),
                active=self.module.startswith(("exploit/", "post/")),
                supports_check=True,
            ),
        )

    @staticmethod
    def _default_runner(*args: Any, **kwargs: Any) -> Any:
        from msf import run_msf_module

        return run_msf_module(*args, **kwargs)

    def applicability(self, request: ActionRequest) -> ApplicabilityResult:
        base = super().applicability(request)
        missing = [
            item
            for item in base.missing_requirements
            if item != "binary:msfconsole"
        ]
        if not self.dependency_check("msfconsole"):
            missing.append("binary:msfconsole")
        assessment_reasons, assessment_missing = canonical_assessment_applicability(
            request.facts,
            {self.module.casefold(), f"msf:{self.module}".casefold()},
        )
        missing.extend(assessment_missing)
        return ApplicabilityResult(
            applicable=not missing,
            reasons=(
                ("metasploit_available", *assessment_reasons)
                if not missing
                else ()
            ),
            missing_requirements=tuple(dict.fromkeys(missing)),
        )

    def _options(self, request: ActionRequest) -> str:
        raw = request.parameters.get("options", "")
        if isinstance(raw, Mapping):
            options = " ".join(f"{key}={value}" for key, value in sorted(raw.items()))
        else:
            options = str(raw or "")
        if request.target and not re.search(r"(?i)\bRHOSTS?\s*=", options):
            options = f"RHOSTS={request.target} {options}".strip()
        return options

    def invocation(self, request: ActionRequest, phase: str):
        policy_name = "msf_check" if phase == "check" else "msf_run"
        command = shlex.join((policy_name, self.module, request.target))
        return self.registered_invocation(command, policy_name)

    def check(self, request: ActionRequest) -> ActionCheckResult:
        raw = self.runner(
            self.module,
            self._options(request),
            timeout=request.execution_context.max_runtime_seconds,
            mode="check",
        )
        text = str(raw or "")
        lowered = text.lower()
        if any(marker in lowered for marker in ("not installed", "not in path", "missing dependency")):
            raw = {"status": "unavailable", "output": text, "executed": False}
            applicable = None
        elif any(marker in lowered for marker in ("does not appear to be vulnerable", "not vulnerable")):
            applicable = False
        elif any(marker in lowered for marker in ("appears to be vulnerable", "is vulnerable", "success:")):
            applicable = True
        else:
            applicable = None
        return ActionCheckResult(result=raw, applicable=applicable, reason="metasploit_check")

    def execute(self, request: ActionRequest) -> Any:
        return self.runner(
            self.module,
            self._options(request),
            timeout=request.execution_context.max_runtime_seconds,
            mode="run",
        )


class PluginActionAdapter(ActionAdapter):
    _ACTIVE_TYPES: ClassVar[set[str]] = {
        "exploit",
        "post",
        "evasion",
        "persistence",
        "lateral",
    }

    def __init__(self, manager: Any, plugin_name: str):
        descriptor = manager.get_plugin(plugin_name)
        if descriptor is None:
            raise KeyError(f"Unknown plugin: {plugin_name}")
        self.manager = manager
        self.plugin_name = plugin_name
        active = str(descriptor.plugin_type) in self._ACTIVE_TYPES
        self.descriptor = ActionDescriptor(
            action_id=f"plugin:{plugin_name}",
            name=plugin_name,
            kind=ActionKind.PLUGIN,
            provider="core.plugins.loader.PluginManager",
            category=str(descriptor.plugin_type),
            description=str(descriptor.description),
            version=str(descriptor.version),
            requirements=ActionRequirements(
                system_dependencies=tuple(descriptor.requires),
                python_dependencies=tuple(descriptor.python_deps),
                capabilities=tuple(descriptor.capabilities),
                active=active,
                supports_check=True,
                supports_cleanup=True,
            ),
        )

    def applicability(self, request: ActionRequest) -> ApplicabilityResult:
        missing = []
        if not request.target.strip():
            missing.append("target")
        missing.extend(str(item) for item in self.manager.validate(self.plugin_name))
        return ApplicabilityResult(
            applicable=not missing,
            reasons=("plugin_validated",) if not missing else (),
            missing_requirements=tuple(missing),
        )

    def _action(self, request: ActionRequest, phase: str) -> str:
        if phase == "check":
            return "check"
        default = "run" if self.descriptor.requirements.active else "scan"
        return str(request.parameters.get("action") or default).lower()

    def invocation(self, request: ActionRequest, phase: str):
        command = shlex.join(
            ("plugin", self.plugin_name, request.target, self._action(request, phase))
        )
        return self.registered_invocation(command, "plugin")

    def check(self, request: ActionRequest) -> ActionCheckResult:
        raw = self.manager.check(
            self.plugin_name,
            request.target,
            timeout=request.execution_context.max_runtime_seconds,
        )
        return ActionCheckResult(
            result=raw,
            applicable=bool(raw.vulnerable),
            reason=str(raw.details or raw.evidence),
        )

    def execute(self, request: ActionRequest) -> Any:
        from core.plugins.base import PluginContext

        parameters = dict(request.parameters)
        action = parameters.pop("action", self._action(request, "execute"))
        parameters.pop("timeout", None)
        return self.manager.execute(
            self.plugin_name,
            context=PluginContext(target=request.target),
            target=request.target,
            action=action,
            timeout=request.execution_context.max_runtime_seconds,
            **parameters,
        )

    def cleanup(
        self,
        request: ActionRequest,
        result: ExecutionResult | None,
    ) -> ActionCleanupResult:
        # PluginManager's worker already executes cleanup in a finally block;
        # it appends an explicit marker when that provider-owned cleanup fails.
        text = "\n".join(
            part for part in ((result.stdout if result else ""), (result.stderr if result else "")) if part
        ).lower()
        failed = "cleanup failed:" in text
        return ActionCleanupResult(
            succeeded=not failed,
            reason=("plugin_worker_cleanup_failed" if failed else "plugin_worker_cleanup_succeeded"),
        )


def register_tool_adapters(
    catalog: Any,
    tool_defs: list[Any] | tuple[Any, ...],
    dispatch: ActionDispatch,
) -> None:
    for tool_def in tool_defs:
        adapter: ActionAdapter
        if str(tool_def.name).startswith("killchain_"):
            adapter = KillchainActionAdapter(tool_def, dispatch)
        else:
            adapter = RegisteredToolAdapter(tool_def, dispatch)
        catalog.register(adapter)


__all__ = [
    "ExploitBaseAdapter",
    "KillchainActionAdapter",
    "MetasploitActionAdapter",
    "PluginActionAdapter",
    "RegisteredToolAdapter",
    "canonical_assessment_applicability",
    "register_tool_adapters",
]
