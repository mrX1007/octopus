"""Controlled follow-up orchestration shared by the AI pipeline facade."""

from __future__ import annotations

from typing import Any

from core.ai.pipeline_types import PipelineMixinBase


class PipelineFollowupsMixin(PipelineMixinBase):
    """Execute bounded follow-ups and resolve their strategy configuration."""

    def _run_controlled_post_access_followups(
        self, scan_id: str, target: str, facts: list[dict[str, Any]]
    ) -> dict[str, Any]:
        parsed_facts = 0
        new_facts = 0
        command_results = []
        result_facts = []
        for cmd in self._controlled_post_access_commands_from_facts(target, facts):
            result = self._execute_pipeline_command(
                scan_id,
                target,
                cmd,
                "Post-Access Fact",
                "[Running Controlled Post-Access]",
            )
            parsed_facts += result["parsed_facts"]
            new_facts += result["new_facts"]
            command_results.append(result["command_result"])
            result_facts.extend(result["facts"])
        return {
            "parsed_facts": parsed_facts,
            "new_facts": new_facts,
            "commands": command_results,
            "facts": result_facts,
        }

    def _controlled_post_access_commands_from_facts(
        self, target: str, facts: list[dict[str, Any]]
    ) -> list[str]:
        """Run read-only SSH inventory once after confirmed SSH authentication."""
        from core.ai.followups import PostAccessFollowupRules

        # Preserve the legacy fact predicate while the typed rule becomes the
        # proposal owner. Cached credentials are intentionally insufficient on
        # this controlled, post-verification path.
        enabled = self._auto_ssh_inventory_enabled()
        confirmed_facts = (
            facts if enabled and self._facts_confirm_ssh_access(facts) else []
        )
        proposals = PostAccessFollowupRules().propose(
            target,
            confirmed_facts,
            enabled=enabled,
            inventory_seen=False,
            already_executed=self.executed_post_access_commands,
            allow_cached_credentials=False,
        )
        commands = [proposal.command for proposal in proposals]
        self.executed_post_access_commands.update(commands)
        return commands

    def _facts_confirm_ssh_access(self, facts: list[dict[str, Any]]) -> bool:
        for fact in facts:
            ftype = str(fact.get("type", "")).lower()
            value = str(fact.get("value", "")).lower()
            if ftype == "credential" and value.startswith("ssh_login_success:"):
                return True
            if ftype == "service_status" and value == "ssh_authenticated":
                return True
        return False

    def _auto_ssh_inventory_enabled(self) -> bool:
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        strategy = CFG.get("strategy", {})
        return bool(
            strategy.get(
                "auto_post_access_inventory",
                strategy.get("auto_ssh_inventory", True),
            )
        )

    def _strategy_enabled(self, key: str, default: bool = False) -> bool:
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        return bool(CFG.get("strategy", {}).get(key, default))

    def _strategy_limit(self, key: str, default=None):
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        raw = CFG.get("strategy", {}).get(key, default)
        if raw is None:
            return None
        if str(raw).strip().lower() in {
            "",
            "0",
            "-1",
            "none",
            "unlimited",
            "false",
        }:
            return None
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        return None if value <= 0 else max(1, value)
