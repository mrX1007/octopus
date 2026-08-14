"""Deployment cleanup handler and recipe manager (§16.5)."""

from __future__ import annotations

import time
from dataclasses import dataclass

from core.c2.deployment_store import DeploymentStore


@dataclass(frozen=True)
class DeploymentCleanupRecipe:
    recipe_id: str
    deployment_ref: str
    target_id: str
    remote_path: str | None
    process_id: int | None
    created_at: float


class DeploymentCleanupManager:
    """Manages cleanup recipes for deployed implants/agents."""

    def __init__(self, store: DeploymentStore) -> None:
        self._store = store
        self._recipes: dict[str, DeploymentCleanupRecipe] = {}

    def register_recipe(
        self,
        deployment_ref: str,
        target_id: str,
        remote_path: str | None = None,
        process_id: int | None = None,
        now: float | None = None,
    ) -> DeploymentCleanupRecipe:
        ts = time.time() if now is None else now
        recipe = DeploymentCleanupRecipe(
            recipe_id=f"recipe-{deployment_ref}",
            deployment_ref=deployment_ref,
            target_id=target_id,
            remote_path=remote_path,
            process_id=process_id,
            created_at=ts,
        )
        self._recipes[deployment_ref] = recipe
        return recipe

    def get_recipe(self, deployment_ref: str) -> DeploymentCleanupRecipe | None:
        return self._recipes.get(deployment_ref)

    def execute_cleanup(self, deployment_ref: str) -> bool:
        """Perform cleanup of deployment artifacts and update deployment status."""
        rec = self._store.get_deployment(deployment_ref)
        if rec is None:
            return False
        self._store.update_status(deployment_ref, "cleaned")
        return True
