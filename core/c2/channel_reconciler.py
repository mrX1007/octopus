"""Channel reconciliation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from core.c2.channel_manager import ChannelManager
from core.c2.channel_models import (
    ChannelConfigV1,
    ChannelRecordV1,
    ChannelStateV1,
    calculate_channel_config_digest,
)


@dataclass(frozen=True)
class ReconciliationReportV1:
    created_channels: tuple[str, ...]
    closed_channels: tuple[str, ...]
    degraded_channels: tuple[str, ...]
    recovered_channels: tuple[str, ...]
    unchanged_channels: tuple[str, ...]


class ChannelReconciler:
    """Reconciles expected channel states with active managed channels."""

    def __init__(
        self,
        manager: ChannelManager,
        probe_fn: Optional[Any] = None,
    ) -> None:
        self.manager = manager
        self._probe_fn = probe_fn or self._default_probe

    def _default_probe(self, config: ChannelConfigV1, record: ChannelRecordV1) -> bool:
        """Default health probe for a channel."""
        return record.state in (ChannelStateV1.ACTIVE, ChannelStateV1.CREATED)

    def reconcile_channels(
        self, desired_configs: List[ChannelConfigV1] | tuple[ChannelConfigV1, ...]
    ) -> ReconciliationReportV1:
        """Reconcile desired channel configurations with manager state."""
        desired_map = {cfg.channel_id: cfg for cfg in desired_configs}
        current_channels = self.manager.list_channels()
        current_map = {rec.channel_id: rec for rec in current_channels}

        created: List[str] = []
        closed: List[str] = []
        degraded: List[str] = []
        recovered: List[str] = []
        unchanged: List[str] = []

        # Create missing desired channels
        for c_id, cfg in desired_map.items():
            if c_id not in current_map:
                self.manager.create_channel(cfg)
                created.append(c_id)
            else:
                existing_rec = current_map[c_id]
                healthy = self._probe_fn(cfg, existing_rec)
                if not healthy:
                    if existing_rec.state != ChannelStateV1.DEGRADED:
                        self.manager.update_channel_state(c_id, ChannelStateV1.DEGRADED)
                        degraded.append(c_id)
                else:
                    if existing_rec.state == ChannelStateV1.DEGRADED:
                        self.manager.update_channel_state(c_id, ChannelStateV1.ACTIVE)
                        recovered.append(c_id)
                    else:
                        unchanged.append(c_id)

        # Close active channels not in desired list
        for c_id, rec in current_map.items():
            if c_id not in desired_map and rec.state != ChannelStateV1.CLOSED:
                self.manager.close_channel(c_id)
                closed.append(c_id)

        return ReconciliationReportV1(
            created_channels=tuple(created),
            closed_channels=tuple(closed),
            degraded_channels=tuple(degraded),
            recovered_channels=tuple(recovered),
            unchanged_channels=tuple(unchanged),
        )

    def recover_channel(self, channel_id: str) -> bool:
        """Attempt recovery of a degraded channel."""
        rec = self.manager.get_channel(channel_id)
        cfg = self.manager.get_config(channel_id)
        if rec is None or cfg is None:
            return False

        if rec.state != ChannelStateV1.DEGRADED:
            return True

        # Re-probe and recover if healthy
        if self._probe_fn(cfg, rec):
            self.manager.update_channel_state(channel_id, ChannelStateV1.ACTIVE)
            return True
        return False

