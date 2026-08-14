"""Channel lifecycle management."""

from __future__ import annotations

import time
from typing import Any

from core.c2.channel_models import (
    ChannelConfigV1,
    ChannelRecordV1,
    ChannelStateV1,
    ChannelTypeV1,
    calculate_channel_config_digest,
)


class ChannelManager:
    """Manager for C2 communication channels lifecycle."""

    def __init__(self) -> None:
        self._providers: dict[str, Any] = {}
        self._configs: dict[str, ChannelConfigV1] = {}
        self._records: dict[str, ChannelRecordV1] = {}

    def register_provider(self, channel_type: ChannelTypeV1 | str, provider: Any) -> None:
        """Register a channel provider for a channel type."""
        key = channel_type.value if hasattr(channel_type, "value") else str(channel_type)
        self._providers[key] = provider

    def get_provider(self, channel_type: ChannelTypeV1 | str) -> Any | None:
        """Get registered channel provider."""
        key = channel_type.value if hasattr(channel_type, "value") else str(channel_type)
        return self._providers.get(key)

    def create_channel(self, config: ChannelConfigV1) -> ChannelRecordV1:
        """Create and register a new channel from config."""
        digest = config.config_digest
        if not digest:
            digest = calculate_channel_config_digest(
                channel_id=config.channel_id,
                channel_type=config.channel_type.value,
                endpoint=config.endpoint,
                mission_id=config.mission_id,
                parameters=config.parameters,
            )
            config = ChannelConfigV1(
                channel_id=config.channel_id,
                channel_type=config.channel_type,
                endpoint=config.endpoint,
                mission_id=config.mission_id,
                retry_interval=config.retry_interval,
                parameters=config.parameters,
                config_digest=digest,
            )

        now = time.time()
        record = ChannelRecordV1(
            channel_id=config.channel_id,
            channel_type=config.channel_type,
            state=ChannelStateV1.ACTIVE,
            config_digest=digest,
            created_at=now,
            updated_at=now,
            bytes_sent=0,
            bytes_received=0,
        )

        self._configs[config.channel_id] = config
        self._records[config.channel_id] = record
        return record

    def get_channel(self, channel_id: str) -> ChannelRecordV1 | None:
        """Retrieve a channel state record by ID."""
        return self._records.get(channel_id)

    def get_config(self, channel_id: str) -> ChannelConfigV1 | None:
        """Retrieve a channel config by ID."""
        return self._configs.get(channel_id)

    def list_channels(self, mission_id: str | None = None) -> list[ChannelRecordV1]:
        """List channels, optionally filtered by mission ID."""
        if mission_id is None:
            return list(self._records.values())

        matched_ids = {c_id for c_id, cfg in self._configs.items() if cfg.mission_id == mission_id}
        return [rec for c_id, rec in self._records.items() if c_id in matched_ids]

    def update_channel_state(self, channel_id: str, new_state: ChannelStateV1) -> ChannelRecordV1:
        """Update channel state."""
        rec = self._records.get(channel_id)
        if rec is None:
            raise KeyError(f"Channel {channel_id} not found")

        updated = ChannelRecordV1(
            channel_id=rec.channel_id,
            channel_type=rec.channel_type,
            state=new_state,
            config_digest=rec.config_digest,
            created_at=rec.created_at,
            updated_at=time.time(),
            bytes_sent=rec.bytes_sent,
            bytes_received=rec.bytes_received,
        )
        self._records[channel_id] = updated
        return updated

    def record_traffic(self, channel_id: str, bytes_sent: int = 0, bytes_received: int = 0) -> ChannelRecordV1:
        """Record network traffic on channel."""
        rec = self._records.get(channel_id)
        if rec is None:
            raise KeyError(f"Channel {channel_id} not found")

        updated = ChannelRecordV1(
            channel_id=rec.channel_id,
            channel_type=rec.channel_type,
            state=rec.state,
            config_digest=rec.config_digest,
            created_at=rec.created_at,
            updated_at=time.time(),
            bytes_sent=rec.bytes_sent + bytes_sent,
            bytes_received=rec.bytes_received + bytes_received,
        )
        self._records[channel_id] = updated
        return updated

    def close_channel(self, channel_id: str) -> bool:
        """Close a channel."""
        rec = self._records.get(channel_id)
        if rec is None:
            return False

        self.update_channel_state(channel_id, ChannelStateV1.CLOSED)
        return True


class ChannelCreateRouter:
    """Router for creating and initializing channels via matching channel providers."""

    def __init__(self, manager: ChannelManager) -> None:
        self.manager = manager

    def route_create(self, config: ChannelConfigV1) -> ChannelRecordV1:
        """Route channel creation to registered provider or manager."""
        provider = self.manager.get_provider(config.channel_type)
        if provider is not None and hasattr(provider, "create_channel"):
            return provider.create_channel(config)
        return self.manager.create_channel(config)
