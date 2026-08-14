"""Channel DTOs and types."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any


class ChannelTypeV1(str, Enum):
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SOCKET = "socket"
    ICMP = "icmp"


class ChannelStateV1(str, Enum):
    CREATED = "created"
    ACTIVE = "active"
    DEGRADED = "degraded"
    RECONCILING = "reconciling"
    CLOSED = "closed"


@dataclass(frozen=True)
class ChannelConfigV1:
    channel_id: str
    channel_type: ChannelTypeV1
    endpoint: str
    mission_id: str
    retry_interval: float = 5.0
    parameters: Dict[str, Any] = field(default_factory=dict)
    config_digest: str = ""

    def __post_init__(self) -> None:
        if not self.channel_id:
            raise ValueError("channel_id must not be empty")
        if not self.endpoint:
            raise ValueError("endpoint must not be empty")


@dataclass(frozen=True)
class ChannelRecordV1:
    channel_id: str
    channel_type: ChannelTypeV1
    state: ChannelStateV1
    config_digest: str
    created_at: float
    updated_at: float
    bytes_sent: int = 0
    bytes_received: int = 0


def calculate_channel_config_digest(
    channel_id: str,
    channel_type: str,
    endpoint: str,
    mission_id: str,
    parameters: Dict[str, Any],
) -> str:
    """Calculate SHA-256 digest of channel config."""
    param_str = json.dumps(parameters, sort_keys=True)
    raw = f"{channel_id}:{channel_type}:{endpoint}:{mission_id}:{param_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def calculate_channel_record_digest(record: ChannelRecordV1) -> str:
    """Calculate SHA-256 digest of channel state record."""
    raw = f"{record.channel_id}:{record.state.value}:{record.config_digest}:{record.updated_at}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

