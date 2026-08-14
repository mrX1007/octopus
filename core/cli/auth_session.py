"""CLI auth session helper issuing IngressInvocationLease for CLI invocations."""

from __future__ import annotations

import os
from core.auth.ingress import IngressSession
from core.auth.ingress_leases import IngressInvocationLease
from core.auth.ingress_store import get_ingress_session_store
from core.auth.types import IngressChannelBinding, Principal, PrincipalRole


class CLIAuthSessionManager:
    def __init__(self) -> None:
        self.store = get_ingress_session_store()
        self._current_session_id: str | None = None
        self._bootstrap_cli_session()

    def _bootstrap_cli_session(self) -> None:
        principal = Principal(
            principal_id="principal:cli-operator",
            name="CLI Operator",
            role=PrincipalRole.OPERATOR,
            revision=1,
        )
        binding = IngressChannelBinding(
            peer_uid=os.getuid() if hasattr(os, "getuid") else 1000,
            peer_gid=os.getgid() if hasattr(os, "getgid") else 1000,
            peer_pid=os.getpid(),
            transport_instance="local:cli",
            channel_binding="channel:cli-stdio",
        )
        session = IngressSession(
            session_id="session:cli-operator",
            principal=principal,
            channel_binding=binding,
            revision=1,
            revoked=False,
        )
        self.store.register_session(session)
        self._current_session_id = session.session_id

    def issue_command_lease(self, request_id: str) -> IngressInvocationLease:
        if not self._current_session_id:
            raise RuntimeError("No active CLI session")
        binding = IngressChannelBinding(
            peer_uid=os.getuid() if hasattr(os, "getuid") else 1000,
            peer_gid=os.getgid() if hasattr(os, "getgid") else 1000,
            peer_pid=os.getpid(),
            transport_instance="local:cli",
            channel_binding="channel:cli-stdio",
        )
        return self.store.issue_invocation_lease(
            session_id=self._current_session_id,
            request_id=request_id,
            channel_binding=binding,
        )


_GLOBAL_CLI_AUTH_MANAGER = CLIAuthSessionManager()


def get_cli_auth_manager() -> CLIAuthSessionManager:
    return _GLOBAL_CLI_AUTH_MANAGER


__all__ = [
    "CLIAuthSessionManager",
    "get_cli_auth_manager",
]
