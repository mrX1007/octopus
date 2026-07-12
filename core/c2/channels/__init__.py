"""
Alternative C2 transport channels.

Components:
  - dns: DNS-based C2 (TXT exfiltration + DNS beaconing)
"""

from core.c2.channels.dns import DNSChannel

__all__ = [
    "DNSChannel",
]
