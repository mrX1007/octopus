"""
Implant and stager generation modules.

Components:
  - python_implant: Python reverse shell implant with AES-GCM encrypted config
  - powershell_stager: PowerShell stager / dropper generation
"""

from core.c2.implants.powershell_stager import (
    generate_hta_dropper,
    generate_ps_amsi_bypass,
    generate_ps_clm_bypass,
    generate_ps_encoded,
    generate_ps_stager,
)
from core.c2.implants.python_implant import generate_python_implant

__all__ = [
    "generate_hta_dropper",
    "generate_ps_amsi_bypass",
    "generate_ps_clm_bypass",
    "generate_ps_encoded",
    "generate_ps_stager",
    "generate_python_implant",
]
