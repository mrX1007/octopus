#!/usr/bin/env python3
"""
Active Directory attack package for the OCTOPUS kill chain.

Provides enumeration, Kerberos attacks, credential attacks,
and AD-specific lateral movement capabilities.
"""

from .credential import (
    dcsync,
    dump_lsass,
    pass_the_hash,
    pass_the_ticket,
    sam_dump,
)
from .enumeration import (
    bloodhound_ingest,
    enumerate_computers,
    enumerate_gpo,
    enumerate_groups,
    enumerate_users,
    run_ad_enum,
)
from .kerberos import (
    asrep_roast,
    crack_tickets,
    extract_tickets,
    kerberoast,
)
from .lateral import (
    dcom_exec,
    psexec,
    smbexec,
    winrm_exec,
    wmiexec,
)
