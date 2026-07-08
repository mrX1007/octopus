#!/usr/bin/env python3
"""
Active Directory attack package for the OCTOPUS kill chain.

Provides enumeration, Kerberos attacks, credential attacks,
and AD-specific lateral movement capabilities.
"""

from .enumeration import (
    run_ad_enum,
    enumerate_users,
    enumerate_groups,
    enumerate_computers,
    enumerate_gpo,
    bloodhound_ingest,
)
from .kerberos import (
    asrep_roast,
    kerberoast,
    extract_tickets,
    crack_tickets,
)
from .credential import (
    dcsync,
    pass_the_hash,
    pass_the_ticket,
    dump_lsass,
    sam_dump,
)
from .lateral import (
    psexec,
    wmiexec,
    smbexec,
    winrm_exec,
    dcom_exec,
)
