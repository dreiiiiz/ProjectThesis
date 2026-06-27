"""Registry artifact parser modules."""

from parsers.registry.hkcu import parse_hkcu
from parsers.registry.persistence import parse_persistence
from parsers.registry.sam import parse_sam
from parsers.registry.security import parse_security
from parsers.registry.shellbags import parse_shellbags
from parsers.registry.shimcache import parse_shimcache
from parsers.registry.software import parse_software
from parsers.registry.system import parse_system
from parsers.registry.userassist import parse_userassist

__all__ = [
    "parse_hkcu",
    "parse_persistence",
    "parse_sam",
    "parse_security",
    "parse_shellbags",
    "parse_shimcache",
    "parse_software",
    "parse_system",
    "parse_userassist",
]
