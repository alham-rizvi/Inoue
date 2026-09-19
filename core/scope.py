# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Scope file parsing and matching.

Every module that can fan out to hosts beyond the one explicitly typed on
the command line - subdomain takeover checks, active subdomain
enumeration, crawl candidates, external tool orchestration - should
respect a program's declared scope before firing a single request at a
host the person never actually authorized scanning. This was flagged as
the first thing to build in the original roadmap and, being honest about
it, kept getting deprioritized in favor of adding more scanning
capability on top of nothing enforcing it. This closes that gap.

File format (plain text, one entry per line):

    # comment
    example.com          # in-scope apex + exact host
    *.example.com        # in-scope wildcard subdomain
    10.0.0.0/8            # in-scope CIDR range
    !internal.example.com # out-of-scope override (deny wins over allow)
    !10.1.0.0/16

An empty or missing scope file means "no restriction" - scope is strictly
opt-in. This is deliberately a plain, dependency-free line format rather
than YAML/JSON, so a program's published scope list can be pasted in with
minimal editing.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Scope:
    allow_domains: list[str] = field(default_factory=list)   # exact or *.wildcard, lowercase
    deny_domains: list[str] = field(default_factory=list)
    allow_networks: list = field(default_factory=list)        # ipaddress network objects
    deny_networks: list = field(default_factory=list)

    @property
    def is_unrestricted(self) -> bool:
        return not (self.allow_domains or self.allow_networks)

    def _domain_matches(self, hostname: str, patterns: list[str]) -> bool:
        hostname = hostname.lower().rstrip(".")
        for pattern in patterns:
            if pattern.startswith("*."):
                suffix = pattern[1:]  # keep the leading dot: ".example.com"
                if hostname.endswith(suffix) or hostname == pattern[2:]:
                    return True
            elif hostname == pattern:
                return True
        return False

    def _ip_matches(self, ip: str, networks: list) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in network for network in networks)

    def allows(self, hostname: str, ip: Optional[str] = None) -> bool:
        """True if `hostname` (and optionally its resolved `ip`) is in scope.

        Deny always wins over allow, regardless of which list is more
        specific - a program that carves out an excluded subdomain or IP
        range means it, even if a broader wildcard would otherwise match.
        """
        if self._domain_matches(hostname, self.deny_domains):
            return False
        if ip and self._ip_matches(ip, self.deny_networks):
            return False

        if self.is_unrestricted:
            return True

        if self.allow_domains and self._domain_matches(hostname, self.allow_domains):
            return True
        if ip and self.allow_networks and self._ip_matches(ip, self.allow_networks):
            return True
        return False


def parse_scope_file(path: str) -> Scope:
    """Parse a scope file. Missing file or empty content means unrestricted."""
    scope = Scope()
    file_path = Path(path).expanduser()
    if not file_path.exists():
        return scope

    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        deny = line.startswith("!")
        if deny:
            line = line[1:].strip()
        if not line:
            continue

        is_network = False
        try:
            network = ipaddress.ip_network(line, strict=False)
            is_network = True
        except ValueError:
            network = None

        if is_network:
            (scope.deny_networks if deny else scope.allow_networks).append(network)
        else:
            (scope.deny_domains if deny else scope.allow_domains).append(line.lower())

    return scope


def filter_hosts(hosts: list[str], scope: Optional[Scope]) -> list[str]:
    """Filter a list of hostnames down to those the scope allows.
    A None scope (no --scope given) means everything passes through."""
    if scope is None or scope.is_unrestricted:
        return list(hosts)
    return [h for h in hosts if h and scope.allows(h)]
