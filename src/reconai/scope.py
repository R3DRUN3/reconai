"""Target parsing and scope enforcement.

The scope of a scan is exactly the list of targets in the request. Every tool
call the LLM makes is checked against it *in code* before anything is executed.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?)*$")
MAX_NET_ADDRESSES = 256  # tool calls may not fan out wider than a /24


class TargetError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    raw: str
    domain: str | None = None
    net: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    is_url: bool = False


def parse_target(raw: str) -> Target:
    """Parse a domain, IP, CIDR, host:port or http(s) URL into a Target."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048 or re.search(r"\s", raw):
        raise TargetError("empty target or contains whitespace")
    if raw.startswith("-"):
        raise TargetError("target must not start with '-'")

    is_url = "://" in raw
    if is_url:
        try:
            u = urlparse(raw)
            host = u.hostname
            u.port  # noqa: B018 - validates port
        except ValueError as e:
            raise TargetError(f"invalid URL: {e}") from None
        if u.scheme not in ("http", "https"):
            raise TargetError("only http/https URLs are supported")
        if u.username or u.password:
            raise TargetError("credentials in URL are not allowed")
        if not host:
            raise TargetError("URL has no host")
    else:
        try:
            return Target(raw, net=ipaddress.ip_network(raw, strict=False))
        except ValueError:
            pass
        try:
            host = urlparse("//" + raw).hostname
        except ValueError as e:
            raise TargetError(f"invalid target: {e}") from None
        if not host:
            raise TargetError("could not extract a host")

    host = host.lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    try:
        return Target(raw, net=ipaddress.ip_network(host), is_url=is_url)
    except ValueError:
        pass
    if not _HOST_RE.match(host):
        raise TargetError(f"invalid hostname: {host!r}")
    return Target(raw, domain=host, is_url=is_url)


class Scope:
    """A set of domains (incl. subdomains) and networks."""

    def __init__(self, targets: list[str]):
        self.targets = [parse_target(t) for t in targets]

    def covers(self, t: Target) -> bool:
        for s in self.targets:
            if t.net is not None and s.net is not None:
                if t.net.version == s.net.version and t.net.subnet_of(s.net):
                    return True
            elif t.domain is not None and s.domain is not None:
                if t.domain == s.domain or t.domain.endswith("." + s.domain):
                    return True
        return False

    def describe(self) -> list[str]:
        return [t.raw for t in self.targets]
