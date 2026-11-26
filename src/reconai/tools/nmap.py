from __future__ import annotations

from .base import Tool

_PROFILES = {
    "quick": ["--top-ports", "100"],
    "default": ["--top-ports", "1000"],
    "service": ["--top-ports", "1000", "-sV", "--version-light"],
}


class Nmap(Tool):
    name = "nmap"
    binary = "nmap"
    target_kind = "host"
    description = (
        "TCP port scan (connect scan, no scripts) of ONE host, IP or small CIDR (<= /24) in scope. "
        "Profiles: quick (top 100), default (top 1000), service (top 1000 + service/version detection)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "hostname, IP or CIDR in scope (no URL)"},
            "profile": {"type": "string", "enum": list(_PROFILES), "description": "Default: default"},
            "ports": {"type": "string", "pattern": r"[0-9,\-]{1,100}",
                      "description": "Optional explicit ports/ranges, e.g. '22,80,443,8000-8100'. Overrides profile ports."},
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def build_argv(self, args):
        flags = list(_PROFILES[args.get("profile", "default")])
        if args.get("ports"):
            i = flags.index("--top-ports") if "--top-ports" in flags else None
            if i is not None:
                del flags[i:i + 2]
            flags += ["-p", args["ports"]]
        # -sT: unprivileged TCP connect scan (works without root / NET_RAW). No NSE scripts.
        return [self.binary, "-sT", "-Pn", "-n", "--open", "-T3", "--max-retries", "2", *flags, args["target"]]
