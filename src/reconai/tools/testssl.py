from __future__ import annotations

import shutil
import subprocess

from ..config import Settings
from .base import Tool, ToolArgError

# check name -> testssl.sh short option (single-check switches; they replace the heavy default run)
_CHECKS = {
    "protocols": "-p",         # SSLv2/3, TLS 1.0-1.3, ALPN/HTTP2
    "ciphers": "-s",           # cipher categories by strength (NULL, export, weak, 3DES, FS...)
    "certificate": "-S",       # server defaults: chain, expiry, SAN, key size, OCSP, extensions
    "headers": "-h",           # HTTP security headers (HSTS, cookies flags, banners...)
    "vulnerabilities": "-U",   # Heartbleed, CCS, ROBOT, POODLE, BEAST, SWEET32, FREAK, DROWN, LOGJAM...
}
_DEFAULT = ["protocols", "ciphers", "certificate", "headers"]
_CANDIDATES = ("testssl.sh", "testssl")  # Debian/Kali package naming varies


class Testssl(Tool):
    name = "testssl"
    target_kind = "host"
    description = (
        "TLS/SSL configuration audit (testssl.sh) of ONE host[:port] (default port 443, no URL, no network). "
        "checks: protocols (SSLv2..TLS1.3), ciphers (weak/NULL/export/3DES/forward secrecy), "
        "certificate (chain, expiry, SANs, key size, OCSP), headers (HSTS and other HTTP security headers), "
        "vulnerabilities (Heartbleed, CCS injection, ROBOT, POODLE, BEAST, SWEET32, FREAK, DROWN, LOGJAM...). "
        "Default: protocols, ciphers, certificate, headers. Slow: takes 1-5 minutes; call it once per host:port "
        "with all the checks you need. ids_friendly=true skips the more intrusive vulnerability probes "
        "(Heartbleed, CCS injection, Ticketbleed, ROBOT)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "pattern": r"[A-Za-z0-9._:\[\]-]{1,255}",
                       "description": "hostname or IP, optionally with :port (e.g. example.com or example.com:8443). "
                                      "No scheme, no path."},
            "checks": {"type": "array",
                       "items": {"type": "string", "enum": list(_CHECKS)},
                       "description": "Which checks to run. Default: protocols, ciphers, certificate, headers."},
            "ids_friendly": {"type": "boolean",
                             "description": "Skip Heartbleed/CCS/Ticketbleed/ROBOT probes. Default false."},
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.binary = settings.testssl_binary or next(
            (c for c in _CANDIDATES if shutil.which(c)), _CANDIDATES[0])
        self.timeout = max(settings.tool_timeout, 900)  # full TLS audits are slow

    def preflight(self):
        try:
            p = subprocess.run([self.binary, "--version"], capture_output=True, text=True,
                               timeout=60, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as e:
            return f"cannot execute {self.binary!r}: {e}"
        out = (p.stdout + p.stderr)
        if "testssl" not in out.lower():
            return f"{self.binary!r} --version did not look like testssl.sh (missing dependency?): {out.strip()[-300:]!r}"
        return None

    def parse_target(self, args):
        t = super().parse_target(args)
        if t.net is not None and t.net.num_addresses > 1:
            raise ToolArgError("target must be a single host or IP, not a network")
        return t

    def build_argv(self, args):
        wanted = args.get("checks") or _DEFAULT
        flags = [flag for name, flag in _CHECKS.items() if name in wanted]  # stable order, de-duplicated
        # `env` sets TERM_WIDTH so long lines are not wrapped when there is no terminal.
        argv = ["env", "TERM_WIDTH=200", self.binary,
                "-q", "--color", "0", "--warnings", "batch",
                "--connect-timeout", "10", "--openssl-timeout", "10"]
        if args.get("ids_friendly"):
            argv.append("--ids-friendly")
        argv += flags
        argv.append(args["target"])  # the URI must be the last parameter
        return argv