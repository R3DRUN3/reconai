from __future__ import annotations

import subprocess

from ..config import Settings
from .base import Tool


class HttpxProbe(Tool):
    """ProjectDiscovery httpx. NOTE: on Kali the package is `httpx-toolkit` and the binary is
    `httpx-toolkit`; /usr/bin/httpx belongs to the unrelated Python HTTP client."""

    name = "httpx"
    target_kind = "url"
    description = (
        "HTTP probe (ProjectDiscovery httpx) of ONE http(s) URL: status code, title, web server, detected "
        "technologies, IP, CDN/WAF, content type/length and redirect location. Does NOT follow redirects - "
        "if a Location is shown, probe that URL next. One request; very cheap, use it first."
    )
    parameters = {
        "type": "object",
        "properties": {"target": {"type": "string", "description": "http(s) URL in scope"}},
        "required": ["target"],
        "additionalProperties": False,
    }

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.binary = settings.httpx_binary

    def preflight(self):
        try:
            p = subprocess.run([self.binary, "-version"], capture_output=True, text=True,
                               timeout=30, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as e:
            return f"cannot execute {self.binary!r}: {e}"
        out = (p.stdout + p.stderr).lower()
        if "projectdiscovery" not in out and "current version" not in out:
            return (f"{self.binary!r} is not ProjectDiscovery's httpx (on Kali it is 'httpx-toolkit'; "
                    f"'httpx' is the Python client). Set RECONAI_HTTPX_BINARY.")
        return None

    def build_argv(self, args):
        return [self.binary, "-u", args["target"], "-silent", "-nc", "-duc",
                "-sc", "-title", "-td", "-server", "-ip", "-cdn", "-location", "-cl", "-ct",
                "-timeout", "10", "-retries", "1"]