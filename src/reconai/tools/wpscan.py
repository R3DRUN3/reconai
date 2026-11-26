from __future__ import annotations

import copy

from ..config import Settings
from .base import Tool

# vp/vt (vulnerable plugins/themes) need a WPScan API token. Without one we fall back to
# ap/at (all plugins/themes, passive detection): names + versions, but no vulnerability data.
_ENUM = ["vp", "vt", "ap", "at", "u", "cb", "dbe"]
_FALLBACK = {"vp": "ap", "vt": "at"}

_DESC = (
    "WordPress security scanner. Detects WordPress version, themes and plugins on ONE http(s) URL. "
    "Follows redirects (only while they stay in scope). Only use if the site appears to run WordPress. "
    "Never brute-forces passwords. "
)
_DESC_TOKEN = _DESC + "A WPScan API token is configured: vp/vt report known vulnerabilities of plugins/themes."
_DESC_NO_TOKEN = _DESC + (
    "NO WPScan API token is configured, so vulnerability data is NOT available: vp/vt are automatically "
    "replaced by ap/at (list plugins/themes and versions only). Do NOT claim a plugin/theme is vulnerable "
    "based on this tool; at most recommend checking the listed versions against a vulnerability database."
)


class WPScan(Tool):
    name = "wpscan"
    binary = "wpscan"
    target_kind = "url"
    secret_flags = ("--api-token",)
    follow_redirects = True  # wpscan must follow redirects; the framework scope-checks every hop first
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "http(s) URL of the WordPress site, in scope"},
            "enumerate": {"type": "array", "items": {"type": "string", "enum": _ENUM},
                          "description": "vp=vulnerable plugins, vt=vulnerable themes (both need an API token), "
                                         "ap=all plugins, at=all themes, u=users, cb=config backups, "
                                         "dbe=db exports. Default: vp,vt."},
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.has_token = bool(settings.wpscan_api_token)
        self.description = _DESC_TOKEN if self.has_token else _DESC_NO_TOKEN
        self.parameters = copy.deepcopy(WPScan.parameters)

    def _enumerate(self, requested: list[str] | None) -> str:
        opts = requested or ["vp", "vt"]
        if not self.has_token:
            opts = [_FALLBACK.get(o, o) for o in opts]
        seen: list[str] = []
        for o in opts:  # de-duplicate, keep order
            if o not in seen:
                seen.append(o)
        return ",".join(seen)

    def build_argv(self, args):
        argv = [self.binary, "--url", args["target"], "--no-update", "--no-banner",
                "--format", "cli-no-colour", "--random-user-agent", "--throttle", "100",
                "--follow-redirect", "--enumerate", self._enumerate(args.get("enumerate"))]
        if self.has_token:
            argv += ["--api-token", self.settings.wpscan_api_token]
        return argv