from __future__ import annotations

from .base import Tool

_ENUM = ["vp", "vt", "u", "cb", "dbe"]


class WPScan(Tool):
    name = "wpscan"
    binary = "wpscan"
    target_kind = "url"
    secret_flags = ("--api-token",)
    follow_redirects = True  # wpscan must follow redirects; the framework scope-checks every hop first
    description = (
        "WordPress security scanner. Detects WordPress version, themes, plugins and known vulnerabilities "
        "on ONE http(s) URL. Follows redirects (only while they stay in scope). Only use if the site appears "
        "to run WordPress. Never brute-forces passwords."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "http(s) URL of the WordPress site, in scope"},
            "enumerate": {"type": "array", "items": {"type": "string", "enum": _ENUM},
                          "description": "vp=vulnerable plugins, vt=vulnerable themes, u=users, "
                                         "cb=config backups, dbe=db exports. Default: vp,vt."},
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def build_argv(self, args):
        enum = ",".join(args.get("enumerate") or ["vp", "vt"])
        argv = [self.binary, "--url", args["target"], "--no-update", "--no-banner",
                "--format", "cli-no-colour", "--random-user-agent", "--throttle", "100",
                "--follow-redirect", "--enumerate", enum]
        if self.settings.wpscan_api_token:
            argv += ["--api-token", self.settings.wpscan_api_token]
        return argv