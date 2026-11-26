from __future__ import annotations

from .base import Tool


class Wafw00f(Tool):
    name = "wafw00f"
    binary = "wafw00f"
    target_kind = "url"
    follow_redirects = True  # framework resolves redirects (scope-checked); wafw00f runs with -r
    description = (
        "Detects and fingerprints a Web Application Firewall (vendor/product) in front of ONE http(s) URL. "
        "Sends a few requests, some with attack-looking payloads to provoke the WAF (nothing is exploited). "
        "Set find_all=true to keep testing after the first match (detects stacked WAFs)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "http(s) URL in scope"},
            "find_all": {"type": "boolean", "description": "Identify all WAFs instead of stopping at the first. Default false."},
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def build_argv(self, args):
        argv = [self.binary, "--no-colors", "-r", "-T", "10"]
        if args.get("find_all"):
            argv.append("-a")
        argv.append(args["target"])
        return argv