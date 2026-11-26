from __future__ import annotations

from .base import Tool

_SEV = ["info", "low", "medium", "high", "critical"]


class Nuclei(Tool):
    name = "nuclei"
    binary = "nuclei"
    target_kind = "url"
    description = (
        "Template-based vulnerability/misconfiguration scanner (ProjectDiscovery nuclei). "
        "Runs only non-intrusive community templates against ONE http(s) URL. "
        "Use 'tags' to focus (e.g. 'wordpress', 'exposure', 'misconfig', 'tech', 'cve')."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "http(s) URL in scope, e.g. https://example.com"},
            "severity": {"type": "array", "items": {"type": "string", "enum": _SEV},
                         "description": "Severities to include. Default: all."},
            "tags": {"type": "string", "pattern": r"[a-z0-9_,-]{1,200}",
                     "description": "Comma separated template tags, e.g. 'exposure,misconfig'."},
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def build_argv(self, args):
        argv = [self.binary, "-u", args["target"], "-silent", "-nc", "-duc",
                "-rl", str(self.settings.nuclei_rate_limit), "-timeout", "10", "-retries", "1",
                # hard exclusions: this tool is for recon, not for hurting things
                "-exclude-tags", "dos,intrusive"]
        if args.get("severity"):
            argv += ["-severity", ",".join(args["severity"])]
        if args.get("tags"):
            argv += ["-tags", args["tags"]]
        return argv
