from __future__ import annotations

from .base import Tool


class WhatWeb(Tool):
    name = "whatweb"
    binary = "whatweb"
    target_kind = "url"
    follow_redirects = True  # framework resolves redirects (scope-checked); whatweb itself never follows
    description = (
        "Web technology fingerprinting (CMS, frameworks, web server, JS libraries, headers) of ONE http(s) URL. "
        "Level 1 = a single request (default). Level 3 = a handful of extra requests, only for technologies "
        "already detected. Use 'verbose' to get versions/evidence per plugin."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "http(s) URL in scope"},
            "aggression": {"type": "integer", "enum": [1, 3],
                           "description": "1 = stealthy single request (default), 3 = aggressive (few more requests)."},
            "verbose": {"type": "boolean", "description": "Detailed per-plugin output. Default false."},
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def build_argv(self, args):
        argv = [self.binary, "--color=never", "--follow-redirect=never",
                "-a", str(args.get("aggression", 1))]
        if args.get("verbose"):
            argv.append("-v")
        argv.append(args["target"])
        return argv