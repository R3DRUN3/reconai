from __future__ import annotations

import os

from .base import Tool


class Gobuster(Tool):
    name = "gobuster"
    binary = "gobuster"
    target_kind = "url"
    description = (
        "Directory/file discovery against ONE http(s) URL using a fixed, rate-limited wordlist. "
        "Finds exposed paths such as /admin, /backup, /.git."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "http(s) base URL in scope"},
            "extensions": {"type": "string", "pattern": r"[a-z0-9,]{1,60}",
                           "description": "Optional comma separated file extensions, e.g. 'php,bak,txt'."},
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def preflight(self):
        wl = self.settings.gobuster_wordlist
        if not os.path.isfile(wl):
            return f"wordlist not found: {wl} (install it or set RECONAI_GOBUSTER_WORDLIST)"
        return None

    def build_argv(self, args):
        # Flags verified against gobuster 3.8.2 (`gobuster dir --help`).
        argv = [self.binary, "dir", "-u", args["target"], "-w", self.settings.gobuster_wordlist,
                "-t", "10", "--delay", "50ms", "--timeout", "10s",
                "-q", "--no-progress", "--no-error", "--no-color"]
        if args.get("extensions"):
            argv += ["-x", args["extensions"]]
        return argv