
from __future__ import annotations

from .base import Tool


class Katana(Tool):
    """ProjectDiscovery Katana web crawler."""

    name = "katana"
    binary = "katana"
    target_kind = "url"
    timeout = 120

    description = (
        "Crawl ONE in-scope HTTP(S) URL to discover linked pages and endpoints, "
        "including endpoints referenced in JavaScript. Uses a fixed conservative "
        "crawl budget: depth 2, maximum 50 pages, 60 seconds, 2 requests/second "
        "and concurrency 2. Restricted to the exact target hostname; redirects "
        "are not followed. Does not use headless browsing or submit forms. "
        "Returns structured JSONL results. Use on assets you own or are "
        "explicitly authorised to test."
    )

    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "A full http(s) URL that is inside the authorised scan scope.",
            },
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def build_argv(self, args: dict) -> list[str]:
        return [
            self.binary,
            "-u", args["target"],

            # Quiet, machine-readable output. Omit response bodies and raw traffic.
            "-silent",
            "-nc",
            "-duc",
            "-j",
            "-or",
            "-ob",

            # Strict crawl boundary: exact hostname, no redirect following.
            "-fs", "fqdn",
            "-dr",

            # Bounded crawl budget.
            "-d", "2",
            "-jc",
            "-ct", "60s",
            "-mdp", "50",

            # Conservative request rate and concurrency.
            "-c", "2",
            "-p", "1",
            "-rl", "2",

            # Per-request network timeout and retry count.
            "-timeout", "10",
            "-retry", "1",
        ]
