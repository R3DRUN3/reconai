
"""Arjun HTTP parameter discovery."""
from __future__ import annotations

from .base import Tool


class Arjun(Tool):
    name = "arjun"
    binary = "arjun"
    target_kind = "url"
    timeout = 180

    description = (
        "Discover hidden HTTP parameters using Arjun. Supports GET, "
        "POST and JSON parameter discovery. Use GET for normal "
        "query parameters, POST for form parameters, JSON for JSON "
        "request bodies. Only scan "
        "explicitly authorized endpoints. Discovery does not confirm "
        "a vulnerability."
    )

    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Full in-scope HTTP(S) URL."
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "JSON", "XML"],
                "description": "HTTP parameter discovery mode."
            },
            "rate_limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 5,
                "description": "Maximum requests per second."
            },
            "request_timeout": {
                "type": "integer",
                "minimum": 5,
                "maximum": 30,
                "description": "Individual HTTP request timeout."
            },
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def build_argv(self, args: dict) -> list[str]:
        method = args.get("method", "GET").upper()
        rate_limit = args.get("rate_limit", 2)
        request_timeout = args.get("request_timeout", 10)

        if method not in {"GET", "POST", "JSON"}:
            raise ValueError(f"Unsupported Arjun method: {method}")

        if not 1 <= rate_limit <= 5:
            raise ValueError("rate_limit must be between 1 and 5")

        if not 5 <= request_timeout <= 30:
            raise ValueError("request_timeout must be between 5 and 30")

        return [
            self.binary,
            "-u", args["target"],
            "-m", method,
            "-t", "1",
            "-T", str(request_timeout),
            "--rate-limit", str(rate_limit),
            "--disable-redirects",
        ]
