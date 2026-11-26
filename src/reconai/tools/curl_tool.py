"""Controlled HTTP requests using curl (no arbitrary curl arguments)."""
from __future__ import annotations

from .base import Tool


# Only headers useful for basic reconnaissance. Deliberately excludes Host,
# Authorization, Cookie, proxy and other credential/routing headers.
_SAFE_HEADER_PATTERN = (
    r"(?i)(accept|accept-language|cache-control|dnt|origin|pragma|user-agent):[ -~]{0,256}"
)

_WRITE_OUT = (
    "\n[reconai curl] status=%{http_code} content_type=%{content_type} "
    "size=%{size_download} time=%{time_total}s remote_ip=%{remote_ip} "
    "redirect=%{redirect_url}\n"
)


class Curl(Tool):
    name = "curl"
    binary = "curl"
    target_kind = "url"
    description = (
        "Use curl to explore and dive deeper into possible findings. "
        "Accept-Language, Cache-Control, DNT, Origin, Pragma and User-Agent; include response headers; "
        "and set a short timeout (1-30 seconds). The response body is capped at 512 KB. "
        "TLS verification is on by default. If curl fails with certificate error 60, you may retry "
        "the same in-scope target ONCE with insecure_tls=true to inspect its HTTP response; clearly report "
        "that TLS verification was bypassed and the certificate remains untrusted. "
        "Redirects are NOT followed: inspect the reported redirect and make a separate in-scope call. "
        "No arbitrary curl flags, credentials, cookies, file URLs, proxies, request bodies, or state-changing methods."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Full http(s) URL in scope, e.g. https://example.com/robots.txt",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "HEAD", "OPTIONS"],
                "description": "HTTP method. Default GET. Only discovery methods are allowed.",
            },
            "headers": {
                "type": "array",
                "maxItems": 8,
                "items": {
                    "type": "string",
                    "pattern": _SAFE_HEADER_PATTERN,
                },
                "description": (
                    "Optional safe headers as 'Name: value'. Allowed names: Accept, Accept-Language, "
                    "Cache-Control, DNT, Origin, Pragma, User-Agent. No credentials or Host header."
                ),
            },
            "include_headers": {
                "type": "boolean",
                "description": "Include response headers in output. Default false; HEAD always returns headers.",
            },
            "timeout": {
                "type": "integer",
                "minimum": 1,
                "maximum": 30,
                "description": "Maximum request time in seconds. Default 10; maximum 30.",
            },
            "insecure_tls": {
                "type": "boolean",
                "description": (
                    "Default false. Set true only to retry an in-scope HTTPS request after certificate "
                    "verification error 60. Adds curl --insecure; the response is then unverified."
                ),
            },
        },
        "required": ["target"],
        "additionalProperties": False,
    }

    def build_argv(self, args):
        method = args.get("method", "GET")
        timeout = args.get("timeout", 10)

        argv = [
            self.binary,
            "--disable",                 # first option: ignore user curlrc files
            "--proto", "=http,https",   # allow only HTTP(S)
            "--silent",
            "--show-error",
            "--connect-timeout", "5",
            "--max-time", str(timeout),
            "--max-filesize", "524288", # 512 KiB response-body limit
            "--user-agent", "reconai/0.1 (authorized perimeter recon)",
            "--write-out", _WRITE_OUT,
        ]

        if args.get("insecure_tls", False):
            argv.append("--insecure")

        if method == "HEAD":
            argv.append("--head")
        elif method == "OPTIONS":
            argv += ["--request", "OPTIONS"]

        if args.get("include_headers") and method != "HEAD":
            argv.append("--include")

        for header in args.get("headers", []):
            argv += ["--header", header]

        # No --location: report redirects but never follow them automatically.
        argv += ["--", args["target"]]
        return argv