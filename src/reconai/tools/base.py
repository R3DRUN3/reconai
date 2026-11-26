"""Tool plugin interface.

To add a tool: subclass `Tool`, fill in the class attributes, implement
`build_argv` (and optionally `preflight` / `follow_redirects`), and register it
in `tools/__init__.py`.

Safety contract (enforced by the framework, not by the LLM):
  * arguments are validated against `parameters` (a JSON schema subset),
  * the `target` argument is parsed and checked against the scan scope,
  * redirects (if the tool needs them) are resolved hop by hop and scope-checked,
  * the command is executed as an argv list (no shell),
  * the LLM can only choose values for the parameters you declare.
"""
from __future__ import annotations

import re
from typing import Any

from ..config import Settings
from ..scope import MAX_NET_ADDRESSES, Scope, Target, TargetError, parse_target


class ToolArgError(ValueError):
    """Raised for invalid arguments; the message is shown to the LLM so it can retry."""


class Tool:
    name: str = ""
    description: str = ""
    binary: str = ""
    parameters: dict[str, Any] = {}
    target_kind: str = "url"  # "url" -> http(s) URL required, "host" -> host/IP/CIDR (no scheme)
    secret_flags: tuple[str, ...] = ()  # flags whose following value is masked in the audit log
    timeout: int | None = None  # overrides RECONAI_TOOL_TIMEOUT
    # True: the framework resolves the redirect chain (every hop scope-checked) and passes the
    # final URL to the tool. Use it for tools that must follow redirects to work.
    follow_redirects: bool = False

    def __init__(self, settings: Settings):
        self.settings = settings

    # -- to implement -----------------------------------------------------
    def build_argv(self, args: dict[str, Any]) -> list[str]:
        raise NotImplementedError

    def preflight(self) -> str | None:
        """Startup check. Return an error message if the tool cannot work
        (missing wordlist, missing config...), else None. A failing tool is disabled."""
        return None

    async def prepare(self, args: dict[str, Any], scope: Scope) -> dict[str, Any]:
        """Async hook run after validation + scope check and before build_argv.
        Default: scope-checked redirect resolution for tools with follow_redirects=True."""
        if self.follow_redirects and self.target_kind == "url":
            from ..redirects import resolve_redirects  # local import avoids an import cycle
            final = await resolve_redirects(args["target"], scope)
            if final != args["target"]:
                return {**args, "target": final}
        return args

    # -- framework --------------------------------------------------------
    def openai_schema(self) -> dict[str, Any]:
        return {"type": "function",
                "function": {"name": self.name, "description": self.description, "parameters": self.parameters}}

    def parse_target(self, args: dict[str, Any]) -> Target:
        raw = args.get("target")
        if not isinstance(raw, str):
            raise ToolArgError("'target' is required and must be a string")
        try:
            t = parse_target(raw)
        except TargetError as e:
            raise ToolArgError(f"invalid target: {e}") from None
        if self.target_kind == "url" and not t.is_url:
            raise ToolArgError("target must be a full http(s) URL, e.g. https://example.com/")
        if self.target_kind == "host" and t.is_url:
            raise ToolArgError("target must be a hostname, IP or CIDR - not a URL")
        if t.net is not None and t.net.num_addresses > MAX_NET_ADDRESSES:
            raise ToolArgError(f"network too large (max {MAX_NET_ADDRESSES} addresses)")
        return t

    def validate(self, args: Any) -> dict[str, Any]:
        if not isinstance(args, dict):
            raise ToolArgError("arguments must be a JSON object")
        props = self.parameters.get("properties", {})
        extra = set(args) - set(props)
        if extra:
            raise ToolArgError(f"unknown argument(s): {sorted(extra)}")
        for req in self.parameters.get("required", []):
            if req not in args:
                raise ToolArgError(f"missing required argument: {req}")
        for k, v in args.items():
            _check(k, v, props[k])
        return args

    def mask(self, argv: list[str]) -> list[str]:
        out, hide = [], False
        for a in argv:
            out.append("***" if hide else a)
            hide = a in self.secret_flags
        return out


def _check(name: str, v: Any, spec: dict[str, Any]) -> None:
    t = spec.get("type")
    if t == "string":
        if not isinstance(v, str):
            raise ToolArgError(f"{name}: must be a string")
        if len(v) > spec.get("maxLength", 2048):
            raise ToolArgError(f"{name}: too long")
        if "pattern" in spec and not re.fullmatch(spec["pattern"], v):
            raise ToolArgError(f"{name}: does not match required format {spec['pattern']}")
    elif t == "integer":
        if isinstance(v, bool) or not isinstance(v, int):
            raise ToolArgError(f"{name}: must be an integer")
        if not spec.get("minimum", v) <= v <= spec.get("maximum", v):
            raise ToolArgError(f"{name}: out of range [{spec.get('minimum')}, {spec.get('maximum')}]")
    elif t == "boolean":
        if not isinstance(v, bool):
            raise ToolArgError(f"{name}: must be true or false")
    elif t == "array":
        if not isinstance(v, list) or len(v) > spec.get("maxItems", 20):
            raise ToolArgError(f"{name}: must be an array")
        for item in v:
            _check(name + "[]", item, spec.get("items", {}))
    if "enum" in spec and v not in spec["enum"] and not isinstance(v, list):
        raise ToolArgError(f"{name}: must be one of {spec['enum']}")