
"""Tool registry. Register new tools in BUILTIN_TOOLS."""
from __future__ import annotations

import logging
import shutil

from ..config import Settings
from .base import Tool, ToolArgError  # noqa: F401
from .arjun import Arjun
from .curl_tool import Curl
from .gobuster import Gobuster
from .httpx_probe import HttpxProbe
from .nmap import Nmap
from .nuclei import Nuclei
from .testssl import Testssl
from .wafw00f import Wafw00f
from .whatweb import WhatWeb
from .wpscan import WPScan

log = logging.getLogger("reconai.tools")

BUILTIN_TOOLS: dict[str, type[Tool]] = {
    c.name: c
    for c in (
        Nuclei,
        Gobuster,
        WPScan,
        Nmap,
        WhatWeb,
        HttpxProbe,
        Wafw00f,
        Testssl,
        Curl,
        Arjun,
    )
}


class Registry:
    def __init__(self, tools: list[Tool]):
        self._tools = {t.name: t for t in tools}

    @property
    def names(self) -> list[str]:
        return list(self._tools)

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def select(self, names: list[str] | None) -> list[Tool]:
        if names is None:
            return list(self._tools.values())
        return [self._tools[n] for n in names]

    def __len__(self) -> int:
        return len(self._tools)


def build_registry(
    settings: Settings,
    available: dict[str, type[Tool]] | None = None,
    check_binaries: bool = True,
) -> Registry:
    """Instantiate tools enabled via RECONAI_TOOLS.

    A tool whose binary is missing or whose preflight() fails
    is skipped with a warning.
    """
    available = available or BUILTIN_TOOLS

    unknown = [
        n for n in settings.enabled_tools
        if n not in available
    ]

    if unknown:
        raise ValueError(
            f"Unknown tool(s) in RECONAI_TOOLS: {unknown}. "
            f"Available: {sorted(available)}"
        )

    tools: list[Tool] = []

    for n in settings.enabled_tools:
        tool = available[n](settings)

        if check_binaries:
            if shutil.which(tool.binary) is None:
                log.warning(
                    "Tool %r disabled: binary %r not found in PATH",
                    n,
                    tool.binary,
                )
                continue

            problem = tool.preflight()

            if problem:
                log.warning("Tool %r disabled: %s", n, problem)
                continue

        tools.append(tool)

    if not tools:
        raise ValueError(
            "No usable tools. Check RECONAI_TOOLS and that "
            "the binaries are installed."
        )

    return Registry(tools)
