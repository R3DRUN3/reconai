"""Scope-checked redirect resolution.

Some tools (wpscan) must follow redirects to work. Instead of letting them follow blindly
(possibly to a host outside the scan scope), we walk the chain ourselves, hop by hop, and
refuse as soon as one hop leaves the scope. The tool is then pointed at the final URL.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urljoin

import aiohttp

from .scope import Scope, TargetError, parse_target
from .tools.base import ToolArgError

REDIRECT_CODES = (301, 302, 303, 307, 308)


async def resolve_redirects(url: str, scope: Scope, max_hops: int = 5, timeout: float = 10.0) -> str:
    """Return the final in-scope URL. Raises ToolArgError if any hop is out of scope."""
    cur = url
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout),
                                     headers={"User-Agent": "reconai-redirect-check"}) as s:
        for _ in range(max_hops + 1):
            try:
                async with s.get(cur, allow_redirects=False, ssl=False) as r:
                    loc = r.headers.get("Location")
                    if r.status not in REDIRECT_CODES or not loc:
                        return cur
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                return cur  # cannot probe; hand the last verified in-scope URL to the tool
            nxt = urljoin(cur, loc)
            try:
                t = parse_target(nxt)
            except TargetError as e:
                raise ToolArgError(f"{cur} redirects to an invalid/unsupported URL ({e}). Not scanned.") from None
            if not scope.covers(t):
                raise ToolArgError(f"{cur} redirects to OUT OF SCOPE URL {nxt}. Not scanned. "
                                   f"In scope: {scope.describe()}")
            cur = nxt
    raise ToolArgError(f"more than {max_hops} redirects starting at {url}. Not scanned.")