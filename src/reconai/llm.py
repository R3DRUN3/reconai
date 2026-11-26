"""Minimal client for any OpenAI-compatible /chat/completions endpoint with tool calling."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiohttp

from .config import Settings

log = logging.getLogger("reconai.llm")


class LLMError(RuntimeError):
    def __init__(self, msg: str, retryable: bool = True):
        super().__init__(msg)
        self.retryable = retryable


class LLMClient:
    def __init__(self, settings: Settings):
        self.s = settings
        self._session: aiohttp.ClientSession | None = None

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    def _sess(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.s.llm_timeout))
        return self._session

    async def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, int]]:
        """Returns (assistant_message, usage)."""
        payload = {"model": self.s.llm_model, "messages": messages, "tools": tools,
                   "tool_choice": "auto", "temperature": self.s.llm_temperature}
        headers = {"Content-Type": "application/json"}
        if self.s.llm_api_key:
            headers["Authorization"] = f"Bearer {self.s.llm_api_key}"
        url = f"{self.s.llm_base_url}/chat/completions"
        last: Exception | None = None
        for attempt in range(4):
            try:
                async with self._sess().post(url, json=payload, headers=headers) as r:
                    if r.status >= 400:
                        retry = r.status in (408, 409, 429) or r.status >= 500
                        raise LLMError(f"HTTP {r.status}: {(await r.text())[:500]}", retryable=retry)
                    data = await r.json(content_type=None)
                try:
                    return data["choices"][0]["message"], data.get("usage") or {}
                except (KeyError, IndexError, TypeError):
                    raise LLMError(f"unexpected response shape: {str(data)[:300]}", retryable=False) from None
            except (aiohttp.ClientError, asyncio.TimeoutError, LLMError) as e:
                last = e
                if isinstance(e, LLMError) and not e.retryable:
                    break
                wait = 2 ** attempt
                log.warning("LLM call failed (%s), retry in %ss", e, wait)
                await asyncio.sleep(wait)
        raise LLMError(f"LLM request failed: {last}")
