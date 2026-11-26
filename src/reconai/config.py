"""Runtime configuration, entirely driven by environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _list(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


@dataclass
class Settings:
    # LLM
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_timeout: float = 120.0
    llm_temperature: float = 0.1
    # API
    host: str = "0.0.0.0"
    port: int = 9889
    api_key: str = ""
    insecure_no_auth: bool = False
    # Agent / scans
    enabled_tools: list[str] = field(default_factory=lambda: ["nuclei", "gobuster", "wpscan", "nmap"])
    scope_allowlist: list[str] = field(default_factory=list)
    max_concurrent_scans: int = 3
    max_queued_scans: int = 100
    max_steps: int = 15
    tool_timeout: int = 600
    max_tool_output_chars: int = 12000   # what the LLM sees per tool call
    max_capture_bytes: int = 2_000_000   # what we keep from a process at most
    data_dir: str = "/data"
    # Tool specific knobs
    nuclei_rate_limit: int = 50
    gobuster_wordlist: str = "/usr/share/dirb/wordlists/common.txt"
    wpscan_api_token: str = ""
    httpx_binary: str = "httpx-toolkit"  # Kali ships ProjectDiscovery httpx under this name

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        e = env if env is not None else os.environ
        d = cls()
        return cls(
            llm_base_url=e.get("RECONAI_LLM_BASE_URL", d.llm_base_url).rstrip("/"),
            llm_api_key=e.get("RECONAI_LLM_API_KEY", ""),
            llm_model=e.get("RECONAI_LLM_MODEL", d.llm_model),
            llm_timeout=float(e.get("RECONAI_LLM_TIMEOUT", d.llm_timeout)),
            llm_temperature=float(e.get("RECONAI_LLM_TEMPERATURE", d.llm_temperature)),
            host=e.get("RECONAI_HOST", d.host),
            port=int(e.get("RECONAI_PORT", d.port)),
            api_key=e.get("RECONAI_API_KEY", ""),
            insecure_no_auth=_bool(e.get("RECONAI_INSECURE_NO_AUTH")),
            enabled_tools=[t.lower() for t in _list(e.get("RECONAI_TOOLS"))] or d.enabled_tools,
            scope_allowlist=_list(e.get("RECONAI_SCOPE_ALLOWLIST")),
            max_concurrent_scans=int(e.get("RECONAI_MAX_CONCURRENT_SCANS", d.max_concurrent_scans)),
            max_queued_scans=int(e.get("RECONAI_MAX_QUEUED_SCANS", d.max_queued_scans)),
            max_steps=int(e.get("RECONAI_MAX_STEPS", d.max_steps)),
            tool_timeout=int(e.get("RECONAI_TOOL_TIMEOUT", d.tool_timeout)),
            max_tool_output_chars=int(e.get("RECONAI_MAX_TOOL_OUTPUT", d.max_tool_output_chars)),
            data_dir=e.get("RECONAI_DATA_DIR", d.data_dir),
            nuclei_rate_limit=int(e.get("RECONAI_NUCLEI_RATE_LIMIT", d.nuclei_rate_limit)),
            gobuster_wordlist=e.get("RECONAI_GOBUSTER_WORDLIST", d.gobuster_wordlist),
            wpscan_api_token=e.get("WPSCAN_API_TOKEN", ""),
            httpx_binary=e.get("RECONAI_HTTPX_BINARY", d.httpx_binary),
        )