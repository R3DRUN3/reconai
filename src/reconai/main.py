from __future__ import annotations

import logging
import sys

from aiohttp import web

from .api import create_app
from .config import Settings


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("reconai")
    s = Settings.from_env()
    if not s.api_key and not s.insecure_no_auth:
        sys.exit("RECONAI_API_KEY is not set. Set it, or set RECONAI_INSECURE_NO_AUTH=true (local testing only).")
    if not s.api_key:
        log.warning("API authentication is DISABLED")
    if not s.llm_api_key:
        log.warning("RECONAI_LLM_API_KEY is empty (ok for local OpenAI-compatible servers)")
    try:
        app = create_app(s)
    except ValueError as e:
        sys.exit(str(e))
    skipped = [t for t in s.enabled_tools if t not in app["registry"].names]
    if skipped:
        log.warning("tools requested but DISABLED (see warnings above): %s", skipped)
    log.info("tools enabled: %s | model: %s @ %s", app["registry"].names, s.llm_model, s.llm_base_url)
    web.run_app(app, host=s.host, port=s.port, print=None)


if __name__ == "__main__":
    main()