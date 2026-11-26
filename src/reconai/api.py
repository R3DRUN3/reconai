"""HTTP API (aiohttp)."""
from __future__ import annotations

import hmac
import json

from aiohttp import web
from pydantic import ValidationError

from .config import Settings
from .llm import LLMClient
from .manager import ScanManager, SubmitError
from .models import ScanRequest
from .tools import Registry, build_registry
from . import __version__


def _json(data, status=200) -> web.Response:
    return web.Response(text=json.dumps(data, default=str), status=status, content_type="application/json")


def _err(status: int, msg: str, details=None) -> web.Response:
    return _json({"error": msg, **({"details": details} if details else {})}, status)


@web.middleware
async def auth_mw(request: web.Request, handler):
    if request.path == "/health":
        return await handler(request)
    key: str = request.app["settings"].api_key
    if key:
        supplied = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(supplied.encode(), key.encode()):
            return _err(401, "unauthorized")
    return await handler(request)


def _parse_requests(body, many: bool) -> list[ScanRequest]:
    if many:
        items = body.get("scans") if isinstance(body, dict) else body
        if not isinstance(items, list) or not items:
            raise ValueError("expected a non-empty list of scans, or {\"scans\": [...]}")
        if len(items) > 50:
            raise ValueError("max 50 scans per batch")
    else:
        items = [body]
    return [ScanRequest.model_validate(i) for i in items]


async def _submit(request: web.Request, many: bool) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return _err(400, "body must be valid JSON")
    try:
        reqs = _parse_requests(body, many)
        results = request.app["manager"].submit_many(reqs)
    except ValidationError as e:
        return _err(422, "invalid scan request", json.loads(e.json(include_url=False, include_context=False)))
    except (ValueError, SubmitError) as e:
        return _err(400, str(e))
    out = [{"scan_id": r.scan_id, "status": r.status, "targets": r.targets, "url": f"/scans/{r.scan_id}"} for r in results]
    return _json(out if many else out[0], 202)


async def post_scan(request):   return await _submit(request, False)
async def post_batch(request):  return await _submit(request, True)


async def health(request):
    return _json({"status": "ok", "version": __version__})


async def list_tools(request):
    reg: Registry = request.app["registry"]
    return _json([{"name": n, "description": reg.get(n).description, "parameters": reg.get(n).parameters} for n in reg.names])


async def list_scans(request):
    st = request.query.get("status")
    scans = sorted(request.app["manager"].scans.values(), key=lambda r: r.created_at, reverse=True)
    return _json([r.brief() for r in scans if not st or r.status == st])


def _get(request) -> "ScanResult | None":
    return request.app["manager"].scans.get(request.match_info["scan_id"])


async def get_scan(request):
    r = _get(request)
    return _err(404, "scan not found") if r is None else web.Response(text=r.model_dump_json(), content_type="application/json")


async def get_report(request):
    r = _get(request)
    if r is None:
        return _err(404, "scan not found")
    return web.Response(text=r.report, content_type="text/markdown", charset="utf-8")


async def delete_scan(request):
    r = _get(request)
    if r is None:
        return _err(404, "scan not found")
    if not request.app["manager"].cancel(r.scan_id):
        return _err(409, f"scan is already {r.status}")
    return _json({"scan_id": r.scan_id, "status": "cancelling"}, 202)


def create_app(settings: Settings, registry: Registry | None = None, llm: LLMClient | None = None) -> web.Application:
    registry = registry or build_registry(settings)
    manager = ScanManager(settings, registry, llm or LLMClient(settings))
    app = web.Application(middlewares=[auth_mw], client_max_size=1024 * 1024)
    app["settings"], app["registry"], app["manager"] = settings, registry, manager
    app.add_routes([
        web.get("/health", health),
        web.get("/tools", list_tools),
        web.get("/scans", list_scans),
        web.post("/scans", post_scan),
        web.post("/scans/batch", post_batch),
        web.get("/scans/{scan_id}", get_scan),
        web.get("/scans/{scan_id}/report", get_report),
        web.delete("/scans/{scan_id}", delete_scan),
    ])

    async def on_start(app):
        manager.load()

    async def on_stop(app):
        await manager.shutdown()

    app.on_startup.append(on_start)
    app.on_cleanup.append(on_stop)
    return app
