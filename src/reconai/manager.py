"""Scan lifecycle: queueing, concurrency limit, persistence, cancellation."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from .agent import ScanAgent
from .config import Settings
from .llm import LLMClient
from .models import ScanRequest, ScanResult, utcnow
from .scope import Scope, parse_target
from .tools import Registry

log = logging.getLogger("reconai.manager")


class SubmitError(ValueError):
    pass


class ScanManager:
    def __init__(self, settings: Settings, registry: Registry, llm: LLMClient):
        self.s, self.registry, self.llm = settings, registry, llm
        self.agent = ScanAgent(llm, settings)
        self.scans: dict[str, ScanResult] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._sem = asyncio.Semaphore(settings.max_concurrent_scans)
        self._dir = Path(settings.data_dir) / "scans"
        self._allow = Scope(settings.scope_allowlist) if settings.scope_allowlist else None

    # -- persistence ------------------------------------------------------
    def load(self) -> None:
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            log.warning("cannot create %s (%s) - results will not persist", self._dir, e)
            return
        for p in self._dir.glob("*.json"):
            try:
                r = ScanResult.model_validate_json(p.read_text())
            except Exception as e:
                log.warning("skipping unreadable %s: %s", p, e)
                continue
            if r.status in ("queued", "running"):
                r.status, r.error, r.finished_at = "failed", "interrupted by restart", utcnow()
                self._save(r)
            self.scans[r.scan_id] = r
        log.info("loaded %d previous scans", len(self.scans))

    def _save(self, r: ScanResult) -> None:
        try:
            tmp = self._dir / f".{r.scan_id}.tmp"
            tmp.write_text(r.model_dump_json(indent=2))
            tmp.replace(self._dir / f"{r.scan_id}.json")
        except OSError as e:
            log.warning("persist failed for %s: %s", r.scan_id, e)

    # -- submission -------------------------------------------------------
    def _validate(self, req: ScanRequest) -> None:
        if req.tools is not None:
            bad = [t for t in req.tools if t not in self.registry.names]
            if bad or not req.tools:
                raise SubmitError(f"tools not enabled: {bad or '(empty list)'}; enabled: {self.registry.names}")
        if self._allow:
            for t in req.targets:
                if not self._allow.covers(parse_target(t)):
                    raise SubmitError(f"target {t!r} is outside RECONAI_SCOPE_ALLOWLIST")
        active = sum(1 for r in self.scans.values() if r.status in ("queued", "running"))
        if active >= self.s.max_queued_scans:
            raise SubmitError("scan queue is full")

    def submit_many(self, reqs: list[ScanRequest]) -> list[ScanResult]:
        """All-or-nothing: validate every request first, then enqueue."""
        for r in reqs:
            self._validate(r)
        return [self._enqueue(r) for r in reqs]

    def _enqueue(self, req: ScanRequest) -> ScanResult:
        tools = self.registry.select(req.tools)
        res = ScanResult(targets=req.targets, objective=req.objective, metadata=req.metadata,
                         model=self.s.llm_model, tools_available=[t.name for t in tools])
        self.scans[res.scan_id] = res
        self._save(res)
        max_steps = min(req.max_steps or self.s.max_steps, 100)
        self._tasks[res.scan_id] = asyncio.create_task(self._run(res, tools, max_steps))
        return res

    async def _run(self, res: ScanResult, tools, max_steps: int) -> None:
        try:
            async with self._sem:
                res.status, res.started_at = "running", utcnow()
                self._save(res)
                log.info("[%s] started targets=%s", res.scan_id, res.targets)
                await self.agent.run(res, Scope(res.targets), tools, max_steps, on_update=lambda: self._save(res))
                res.status = "completed"
        except asyncio.CancelledError:
            res.status, res.error = "cancelled", "cancelled by user"
        except Exception as e:
            log.exception("[%s] failed", res.scan_id)
            res.status, res.error = "failed", f"{type(e).__name__}: {e}"
        finally:
            res.finished_at = utcnow()
            self._save(res)
            self._tasks.pop(res.scan_id, None)
            log.info("[%s] %s", res.scan_id, res.status)

    # -- control ----------------------------------------------------------
    def cancel(self, scan_id: str) -> bool:
        t = self._tasks.get(scan_id)
        if t and not t.done():
            t.cancel()
            return True
        return False

    async def shutdown(self) -> None:
        for t in list(self._tasks.values()):
            t.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        await self.llm.close()
