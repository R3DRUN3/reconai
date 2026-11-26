"""Subprocess execution. Never uses a shell: argv list in, bounded output out."""
from __future__ import annotations

import asyncio
import os
import signal
from dataclasses import dataclass


@dataclass
class ProcResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool


def _clean_env() -> dict[str, str]:
    # Do NOT leak RECONAI_* / LLM credentials to scanned tooling.
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.setdefault("LANG", "C.UTF-8")
    return env


async def _read_capped(stream: asyncio.StreamReader, cap: int) -> tuple[bytes, bool]:
    buf = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        room = cap - len(buf)
        if room > 0:
            buf.extend(chunk[:room])
        if len(chunk) > room:
            truncated = True  # keep draining so the child never blocks on a full pipe
    return bytes(buf), truncated


def _kill(proc: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


async def run_process(argv: list[str], timeout: float, cap_bytes: int) -> ProcResult:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_clean_env(),
        start_new_session=True,  # own process group so we can kill children too
    )
    out_t = asyncio.create_task(_read_capped(proc.stdout, cap_bytes))
    err_t = asyncio.create_task(_read_capped(proc.stderr, cap_bytes))
    timed_out = False
    try:
        await asyncio.wait_for(proc.wait(), timeout)
    except asyncio.TimeoutError:
        timed_out = True
        _kill(proc)
        await proc.wait()
    except BaseException:  # includes CancelledError (scan cancelled)
        _kill(proc)
        out_t.cancel()
        err_t.cancel()
        raise
    (out, t1), (err, t2) = await asyncio.gather(out_t, err_t)
    return ProcResult(
        exit_code=None if timed_out else proc.returncode,
        stdout=out.decode("utf-8", "replace"),
        stderr=err.decode("utf-8", "replace"),
        timed_out=timed_out,
        truncated=t1 or t2,
    )
