"""End-to-end tests: real HTTP API + real subprocesses, scripted fake LLM, harmless fake tool.

Run:  python -m unittest discover -s tests -v
"""
import asyncio
import json
import os
import sys
import tempfile
import unittest

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reconai.api import create_app  # noqa: E402
from reconai.config import Settings  # noqa: E402
from reconai.runner import run_process  # noqa: E402
from reconai.scope import Scope, TargetError, parse_target  # noqa: E402
from reconai.tools import Registry, build_registry  # noqa: E402
from reconai.tools.base import Tool  # noqa: E402


class EchoTool(Tool):
    """Plugin example: shows how little a new tool needs."""
    name, binary, target_kind = "echo_scan", "echo", "host"
    description = "test tool"
    parameters = {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"],
                  "additionalProperties": False}

    def build_argv(self, args):
        return [self.binary, "scanned", args["target"]]


def tc(name, args, i="c1"):
    return {"id": i, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def fake_llm_app(mode="normal"):
    async def handler(request):
        body = await request.json()
        msgs = body["messages"]
        tool_msgs = [m for m in msgs if m["role"] == "tool"]
        if mode == "never_submit":
            return web.json_response({"choices": [{"message": {"role": "assistant", "content": "thinking"}}]})
        if not tool_msgs:
            host = next(l for l in msgs[1]["content"].splitlines() if l.startswith("- "))[2:]
            calls = [tc("echo_scan", {"target": "evil.invalid"}, "c1"),
                     tc("echo_scan", {"target": host}, "c2"),
                     tc("echo_scan", {"target": "-oX /etc/passwd"}, "c3")]
            return web.json_response({"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": calls}}],
                                      "usage": {"prompt_tokens": 10, "completion_tokens": 5}})
        joined = "\n".join(m["content"] for m in tool_msgs)
        rep = {"summary": "ok", "risk_rating": "low",
               "findings": [{"title": "F1", "severity": "low", "target": "t", "description": "d",
                             "evidence": joined[:200], "recommendation": "r"}],
               "report_markdown": "# Report\n" + joined}
        return web.json_response({"choices": [{"message": {"role": "assistant", "content": None,
                                                           "tool_calls": [tc(SUBMIT, rep)]}}]})
    SUBMIT = "submit_report"
    app = web.Application()
    app.router.add_post("/v1/chat/completions", handler)
    return app


class Harness(unittest.IsolatedAsyncioTestCase):
    mode = "normal"
    extra: dict = {}

    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.llm_srv = TestServer(fake_llm_app(self.mode))
        await self.llm_srv.start_server()
        env = {"RECONAI_LLM_BASE_URL": f"http://127.0.0.1:{self.llm_srv.port}/v1", "RECONAI_API_KEY": "k",
               "RECONAI_DATA_DIR": self.tmp.name, "RECONAI_TOOLS": "echo_scan", "RECONAI_MAX_STEPS": "3", **self.extra}
        s = Settings.from_env(env)
        reg = build_registry(s, {"echo_scan": EchoTool})
        self.api = TestServer(create_app(s, reg))
        await self.api.start_server()
        self.http = ClientSession(base_url=f"http://127.0.0.1:{self.api.port}", headers={"Authorization": "Bearer k"})

    async def asyncTearDown(self):
        await self.http.close()
        await self.api.close()
        await self.llm_srv.close()
        self.tmp.cleanup()

    async def wait(self, sid, timeout=15):
        for _ in range(timeout * 20):
            async with self.http.get(f"/scans/{sid}") as r:
                d = await r.json()
            if d["status"] in ("completed", "failed", "cancelled"):
                return d
            await asyncio.sleep(0.05)
        self.fail("timeout")


class TestApi(Harness):
    async def test_auth(self):
        async with ClientSession(base_url=f"http://127.0.0.1:{self.api.port}") as c:
            self.assertEqual((await c.get("/scans")).status, 401)
            self.assertEqual((await c.get("/health")).status, 200)

    async def test_batch_concurrent_scans(self):
        body = {"scans": [{"targets": [f"host{i}.example.com"], "metadata": {"n": str(i)}} for i in range(5)]}
        async with self.http.post("/scans/batch", json=body) as r:
            self.assertEqual(r.status, 202)
            subs = await r.json()
        self.assertEqual(len(subs), 5)
        for i, sub in enumerate(subs):
            d = await self.wait(sub["scan_id"])
            self.assertEqual(d["status"], "completed", d.get("error"))
            self.assertEqual(d["metadata"]["n"], str(i))
            self.assertEqual(d["risk_rating"], "low")
            self.assertIn(f"scanned host{i}.example.com", d["report"])
            statuses = [t["status"] for t in d["tool_runs"]]
            self.assertEqual(statuses.count("rejected"), 2)  # out of scope + option injection
            self.assertEqual(statuses.count("ok"), 1)
            self.assertNotIn("scanned evil.invalid", d["report"])
            self.assertTrue(all(t["argv"] == [] for t in d["tool_runs"] if t["status"] == "rejected"))
            self.assertEqual(d["usage"]["llm_calls"], 2)
        async with self.http.get(f"/scans/{subs[0]['scan_id']}/report") as r:
            self.assertTrue((await r.text()).startswith("# Report"))
        async with self.http.get("/scans?status=completed") as r:
            self.assertEqual(len(await r.json()), 5)

    async def test_validation(self):
        for body in ({"targets": []}, {"targets": ["-oX x"]}, {"targets": ["a.com"], "bogus": 1},
                     {"targets": ["file:///etc/passwd"]}):
            async with self.http.post("/scans", json=body) as r:
                self.assertEqual(r.status, 422, body)
        async with self.http.post("/scans", json={"targets": ["a.com"], "tools": ["metasploit"]}) as r:
            self.assertEqual(r.status, 400)
        async with self.http.get("/tools") as r:
            self.assertEqual([t["name"] for t in await r.json()], ["echo_scan"])

    async def test_persistence_file(self):
        async with self.http.post("/scans", json={"targets": ["a.example.com"]}) as r:
            sid = (await r.json())["scan_id"]
        await self.wait(sid)
        saved = json.load(open(os.path.join(self.tmp.name, "scans", f"{sid}.json")))
        self.assertEqual(saved["status"], "completed")


class TestNeverSubmit(Harness):
    mode = "never_submit"

    async def test_fails_cleanly(self):
        async with self.http.post("/scans", json={"targets": ["a.example.com"]}) as r:
            sid = (await r.json())["scan_id"]
        d = await self.wait(sid)
        self.assertEqual(d["status"], "failed")
        self.assertIn("submit_report", d["error"])
        self.assertEqual(d["report"], "thinking")


class TestAllowlist(Harness):
    extra = {"RECONAI_SCOPE_ALLOWLIST": "corp.example,10.0.0.0/24"}

    async def test_allowlist(self):
        async with self.http.post("/scans", json={"targets": ["x.corp.example", "10.0.0.5"]}) as r:
            self.assertEqual(r.status, 202)
        async with self.http.post("/scans", json={"targets": ["other.com"]}) as r:
            self.assertEqual(r.status, 400)
        async with self.http.post("/scans", json={"targets": ["10.0.0.0/16"]}) as r:
            self.assertEqual(r.status, 400)


class TestUnits(unittest.IsolatedAsyncioTestCase):
    def test_scope(self):
        sc = Scope(["example.com", "https://app.other.org/x", "192.0.2.0/28"])
        ok = ["example.com", "https://a.b.example.com/p", "192.0.2.7", "app.other.org:8443", "192.0.2.0/29"]
        bad = ["notexample.com", "example.com.evil.io", "other.org", "192.0.2.99", "192.0.2.0/24", "2001:db8::1"]
        for t in ok:
            self.assertTrue(sc.covers(parse_target(t)), t)
        for t in bad:
            self.assertFalse(sc.covers(parse_target(t)), t)
        for t in ["", "-x", "a b", "ftp://a.com", "http://u:p@a.com", "ex_ample!.com"]:
            with self.assertRaises(TargetError):
                parse_target(t)

    def test_builtin_argv(self):
        s = Settings.from_env({"WPSCAN_API_TOKEN": "SECRET"})
        from reconai.tools import BUILTIN_TOOLS as B
        w = B["wpscan"](s)
        argv = w.build_argv(w.validate({"target": "https://x.com", "enumerate": ["vp", "u"]}))
        self.assertIn("SECRET", argv)
        self.assertNotIn("SECRET", w.mask(argv))
        n = B["nmap"](s)
        self.assertEqual(n.build_argv(n.validate({"target": "x.com", "ports": "22,80"}))[-3:], ["-p", "22,80", "x.com"])
        self.assertNotIn("--top-ports", n.build_argv({"target": "x.com", "ports": "22"}))
        nu = B["nuclei"](s)
        from reconai.tools.base import ToolArgError
        for bad in ({"target": "https://x.com", "tags": "a;rm -rf /"}, {"target": "https://x.com", "templates": "/x"},
                    {"target": "https://x.com", "severity": ["bogus"]}):
            with self.assertRaises(ToolArgError):
                nu.validate(bad)
        with self.assertRaises(ToolArgError):
            nu.parse_target({"target": "x.com"})          # url tool needs a URL
        with self.assertRaises(ToolArgError):
            n.parse_target({"target": "https://x.com"})   # host tool rejects URL
        with self.assertRaises(ToolArgError):
            n.parse_target({"target": "10.0.0.0/8"})      # too big

    async def test_runner(self):
        r = await run_process(["sleep", "30"], timeout=0.3, cap_bytes=100)
        self.assertTrue(r.timed_out)
        r = await run_process(["sh", "-c", "yes | head -c 100000"], timeout=5, cap_bytes=100)
        self.assertTrue(r.truncated)
        self.assertEqual(len(r.stdout), 100)
        os.environ["RECONAI_LLM_API_KEY"] = "leak"
        r = await run_process(["env"], timeout=5, cap_bytes=10000)
        self.assertNotIn("RECONAI", r.stdout)


if __name__ == "__main__":
    unittest.main()
