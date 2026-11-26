# reconai  

<img src="./media/logo.png" width="220" alt="ReconAI Logo">  


ReconAI is a small Kali container with an LLM agent inside.  
You POST a target, the agent runs a handful of recon tools **you** chose (nuclei, gobuster, wpscan, nmap...), and you get back a JSON result with a written report.  
That's it.  

> [!WARNING]  
> **Only scan assets you own or are explicitly authorised to test**.

## Why this is *not* an exploitation framework

Autonomous pentest agents give an LLM a shell and a mission. reconai gives it a simple **menu**.

| | Exploitation frameworks | reconai |
|---|---|---|
| Shell access for the LLM | Yes | **No**. Only allow-listed tools run |
| What the LLM controls | Any command | Validated parameters of tools you enabled |
| Exploitation / brute force | Part of the job | **Not possible**. Tools run with non-intrusive flags |
| Scope | "Please stay in scope" | **Enforced in code** on every call, including redirects |
| Goal | Get in | **Look and report** |

Even a prompt-injected or confused model can't scan outside scope or run anything you didn't enable.

## Use cases

- 🔁 **Continuous perimeter checks**: cron or CI posts your domains every night and diffs the reports
- 🤖 **Programmatic lightweight scans**: one HTTP call instead of a pile of tool wrappers
- 🚦 **Triage**: "what's actually exposed on this new subdomain?" in minutes
- 📦 **Batch**: submit up to 50 scans at once, they run concurrently
- 🛡️ **Safe automation**: let non-experts trigger scans without handing them a shell

## Quick start
```bash
cp .env.example .env     # set RECONAI_LLM_*, RECONAI_API_KEY, RECONAI_TOOLS
docker compose up --build -d
```

Works with any OpenAI-compatible API that supports tool calling (OpenAI, Azure, vLLM, Ollama, LiteLLM...).
```bash
KEY=your-api-key

# submit a scan
curl -s -X POST localhost:9889/scans -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"targets":["example.com"],"tools":["nmap","nuclei"],"max_steps":10}'

# batch: many scans at once
curl -s -X POST localhost:9889/scans/batch -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"scans":[{"targets":["a.example.com"]},{"targets":["203.0.113.0/28"],"tools":["nmap"]}]}'

# get the result / the report
curl -s -H "Authorization: Bearer $KEY" localhost:9889/scans/<id>
curl -s -H "Authorization: Bearer $KEY" localhost:9889/scans/<id>/report
```

## API

| | | |
|---|---|---|
| `POST` | `/scans` | submit one scan |
| `POST` | `/scans/batch` | submit up to 50 |
| `GET` | `/scans`, `/scans/{id}`, `/scans/{id}/report` | list, result, Markdown report |
| `DELETE` | `/scans/{id}` | cancel |
| `GET` | `/tools`, `/health` | enabled tools, liveness |

`targets` is the scope: domains (subdomains included), IPs, CIDRs up to /24, or http(s) URLs.

## What you get back
```jsonc
{
  "scan_id": "3f2a9c1d7b10",
  "status": "completed",            // queued | running | completed | failed | cancelled
  "risk_rating": "low",
  "summary": "...",
  "findings": [{"title": "...", "severity": "low", "evidence": "...", "recommendation": "..."}],
  "report": "# Full Markdown report ...",
  "tool_runs": [{"tool": "nmap", "argv": ["nmap", "..."], "status": "ok", "output": "..."}]
}
```

`tool_runs` is a full audit trail of every command the agent ran, or tried to run and was refused.

## Configuration

| Variable | Default | |
|---|---|---|
| `RECONAI_LLM_BASE_URL`, `_API_KEY`, `_MODEL` | OpenAI | your LLM |
| `RECONAI_API_KEY` | required | bearer key for this API |
| `RECONAI_TOOLS` | `nuclei,gobuster,wpscan,nmap` | what the agent may use |
| `RECONAI_SCOPE_ALLOWLIST` | empty | only accept targets inside these domains/CIDRs |
| `RECONAI_MAX_CONCURRENT_SCANS` | 3 | parallel scans |
| `RECONAI_MAX_STEPS` | 15 | LLM calls per scan |
| `RECONAI_TOOL_TIMEOUT` | 600 | seconds per tool run |

## Add a tool in ~10 lines
```python
class WhatWeb(Tool):
    name = "whatweb"; binary = "whatweb"; target_kind = "url"
    description = "Fingerprint web technologies of ONE http(s) URL."
    parameters = {"type": "object", "properties": {"target": {"type": "string"}},
                  "required": ["target"], "additionalProperties": False}
    def build_argv(self, args):
        return [self.binary, "--color=never", args["target"]]
```

Register it in `tools/__init__.py`, install it in the Dockerfile, add it to `RECONAI_TOOLS`. Validation, scope checks, timeouts and auditing come for free.


## License

MIT. Be nice, scan only what's yours. 🙂




```bash
export API=http://localhost:9889
export KEY=$(grep ^RECONAI_API_KEY .env | cut -d= -f2)
```  

```bash
ID=$(curl -s -X POST $API/scans \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
    "targets": ["sassi.it"],
    "tools": ["nuclei", "gobuster", "wpscan"],
    "objective": "Light perimeter check: open ports, web technology, exposed files or directories, obvious misconfigurations and vulnerabilities",
    "max_steps": 10,
    "metadata": {"note": "first PoC test"}
  }' | jq -r .scan_id)
echo "scan id: $ID"
```  

```bash
docker compose logs -f reconai
```  

Poll the status. It goes queued, then running, then completed or failed:  
```bash
watch -n 5 "curl -s -H 'Authorization: Bearer $KEY' $API/scans/$ID | jq '{status,steps,tools_used,error,runs:[.tool_runs[]|{tool,status,exit_code,duration_s}]}'"
```  

Read the result:  
```bash
# Summary and findings
curl -s -H "Authorization: Bearer $KEY" $API/scans/$ID | jq '{status,risk_rating,summary,findings,usage,error}'


# Report as Markdown
curl -s -H "Authorization: Bearer $KEY" $API/scans/$ID/report


# What actually ran (exact commands, status, output)
curl -s -H "Authorization: Bearer $KEY" $API/scans/$ID | jq '.tool_runs[] | {id,tool,status,exit_code,argv,output}'


# Full JSON saved to a file
curl -s -H "Authorization: Bearer $KEY" $API/scans/$ID > scan-$ID.json
```  

Multiple Scans:  
Use POST /scans/batch with {"scans":[{...},{...}]} (max 50 per request). They run concurrently, up to RECONAI_MAX_CONCURRENT_SCANS (default 3), and the rest queue. You can also just call POST /scans multiple times.  






