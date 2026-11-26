# reconai  

[![release](https://github.com/R3DRUN3/reconai/actions/workflows/release.yml/badge.svg)](https://github.com/R3DRUN3/reconai/actions/workflows/release.yml) 
![Red Team Badge](https://img.shields.io/badge/Team-Red-red)  ![Blue Team Badge](https://img.shields.io/badge/Team-Blue-blue)  


<img src="./media/logo.png" width="220" alt="reconai Logo">  



## Table of Contents

- [reconai](#reconai)
  - [Table of Contents](#table-of-contents)
  - [Abstract](#abstract)
  - [Why this is *not* an Agentic Offensive Framework](#why-this-is-not-an-agentic-offensive-framework)
  - [Use cases](#use-cases)
  - [Quick start](#quick-start)
  - [API](#api)
    - [API Examples](#api-examples)
  - [Configuration](#configuration)


## Abstract  

reconai is a small Kali container with an API and an LLM agent inside.   
You POST a target, the agent runs a handful of recon tools **you** chose (nuclei, gobuster, wpscan, nmap...), and you get back a JSON result with a written report.  
That's it.  

> [!WARNING]  
> **Only scan assets you own or are explicitly authorised to test**.

## Why this is *not* an Agentic Offensive Framework  

AOFs give an LLM a shell, sub-agents, graphs, loops and a mission. reconai gives it a simple **menu**.  

| | AOFs | reconai |
|---|---|---|
| Shell access for the LLM | Yes | **No**. Only allow-listed tools run |
|Complex multi-agent loops and graphs| Yes | **No**. Single agent with limited calls |
| What the LLM controls | Any command | Validated parameters of tools you enabled |
| Exploitation / brute force | Part of the job | **Not possible**. Tools run with non-intrusive flags |
| Scope | "Please stay in scope" | **Enforced in code** on every call, including redirects |
| Goal | Get in | **Look and report** |

reconai is much more limited, but also much safer to run, than Agentic Offensive Frameworks.   

## Use cases

- 🔁 **Continuous perimeter checks**: cron or CI posts your domains every night and diffs the reports
- 🤖 **Programmatic lightweight scans**: one HTTP call instead of a pile of tool wrappers
- 🚦 **Triage and Compliance**: "what's actually exposed on this new subdomain?" in minutes
- 📦 **Batch**: submit up to 50 scans at once, they run concurrently
- 🛡️ **Safe automation**: let non-experts trigger scans without handing them a shell

## Quick start  

reconai works with any OpenAI-compatible API that supports tool calling (OpenAI, Azure Foundry, vLLM, Ollama, LiteLLM...).  
Run the tool via docker:  

```bash
cp .env.example .env     # set reconai_LLM_*, reconai_API_KEY, reconai_TOOLS

docker run -d \
  --name reconai \
  --restart unless-stopped \
  --env-file .env \
  -p 127.0.0.1:9889:9889 \
  --mount type=volume,source=reconai-data,target=/data \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp \
  ghcr.io/r3drun3/reconai:v0.0.2

sleep 3
docker logs reconai 
curl http://localhost:9889/health 
```    

Now go to [API Examples](#api-examples).    


## API

| | | |
|---|---|---|
| `POST` | `/scans` | submit one scan |
| `POST` | `/scans/batch` | submit up to 50 |
| `GET` | `/scans`, `/scans/{id}`, `/scans/{id}/report` | list, result, Markdown report |
| `DELETE` | `/scans/{id}` | cancel |
| `GET` | `/tools`, `/health` | enabled tools, liveness |

### API Examples  
```bash
export API=http://localhost:9889
export KEY=$(grep ^reconai_API_KEY .env | cut -d= -f2)
```  

```bash
ID=$(curl -s -X POST $API/scans \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
    "targets": ["exampletarget.com"],
    "tools": ["nuclei", "gobuster", "wpscan", "wafw00f", "whatweb", "httpx", "testssl", "curl"],
    "objective": "Light perimeter check: open ports, web technology, exposed files or directories, obvious misconfigurations and vulnerabilities",
    "max_steps": 30,
    "metadata": {"note": "first PoC test"}
  }' | jq -r .scan_id)
echo "scan id: $ID"
```  


Poll the status. It goes queued, then running, then completed or failed:  
```bash
watch -n 5 "curl -s -H 'Authorization: Bearer $KEY' $API/scans/$ID | jq '{status,steps,tools_used,error,runs:[.tool_runs[]|{tool,status,exit_code,duration_s}]}'"
```  

Read the result:  
```bash
# What is actually running (exact commands, status, output)
curl -s -H "Authorization: Bearer $KEY" $API/scans/$ID | jq '.tool_runs[] | {id,tool,status,exit_code,argv,output}'

# Summary and findings
curl -s -H "Authorization: Bearer $KEY" $API/scans/$ID | jq '{status,risk_rating,summary,findings,usage,error}'

# Report as Markdown
curl -s -H "Authorization: Bearer $KEY" $API/scans/$ID/report

# Full JSON saved to a file
curl -s -H "Authorization: Bearer $KEY" $API/scans/$ID > scan-$ID.json
```  


## Configuration

| Variable | Default | |
|---|---|---|
| `reconai_LLM_BASE_URL`, `_API_KEY`, `_MODEL` | OpenAI | your LLM |
| `reconai_API_KEY` | required | bearer key for this API |
| `reconai_TOOLS` | `nuclei,gobuster,wpscan,nmap` | what the agent may use |
| `reconai_SCOPE_ALLOWLIST` | empty | only accept targets inside these domains/CIDRs |
| `reconai_MAX_CONCURRENT_SCANS` | 3 | parallel scans |
| `reconai_MAX_STEPS` | 30 | LLM calls per scan |
| `reconai_TOOL_TIMEOUT` | 600 | seconds per tool run |













