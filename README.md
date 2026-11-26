# reconai  

 <img src="./media/logo.png" width="220" alt="ReconAI Logo">

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
