import re
from pathlib import Path

# 1. Update parser.py
parser_path = Path("/home/hollowedtemplar/sentinel/backend/app/services/parser.py")
content = parser_path.read_text()

# Modify generate_ai_assessment
old_generate = """async def generate_ai_assessment(findings: List[Finding], api_url, api_key, model_name, temp, top_k, top_p, min_p) -> str:
    resolved_url = api_url.strip() if api_url else os.getenv("LLAMA_API_URL", "")
    resolved_model = model_name.strip() if model_name else os.getenv("AI_MODEL_NAME", "")
    resolved_key = api_key.strip() if api_key else "local-only"

    if not resolved_url or not resolved_model:
        return "AI Assessment disabled (Non-AI Mode)."

    filtered = [f for f in findings if f.severity != "Info"]
    if not filtered:
        return "No high-severity findings to analyze."

    client = AsyncOpenAI(api_key=resolved_key, base_url=resolved_url)
    
    payload = [{"type": f.type, "value": f.value, "severity": f.severity} for f in filtered[:200]]
    prompt = f\"\"\"You are a Red Team Lead. Based on these recon findings, write a 2-3 paragraph Executive Summary of the attack surface, followed by 2-3 bullet points of potential attack vectors or exploit chains the tester should try next. Use Markdown formatting.

Findings:
{json.dumps(payload)}\"\"\"

    try:
        response = await client.chat.completions.create(
            model=resolved_model, messages=[{"role": "user", "content": prompt}],
            temperature=temp, top_p=top_p, extra_body={"top_k": top_k, "min_p": min_p}
        )
        return response.choices[0].message.content or "No response from AI."
    except Exception as e:
        return f"AI Assessment failed: {e}\""""

new_generate = """async def generate_ai_assessment(findings: List[Finding], tech_findings: List[TechFinding], api_url, api_key, model_name, temp, top_k, top_p, min_p) -> str:
    resolved_url = api_url.strip() if api_url else os.getenv("LLAMA_API_URL", "")
    resolved_model = model_name.strip() if model_name else os.getenv("AI_MODEL_NAME", "")
    resolved_key = api_key.strip() if api_key else "local-only"

    if not resolved_url or not resolved_model:
        return "AI Assessment disabled (Non-AI Mode)."

    filtered = [f for f in findings if f.severity != "Info"]
    if not filtered:
        return "No high-severity findings to analyze."

    client = AsyncOpenAI(api_key=resolved_key, base_url=resolved_url)
    
    payload = [{"type": f.type, "value": f.value, "severity": f.severity} for f in filtered[:200]]
    tech_payload = [{"technology": t.technology, "location": t.location} for t in tech_findings[:50]]
    
    prompt = f\"\"\"You are a Red Team Lead. Based on these recon findings and the infrastructure profile, write a 2-3 paragraph Executive Summary of the attack surface, a summary of the infrastructure profile based on your interpretation of the findings, followed by 2-3 bullet points of potential attack vectors or exploit chains the tester should try next. Use Markdown formatting.

Findings:
{json.dumps(payload)}

Infrastructure:
{json.dumps(tech_payload)}\"\"\"

    try:
        response = await client.chat.completions.create(
            model=resolved_model, messages=[{"role": "user", "content": prompt}],
            temperature=temp, top_p=top_p, extra_body={"top_k": top_k, "min_p": min_p},
            timeout=120.0, stream=True
        )
        full_text = ""
        async for chunk in response:
            content = chunk.choices[0].delta.content
            if content:
                full_text += content
                await ws_manager.broadcast(f"[AI_STREAM]{content}")
        return full_text
    except Exception as e:
        return f"AI Assessment failed: {e}\""""

content = content.replace(old_generate, new_generate)

# Modify analyze_findings_with_ai
import re
new_analyze = """import asyncio

async def analyze_findings_with_ai(findings: List[Finding], api_url, api_key, model_name, temp, top_k, top_p, min_p) -> List[Finding]:
    if not findings: return findings
    unique_findings = list({ (f.type, f.value): f for f in findings }.values())
    
    resolved_url = api_url.strip() if api_url else os.getenv("LLAMA_API_URL", "")
    resolved_model = model_name.strip() if model_name else os.getenv("AI_MODEL_NAME", "")
    resolved_key = api_key.strip() if api_key else "local-only"

    if not resolved_url or not resolved_model:
        await ws_manager.broadcast("[*] Running in Non-AI Mode. Returning deterministic findings.")
        return unique_findings

    def is_junk(f: Finding):
        v = str(f.value).lower()
        if f.type == "Open Port" and v.split(":")[-1] in ["80", "443"]: return True
        if f.type == "Directory":
            if any(ext in v for ext in [".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".gif"]): return True
            if any(p in v for p in ["/images", "/css", "/assets", "/fonts", "/js"]): return True
        return False

    items_to_process = [f for f in unique_findings if not is_junk(f)][:750]
    
    if len(items_to_process) < len(unique_findings):
        await ws_manager.broadcast(f"[*] Junk Filter: Ignored {len(unique_findings) - len(items_to_process)} standard findings to save AI tokens.")

    client = AsyncOpenAI(api_key=resolved_key, base_url=resolved_url)
    
    from app.services.recon import target_domain, WORKSPACE_DIR
    import json
    
    for i in range(0, len(items_to_process), 50):
        batch = items_to_process[i:i + 50]
        payload = [{"type": f.type, "value": f.value, "severity": f.severity} for f in batch]
        
        prompt = f\"\"\"You are a Lead Bug Bounty Triage Analyst. Evaluate these raw recon findings.
Nuclei findings already have accurate severities—do NOT change them. 
For all other findings, you MUST apply Context-Aware Heuristics:
1. Subdomain Context: A finding on 'dev.', 'staging.', or 'admin.' is higher severity than 'www.'.
2. Port Context: Port 80/443 is Info. Exposed databases (3306, 5432), management ports (22, 2082), or weird high ports should be Medium/High.
3. File/Directory Context: Generic paths (images, css) are Info. Exposure of source code (.git), environment variables (.env), config files, or admin panels are High/Critical.
4. Katana/WhatWeb Context: General framework fingerprints are Info. 

CRITICAL INSTRUCTIONS:
- Return ONLY a valid JSON array.
- DO NOT assume protocols based on path names (e.g., an HTTP directory named '/ftp' is just a web directory, do NOT invent anonymous FTP login attacks). Evaluate the literal HTTP risk.
- DO NOT hallucinate vulnerabilities not explicitly proven by the tools.
- DO NOT format values as Markdown links. Keep the exact original 'type' and 'value' strings.
- Modify ONLY the 'severity' field to (Info, Low, Medium, High, Critical).

Format: [{{"type": "...", "value": "...", "severity": "..."}}]
Findings:
{json.dumps(payload)}\"\"\"

        try:
            await ws_manager.broadcast(f"[*] Processing AI Batch {i//50 + 1} ({len(batch)} findings)...")
            response = await client.chat.completions.create(
                model=resolved_model, messages=[{"role": "user", "content": prompt}],
                temperature=temp, top_p=top_p, extra_body={"top_k": top_k, "min_p": min_p},
                timeout=120.0
            )
            ai_text = response.choices[0].message.content or "[]"
            parsed_data = extract_json(ai_text)
            if parsed_data is None: parsed_data = []
            if isinstance(parsed_data, dict): parsed_data = parsed_data.get("findings", parsed_data.get("results", []))
            if parsed_data is None: parsed_data = []
            severity_map = { (item.get("type"), item.get("value")): item.get("severity", "Unknown") for item in parsed_data if isinstance(item, dict) }
            for f in batch:
                mapped = severity_map.get((f.type, f.value))
                if mapped in ["Info", "Low", "Medium", "High", "Critical"]:
                    if not f.type.startswith("Nuclei:"): f.severity = mapped
            
            # Send batch update
            await ws_manager.broadcast("[HUNT:BATCH_COMPLETED]")
            await asyncio.sleep(5)
            
        except Exception as e:
            await ws_manager.broadcast(f"[!] AI enrichment failed: {e}")
            await asyncio.sleep(5)
    return unique_findings"""

# Regex replace analyze_findings_with_ai block
content = re.sub(r'async def analyze_findings_with_ai.*?return unique_findings', new_analyze, content, flags=re.DOTALL)
if "import asyncio" not in content[:500]:
    content = "import asyncio\n" + content

parser_path.write_text(content)


# 2. Update recon.py
recon_path = Path("/home/hollowedtemplar/sentinel/backend/app/services/recon.py")
content = recon_path.read_text()

old_recon_end = """    enriched = await analyze_findings_with_ai(raw_findings, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    ai_assessment = await generate_ai_assessment(enriched, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    final_output = {"target": target_domain, "stage": "completed", "technologies": [t.model_dump() for t in tech_findings], "findings": [f.model_dump() for f in enriched], "ai_analysis": ai_assessment}
    (WORKSPACE_DIR / "final_report.json").write_text(json.dumps(final_output, indent=2))
    
    await ws_manager.broadcast("[+] Pipeline execution successful.")
    await ws_manager.broadcast("[SENTINEL:COMPLETED]")"""

new_recon_end = """    enriched = await analyze_findings_with_ai(raw_findings, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    
    # Save triage output before AI assessment
    final_output = {"target": target_domain, "stage": "completed", "technologies": [t.model_dump() for t in tech_findings], "findings": [f.model_dump() for f in enriched], "ai_analysis": ""}
    (WORKSPACE_DIR / "final_report.json").write_text(json.dumps(final_output, indent=2))
    
    await ws_manager.broadcast("[+] Pipeline execution successful.")
    await ws_manager.broadcast("[HUNT:COMPLETED]")
    
    ai_assessment = await generate_ai_assessment(enriched, tech_findings, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    final_output["ai_analysis"] = ai_assessment
    (WORKSPACE_DIR / "final_report.json").write_text(json.dumps(final_output, indent=2))"""

content = content.replace(old_recon_end, new_recon_end)
recon_path.write_text(content)


# 3. Update App.jsx
app_path = Path("/home/hollowedtemplar/sentinel/frontend/src/App.jsx")
content = app_path.read_text()

old_ws = """      if (msg === "[SENTINEL:COMPLETED]") {
        try {
          const res = await fetch('http://localhost:8000/results')
          const data = await res.json()
          if (data.stage === 'completed') {
            setFindings(data.findings || [])
            setTechnologies(data.technologies || [])
            setAiAnalysis(data.ai_analysis || '')
            setStatus('completed')
            setProgress({ percent: 100, label: 'Scan Complete' })
          }
        } catch (err) {
          setStatus('error')
          setErrorMsg('Failed to fetch final results.')
        }
        return
      }"""

new_ws = """      if (msg === "[HUNT:COMPLETED]") {
        try {
          const res = await fetch('http://localhost:8000/results')
          const data = await res.json()
          if (data.stage === 'completed') {
            setFindings(data.findings || [])
            setTechnologies(data.technologies || [])
            setAiAnalysis(data.ai_analysis || '')
            setStatus('completed')
            setProgress({ percent: 100, label: 'Scan Complete' })
          }
        } catch (err) {
          setStatus('error')
          setErrorMsg('Failed to fetch final results.')
        }
        return
      }
      
      if (msg === "[HUNT:BATCH_COMPLETED]") {
        try {
          const res = await fetch('http://localhost:8000/results')
          const data = await res.json()
          if (data.findings) setFindings(data.findings)
          if (data.technologies) setTechnologies(data.technologies)
        } catch (err) {}
        return
      }

      if (msg.startsWith("[AI_STREAM]")) {
        setAiAnalysis(prev => prev + msg.replace("[AI_STREAM]", ""))
        return
      }"""

content = content.replace(old_ws, new_ws)
app_path.write_text(content)

print("Patch applied.")
