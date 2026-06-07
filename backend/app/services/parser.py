import os, json, re
from pathlib import Path
from typing import List
from pydantic import BaseModel
from openai import AsyncOpenAI
from app.core.executor import ws_manager

WORKSPACE_DIR = Path("/workspace")
class Finding(BaseModel): type: str; value: str; severity: str = "Info"
class TechFinding(BaseModel): technology: str; location: str; category: str; evidence: str

def _safe_read_json(file_path: Path):
    if not file_path.exists(): return []
    try:
        raw = file_path.read_text(encoding='utf-8', errors='replace').strip()
        if not raw: return []
        return json.loads(raw)
    except json.JSONDecodeError:
        results = []
        for line in raw.splitlines():
            line = line.strip()
            if not line: continue
            try: results.append(json.loads(line))
            except: continue
        return results

def parse_ports() -> List[Finding]:
    return [Finding(type="Open Port", value=l.strip(), severity="Info") for l in (WORKSPACE_DIR / "ports.txt").read_text(errors="ignore").splitlines() if ":" in l] if (WORKSPACE_DIR / "ports.txt").exists() else []

def parse_ffuf() -> List[Finding]:
    return [Finding(type="Directory", value=e.get("url") or e.get("input",{}).get("FUZZ") or "", severity="Low") for e in (_safe_read_json(WORKSPACE_DIR / "ffuf.json").get("results", []) if isinstance(_safe_read_json(WORKSPACE_DIR / "ffuf.json"), dict) else [])]

def parse_whatweb() -> List[TechFinding]:
    data = _safe_read_json(WORKSPACE_DIR / "whatweb.json")
    if isinstance(data, dict): data = [data]
    techs = [TechFinding(technology=", ".join(list(e.get('plugins',{}).keys())[:5]), location=e.get('target',''), category="WhatWeb Fingerprint", evidence="") for e in data if e.get("target")]
    return list({(t.technology, t.location): t for t in techs}.values())

def parse_katana() -> List[Finding]:
    data = _safe_read_json(WORKSPACE_DIR / "katana.json")
    if isinstance(data, dict): data = [data]
    findings = [Finding(type="Endpoint", value=o.get("request",{}).get("endpoint") or o.get("endpoint") or "", severity="Info") for o in data if o.get("request",{}).get("endpoint") or o.get("endpoint")]
    return list({(f.type, f.value): f for f in findings}.values())

def parse_dalfox() -> List[Finding]:
    data = _safe_read_json(WORKSPACE_DIR / "dalfox.json")
    if isinstance(data, dict): data = [data]
    findings = []
    for o in data:
        if o.get("type") in ["V", "G", "S"] or o.get("poc"):
            url = o.get("data") or o.get("url") or o.get("poc") or ""
            if url: findings.append(Finding(type="XSS", value=url, severity="High"))
    return list({(f.type, f.value): f for f in findings}.values())

def parse_nuclei() -> tuple[List[Finding], List[TechFinding]]:
    data = _safe_read_json(WORKSPACE_DIR / "nuclei.json")
    if isinstance(data, dict): data = [data]
    if (WORKSPACE_DIR / "nucleidast.json").exists():
        dast_data = _safe_read_json(WORKSPACE_DIR / "nucleidast.json")
        if isinstance(dast_data, list): data.extend(dast_data)
        elif isinstance(dast_data, dict): data.append(dast_data)
    findings = []
    techs = []
    for o in data:
        if not (o.get("matched-at") or o.get("host")): continue
        info = o.get("info", {})
        severity = info.get("severity", "info").capitalize()
        tags = [t.lower() for t in info.get("tags", [])] if isinstance(info.get("tags"), list) else []
        if any(t in tags for t in ["tech", "technology", "fingerprint", "osint"]):
            techs.append(TechFinding(technology=info.get("name","Unknown"), location=o.get("matched-at") or o.get("host", ""), category="Nuclei Fingerprint", evidence=""))
        else:
            findings.append(Finding(type=f"Nuclei: {info.get('name','Unknown')}", value=o.get("matched-at") or o.get("host", ""), severity=severity))
    unique_techs = list({(t.technology, t.location): t for t in techs}.values())
    return findings, unique_techs

def extract_json(text: str) -> list:
    try: return json.loads(text)
    except: pass
    match = re.search(r'```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try: return json.loads(match.group(1))
        except: pass
    start, end = text.find('['), text.rfind(']')
    if start != -1 and end != -1:
        try: return json.loads(text[start:end+1])
        except: pass
    return []

async def generate_ai_assessment(findings: List[Finding], api_url, api_key, model_name, temp, top_k, top_p, min_p) -> str:
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
    prompt = f"""You are a Red Team Lead. Based on these recon findings, write a 2-3 paragraph Executive Summary of the attack surface, followed by 2-3 bullet points of potential attack vectors or exploit chains the tester should try next. Use Markdown formatting.

Findings:
{json.dumps(payload)}"""

    try:
        response = await client.chat.completions.create(
            model=resolved_model, messages=[{"role": "user", "content": prompt}],
            temperature=temp, top_p=top_p, extra_body={"top_k": top_k, "min_p": min_p}
        )
        return response.choices[0].message.content or "No response from AI."
    except Exception as e:
        return f"AI Assessment failed: {e}"

async def analyze_findings_with_ai(findings: List[Finding], api_url, api_key, model_name, temp, top_k, top_p, min_p) -> List[Finding]:
    if not findings: return findings
    unique_findings = list({ (f.type, f.value): f for f in findings }.values())
    
    resolved_url = api_url.strip() if api_url else os.getenv("LLAMA_API_URL", "")
    resolved_model = model_name.strip() if model_name else os.getenv("AI_MODEL_NAME", "")
    resolved_key = api_key.strip() if api_key else "local-only"

    if not resolved_url or not resolved_model:
        await ws_manager.broadcast("[*] Running in Non-AI Mode. Returning deterministic findings.")
        return unique_findings

    if len(unique_findings) > 500: await ws_manager.broadcast(f"[!] Warning: Truncating {len(unique_findings)} findings to top 500 for AI context limit.")
    
    items_to_process = unique_findings[:500]
    client = AsyncOpenAI(api_key=resolved_key, base_url=resolved_url)
    
    for i in range(0, len(items_to_process), 100):
        batch = items_to_process[i:i + 100]
        payload = [{"type": f.type, "value": f.value, "severity": f.severity} for f in batch]
        
        # Gemma 4's Fix: Strict Markdown Prohibition
        prompt = f"""You are a Lead Bug Bounty Triage Analyst. Evaluate these raw recon findings.
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
{json.dumps(payload)}"""

        try:
            await ws_manager.broadcast(f"[*] Processing AI Batch {i//100 + 1} ({len(batch)} findings)...")
            response = await client.chat.completions.create(
                model=resolved_model, messages=[{"role": "user", "content": prompt}],
                temperature=temp, top_p=top_p, extra_body={"top_k": top_k, "min_p": min_p}
            )
            ai_text = response.choices[0].message.content or "[]"
            parsed_data = extract_json(ai_text)
            if isinstance(parsed_data, dict): parsed_data = parsed_data.get("findings", parsed_data.get("results", []))
            severity_map = { (item.get("type"), item.get("value")): item.get("severity", "Unknown") for item in parsed_data if isinstance(item, dict) }
            for f in batch:
                mapped = severity_map.get((f.type, f.value))
                if mapped in ["Info", "Low", "Medium", "High", "Critical"]:
                    if not f.type.startswith("Nuclei:"): f.severity = mapped
        except Exception as e:
            await ws_manager.broadcast(f"[!] AI enrichment failed: {e}")
    return unique_findings
