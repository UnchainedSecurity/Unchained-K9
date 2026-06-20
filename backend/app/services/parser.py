import asyncio
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
    findings = []
    data = _safe_read_json(WORKSPACE_DIR / "ffuf.json")
    results = data.get("results", []) if isinstance(data, dict) else []
    for e in results:
        url = e.get("url") or e.get("input", {}).get("FUZZ") or ""
        status = e.get("status", "Unknown")
        if url:
            content_type = e.get("content-type", "").lower()
            filename = url.split("?")[0].split("/")[-1]
            
            if url.endswith("/") or not filename:
                type_str = f"Directory [HTTP {status}]"
            elif "." in filename or filename.isupper() or "text/plain" in content_type:
                type_str = f"File [HTTP {status}]"
            elif "application/json" in content_type:
                type_str = f"API Endpoint [HTTP {status}]"
            else:
                type_str = f"Discovered Path [HTTP {status}]"
                
            findings.append(Finding(type=type_str, value=url, severity="Low"))
    return findings

def parse_vhost(targets: List[str]) -> List[Finding]:
    findings = []
    for t in targets:
        data = _safe_read_json(WORKSPACE_DIR / f"vhost_{t}.json")
        if isinstance(data, dict):
            results = data.get("results", [])
        elif isinstance(data, list):
            results = data
        else:
            results = []
        for e in results:
            fuzz_val = e.get("input", {}).get("FUZZ", "")
            if fuzz_val:
                findings.append(Finding(type="VHost", value=f"{fuzz_val}.{t}", severity="Medium"))
    return list({(f.type, f.value): f for f in findings}.values())

def parse_whatweb() -> List[TechFinding]:
    data = _safe_read_json(WORKSPACE_DIR / "whatweb.json")
    if isinstance(data, dict): data = [data]
    techs = [TechFinding(technology=", ".join(list(e.get('plugins',{}).keys())[:5]), location=e.get('target',''), category="WhatWeb Fingerprint", evidence="") for e in data if e.get("target")]
    return list({(t.technology, t.location): t for t in techs}.values())

def parse_katana() -> List[Finding]:
    if not (WORKSPACE_DIR / "katana.txt").exists(): return []
    findings = []
    for line in (WORKSPACE_DIR / "katana.txt").read_text(errors="ignore").splitlines():
        ep = line.strip()
        if ep: findings.append(Finding(type="Endpoint", value=ep, severity="Info"))
    return list({(f.type, f.value): f for f in findings}.values())

def parse_wafw00f() -> List[TechFinding]:
    data = _safe_read_json(WORKSPACE_DIR / "waf.json")
    if isinstance(data, dict): data = [data]
    techs = []
    for e in data:
        if e.get("detected"):
            waf_name = e.get("firewall") or "Unknown WAF"
            url = e.get("url") or ""
            techs.append(TechFinding(technology=waf_name, location=url, category="WAF", evidence="wafw00f"))
    return list({(t.technology, t.location): t for t in techs}.values())

def parse_favicon() -> List[TechFinding]:
    data = _safe_read_json(WORKSPACE_DIR / "favicon.json")
    if isinstance(data, dict): data = [data]
    techs = []
    for e in data:
        if e.get("technology"):
            techs.append(TechFinding(**e))
    return techs

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
        
    if (WORKSPACE_DIR / "nuclei_js.json").exists():
        js_data = _safe_read_json(WORKSPACE_DIR / "nuclei_js.json")
        if isinstance(js_data, list): data.extend(js_data)
        elif isinstance(js_data, dict): data.append(js_data)
        
    if (WORKSPACE_DIR / "nuclei_cloud.json").exists():
        cloud_data = _safe_read_json(WORKSPACE_DIR / "nuclei_cloud.json")
        if isinstance(cloud_data, list): data.extend(cloud_data)
        elif isinstance(cloud_data, dict): data.append(cloud_data)
        
    findings = []
    techs = []
    for o in data:
        if not (o.get("matched-at") or o.get("host")): continue
        info = o.get("info", {})
        severity = info.get("severity", "info").capitalize()
        tags = [t.lower() for t in info.get("tags", [])] if isinstance(info.get("tags"), list) else []
        
        name = info.get('name','Unknown')
        extracted = str(o.get('extracted-results', []))
        
        # JS Secret Noise Reduction
        search_str = (name + " " + extracted).lower()
        if any(k in search_str for k in ["public", "pk_live", "recaptcha", "google-maps", "firebase"]):
            if any(t in tags for t in ["exposure", "token"]) or ".js" in str(o.get("matched-at", "")):
                severity = "Info"
                
        if any(t in tags for t in ["tech", "technology", "fingerprint", "osint"]):
            techs.append(TechFinding(technology=name, location=o.get("matched-at") or o.get("host", ""), category="Nuclei Fingerprint", evidence=""))
        else:
            findings.append(Finding(type=f"Nuclei: {name}", value=o.get("matched-at") or o.get("host", ""), severity=severity))
    unique_techs = list({(t.technology, t.location): t for t in techs}.values())
    return findings, unique_techs

def extract_json(text: str) -> list:
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    
    try: 
        res = json.loads(text)
        return res if res is not None else []
    except: pass
    
    match = re.search(r'```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try: 
            res = json.loads(match.group(1))
            return res if res is not None else []
        except: pass
        
    start_brace, end_brace = text.find('{'), text.rfind('}')
    start_bracket, end_bracket = text.find('['), text.rfind(']')
    
    if start_brace != -1 and end_brace != -1 and start_brace < end_brace:
        try:
            res = json.loads(text[start_brace:end_brace+1])
            return res if res is not None else []
        except: pass
        
    if start_bracket != -1 and end_bracket != -1 and start_bracket < end_bracket:
        try:
            res = json.loads(text[start_bracket:end_bracket+1])
            return res if res is not None else []
        except: pass
        
    return []

async def generate_ai_assessment(findings: List[Finding], tech_findings: List[TechFinding], api_url, api_key, model_name, temp, top_k, top_p, min_p) -> str:
    resolved_url = api_url.strip() if api_url else os.getenv("LLAMA_API_URL", "")
    resolved_model = model_name.strip() if model_name else os.getenv("AI_MODEL_NAME", "")
    resolved_key = api_key.strip() if api_key else "local-only"

    if not resolved_url or not resolved_model:
        return "AI Assessment disabled (Non-AI Mode)."

    filtered = [f for f in findings if f.severity in ["Critical", "High", "Medium"]]
    if not filtered:
        filtered = [f for f in findings if f.severity in ["Low", "Info"]][:100]
        if not filtered and not tech_findings:
            return "No findings or infrastructure data to analyze."

    client = AsyncOpenAI(api_key=resolved_key, base_url=resolved_url)
    
    payload = [{"type": f.type, "value": f.value, "severity": f.severity} for f in filtered[:200]]
    tech_payload = [{"technology": t.technology, "location": t.location} for t in tech_findings[:50]]
    
    prompt = f"""Based on these recon findings and the infrastructure profile, write a 2-3 paragraph Executive Summary of the attack surface, a summary of the infrastructure profile based on your interpretation of the findings, followed by 2-3 bullet points of potential attack vectors or exploit chains the tester should try next. Use Markdown formatting.

Findings:
{json.dumps(payload)}

Infrastructure:
{json.dumps(tech_payload)}"""

    try:
        response = await client.chat.completions.create(
            model=resolved_model, 
            messages=[
                {"role": "system", "content": "You are a Red Team Lead. You must provide your analysis in Markdown formatting."},
                {"role": "user", "content": prompt}
            ],
            temperature=temp, top_p=top_p, extra_body={"top_k": top_k, "min_p": min_p},
            timeout=900.0, stream=True
        )
        full_text = ""
        async for chunk in response:
            content = chunk.choices[0].delta.content
            if content:
                full_text += content
                await ws_manager.broadcast(f"[AI_STREAM]{content}")
        return full_text
    except Exception as e:
        return f"AI Assessment failed: {e}"

import asyncio

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
        if "[FP]" in f.type: return True
        v = str(f.value).lower()
        if f.type == "Open Port" and v.split(":")[-1] in ["80", "443"]: return True
        if f.type == "Directory":
            if any(ext in v for ext in [".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".gif"]): return True
            if any(p in v for p in ["/images", "/css", "/assets", "/fonts", "/js"]): return True
        return False

    items_to_process = [f for f in unique_findings if not is_junk(f)][:1500]
    
    if len(items_to_process) < len(unique_findings):
        await ws_manager.broadcast(f"[*] Junk Filter: Ignored {len(unique_findings) - len(items_to_process)} standard findings to save AI tokens.")

    client = AsyncOpenAI(api_key=resolved_key, base_url=resolved_url)
    
    from app.services.recon import WORKSPACE_DIR
    import json
    
    for i in range(0, len(items_to_process), 25):
        batch = items_to_process[i:i + 25]
        payload = [{"type": f.type, "value": f.value, "severity": f.severity} for f in batch]
        
        prompt = f"""Evaluate these raw recon findings.
For Nuclei findings, only modify their severity if the original severity is 'Unknown' or 'Info' (e.g., triage generic token or dependency warnings based on context). 
For all findings, you MUST apply Context-Aware Heuristics:
1. Subdomain Context: A finding on 'dev.', 'staging.', or 'admin.' is higher severity than 'www.'.
2. Port Context: Port 80/443 is Info. Exposed databases (3306, 5432), management ports (22, 2082), or weird high ports should be Medium/High.
3. File/Directory/Path Context: Generic paths (images, css, standard chunks) are Info. Sensitive files or directories (like '.env', '.git', '/ftp', '/metrics', '/backup', '/admin') that are accessible (e.g., [HTTP 200]) should be Medium/High/Critical. If the Type indicates [HTTP 401], [HTTP 403], or [HTTP 404], the server is blocking access, so you MUST downgrade it to Low or Info.
4. Endpoint/API Context: Exposed API or administrative endpoints (like '/rest/admin/...', '/api/v1/users', '/wallet-web3', '/faucet') should be Medium/High. General frontend bundles or static assets are Info.
5. Token/Exposure Context: Generic token exposures found in JS or public endpoints should be triaged. If the value or context shows a potentially high-value key, private token, or mnemonic, elevate it to Medium or High. If it looks like a false positive or public token (like recaptcha), keep it as Info/Low.

CRITICAL INSTRUCTIONS:
- Return ONLY a valid JSON object.
- DO NOT assume protocols based on path names (e.g., an HTTP directory named '/ftp' is just a web directory, do NOT invent anonymous FTP login attacks). Evaluate the literal HTTP risk.
- DO NOT hallucinate vulnerabilities not explicitly proven by the tools.
- DO NOT format values as Markdown links. Keep the exact original 'type' and 'value' strings.
- Modify ONLY the 'severity' field to (Info, Low, Medium, High, Critical).

Format: {{"findings": [{{"type": "...", "value": "...", "severity": "..."}}]}}
Findings:
{json.dumps(payload)}"""

        try:
            await ws_manager.broadcast(f"[*] Processing AI Batch {i//25 + 1} ({len(batch)} findings)...")
            response = await client.chat.completions.create(
                model=resolved_model, 
                messages=[
                    {"role": "system", "content": "You are a Lead Bug Bounty Triage Analyst. You must output your results in strictly valid JSON format."},
                    {"role": "user", "content": prompt}
                ],
                temperature=temp, top_p=top_p, extra_body={"top_k": top_k, "min_p": min_p},
                timeout=900.0
            )
            
            if not response or not hasattr(response, 'choices') or not response.choices:
                raise Exception(f"Invalid API response received (Empty choices or model overload): {response}")
                
            ai_text = response.choices[0].message.content or "[]"
            parsed_data = extract_json(ai_text)
            if parsed_data is None: parsed_data = []
            if isinstance(parsed_data, dict): parsed_data = parsed_data.get("findings", parsed_data.get("results", []))
            if parsed_data is None: parsed_data = []
            severity_map = { (item.get("type"), item.get("value")): item.get("severity", "Unknown") for item in parsed_data if isinstance(item, dict) }
            for f in batch:
                mapped = severity_map.get((f.type, f.value))
                if mapped in ["Info", "Low", "Medium", "High", "Critical"]:
                    if not f.type.startswith("Nuclei:") or f.severity in ["Unknown", "Info"]:
                        f.severity = mapped
            
            # Send batch update
            await ws_manager.broadcast("[HUNT:BATCH_COMPLETED]")
            await asyncio.sleep(5)
            
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            print(f"[ERROR] AI enrichment failed:\n{tb}")
            await ws_manager.broadcast(f"[!] AI enrichment failed: {e}\n{tb}")
            await asyncio.sleep(5)
    return unique_findings

import httpx
import re
import asyncio

async def validate_high_value_findings(findings: List[Finding], custom_headers: str, proxy_url: str, rate_limit: int = 10, timeout: int = 5) -> List[Finding]:
    headers_dict = {}
    if custom_headers:
        for line in custom_headers.strip().split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers_dict[k.strip()] = v.strip()
    
    proxy_mounts = {"http://": proxy_url, "https://": proxy_url} if proxy_url else None
    
    sem = asyncio.Semaphore(max(1, rate_limit))
    
    async def validate_finding(client, f):
        if not ("Directory" in f.type or "File" in f.type or "Sensitive" in f.type or "Config" in f.type): return
        url = str(f.value)
        if not url.startswith("http"): return
        
        val_lower = url.lower()
        if not any(x in val_lower for x in [".env", ".git/config", ".htpasswd", ".ssh", "id_rsa", ".npmrc", ".aws/credentials"]): return
        
        async with sem:
            try:
                resp = await client.get(url, follow_redirects=True)
                if resp.status_code != 200: return
                
                content_type = resp.headers.get("Content-Type", "").lower()
                if "text/html" in content_type:
                    f.type += " [FP]"
                    f.severity = "Info"
                    setattr(f, 'fp_reason', "WAF/Soft 404 HTML Detected (Header)")
                    return
                
                text = resp.text
                chunk = text[:4096].lower()
                
                if "<html" in chunk or "cloudflare" in chunk or "access denied" in chunk or "incapsula" in chunk:
                    f.type += " [FP]"
                    f.severity = "Info"
                    setattr(f, 'fp_reason', "WAF/Soft 404 HTML Detected (Body)")
                    return
                
                is_fp = False
                reason = ""
                if ".env" in val_lower:
                    if not re.search(r'^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+', text, re.MULTILINE):
                        is_fp, reason = True, "Missing KEY=VALUE format"
                elif "id_rsa" in val_lower or ".ssh" in val_lower:
                    if not re.search(r'-----BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----', text):
                        is_fp, reason = True, "Missing Private Key signature"
                elif ".git/config" in val_lower:
                    if "[core]" not in text and "repositoryformatversion" not in text:
                        is_fp, reason = True, "Missing Git config signature"
                elif ".aws/credentials" in val_lower:
                    if "[default]" not in text and "aws_access_key_id" not in text:
                        is_fp, reason = True, "Missing AWS credentials signature"
                elif ".npmrc" in val_lower:
                    if "_authToken" not in text and "registry=" not in text:
                        is_fp, reason = True, "Missing .npmrc signature"
                elif ".htpasswd" in val_lower:
                    if ":" not in text:
                        is_fp, reason = True, "Missing basic auth signature"
                
                if is_fp:
                    f.type += " [FP]"
                    f.severity = "Info"
                    setattr(f, 'fp_reason', reason)
            except Exception:
                pass

    try:
        async with httpx.AsyncClient(headers=headers_dict, proxies=proxy_mounts, verify=False, timeout=timeout) as client:
            tasks = [validate_finding(client, f) for f in findings]
            await asyncio.gather(*tasks)
    except Exception:
        pass
        
    return findings
