import asyncio, urllib.request, json
from pathlib import Path
from app.core.executor import run_tool, WORKSPACE_DIR, ws_manager

WORDLISTS = {
    "common": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    "raft": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
    "big": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt"
}
WORDLIST_FILE = WORKSPACE_DIR / "wordlist.txt"

def _ensure_wordlist_sync(wordlist_key: str):
    if WORDLIST_FILE.exists() and WORDLIST_FILE.stat().st_size > 1000: return
    url = WORDLISTS.get(wordlist_key, WORDLISTS["common"])
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            WORDLIST_FILE.write_bytes(resp.read())
    except Exception: pass

def _extract_harvester_hosts(filepath: Path) -> set:
    subs = set()
    if not filepath.exists(): return subs
    try:
        data = json.loads(filepath.read_text(errors="ignore"))
        for key in ["hosts", "subdomains"]:
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, str):
                        host = item.split(":")[0].strip().lower()
                        if host: subs.add(host)
    except Exception: pass
    return subs


import urllib.parse
import re

def _extract_params():
    params = []
    seen_sigs = set()
    
    def process_url(url: str):
        if "?" not in url or "=" not in url: return
        try:
            parsed = urllib.parse.urlparse(url)
            raw_keys = urllib.parse.parse_qs(parsed.query).keys()
            
            clean_keys = []
            for k in raw_keys:
                if len(k) > 20: continue
                if not re.match(r'^[a-zA-Z0-9_\-\[\]]+$', k): continue
                clean_keys.append(k)
                
            if not clean_keys: return
            
            keys = tuple(sorted(clean_keys))
            sig = (parsed.hostname, parsed.path, keys)
            if sig not in seen_sigs:
                seen_sigs.add(sig)
                
                clean_query = urllib.parse.urlencode({k: "FUZZ" for k in keys})
                clean_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, clean_query, ""))
                params.append(clean_url)
        except Exception:
            pass

    try:
        if (WORKSPACE_DIR / "gau.txt").exists():
            for line in (WORKSPACE_DIR / "gau.txt").read_text(errors="ignore").splitlines():
                process_url(line.strip())
    except Exception: pass
    
    try:
        if (WORKSPACE_DIR / "katana.json").exists():
            for line in (WORKSPACE_DIR / "katana.json").read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line: continue
                try:
                    import json
                    o = json.loads(line)
                    endpoint = o.get("request", {}).get("endpoint") or o.get("endpoint")
                    if endpoint: process_url(endpoint)
                except Exception: pass
    except Exception: pass

    if params:
        (WORKSPACE_DIR / "params.txt").write_text("\n".join(params))
    return len(params)

# SAFE HARBOR PIPELINE UPDATE
async def run_pipeline(target_domain, threads, scan_depth, api_url, api_key, model_name, temp, top_k, top_p, min_p, wordlist_key, custom_header, rate_limit, toggles):
    await ws_manager.broadcast(f"[*] Initializing BlackHound K9 (Alpha V3.3) Pipeline against {target_domain}")
    safe_threads = str(min(int(threads), rate_limit))

    # Setup the Custom Header Flags for HTTP-based tools
    h_flag = ["-H", custom_header] if custom_header else []
    ww_flag = ["-H", custom_header] if custom_header else []
    
    if custom_header:
        await ws_manager.broadcast(f"[*] Safe Harbor Compliance Active: Injecting '{custom_header}' into all HTTP requests.")

    await ws_manager.broadcast("[PROGRESS] 1/5: OSINT & Subdomain Discovery")
    await run_tool(["/usr/local/bin/subfinder", "-d", target_domain, "-all", "-silent", "-t", safe_threads, "-rl", str(rate_limit)], "subdomains.txt", timeout=300)
    
    if toggles.get("run_harvester", True):
        await run_tool(["theHarvester", "-d", target_domain, "-b", "crtsh,hackertarget", "-f", str(WORKSPACE_DIR / "harvester")], "harvester.log", timeout=300, retries=1)

    all_subs = set()
    if (WORKSPACE_DIR / "subdomains.txt").exists():
        all_subs.update(line.strip().lower() for line in (WORKSPACE_DIR / "subdomains.txt").read_text().splitlines() if line.strip())
    all_subs.update(_extract_harvester_hosts(WORKSPACE_DIR / "harvester.json"))
    all_subs.add(target_domain)
    
    all_subs_file = WORKSPACE_DIR / "all_subs.txt"
    all_subs_file.write_text("\n".join(sorted(all_subs)))

    await run_tool(["/usr/local/bin/dnsx", "-l", str(all_subs_file), "-silent", "-o", str(WORKSPACE_DIR / "dns_valid.txt"), "-rl", str(rate_limit)], "dns.log", timeout=300)
    
    with open(WORKSPACE_DIR / "dns_valid.txt", "a") as f:
        f.write(f"\n{target_domain}")

    await ws_manager.broadcast("[PROGRESS] 2/5: Port Scanning & HTTP Probing")
    await run_tool(["/usr/local/bin/naabu", "-list", str(WORKSPACE_DIR / "dns_valid.txt"), "-silent", "-top-ports", "100", "-c", safe_threads, "-rate", str(rate_limit), "-o", str(WORKSPACE_DIR / "ports.txt")], "naabu.log", timeout=600)
    
    # Inject Header into httpx
    await run_tool(["/usr/local/bin/httpx", "-l", str(WORKSPACE_DIR / "ports.txt"), "-silent", "-threads", safe_threads, "-rl", str(rate_limit)] + h_flag, "alive.txt", timeout=300)
    alive_file = WORKSPACE_DIR / "alive.txt"

    if alive_file.exists() and alive_file.stat().st_size > 0:
        # Inject Header into WhatWeb
        await run_tool(["whatweb", "-i", str(alive_file), "--log-json", str(WORKSPACE_DIR / "whatweb.json")] + ww_flag, "whatweb.log", timeout=300)

    await ws_manager.broadcast("[PROGRESS] 3/5: Crawling & Directory Fuzzing")
    if toggles.get("run_gau", True):
        await run_tool(["/usr/local/bin/gau", target_domain, "--o", str(WORKSPACE_DIR / "gau.txt"), "--threads", safe_threads], "gau.log", timeout=300)
    if toggles.get("run_katana", True) and alive_file.exists() and alive_file.stat().st_size > 0:
        # Inject Header into Katana
        await run_tool(["/usr/local/bin/katana", "-list", str(alive_file), "-jc", "-o", str(WORKSPACE_DIR / "katana.json"), "-c", safe_threads, "-rl", str(rate_limit)] + h_flag, "katana.log", timeout=600)

    await asyncio.to_thread(_ensure_wordlist_sync, wordlist_key)
    if alive_file.exists() and alive_file.stat().st_size > 0:
        # Inject Header into Ffuf
        ffuf_cmd = [
            "/usr/local/bin/ffuf", "-w", f"{alive_file}:URL", "-w", f"{WORDLIST_FILE}:PATH",
            "-u", "URL/PATH", "-mc", "200,204,401,403", "-ac", "-s", "-t", safe_threads,
            "-of", "json", "-o", str(WORKSPACE_DIR / "ffuf.json")
        ] + h_flag
        if rate_limit < 100: ffuf_cmd.extend(["-p", str(round(1.0 / rate_limit, 3))])
        await run_tool(ffuf_cmd, "ffuf.log", timeout=900)

    unique_param_count = await asyncio.to_thread(_extract_params)
    await ws_manager.broadcast("[PROGRESS] 3.5: Active DAST Fuzzing")
    await ws_manager.broadcast(f"[*] DAST Deduplication: Reduced raw URLs down to {unique_param_count} unique parameter signatures.")
    params_file = WORKSPACE_DIR / "params.txt"
    if toggles.get("run_dalfox", False) and params_file.exists() and params_file.stat().st_size > 0:
        dalfox_cmd = ["/usr/local/bin/dalfox", "file", str(params_file), "-b", "skip-bav", "--silence", "--format", "json", "--mining-dict=false", "-o", str(WORKSPACE_DIR / "dalfox.json")]
        if custom_header: dalfox_cmd.extend(["-H", custom_header])
        await run_tool(dalfox_cmd, "dalfox.log", timeout=14400)
    
    if toggles.get("run_nucleidast", False) and params_file.exists() and params_file.stat().st_size > 0:
        nucleidast_cmd = ["/usr/local/bin/nuclei", "-l", str(params_file), "-tags", "sqli,redirect,fuzz", "-j", "-o", str(WORKSPACE_DIR / "nucleidast.json"), "-c", safe_threads, "-rl", str(rate_limit), "-mhe", "100", "-timeout", "10"]
        nucleidast_cmd.extend(h_flag)
        await run_tool(nucleidast_cmd, "nucleidast.log", timeout=7200)

    await ws_manager.broadcast("[PROGRESS] 4/5: Vulnerability Scanning")
    if toggles.get("run_nuclei", True) and alive_file.exists() and alive_file.stat().st_size > 0:
        nuclei_cmd = ["/usr/local/bin/nuclei", "-l", str(alive_file), "-j", "-o", str(WORKSPACE_DIR / "nuclei.json"), "-c", safe_threads, "-stats"]
        if scan_depth == "Sniper": nuclei_cmd.extend(["-t", "http/cves,http/vulnerabilities", "-severity", "critical,high"])
        elif scan_depth == "Carpet Bomb": nuclei_cmd.extend(["-t", "http/misconfiguration,http/exposed-panels,http/technologies,http/cves,http/vulnerabilities"])
        else: nuclei_cmd.extend(["-t", "http/cves,http/vulnerabilities,http/exposed-panels", "-severity", "critical,high,medium"])
        
        # Inject Header into Nuclei
        nuclei_cmd.extend(["-rl", str(rate_limit)])
        nuclei_cmd.extend(["-mhe", "100", "-timeout", "10"])
        nuclei_cmd.extend(h_flag)
        await run_tool(nuclei_cmd, "nuclei.log", timeout=14400)

    await ws_manager.broadcast("[PROGRESS] 5/5: Context-Aware AI Triage")
    from app.services.parser import parse_ports, parse_ffuf, parse_whatweb, parse_katana, parse_nuclei, parse_dalfox, analyze_findings_with_ai, generate_ai_assessment
    nuclei_findings, nuclei_tech = parse_nuclei()
    raw_findings = parse_ports() + parse_ffuf() + parse_katana() + parse_dalfox() + nuclei_findings
    tech_findings = parse_whatweb() + nuclei_tech
    
    enriched = await analyze_findings_with_ai(raw_findings, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    
    # Save triage output before AI assessment
    final_output = {"target": target_domain, "stage": "completed", "technologies": [t.model_dump() for t in tech_findings], "findings": [f.model_dump() for f in enriched], "ai_analysis": ""}
    (WORKSPACE_DIR / "final_report.json").write_text(json.dumps(final_output, indent=2))
    
    await ws_manager.broadcast("[+] Pipeline execution successful.")
    await ws_manager.broadcast("[HUNT:COMPLETED]")
    
    ai_assessment = await generate_ai_assessment(enriched, tech_findings, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    final_output["ai_analysis"] = ai_assessment
    (WORKSPACE_DIR / "final_report.json").write_text(json.dumps(final_output, indent=2))
