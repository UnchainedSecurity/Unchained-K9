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

    await ws_manager.broadcast("[PROGRESS] 4/5: Vulnerability Scanning")
    if toggles.get("run_nuclei", True) and alive_file.exists() and alive_file.stat().st_size > 0:
        nuclei_cmd = ["/usr/local/bin/nuclei", "-l", str(alive_file), "-j", "-o", str(WORKSPACE_DIR / "nuclei.json"), "-c", safe_threads, "-stats"]
        if scan_depth == "Sniper": nuclei_cmd.extend(["-t", "http/cves,http/vulnerabilities", "-severity", "critical,high"])
        elif scan_depth == "Carpet Bomb": nuclei_cmd.extend(["-t", "http/misconfiguration,http/exposed-panels,http/technologies,http/cves,http/vulnerabilities"])
        else: nuclei_cmd.extend(["-t", "http/cves,http/vulnerabilities,http/exposed-panels", "-severity", "critical,high,medium"])
        
        # Inject Header into Nuclei
        nuclei_cmd.extend(["-rl", str(rate_limit)])
        nuclei_cmd.extend(h_flag)
        await run_tool(nuclei_cmd, "nuclei.log", timeout=3600)

    await ws_manager.broadcast("[PROGRESS] 5/5: Context-Aware AI Triage")
    from app.services.parser import parse_ports, parse_ffuf, parse_whatweb, parse_katana, parse_nuclei, analyze_findings_with_ai, generate_ai_assessment
    nuclei_findings, nuclei_tech = parse_nuclei()
    raw_findings = parse_ports() + parse_ffuf() + parse_katana() + nuclei_findings
    tech_findings = parse_whatweb() + nuclei_tech
    
    enriched = await analyze_findings_with_ai(raw_findings, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    ai_assessment = await generate_ai_assessment(enriched, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    final_output = {"target": target_domain, "stage": "completed", "technologies": [t.model_dump() for t in tech_findings], "findings": [f.model_dump() for f in enriched], "ai_analysis": ai_assessment}
    (WORKSPACE_DIR / "final_report.json").write_text(json.dumps(final_output, indent=2))
    
    await ws_manager.broadcast("[+] Pipeline execution successful.")
    await ws_manager.broadcast("[SENTINEL:COMPLETED]")
