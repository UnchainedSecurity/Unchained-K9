import asyncio, urllib.request, json
from pathlib import Path
from app.core.executor import run_tool, WORKSPACE_DIR, ws_manager

WORDLIST_URLS = {
    "quick": ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt"],
    "directories": ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"],
    "files": ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt"],
    "apis": ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints-res.txt", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/swagger.txt", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt"],
    "backups": ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-Backups.txt", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/backup-filenames.txt"],
    "admin_panels": ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/admin-panels.txt"],
    "cms": ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress.fuzz.txt", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/joomla.txt"],
    "infrastructure": ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Apache.fuzz.txt", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/nginx.txt"],
    "parameters": ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/BurpSuite-ParamMiner/parameter-names.txt"]
}
MERGED_WORDLIST = WORKSPACE_DIR / "merged_wordlist.txt"
VHOST_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
VHOST_WORDLIST = WORKSPACE_DIR / "vhost_wordlist.txt"

def _compile_wordlists(categories: list):
    """Download all selected wordlist categories, merge and deduplicate."""
    all_lines = set()
    for cat in categories:
        urls = WORDLIST_URLS.get(cat, [])
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=60) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')
                    for line in data.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            all_lines.add(line)
            except Exception:
                pass
    if all_lines:
        MERGED_WORDLIST.write_text("\n".join(sorted(all_lines)))
    return len(all_lines)

def _ensure_vhost_wordlist():
    if VHOST_WORDLIST.exists() and VHOST_WORDLIST.stat().st_size > 1000:
        return
    try:
        with urllib.request.urlopen(VHOST_WORDLIST_URL, timeout=30) as resp:
            VHOST_WORDLIST.write_bytes(resp.read())
    except Exception:
        pass

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

    try:
        if (WORKSPACE_DIR / "x8.json").exists():
            x8_data = (WORKSPACE_DIR / "x8.json").read_text(errors="ignore").strip()
            if x8_data:
                import json
                try:
                    o = json.loads(x8_data)
                    if isinstance(o, list):
                        for item in o:
                            url = item.get("url")
                            params = item.get("parameters", [])
                            if url and params:
                                for p in params:
                                    pname = p.get("name") if isinstance(p, dict) else str(p)
                                    if pname:
                                        sep = "&" if "?" in url else "?"
                                        process_url(f"{url}{sep}{pname}=FUZZ")
                except Exception:
                    pass
    except Exception: pass

    if params:
        (WORKSPACE_DIR / "params.txt").write_text("\n".join(params))
    return len(params)

# SAFE HARBOR PIPELINE UPDATE
async def run_pipeline(targets, threads, scan_depth, api_url, api_key, model_name, temp, top_k, top_p, min_p, wordlist_categories, custom_headers, rate_limit, toggles, proxy_url, webhook_url):
    await ws_manager.broadcast(f"[*] Initializing BlackHound K9 (Pro) Pipeline against {len(targets)} targets")
    safe_threads = str(min(int(threads), rate_limit))
    recursion_depth = int(toggles.get("recursion_depth", 0))

    # Setup the Custom Header Flags for HTTP-based tools
    h_flag = []
    for header in custom_headers:
        if header.strip():
            h_flag.extend(["-H", header.strip()])
    ww_flag = h_flag.copy()
    
    if custom_headers:
        await ws_manager.broadcast(f"[*] Safe Harbor Compliance Active: Injecting {len(custom_headers)} custom headers into all HTTP requests.")

    targets_file = WORKSPACE_DIR / "targets.txt"
    targets_file.write_text("\n".join(targets))

    await ws_manager.broadcast("[PROGRESS] 1/6: OSINT & Subdomain Discovery")
    await run_tool(["/usr/local/bin/subfinder", "-dL", str(targets_file), "-all", "-silent", "-t", safe_threads, "-rl", str(rate_limit)], "subdomains.txt", timeout=300, proxy_url=proxy_url)
    
    if toggles.get("run_harvester", True):
        for t in targets:
            await run_tool(["theHarvester", "-d", t, "-b", "crtsh,hackertarget", "-f", str(WORKSPACE_DIR / f"harvester_{t}")], f"harvester_{t}.log", timeout=300, retries=1, proxy_url=proxy_url)

    all_subs = set(targets)
    if (WORKSPACE_DIR / "subdomains.txt").exists():
        all_subs.update(line.strip().lower() for line in (WORKSPACE_DIR / "subdomains.txt").read_text().splitlines() if line.strip())
    for t in targets:
        all_subs.update(_extract_harvester_hosts(WORKSPACE_DIR / f"harvester_{t}.json"))
    
    all_subs_file = WORKSPACE_DIR / "all_subs.txt"
    all_subs_file.write_text("\n".join(sorted(all_subs)))

    await run_tool(["/usr/local/bin/dnsx", "-l", str(all_subs_file), "-silent", "-hf", "-o", str(WORKSPACE_DIR / "dns_valid.txt"), "-rl", str(rate_limit)], "dns.log", timeout=300, proxy_url=proxy_url)

    await ws_manager.broadcast("[PROGRESS] 2/6: Port Scanning & HTTP Probing")
    await run_tool(["/usr/local/bin/naabu", "-list", str(WORKSPACE_DIR / "dns_valid.txt"), "-silent", "-top-ports", "1000", "-p", "3000", "-c", safe_threads, "-rate", str(rate_limit), "-o", str(WORKSPACE_DIR / "ports.txt")], "naabu.log", timeout=600, proxy_url=proxy_url)
    
    ports_file = WORKSPACE_DIR / "ports.txt"
    if not ports_file.exists() or ports_file.stat().st_size == 0:
        await ws_manager.broadcast("[!] Naabu found no open ports (Possible Firewall). Falling back to standard web ports.")
        import shutil
        if (WORKSPACE_DIR / "dns_valid.txt").exists():
            shutil.copy(WORKSPACE_DIR / "dns_valid.txt", ports_file)

    # Inject Header into httpx
    await run_tool(["/usr/local/bin/httpx", "-l", str(ports_file), "-silent", "-threads", safe_threads, "-rl", str(rate_limit)] + h_flag, "alive.txt", timeout=300, proxy_url=proxy_url)
    alive_file = WORKSPACE_DIR / "alive.txt"

    if alive_file.exists() and alive_file.stat().st_size > 0:
        # Inject Header into WhatWeb
        await run_tool(["whatweb", "-i", str(alive_file), "--log-json", str(WORKSPACE_DIR / "whatweb.json")] + ww_flag, "whatweb.log", timeout=300, proxy_url=proxy_url)
        
        # WAF Detection
        await ws_manager.broadcast("[*] Running WAF Detection with wafw00f...")
        await run_tool(["wafw00f", "-i", str(alive_file), "-f", "json", "-o", str(WORKSPACE_DIR / "waf.json")], "wafw00f.log", timeout=300, proxy_url=proxy_url)

    await ws_manager.broadcast("[PROGRESS] 3/6: Crawling & Directory Fuzzing")
    if toggles.get("run_gau", True):
        await run_tool(["/usr/local/bin/gau", "--o", str(WORKSPACE_DIR / "gau.txt"), "--threads", safe_threads] + targets, "gau.log", timeout=300, proxy_url=proxy_url)
    if toggles.get("run_katana", True) and alive_file.exists() and alive_file.stat().st_size > 0:
        # Inject Header into Katana
        await run_tool(["/usr/local/bin/katana", "-list", str(alive_file), "-jc", "-o", str(WORKSPACE_DIR / "katana.json"), "-c", safe_threads, "-rl", str(rate_limit)] + h_flag, "katana.log", timeout=600, proxy_url=proxy_url)

    # Compile merged wordlist from selected categories
    if isinstance(wordlist_categories, list) and len(wordlist_categories) > 0:
        await ws_manager.broadcast(f"[*] Payload Compiler: Merging {len(wordlist_categories)} wordlist categories...")
        total_words = await asyncio.to_thread(_compile_wordlists, wordlist_categories)
        await ws_manager.broadcast(f"[+] Payload Compiler: {total_words} unique words compiled into merged_wordlist.txt.")
    else:
        # Fallback: download quickhits if nothing selected
        await ws_manager.broadcast("[*] No wordlist categories selected. Using quickhits as fallback.")
        await asyncio.to_thread(_compile_wordlists, ["quick"])

    wordlist_file = MERGED_WORDLIST

    # VHost Discovery
    if toggles.get("run_vhost", False) and alive_file.exists() and alive_file.stat().st_size > 0:
        await ws_manager.broadcast("[PROGRESS] 3.3: VHost Discovery")
        await asyncio.to_thread(_ensure_vhost_wordlist)
        for t in targets:
            vhost_cmd = [
                "/usr/local/bin/ffuf", "-w", str(VHOST_WORDLIST) + ":FUZZ",
                "-u", f"http://{t}",
                "-H", f"Host: FUZZ.{t}",
                "-ac", "-s", "-t", safe_threads,
                "-of", "json", "-o", str(WORKSPACE_DIR / f"vhost_{t}.json")
            ] + h_flag
            if rate_limit < 100:
                vhost_cmd.extend(["-p", str(round(1.0 / rate_limit, 3))])
            await run_tool(vhost_cmd, f"vhost_{t}.log", timeout=900, proxy_url=proxy_url)

    # Directory Fuzzing
    if alive_file.exists() and alive_file.stat().st_size > 0 and wordlist_file.exists():
        # Inject Header into Ffuf
        ffuf_cmd = [
            "/usr/local/bin/ffuf", "-w", f"{alive_file}:URL", "-w", f"{wordlist_file}:FUZZ",
            "-u", "URL/FUZZ", "-mc", "200,204,401,403", "-ac", "-s", "-t", safe_threads,
            "-of", "json", "-o", str(WORKSPACE_DIR / "ffuf.json")
        ] + h_flag
        if rate_limit < 100: ffuf_cmd.extend(["-p", str(round(1.0 / rate_limit, 3))])
        if recursion_depth > 0:
            ffuf_cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])
            await ws_manager.broadcast(f"[*] Recursive Fuzzing enabled: depth={recursion_depth}")
        await run_tool(ffuf_cmd, "ffuf.log", timeout=14400, proxy_url=proxy_url)

    # Hidden Parameter Discovery (x8)
    if "parameters" in wordlist_categories and alive_file.exists() and wordlist_file.exists():
        await ws_manager.broadcast("[PROGRESS] 3.5: Hidden Parameter Discovery (x8)")
        x8_targets_file = WORKSPACE_DIR / "x8_targets.txt"
        
        # Extract base URLs from gau and katana without params for x8
        x8_urls = set()
        try:
            if (WORKSPACE_DIR / "gau.txt").exists():
                for line in (WORKSPACE_DIR / "gau.txt").read_text(errors="ignore").splitlines():
                    if "?" in line: line = line.split("?")[0]
                    x8_urls.add(line.strip())
            if (WORKSPACE_DIR / "katana.json").exists():
                for line in (WORKSPACE_DIR / "katana.json").read_text(errors="ignore").splitlines():
                    try:
                        o = json.loads(line)
                        ep = o.get("request", {}).get("endpoint") or o.get("endpoint")
                        if ep:
                            if "?" in ep: ep = ep.split("?")[0]
                            x8_urls.add(ep.strip())
                    except: pass
        except: pass
        
        if x8_urls:
            x8_targets_file.write_text("\n".join(x8_urls))
            x8_cmd = ["/usr/local/bin/x8", "-u", str(x8_targets_file), "-w", str(wordlist_file), "-O", "json", "-o", str(WORKSPACE_DIR / "x8.json"), "-W", safe_threads]
            await run_tool(x8_cmd, "x8.log", timeout=3600, proxy_url=proxy_url)

    unique_param_count = await asyncio.to_thread(_extract_params)
    await ws_manager.broadcast("[PROGRESS] 4/6: Active DAST Fuzzing")
    await ws_manager.broadcast(f"[*] DAST Deduplication: Reduced raw URLs down to {unique_param_count} unique parameter signatures.")
    params_file = WORKSPACE_DIR / "params.txt"
    if toggles.get("run_dalfox", False) and params_file.exists() and params_file.stat().st_size > 0:
        dalfox_cmd = ["/usr/local/bin/dalfox", "file", str(params_file), "-b", "skip-bav", "--silence", "--format", "json", "--mining-dict=false", "-o", str(WORKSPACE_DIR / "dalfox.json")]
        if custom_headers: dalfox_cmd.extend(h_flag)
        await run_tool(dalfox_cmd, "dalfox.log", timeout=14400, proxy_url=proxy_url)
    
    if toggles.get("run_nucleidast", False) and params_file.exists() and params_file.stat().st_size > 0:
        nucleidast_cmd = ["/usr/local/bin/nuclei", "-l", str(params_file), "-tags", "sqli,redirect,fuzz", "-j", "-o", str(WORKSPACE_DIR / "nucleidast.json"), "-c", safe_threads, "-rl", str(rate_limit), "-mhe", "100", "-timeout", "10"]
        nucleidast_cmd.extend(h_flag)
        await run_tool(nucleidast_cmd, "nucleidast.log", timeout=7200, proxy_url=proxy_url)

    await ws_manager.broadcast("[PROGRESS] 5/6: Vulnerability Scanning")
    if toggles.get("run_nuclei", True) and alive_file.exists() and alive_file.stat().st_size > 0:
        nuclei_cmd = ["/usr/local/bin/nuclei", "-l", str(alive_file), "-j", "-o", str(WORKSPACE_DIR / "nuclei.json"), "-c", safe_threads, "-stats"]
        if scan_depth == "Sniper": nuclei_cmd.extend(["-t", "http/cves,http/vulnerabilities", "-severity", "critical,high"])
        elif scan_depth == "Carpet Bomb": nuclei_cmd.extend(["-t", "http/misconfiguration,http/exposed-panels,http/technologies,http/cves,http/vulnerabilities"])
        else: nuclei_cmd.extend(["-t", "http/cves,http/vulnerabilities,http/exposed-panels", "-severity", "critical,high,medium"])
        
        # Inject Header into Nuclei
        nuclei_cmd.extend(["-rl", str(rate_limit)])
        nuclei_cmd.extend(["-mhe", "100", "-timeout", "10"])
        nuclei_cmd.extend(h_flag)
        await run_tool(nuclei_cmd, "nuclei.log", timeout=14400, proxy_url=proxy_url)

    await ws_manager.broadcast("[PROGRESS] 6/6: Context-Aware AI Triage")
    from app.services.parser import parse_ports, parse_ffuf, parse_vhost, parse_whatweb, parse_katana, parse_nuclei, parse_dalfox, parse_wafw00f, analyze_findings_with_ai, generate_ai_assessment
    nuclei_findings, nuclei_tech = parse_nuclei()
    
    # We pass targets list to parse_vhost to load vhost_{t}.json
    raw_findings = parse_ports() + parse_ffuf() + parse_vhost(targets) + parse_katana() + parse_dalfox() + nuclei_findings
    tech_findings = parse_whatweb() + parse_wafw00f() + nuclei_tech
    
    enriched = await analyze_findings_with_ai(raw_findings, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    
    # Save triage output before AI assessment
    final_output = {"target": ", ".join(targets), "stage": "completed", "technologies": [t.model_dump() for t in tech_findings], "findings": [f.model_dump() for f in enriched], "ai_analysis": ""}
    (WORKSPACE_DIR / "final_report.json").write_text(json.dumps(final_output, indent=2))
    
    await ws_manager.broadcast("[+] Pipeline execution successful.")
    await ws_manager.broadcast("[HUNT:COMPLETED]")
    
    ai_assessment = await generate_ai_assessment(enriched, tech_findings, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    final_output["ai_analysis"] = ai_assessment
    (WORKSPACE_DIR / "final_report.json").write_text(json.dumps(final_output, indent=2))

    if webhook_url:
        try:
            req = urllib.request.Request(webhook_url, method="POST", headers={"Content-Type": "application/json"})
            summary = f"**BlackHound K9 Scan Completed**\nTargets: {len(targets)}\nVulnerabilities Found: {len(enriched)}"
            urllib.request.urlopen(req, data=json.dumps({"content": summary}).encode("utf-8"), timeout=10)
        except Exception as e:
            await ws_manager.broadcast(f"[!] Failed to send webhook: {e}")
