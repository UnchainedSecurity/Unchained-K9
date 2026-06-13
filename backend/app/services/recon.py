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
PARAM_WORDLIST = WORKSPACE_DIR / "param_wordlist.txt"
VHOST_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
VHOST_WORDLIST = WORKSPACE_DIR / "vhost_wordlist.txt"

def is_in_scope(domain: str, exclusions: list) -> bool:
    if not exclusions:
        return True
    domain = domain.lower().strip().rstrip('.')
    for exclusion in exclusions:
        exclusion = exclusion.lower().strip().rstrip('.')
        if not exclusion:
            continue
        if exclusion.startswith('*.'):
            base_domain = exclusion[2:]
            if domain == base_domain or domain.endswith(f'.{base_domain}'):
                return False
        else:
            if domain == exclusion:
                return False
    return True

def _compile_wordlists(categories: list):
    """Download all selected wordlist categories, merge and deduplicate."""
    all_lines = set()
    param_lines = set()
    for cat in categories:
        urls = WORDLIST_URLS.get(cat, [])
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=60) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')
                    for line in data.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if cat == "parameters":
                                param_lines.add(line)
                            else:
                                all_lines.add(line)
            except Exception:
                pass
    if all_lines:
        MERGED_WORDLIST.write_text("\n".join(sorted(all_lines)))
    if param_lines:
        PARAM_WORDLIST.write_text("\n".join(sorted(param_lines)))
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

def _extract_params(out_of_scope: list = None):
    params = []
    seen_sigs = set()
    
    def process_url(url: str):
        if "?" not in url or "=" not in url: return
        try:
            parsed = urllib.parse.urlparse(url)
            if not is_in_scope(parsed.hostname, out_of_scope): return
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
                    o = json.loads(line)
                    endpoint = o.get("request", {}).get("endpoint") or o.get("endpoint")
                    if endpoint: process_url(endpoint)
                except Exception: pass
    except Exception: pass

    try:
        if (WORKSPACE_DIR / "x8.json").exists():
            x8_data = (WORKSPACE_DIR / "x8.json").read_text(errors="ignore").strip()
            if x8_data:
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

def _generate_cloud_permutations(targets: list) -> int:
    keywords = set()
    for t in targets:
        base = t.split('.')[0]
        keywords.add(base)
    
    suffixes = ['-dev', '-staging', '-prod', '-assets', '-backup', '-public', '-private']
    cloud_urls = set()
    for k in keywords:
        for s in suffixes:
            cloud_urls.add(f"{k}{s}.s3.amazonaws.com")
            cloud_urls.add(f"{k}{s}.blob.core.windows.net")
            
    if cloud_urls:
        (WORKSPACE_DIR / "cloud_perms.txt").write_text("\n".join(sorted(cloud_urls)))
    return len(cloud_urls)

async def _fetch_and_hash_favicon(target_url: str, custom_headers: list, proxy_url: str):
    import httpx, base64, mmh3, re
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin
    from app.services.parser import TechFinding
    
    headers_dict = {}
    if custom_headers:
        for line in custom_headers:
            if ":" in line:
                k, v = line.split(":", 1)
                headers_dict[k.strip()] = v.strip()
                
    proxy_mounts = {"http://": proxy_url, "https://": proxy_url} if proxy_url else None
    
    try:
        async with httpx.AsyncClient(headers=headers_dict, proxies=proxy_mounts, verify=False, timeout=10) as client:
            resp = await client.get(target_url, follow_redirects=True)
            icon_url = None
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                icon_link = soup.find('link', rel=lambda r: r and r.lower() in ['icon', 'shortcut icon'])
                
                if icon_link and icon_link.get('href'):
                    icon_url = urljoin(str(resp.url), icon_link['href'])
                    icon_resp = await client.get(icon_url, follow_redirects=True)
                    if icon_resp.status_code != 200:
                        icon_url = None
                        
            if not icon_url:
                icon_url = urljoin(target_url, "/favicon.ico")
                icon_resp = await client.get(icon_url, follow_redirects=True)
                
            if icon_resp.status_code == 200:
                utf8_b64 = base64.b64encode(icon_resp.content).decode('utf-8')
                b64_formatted = re.sub("(.{76}|$)", "\\1\n", utf8_b64, 0, re.DOTALL)
                favicon_hash = mmh3.hash(b64_formatted)
                return TechFinding(category="Favicon Hash", technology=str(favicon_hash), location=target_url, evidence=icon_url)
    except Exception:
        pass
    return None

# SAFE HARBOR PIPELINE UPDATE
async def run_pipeline(targets, threads, scan_depth, api_url, api_key, model_name, temp, top_k, top_p, min_p, wordlist_categories, custom_headers, rate_limit, toggles, proxy_url, webhook_url, out_of_scope):
    import urllib.parse
    clean_targets = []
    for t in targets:
        t = t.strip()
        if not t: continue
        if "://" in t:
            parsed = urllib.parse.urlparse(t)
            hostname = parsed.hostname or parsed.netloc.split(":")[0]
        else:
            hostname = t.split(":")[0].split("/")[0]
        if hostname and is_in_scope(hostname, out_of_scope):
            clean_targets.append(hostname)
    targets = list(set(clean_targets))
    
    if not targets:
        await ws_manager.broadcast("[!] Pipeline aborted: All targets are out of scope.")
        return

    await ws_manager.broadcast(f"[*] Initializing Unchained K9 (Pro) Pipeline against {len(targets)} targets")
    safe_threads = str(min(int(threads), rate_limit))
    recursion_depth = int(toggles.get("recursion_depth", 0))

    if proxy_url:
        if "127.0.0.1" in proxy_url or "localhost" in proxy_url:
            proxy_url = proxy_url.replace("127.0.0.1", "host.docker.internal").replace("localhost", "host.docker.internal")
            await ws_manager.broadcast("[*] Proxy Rewrite: Adjusted localhost to host.docker.internal for Docker networking.")

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
    
    all_subs = {s for s in all_subs if is_in_scope(s, out_of_scope)}
    
    all_subs_file = WORKSPACE_DIR / "all_subs.txt"
    all_subs_file.write_text("\n".join(sorted(all_subs)))

    await run_tool(["/usr/local/bin/dnsx", "-l", str(all_subs_file), "-silent", "-hf", "-o", str(WORKSPACE_DIR / "dns_valid.txt"), "-rl", str(rate_limit)], "dns.log", timeout=300, proxy_url=proxy_url)

    if toggles.get("run_cloud_enum", False):
        await ws_manager.broadcast("[*] Running Cloud Asset Discovery...")
        await asyncio.to_thread(_generate_cloud_permutations, list(all_subs))
        
        # Merge targets into a single file for Nuclei
        cloud_targets_file = WORKSPACE_DIR / "cloud_targets.txt"
        cloud_targets_content = all_subs_file.read_text() + "\n"
        if (WORKSPACE_DIR / "cloud_perms.txt").exists():
            cloud_targets_content += (WORKSPACE_DIR / "cloud_perms.txt").read_text()
        cloud_targets_file.write_text(cloud_targets_content)
        
        cloud_cmd = ["/usr/local/bin/nuclei", "-l", str(cloud_targets_file), "-tags", "cloud,s3,bucket,azure,gcp", "-j", "-o", str(WORKSPACE_DIR / "nuclei_cloud.json"), "-c", safe_threads, "-rl", str(rate_limit)]
        cloud_cmd.extend(h_flag)
        await run_tool(cloud_cmd, "nuclei_cloud.log", timeout=1800, proxy_url=proxy_url)

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
        
        # Smart Favicon Hashing
        if toggles.get("run_favicon", True):
            await ws_manager.broadcast("[*] Running Smart Favicon Hashing...")
            sem = asyncio.Semaphore(rate_limit)
            async def bounded_fetch(url):
                async with sem:
                    u = url if url.startswith("http") else f"http://{url}"
                    return await _fetch_and_hash_favicon(u, custom_headers, proxy_url)
            favicon_tasks = [bounded_fetch(t) for t in targets]
            favicon_results = await asyncio.gather(*favicon_tasks, return_exceptions=True)
            favicon_data = [f.model_dump() for f in favicon_results if f and not isinstance(f, Exception)]
            if favicon_data:
                (WORKSPACE_DIR / "favicon.json").write_text(json.dumps(favicon_data))

        # Gowitness (Screenshot Gallery)
        if toggles.get("run_gowitness", True):
            await ws_manager.broadcast("[*] Running Gowitness (Screenshot Gallery)...")
            await run_tool(["/usr/local/bin/gowitness", "scan", "file", "-f", str(alive_file), "-s", str(WORKSPACE_DIR / "screenshots"), "--screenshot-format", "png", "-q", "--write-none"], "gowitness.log", timeout=900, proxy_url=proxy_url)

    await ws_manager.broadcast("[PROGRESS] 3/6: Crawling & Directory Fuzzing")
    if toggles.get("run_gau", True):
        await run_tool(["/usr/local/bin/gau", "--o", str(WORKSPACE_DIR / "gau.txt"), "--threads", safe_threads] + targets, "gau.log", timeout=300, proxy_url=proxy_url)
    if toggles.get("run_katana", True) and alive_file.exists() and alive_file.stat().st_size > 0:
        # Inject Header into Katana
        await run_tool(["/usr/local/bin/katana", "-list", str(alive_file), "-jc", "-j", "-o", str(WORKSPACE_DIR / "katana.json"), "-c", safe_threads, "-rl", str(rate_limit)] + h_flag, "katana.log", timeout=600, proxy_url=proxy_url)

        if toggles.get("run_js_secrets", False) and (WORKSPACE_DIR / "katana.json").exists():
            await ws_manager.broadcast("[*] Running JS Secret Hunting...")
            js_urls = set()
            for line in (WORKSPACE_DIR / "katana.json").read_text(errors="ignore").splitlines():
                try:
                    o = json.loads(line)
                    ep = o.get("request", {}).get("endpoint") or o.get("endpoint", "")
                    if ep.split("?")[0].endswith(".js"):
                        js_urls.add(ep)
                except: pass
            if js_urls:
                (WORKSPACE_DIR / "js_targets.txt").write_text("\n".join(js_urls))
                js_cmd = ["/usr/local/bin/nuclei", "-l", str(WORKSPACE_DIR / "js_targets.txt"), "-tags", "exposure,token", "-j", "-o", str(WORKSPACE_DIR / "nuclei_js.json"), "-c", safe_threads, "-rl", str(rate_limit)]
                js_cmd.extend(h_flag)
                await run_tool(js_cmd, "nuclei_js.log", timeout=3600, proxy_url=proxy_url)

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
        import urllib.parse
        junk_exts = (".png", ".jpg", ".jpeg", ".gif", ".css", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".pdf")
        
        def is_clean_url(u: str) -> bool:
            u = u.strip()
            if not u.startswith("http"): return False
            if "%" in u or "[" in u or "{" in u or "<" in u or ">" in u: return False
            try:
                parsed = urllib.parse.urlparse(u)
                if not is_in_scope(parsed.hostname, out_of_scope): return False
                path = parsed.path.lower()
                if path.endswith(junk_exts): return False
            except:
                return False
            return True

        try:
            if (WORKSPACE_DIR / "gau.txt").exists():
                for line in (WORKSPACE_DIR / "gau.txt").read_text(errors="ignore").splitlines():
                    if "?" in line: line = line.split("?")[0]
                    if is_clean_url(line): x8_urls.add(line.strip())
            if (WORKSPACE_DIR / "katana.json").exists():
                for line in (WORKSPACE_DIR / "katana.json").read_text(errors="ignore").splitlines():
                    try:
                        o = json.loads(line)
                        ep = o.get("request", {}).get("endpoint") or o.get("endpoint")
                        if ep:
                            if "?" in ep: ep = ep.split("?")[0]
                            if is_clean_url(ep): x8_urls.add(ep.strip())
                    except: pass
        except: pass
        
        if x8_urls:
            capped_urls = sorted(list(x8_urls))[:500]
            x8_targets_file.write_text("\n".join(capped_urls))
            await ws_manager.broadcast(f"[*] x8 Deduplication: Filtered raw endpoints down to {len(capped_urls)} clean base paths.")
            
            # Use dedicated PARAM_WORDLIST instead of wordlist_file (MERGED_WORDLIST)
            from app.services.recon import PARAM_WORDLIST
            if not PARAM_WORDLIST.exists(): PARAM_WORDLIST.write_text("id\nuser\nadmin\nconfig")
            
            x8_cmd = ["/usr/local/bin/x8", "-u", str(x8_targets_file), "-w", str(PARAM_WORDLIST), "-O", "json", "-o", str(WORKSPACE_DIR / "x8.json"), "-W", safe_threads]
            await run_tool(x8_cmd, "x8.log", timeout=3600, proxy_url=proxy_url)

    unique_param_count = await asyncio.to_thread(_extract_params, out_of_scope)
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
        
        custom_templates_dir = WORKSPACE_DIR / "custom-templates"
        if custom_templates_dir.exists() and custom_templates_dir.is_dir() and list(custom_templates_dir.glob("*.yaml")):
            nuclei_cmd.extend(["-t", str(custom_templates_dir)])
            await ws_manager.broadcast("[*] Loaded Custom Nuclei Templates from /workspace/custom-templates")
        
        # Inject Header into Nuclei
        nuclei_cmd.extend(["-rl", str(rate_limit)])
        nuclei_cmd.extend(["-mhe", "100", "-timeout", "10"])
        nuclei_cmd.extend(h_flag)
        await run_tool(nuclei_cmd, "nuclei.log", timeout=14400, proxy_url=proxy_url)

    await ws_manager.broadcast("[PROGRESS] 6/6: Context-Aware AI Triage")
    from app.services.parser import parse_ports, parse_ffuf, parse_vhost, parse_whatweb, parse_katana, parse_nuclei, parse_dalfox, parse_wafw00f, analyze_findings_with_ai, generate_ai_assessment, validate_high_value_findings, parse_favicon
    nuclei_findings, nuclei_tech = parse_nuclei()
    
    # We pass targets list to parse_vhost to load vhost_{t}.json
    raw_findings = parse_ports() + parse_ffuf() + parse_vhost(targets) + parse_katana() + parse_dalfox() + nuclei_findings
    tech_findings = parse_whatweb() + parse_wafw00f() + nuclei_tech + parse_favicon()
    
    await ws_manager.broadcast("[*] Performing active content validation on high-value files...")
    raw_findings = await validate_high_value_findings(raw_findings, custom_headers, proxy_url, rate_limit, timeout=5)
    
    enriched = await analyze_findings_with_ai(raw_findings, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    
    # Save triage output before AI assessment
    final_output = {"target": ", ".join(targets), "stage": "completed", "technologies": [t.model_dump() for t in tech_findings], "findings": [f.model_dump() for f in enriched], "ai_analysis": ""}
    (WORKSPACE_DIR / "final_report.json").write_text(json.dumps(final_output, indent=2))
    
    await ws_manager.broadcast("[+] Pipeline execution successful.")
    
    ai_assessment = await generate_ai_assessment(enriched, tech_findings, api_url, api_key, model_name, temp, top_k, top_p, min_p)
    final_output["ai_analysis"] = ai_assessment
    (WORKSPACE_DIR / "final_report.json").write_text(json.dumps(final_output, indent=2))

    from sqlalchemy import select
    from app.db.database import engine
    from sqlalchemy.ext.asyncio import AsyncSession
    from app.db.models import ScanHistory, Vulnerability
    
    target_str = ", ".join(targets)
    try:
        async with AsyncSession(engine) as session:
            stmt = select(Vulnerability).join(ScanHistory).where(ScanHistory.targets == target_str)
            res = await session.execute(stmt)
            prev_vulns = res.scalars().all()
            
            history_map = {(v.type, v.value): (v.status, getattr(v, "fp_reason", "")) for v in prev_vulns}
            
            from app.services.attack_surface import build_attack_surface_tree
            tree_json = await asyncio.to_thread(build_attack_surface_tree, enriched, targets)
            
            db_scan = ScanHistory(targets=target_str, technologies=json.dumps([t.model_dump() for t in tech_findings]), ai_analysis=ai_assessment, attack_surface_tree=tree_json)
            session.add(db_scan)
            await session.flush()
            
            for f in enriched:
                is_new = (f.type, f.value) not in history_map
                status, prev_reason = history_map.get((f.type, f.value), ("Investigating", ""))
                
                # Default reason to whatever the active sniff test produced
                fp_reason = getattr(f, "fp_reason", "")
                
                # Persistent FP Memory Downgrade
                if status == "False Positive":
                    f.severity = "Info"
                    if "[FP]" not in f.type:
                        f.type += " [FP]"
                    fp_reason = "Inherited from User Verification"
                        
                db_vuln = Vulnerability(
                    scan_id=db_scan.id,
                    type=f.type,
                    value=f.value,
                    severity=f.severity,
                    status=status,
                    is_new=is_new,
                    fp_reason=fp_reason
                )
                session.add(db_vuln)
            await session.commit()
    except Exception as e:
        await ws_manager.broadcast(f"[!] DB Persistence Error: {e}")

    await ws_manager.broadcast("[HUNT:COMPLETED]")

    if webhook_url:
        try:
            req = urllib.request.Request(webhook_url, method="POST", headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            summary = f"**Unchained K9 Scan Completed**\nTargets: {len(targets)}\nVulnerabilities Found: {len(enriched)}"
            payload = {"text": summary} if "hooks.slack.com" in webhook_url else {"content": summary}
            urllib.request.urlopen(req, data=json.dumps(payload).encode("utf-8"), timeout=10)
        except Exception as e:
            await ws_manager.broadcast(f"[!] Failed to send webhook: {e}")
