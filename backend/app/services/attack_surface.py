import json
import urllib.parse
from pathlib import Path
from app.core.executor import WORKSPACE_DIR

def build_attack_surface_tree(findings: list, targets: list = None) -> str:
    """
    Ingests crawler logs and K9 findings to build a nested JSON tree.
    """
    raw_urls = set()
    
    # 1. Ingest Katana
    katana_file = WORKSPACE_DIR / "katana.txt"
    if katana_file.exists():
        for line in katana_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("http"):
                raw_urls.add(line)
                
    # 2. Ingest GAU
    gau_file = WORKSPACE_DIR / "gau.txt"
    if gau_file.exists():
        for line in gau_file.read_text(errors="ignore").splitlines():
            if line.strip():
                raw_urls.add(line.strip())

    # 3. Filter raw_urls to only include those belonging to targets
    if targets:
        filtered_urls = set()
        # Create a set of base target hosts
        base_hosts = set()
        for t in targets:
            clean_t = t.lower().replace("http://", "").replace("https://", "").split(":")[0]
            base_hosts.add(clean_t)
            
        for url in raw_urls:
            try:
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname
                if host:
                    # Check if the host is or ends with any of the base_hosts
                    if any(host == base or host.endswith("." + base) for base in base_hosts):
                        filtered_urls.add(url)
            except:
                pass
        raw_urls = filtered_urls

    import re
    def is_dynamic_id(part):
        if re.match(r'^\d+$', part): return True
        if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', part): return True
        if re.match(r'^[a-zA-Z0-9_-]{16,}$', part) and not part.endswith(('.js', '.css', '.png', '.jpg', '.php', '.html', '.txt')): return True
        return False
        
    def is_garbage(part):
        if part in [".", ".."]: return True
        if len(re.sub(r'[a-zA-Z0-9_\-\.\~]', '', part)) > 5: return True
        return False

    # Map findings by clean URL (stripped of query/fragments, unquoted, trailing slash removed)
    finding_map = {}
    severity_weights = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    
    for f in findings:
        f_dict = f.model_dump() if hasattr(f, 'model_dump') else f
        val = f_dict.get("value", "")
        if val.startswith("http"):
            parsed = urllib.parse.urlparse(val)
            path = urllib.parse.unquote(parsed.path).rstrip("/")
            clean_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        else:
            clean_url = val.split("?")[0].split("#")[0].rstrip("/")
            
        raw_urls.add(clean_url)
            
        sev = f_dict.get("severity", "Info")
        if sev not in ["Critical", "High", "Medium"]:
            continue
        
        if clean_url not in finding_map:
            finding_map[clean_url] = f_dict
        else:
            existing_sev = finding_map[clean_url].get("severity", "Info")
            if severity_weights.get(sev, 0) > severity_weights.get(existing_sev, 0):
                finding_map[clean_url] = f_dict

    # Build the tree
    tree_root = {}

    for url in raw_urls:
        if not url.startswith("http"): continue
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.netloc
            path = urllib.parse.unquote(parsed.path).rstrip("/")
            
            clean_url = f"{parsed.scheme}://{host}{path}"
            has_finding = clean_url in finding_map
            
            raw_parts = [host] + [p for p in path.split("/") if p]
            
            parts = []
            skip = False
            for i, p in enumerate(raw_parts):
                if is_garbage(p):
                    skip = True
                    break
                if not has_finding and i > 0 and is_dynamic_id(p):
                    parts.append("[ID]")
                else:
                    parts.append(p)
                    
            if skip: continue
            
            current_level = tree_root
            current_path_str = f"{parsed.scheme}://"
            
            for i, part in enumerate(parts):
                if i == 0:
                    current_path_str += part
                else:
                    current_path_str += f"/{part}"
                    
                if part not in current_level:
                    current_level[part] = {
                        "id": current_path_str,
                        "name": part,
                        "children": {},
                        "finding": None,
                        "severity": "None",
                        "weight": 0,
                        "is_dir": i < len(parts) - 1
                    }
                    
                # If this is the exact endpoint, attach finding
                if i == len(parts) - 1:
                    if clean_url in finding_map:
                        f_data = finding_map[clean_url]
                        current_level[part]["finding"] = f_data
                        sev = f_data.get("severity", "Info")
                        current_level[part]["severity"] = sev
                        current_level[part]["weight"] = severity_weights.get(sev, 0)

                current_level = current_level[part]["children"]
        except:
            pass

    # Recursively convert dict to list and bubble up severities
    def convert_and_bubble(node_dict):
        result_list = []
        max_weight = 0
        max_sev = "None"
        
        for key, node in node_dict.items():
            children_list, child_max_weight, child_max_sev = convert_and_bubble(node["children"])
            
            node["children"] = children_list
            if not children_list:
                node.pop("children")
                
            # Bubble up
            node_weight = node["weight"]
            if child_max_weight > node_weight:
                node["weight"] = child_max_weight
                node["severity"] = child_max_sev
                
            if node["weight"] > max_weight:
                max_weight = node["weight"]
                max_sev = node["severity"]
                
            result_list.append(node)
            
        # Sort so directories are first, then alphabetical
        result_list.sort(key=lambda x: (not x.get("is_dir", False), x["name"].lower()))
        return result_list, max_weight, max_sev

    final_tree, _, _ = convert_and_bubble(tree_root)
    return json.dumps(final_tree)
