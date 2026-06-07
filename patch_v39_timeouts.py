from pathlib import Path

recon_path = Path("/home/hollowedtemplar/sentinel/backend/app/services/recon.py")
content = recon_path.read_text()

# Increase the Python execution timeouts drastically to accommodate the slow Carpet Bomb at 5 req/s.
content = content.replace('await run_tool(nucleidast_cmd, "nucleidast.log", timeout=900)', 'await run_tool(nucleidast_cmd, "nucleidast.log", timeout=7200)')
content = content.replace('await run_tool(nuclei_cmd, "nuclei.log", timeout=3600)', 'await run_tool(nuclei_cmd, "nuclei.log", timeout=14400)')
content = content.replace('await run_tool(dalfox_cmd, "dalfox.log", timeout=3600)', 'await run_tool(dalfox_cmd, "dalfox.log", timeout=14400)')

recon_path.write_text(content)
print("Timeouts patched.")
