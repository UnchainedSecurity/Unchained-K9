import sys
import json
import asyncio
import aiohttp
import websockets

API_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000/ws/logs"

async def test_k9(target):
    payload = {
        "targets": [target],
        "threads": 5,             # LOW THREADS to protect juiceshop
        "scan_depth": "Normal",
        "rate_limit": 20,         # LOW RATE LIMIT (req/s)
        "toggles": {
            "run_harvester": False, # Irrelevant for a local IP/host
            "run_gau": False,       # Irrelevant for a local IP/host
            "run_katana": True,
            "katana_depth": 2,      # Cap katana depth
            "run_nuclei": True,
            "run_dalfox": True,
            "run_vhost": False,
            "run_gowitness": False, # Screenshots may fail on internal host
            "run_js_secrets": True
        },
        "wordlist": ["quick"],    # Fast wordlist
    }

    async with aiohttp.ClientSession() as session:
        print(f"[*] Starting scan against {target}...")
        async with session.post(f"{API_URL}/scan", json=payload) as resp:
            if resp.status != 200:
                print(f"[!] Failed to start scan: {await resp.text()}")
                return

    # Connect to WebSocket
    print("[*] Connecting to WebSocket for live logs...")
    try:
        async with websockets.connect(WS_URL) as ws:
            while True:
                msg = await ws.recv()
                if msg == "[HUNT:COMPLETED]":
                    print("\n[+] Scan Completed! Fetching Results...")
                    break
                print(msg)
    except Exception as e:
        print(f"[!] WebSocket disconnected: {e}")

    # Fetch Results
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{API_URL}/results") as resp:
            data = await resp.json()
            findings = data.get("findings", [])
            print(f"\n========================================")
            print(f"[*] Unchained K9 found {len(findings)} vulnerabilities!")
            for f in findings:
                print(f"   - [{f.get('severity')}] {f.get('type')}: {f.get('value')}")
            print(f"========================================\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test_k9.py <target>")
        sys.exit(1)
    asyncio.run(test_k9(sys.argv[1]))
