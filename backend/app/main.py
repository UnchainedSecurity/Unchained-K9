import re, json, asyncio
from pathlib import Path
from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from app.services.recon import run_pipeline
from app.core.executor import ws_manager, cancel_active_scan

app = FastAPI(title="BlackHound K9 API", version="3.3.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

WORKSPACE_DIR = Path("/workspace")
FINAL_REPORT = WORKSPACE_DIR / "final_report.json"

SCAN_IN_PROGRESS = False
scan_lock = asyncio.Lock()
current_scan_task = None

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=253)
    threads: int = 50
    scan_depth: str = "Normal"
    api_url: str = ""
    api_key: str = ""
    model_name: str = ""
    temperature: float = 0.1
    top_k: int = 64
    top_p: float = 0.95
    min_p: float = 0.0
    wordlist: str = "common"
    custom_header: str = ""  # NEW: Safe Harbor Compliance Header
    rate_limit: int = 150
    toggles: dict = {}

@app.get("/health")
async def health_check(): return {"status": "healthy"}

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True: await websocket.receive_text()
    except Exception:
        ws_manager.disconnect(websocket)

async def _pipeline_wrapper(target, threads, depth, api_url, api_key, model, temp, tk, tp, mp, wl, custom_header, rate_limit, togs):
    global SCAN_IN_PROGRESS
    try:
        await run_pipeline(target, threads, depth, api_url, api_key, model, temp, tk, tp, mp, wl, custom_header, rate_limit, togs)
    except asyncio.CancelledError:
        await ws_manager.broadcast("\n[!] Pipeline script terminated successfully.")
    except Exception as e:
        await ws_manager.broadcast(f"[!] Pipeline crashed: {e}")
    finally:
        async with scan_lock:
            SCAN_IN_PROGRESS = False

@app.post("/scan")
async def start_scan(req: ScanRequest):
    global SCAN_IN_PROGRESS, current_scan_task
    
    target = req.target.lower().strip()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")

    if not re.match(r"^[a-zA-Z0-9.-]+(:\d+)?$", target):
        raise HTTPException(status_code=400, detail="Invalid format. Use domain.com or IP:PORT")

    async with scan_lock:
        if SCAN_IN_PROGRESS:
            raise HTTPException(status_code=409, detail="Scan in progress. Cancel it first.")
        SCAN_IN_PROGRESS = True

    for file in WORKSPACE_DIR.glob("*"):
        if file.is_file() and file.name != "wordlist.txt":
            file.unlink()

    current_scan_task = asyncio.create_task(_pipeline_wrapper(
        target, req.threads, req.scan_depth, req.api_url, req.api_key, req.model_name,
        req.temperature, req.top_k, req.top_p, req.min_p, req.wordlist, req.custom_header, req.rate_limit, req.toggles
    ))
    return {"status": "queued"}

@app.post("/cancel")
async def cancel_scan():
    global SCAN_IN_PROGRESS, current_scan_task
    if not SCAN_IN_PROGRESS:
        return {"status": "ignored", "message": "No scan running."}
    await cancel_active_scan()
    if current_scan_task: current_scan_task.cancel()
    return {"status": "cancelled", "message": "Termination signal sent."}

@app.get("/results")
async def get_results():
    if FINAL_REPORT.exists():
        try: return json.loads(FINAL_REPORT.read_text(encoding="utf-8"))
        except Exception: return {"stage": "running", "findings": []}
    return {"stage": "running", "findings": []}
