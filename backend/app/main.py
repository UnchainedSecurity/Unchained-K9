import re, json, asyncio
from pathlib import Path
from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from app.services.recon import run_pipeline
from app.core.executor import ws_manager, cancel_active_scan

from fastapi.staticfiles import StaticFiles
import shutil

from contextlib import asynccontextmanager
from app.db.database import init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(title="BlackHound K9 API", version="3.3.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

WORKSPACE_DIR = Path("/workspace")
FINAL_REPORT = WORKSPACE_DIR / "final_report.json"
SCREENSHOTS_DIR = WORKSPACE_DIR / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/screenshots", StaticFiles(directory=str(SCREENSHOTS_DIR)), name="screenshots")

SCAN_IN_PROGRESS = False
scan_lock = asyncio.Lock()
current_scan_task = None

class ScanRequest(BaseModel):
    targets: list[str] = Field(..., min_items=1)
    threads: int = 50
    scan_depth: str = "Normal"
    api_url: str = ""
    api_key: str = ""
    model_name: str = ""
    temperature: float = 0.1
    top_k: int = 64
    top_p: float = 0.95
    min_p: float = 0.0
    wordlist: list = ["quick", "backups", "admin_panels"]
    custom_headers: list[str] = []  # NEW: Multiple Custom Headers
    proxy_url: str = ""
    webhook_url: str = ""
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

async def _pipeline_wrapper(targets, threads, depth, api_url, api_key, model, temp, tk, tp, mp, wl, custom_headers, rate_limit, togs, proxy_url, webhook_url):
    global SCAN_IN_PROGRESS
    try:
        await run_pipeline(targets, threads, depth, api_url, api_key, model, temp, tk, tp, mp, wl, custom_headers, rate_limit, togs, proxy_url, webhook_url)
    except asyncio.CancelledError:
        await ws_manager.broadcast("\n[!] Pipeline script terminated successfully.")
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[ERROR] Pipeline crashed:\n{tb}")
        await ws_manager.broadcast(f"[!] Pipeline crashed: {e}\n{tb}")
    finally:
        async with scan_lock:
            SCAN_IN_PROGRESS = False

@app.post("/scan")
async def start_scan(req: ScanRequest):
    global SCAN_IN_PROGRESS, current_scan_task
    
    clean_targets = []
    for t in req.targets:
        t = t.lower().strip().replace("http://", "").replace("https://", "").rstrip("/")
        if re.match(r"^[a-zA-Z0-9.-]+(:\d+)?$", t):
            clean_targets.append(t)

    if not clean_targets:
        raise HTTPException(status_code=400, detail="No valid targets provided.")

    async with scan_lock:
        if SCAN_IN_PROGRESS:
            raise HTTPException(status_code=409, detail="Scan in progress. Cancel it first.")
        SCAN_IN_PROGRESS = True

    for file in WORKSPACE_DIR.glob("*"):
        if file.is_file() and file.name not in ["wordlist.txt", "k9.db", "k9.db-journal", "k9.db-wal"]:
            file.unlink()
        elif file.is_dir() and file.name == "screenshots":
            for screenshot in file.glob("*"):
                if screenshot.is_file():
                    screenshot.unlink()

    current_scan_task = asyncio.create_task(_pipeline_wrapper(
        clean_targets, req.threads, req.scan_depth, req.api_url, req.api_key, req.model_name,
        req.temperature, req.top_k, req.top_p, req.min_p, req.wordlist, req.custom_headers, req.rate_limit, req.toggles, req.proxy_url, req.webhook_url
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

from sqlalchemy import select, desc
from app.db.database import async_session
from app.db.models import ScanHistory, Vulnerability

@app.get("/results")
async def get_results():
    screenshots = [f.name for f in SCREENSHOTS_DIR.glob("*.png")] if SCREENSHOTS_DIR.exists() else []
    
    if SCAN_IN_PROGRESS:
        return {"stage": "running", "findings": [], "screenshots": screenshots}
        
    async with async_session() as session:
        stmt = select(ScanHistory).order_by(desc(ScanHistory.timestamp)).limit(1)
        res = await session.execute(stmt)
        scan = res.scalar_one_or_none()
        
        if not scan:
            return {"stage": "idle", "findings": [], "screenshots": screenshots}
            
        vulns_stmt = select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        vulns_res = await session.execute(vulns_stmt)
        vulns = vulns_res.scalars().all()
        
        try:
            techs = json.loads(scan.technologies)
        except:
            techs = []
            
        findings_list = [v.model_dump() for v in vulns]
            
        return {
            "target": scan.targets,
            "stage": "completed",
            "technologies": techs,
            "findings": findings_list,
            "ai_analysis": scan.ai_analysis,
            "screenshots": screenshots,
            "scan_id": scan.id
        }

@app.get("/history")
async def get_history():
    async with async_session() as session:
        stmt = select(ScanHistory).order_by(desc(ScanHistory.timestamp))
        res = await session.execute(stmt)
        scans = res.scalars().all()
        
        history = []
        for s in scans:
            history.append({
                "id": s.id,
                "targets": s.targets,
                "timestamp": s.timestamp.isoformat()
            })
        return history

@app.get("/history/{scan_id}")
async def get_history_by_id(scan_id: int):
    screenshots = [f.name for f in SCREENSHOTS_DIR.glob("*.png")] if SCREENSHOTS_DIR.exists() else []
    async with async_session() as session:
        scan = await session.get(ScanHistory, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        vulns_stmt = select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        vulns_res = await session.execute(vulns_stmt)
        vulns = vulns_res.scalars().all()
        
        try:
            techs = json.loads(scan.technologies)
        except:
            techs = []
            
        findings_list = [v.model_dump() for v in vulns]
            
        return {
            "target": scan.targets,
            "stage": "completed",
            "technologies": techs,
            "findings": findings_list,
            "ai_analysis": scan.ai_analysis,
            "screenshots": screenshots,
            "scan_id": scan.id
        }

@app.get("/attack-surface")
async def get_attack_surface():
    if SCAN_IN_PROGRESS:
        return {"tree": "[]"}
    async with async_session() as session:
        stmt = select(ScanHistory).order_by(desc(ScanHistory.timestamp)).limit(1)
        res = await session.execute(stmt)
        scan = res.scalar_one_or_none()
        if not scan or not hasattr(scan, "attack_surface_tree"):
            return {"tree": "[]"}
        return {"tree": scan.attack_surface_tree}

@app.get("/history/{scan_id}/attack-surface")
async def get_history_attack_surface(scan_id: int):
    async with async_session() as session:
        scan = await session.get(ScanHistory, scan_id)
        if not scan or not hasattr(scan, "attack_surface_tree"):
            raise HTTPException(status_code=404, detail="Tree not found")
        return {"tree": scan.attack_surface_tree}

class StatusUpdate(BaseModel):
    status: str

@app.patch("/findings/{finding_id}/status")
async def update_finding_status(finding_id: int, req: StatusUpdate):
    async with async_session() as session:
        vuln = await session.get(Vulnerability, finding_id)
        if not vuln:
            raise HTTPException(status_code=404, detail="Finding not found")
            
        vuln.status = req.status
        if req.status != "False Positive":
            vuln.fp_reason = ""
            vuln.type = vuln.type.replace(" [FP]", "")
            
        await session.commit()
        return {"status": "success"}

from app.db.models import ScanProfile

@app.get("/profiles")
async def get_profiles():
    from sqlalchemy import select
    async with async_session() as session:
        stmt = select(ScanProfile)
        res = await session.execute(stmt)
        profiles = res.scalars().all()
        return [{"id": p.id, "name": p.name, "config_json": p.config_json} for p in profiles]

class ProfileCreate(BaseModel):
    name: str
    config_json: str

@app.post("/profiles")
async def create_profile(req: ProfileCreate):
    async with async_session() as session:
        profile = ScanProfile(name=req.name, config_json=req.config_json)
        session.add(profile)
        try:
            await session.commit()
        except Exception:
            raise HTTPException(status_code=400, detail="Profile name must be unique")
        return {"status": "success", "id": profile.id}

@app.delete("/profiles/{profile_id}")
async def delete_profile(profile_id: int):
    if profile_id in [1, 2, 3]:
        raise HTTPException(status_code=403, detail="Cannot delete default profiles")
    async with async_session() as session:
        profile = await session.get(ScanProfile, profile_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        await session.delete(profile)
        await session.commit()
        return {"status": "success"}
