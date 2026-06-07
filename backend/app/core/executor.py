import asyncio
import os
import signal
from pathlib import Path
from fastapi import WebSocket

WORKSPACE_DIR = Path("/workspace").resolve()
active_process = None

class ConnectionManager:
    def __init__(self): self.active_connections: list[WebSocket] = []
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections: self.active_connections.remove(websocket)
    async def broadcast(self, message: str):
        for connection in list(self.active_connections):
            try: await connection.send_text(message)
            except Exception: self.disconnect(connection)

ws_manager = ConnectionManager()

async def _kill_process_group():
    global active_process
    if active_process and active_process.returncode is None:
        try:
            pgid = os.getpgid(active_process.pid)
            os.killpg(pgid, signal.SIGTERM)
            await asyncio.sleep(0.5)
            if active_process.returncode is None:
                os.killpg(pgid, signal.SIGKILL)
        except Exception: pass
        finally: active_process = None

async def cancel_active_scan():
    global active_process
    if active_process is not None:
        await _kill_process_group()
        await ws_manager.broadcast("[!] SCAN ABORTED BY USER. Processes killed.")
        return True
    return False

# RETRY LOGIC PROPERLY IMPLEMENTED HERE
async def run_tool(command: list[str], output_file: str, timeout: int = 900, retries: int = 0, proxy_url: str = None) -> bool:
    global active_process
    safe_output_path = (WORKSPACE_DIR / output_file).resolve()
    if not safe_output_path.is_relative_to(WORKSPACE_DIR): return False
    safe_output_path.parent.mkdir(parents=True, exist_ok=True)

    for attempt in range(retries + 1):
        if attempt > 0: await ws_manager.broadcast(f"[*] Retrying {' '.join(command[:2])}... (Attempt {attempt + 1})")
        else: await ws_manager.broadcast(f"> Executing: {' '.join(command)}")

        custom_env = os.environ.copy()
        if proxy_url:
            custom_env["HTTP_PROXY"] = proxy_url
            custom_env["HTTPS_PROXY"] = proxy_url

        try:
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                cwd=str(WORKSPACE_DIR), env=custom_env, start_new_session=True, limit=10485760 
            )
            active_process = process

            async def _stream_and_write():
                with open(safe_output_path, "w", encoding="utf-8") as f:
                    async for line in process.stdout:
                        decoded = line.decode("utf-8", errors="ignore")
                        f.write(decoded)
                        if decoded.strip(): await ws_manager.broadcast(decoded.strip()[:500])
                await process.wait()

            await asyncio.wait_for(_stream_and_write(), timeout=timeout)
            
            if process.returncode == 0:
                if attempt == 0: await ws_manager.broadcast(f"[+] Success: {command[0]}")
                return True
            else:
                await ws_manager.broadcast(f"[!] Failed: {command[0]} (Exit Code {process.returncode})")
                if attempt == retries: return False

        except asyncio.TimeoutError:
            await _kill_process_group()
            await ws_manager.broadcast(f"[!] TIMEOUT: {command[0]} took longer than {timeout}s.")
            if attempt == retries: return False
        except asyncio.CancelledError:
            await _kill_process_group()
            raise
        except Exception as e:
            await ws_manager.broadcast(f"[!] Error: {e}")
            if attempt == retries: return False
        finally:
            active_process = None
    return False
