"""FastAPI backend for GitVulture Web Dashboard.

Wraps the gitvulture CLI core in a REST API + Server-Sent Events stream so the
React frontend can drive scans, watch real-time progress and display findings.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, ConfigDict, Field

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import sys
sys.path.insert(0, str(ROOT_DIR.parent))
from gitvulture.core.orchestrator import ScanOptions, run_scan  # noqa: E402
from gitvulture.storage import default_base_dir, new_scan_dir, slugify_host  # noqa: E402

# ---------------------------------------------------------------------- #
# DB
# ---------------------------------------------------------------------- #
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

# Sqlmap-style persistent storage: ~/.gitvulture/output/<host>/<timestamp>/
SCANS_DIR = default_base_dir() / "output"
SCANS_DIR.mkdir(parents=True, exist_ok=True)

# In-memory event queues for live progress (one per scan_id)
event_queues: dict[str, asyncio.Queue] = {}
scan_tasks: dict[str, asyncio.Task] = {}

logger = logging.getLogger("gitvulture")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(title="GitVulture API")
api = APIRouter(prefix="/api")


# ---------------------------------------------------------------------- #
# Models
# ---------------------------------------------------------------------- #
class ScanRequest(BaseModel):
    target_url: str
    ai_triage: bool = True
    verify_secrets: bool = False
    insecure_ssl: bool = True
    bypass_403: bool = True
    ua_rotate: bool = True
    proxy: Optional[str] = None
    proxy_list: list[str] = Field(default_factory=list)
    rate_limit: float = 30.0
    concurrency: int = 20
    timeout: float = 15.0
    escalate: bool = False
    offensive: bool = False


class ScanRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    status: str = "pending"  # pending|running|done|failed
    phase: str = "init"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    duration_s: Optional[float] = None
    report: Optional[dict] = None
    options: Optional[dict] = None
    storage_path: Optional[str] = None        # sqlmap-style absolute path
    host: Optional[str] = None                # slugified host of the target


# ---------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------- #
def _scan_dir(scan_id: str) -> Path:
    """Resolve the stored path for a given scan_id by querying the DB-recorded
    storage_path. Falls back to the legacy <SCANS_DIR>/<scan_id> layout."""
    # Synchronous fallback path used by sync endpoints
    legacy = SCANS_DIR / scan_id
    return legacy


async def _resolve_scan_dir(scan_id: str) -> Path:
    rec = await db.scans.find_one({"id": scan_id}, {"storage_path": 1, "_id": 0})
    if rec and rec.get("storage_path"):
        return Path(rec["storage_path"])
    return _scan_dir(scan_id)


async def _save_scan(rec: dict) -> None:
    await db.scans.update_one({"id": rec["id"]}, {"$set": rec}, upsert=True)


async def _get_scan(scan_id: str) -> Optional[dict]:
    return await db.scans.find_one({"id": scan_id}, {"_id": 0})


async def _run_scan_task(scan_id: str, opts: ScanOptions) -> None:
    queue = event_queues[scan_id]

    async def progress_cb(evt: dict):
        await queue.put(evt)
        if evt.get("type") == "phase":
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {"phase": evt.get("phase"), "status": "running"}},
            )

    try:
        result = await run_scan(opts, progress=progress_cb)
        report = result.to_dict()
        # Sanitize for Mongo (no Path objects, ensure JSON-safe)
        report_safe = json.loads(json.dumps(report, default=str))
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "done" if result.recon and result.recon.exposed else "failed",
                "phase": "done",
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "duration_s": result.duration_s,
                "report": report_safe,
            }},
        )
        await queue.put({"type": "finished", "scan_id": scan_id})
    except Exception as e:
        logger.exception("scan failed")
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "failed", "phase": "error", "error": str(e)}},
        )
        await queue.put({"type": "error", "message": str(e)})
    finally:
        await queue.put({"type": "close"})


# ---------------------------------------------------------------------- #
# Routes
# ---------------------------------------------------------------------- #
@api.get("/")
async def root():
    return {"name": "GitVulture API", "version": "1.0.0"}


@api.post("/scans", response_model=dict)
async def create_scan(req: ScanRequest):
    if not req.target_url.startswith(("http://", "https://")):
        raise HTTPException(400, "target_url must start with http(s)://")

    rec = ScanRecord(target_url=req.target_url, options=req.model_dump())
    scan_id = rec.id

    # Sqlmap-style scan dir: ~/.gitvulture/output/<host>/<timestamp>/
    out_dir = new_scan_dir(req.target_url, base=default_base_dir())
    rec.storage_path = str(out_dir)
    rec.host = slugify_host(req.target_url)
    # Persist the scan_id inside the dir for easy back-resolution
    (out_dir / "scan_id.txt").write_text(scan_id + "\n")

    rec_dict = rec.model_dump()
    rec_dict["created_at"] = rec_dict["created_at"].isoformat()
    await _save_scan(rec_dict)

    opts = ScanOptions(
        target_url=req.target_url.rstrip("/"),
        output_dir=out_dir,
        ai_triage=req.ai_triage,
        verify_secrets=req.verify_secrets,
        insecure_ssl=req.insecure_ssl,
        bypass_403=req.bypass_403,
        ua_rotate=req.ua_rotate,
        proxy=req.proxy,
        proxy_list=req.proxy_list,
        rate_limit=req.rate_limit,
        concurrency=req.concurrency,
        timeout=req.timeout,
        escalate=req.escalate,
        offensive=req.offensive,
    )

    event_queues[scan_id] = asyncio.Queue()
    scan_tasks[scan_id] = asyncio.create_task(_run_scan_task(scan_id, opts))
    return {"scan_id": scan_id, "status": "running"}


@api.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    rec = await _get_scan(scan_id)
    if not rec:
        raise HTTPException(404, "scan not found")
    return rec


@api.get("/scans")
async def list_scans():
    cur = db.scans.find({}, {"_id": 0, "report": 0}).sort("created_at", -1).limit(100)
    return await cur.to_list(100)


@api.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    p = await _resolve_scan_dir(scan_id)
    await db.scans.delete_one({"id": scan_id})
    shutil.rmtree(p, ignore_errors=True)
    return {"deleted": scan_id}


@api.get("/scans/{scan_id}/events")
async def stream_events(scan_id: str):
    queue = event_queues.get(scan_id)

    async def gen():
        # Emit a hello so the client knows the stream is open
        yield f"data: {json.dumps({'type':'hello','scan_id':scan_id})}\n\n"
        if queue is None:
            rec = await _get_scan(scan_id)
            if rec:
                yield f"data: {json.dumps({'type':'snapshot','scan':rec}, default=str)}\n\n"
            yield "data: {\"type\":\"close\"}\n\n"
            return
        while True:
            try:
                evt = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue
            yield f"data: {json.dumps(evt, default=str)}\n\n"
            if evt.get("type") in ("close", "error"):
                break

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@api.get("/scans/{scan_id}/report")
async def download_report(scan_id: str):
    base = await _resolve_scan_dir(scan_id)
    p = base / "gitvulture-report.json"
    if not p.exists():
        raise HTTPException(404, "report not yet available")
    return FileResponse(p, filename=f"gitvulture-{scan_id}.json",
                        media_type="application/json")


@api.get("/scans/{scan_id}/dump")
async def download_dump(scan_id: str):
    """Stream the reconstructed .git directory as a tar.gz archive."""
    base = await _resolve_scan_dir(scan_id)
    if not base.exists():
        raise HTTPException(404, "dump not found")
    archive_base = base.parent / f"gitvulture-dump-{scan_id}"
    archive_path = Path(str(archive_base) + ".tar.gz")
    if not archive_path.exists():
        shutil.make_archive(str(archive_base), "gztar", root_dir=str(base))
    return FileResponse(archive_path, filename=f"gitvulture-dump-{scan_id}.tar.gz",
                        media_type="application/gzip")


@api.get("/scans/{scan_id}/forgery")
async def download_forgery(scan_id: str):
    """Download the AI-generated forgery script (proof-of-impact)."""
    base = await _resolve_scan_dir(scan_id)
    p = base / "forgery_lab" / "forge.py"
    if not p.exists():
        raise HTTPException(404, "forgery script not generated for this scan")
    return FileResponse(p, filename=f"gitvulture-forge-{scan_id}.py",
                        media_type="text/x-python")


@api.get("/targets")
async def list_targets_endpoint():
    """List every host folder under ~/.gitvulture/output/ (sqlmap-style)."""
    from gitvulture.storage import list_targets
    return list_targets()


@api.get("/health")
async def health():
    return {"ok": True, "llm": bool(os.environ.get("EMERGENT_LLM_KEY"))}


@api.get("/architecture")
async def architecture_diagram():
    """Serve the static GitVulture architecture diagram (single-file HTML).
    Reachable from the frontend host at `${REACT_APP_BACKEND_URL}/api/architecture`."""
    diagram_path = ROOT_DIR.parent / "docs" / "architecture-diagram.html"
    if not diagram_path.exists():
        raise HTTPException(404, "architecture-diagram.html not found")
    return FileResponse(diagram_path, media_type="text/html; charset=utf-8")


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown():
    for t in scan_tasks.values():
        t.cancel()
    client.close()
