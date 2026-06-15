"""
backend/api/routes/scans.py
"""
import uuid
import datetime
import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional

router = APIRouter()

class ScanRequest(BaseModel):
    target_url: str
    mode: str = "passive"
    intensity: int = 1
    modules: List[str] = ["xss", "sqli", "csrf", "headers", "sast", "config"]

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    eta_seconds: int
    created_at: str

# In-memory database of scan jobs
scans_db = {}

# ── POST / — create a new scan ─────────────────────────────────────────────────
@router.post("/", response_model=ScanResponse, status_code=202)
async def create_scan(payload: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    eta = 5 # Rapid SAST and passive config scanning completes in under 5 seconds
    created_at = datetime.datetime.utcnow().isoformat()

    scans_db[scan_id] = {
        "scan_id":   scan_id,
        "status":    "RUNNING",
        "progress":  10,
        "findings":  [],
        "created_at": created_at,
        "config":    payload.dict(),
    }

    # Import run scan to avoid circular references and schedule it in the background
    from main import _run_scan, _jobs
    _jobs[scan_id] = {
        "status": "running",
        "started_at": created_at,
        "target_url": payload.target_url,
        "result": None,
        "error": None,
    }
    
    background_tasks.add_task(_run_scan, scan_id, payload.target_url, payload.modules)

    return ScanResponse(
        scan_id=scan_id,
        status="RUNNING",
        eta_seconds=eta,
        created_at=created_at,
    )

# ── GET / — list scans ──────────────────────────────────────────────────────────
@router.get("/")
async def list_scans():
    # Gather all active scans and finished scans
    return {
        "scans": list(scans_db.values()),
        "total": len(scans_db),
        "page": 1,
    }

# ── GET /{scan_id} — get scan status / results ─────────────────────────────────
@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    scan = scans_db.get(scan_id)
    if not scan:
        # Check backend _jobs store
        from main import _jobs
        job = _jobs.get(scan_id)
        if job:
            if job["status"] == "completed" and job.get("result"):
                return {
                    "scan_id": scan_id,
                    "status": "COMPLETE",
                    "progress": 100,
                    "findings": job["result"]["findings"],
                    "created_at": job["started_at"],
                    "config": {"target_url": job["target_url"]},
                    "result": job["result"]
                }
            return {
                "scan_id": scan_id,
                "status": "RUNNING",
                "progress": 50,
                "findings": [],
                "created_at": job["started_at"],
                "config": {"target_url": job["target_url"]}
            }
        raise HTTPException(status_code=404, detail="Scan not found")

    # If it has complete scans, return
    return scan

# ── DELETE /{scan_id} — delete a scan ──────────────────────────────────────────
@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_id in scans_db:
        del scans_db[scan_id]
        return {"message": "Scan deleted"}
    raise HTTPException(status_code=404, detail="Scan not found")