from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
import uuid
import datetime
import random

router = APIRouter()

class ScanRequest(BaseModel):
    target_url: HttpUrl
    mode: str = "passive"
    intensity: int = 1
    modules: List[str] = ["xss", "sqli", "csrf"]

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    eta_seconds: int
    created_at: str

# In-memory storage
scans_db = {}

@router.post("/", response_model=ScanResponse, status_code=202)
async def create_scan(payload: ScanRequest):
    scan_id = str(uuid.uuid4())
    eta = {1: 15, 2: 60, 3: 300}[payload.intensity]
    created_at = datetime.datetime.utcnow().isoformat()
    scans_db[scan_id] = {
        "scan_id": scan_id,
        "status": "QUEUED",
        "progress": 0,
        "findings": [],
        "created_at": created_at,
        "config": payload.dict()
    }
    # In a real app, dispatch Celery task here
    return ScanResponse(scan_id=scan_id, status="QUEUED", eta_seconds=eta, created_at=created_at)

@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    scan = scans_db.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    # Simulate progress
    if scan["status"] == "QUEUED":
        scan["status"] = "RUNNING"
        scan["progress"] = random.randint(10, 90)
    elif scan["status"] == "RUNNING":
        if scan["progress"] >= 100:
            scan["status"] = "COMPLETE"
        else:
            scan["progress"] += random.randint(5, 20)
            if scan["progress"] > 100:
                scan["progress"] = 100
                scan["status"] = "COMPLETE"
                # Add mock findings
                scan["findings"] = [
                    {"id": 1, "type": "SQL Injection", "severity": "CRITICAL", "url": "/api/users", "param": "id", "payload": "' OR 1=1 --", "confidence": 0.97},
                    {"id": 2, "type": "Reflected XSS", "severity": "HIGH", "url": "/search", "param": "q", "payload": "<script>alert(1)</script>", "confidence": 0.91},
                ]
    return scan