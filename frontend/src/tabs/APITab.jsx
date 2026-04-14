import React from 'react';
import { Section } from '../components/Section';
import { CodeBlock } from '../components/CodeBlock';
import { Badge } from '../components/Badge';
import { COLORS } from '../constants/colors';

export const APITab = () => {
  const endpoints = [
    { method: "POST", path: "/api/v1/auth/register", desc: "Register new user", auth: false, body: '{ "email": "...", "password": "..." }', response: '{ "user_id": "uuid", "token": "jwt" }', color: COLORS.success },
    { method: "POST", path: "/api/v1/auth/login", desc: "Authenticate user, get JWT", auth: false, body: '{ "email": "...", "password": "..." }', response: '{ "access_token": "...", "expires_in": 3600 }', color: COLORS.success },
    { method: "POST", path: "/api/v1/scans", desc: "Initiate a new scan", auth: true, body: '{ "target_url": "https://...", "mode": "passive", "intensity": 2, "modules": ["xss","sqli","csrf"] }', response: '{ "scan_id": "uuid", "status": "QUEUED", "eta_seconds": 45 }', color: COLORS.warn },
    { method: "GET", path: "/api/v1/scans/{scan_id}", desc: "Poll scan status + partial results", auth: true, body: null, response: '{ "status": "RUNNING", "progress": 67, "findings_so_far": [...] }', color: COLORS.accent },
    { method: "GET", path: "/api/v1/scans/{scan_id}/report", desc: "Full NLP-enriched report", auth: true, body: null, response: '{ "summary": "...", "findings": [...], "risk_score": 8.4, "recommendations": [...] }', color: COLORS.accent },
    { method: "GET", path: "/api/v1/scans", desc: "List all scans for user", auth: true, body: null, response: '{ "scans": [...], "total": 12, "page": 1 }', color: COLORS.accent },
    { method: "DELETE", path: "/api/v1/scans/{scan_id}", desc: "Cancel or delete a scan", auth: true, body: null, response: '{ "deleted": true }', color: COLORS.danger },
    { method: "GET", path: "/api/v1/admin/metrics", desc: "System health + scan stats", auth: true, body: null, response: '{ "scans_today": 42, "queue_depth": 3, "model_version": "v2.1" }', color: "#f06292" },
    { method: "WS", path: "/ws/scans/{scan_id}", desc: "Real-time scan progress stream", auth: true, body: null, response: '{ "event": "progress", "pct": 45, "current_module": "sqli" }', color: COLORS.info },
  ];

  const METHOD_COLORS = { POST: COLORS.success, GET: COLORS.accent, DELETE: COLORS.danger, WS: COLORS.info, PUT: COLORS.warn };

  return (
    <div>
      <Section title="REST API Specification">
        <div style={{ marginBottom: 8, color: COLORS.textDim, fontSize: 13 }}>
          Base URL: <code style={{ color: COLORS.accent, background: COLORS.card, padding: "2px 8px", borderRadius: 4 }}>https://api.secanalyzer.dev/api/v1</code>
          &nbsp;&nbsp;•&nbsp;&nbsp; Auth: <code style={{ color: COLORS.warn, background: COLORS.card, padding: "2px 8px", borderRadius: 4 }}>Bearer JWT</code>
        </div>
      </Section>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {endpoints.map((ep, i) => (
          <div key={i} style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 10, overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "12px 20px", borderBottom: `1px solid ${COLORS.border}33` }}>
              <Badge label={ep.method} color={METHOD_COLORS[ep.method] || COLORS.accent} />
              <code style={{ color: COLORS.text, fontSize: 13 }}>{ep.path}</code>
              {ep.auth && <Badge label="AUTH" color={COLORS.warn} />}
              <span style={{ color: COLORS.textDim, fontSize: 12, marginLeft: "auto" }}>{ep.desc}</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: ep.body ? "1fr 1fr" : "1fr", gap: 0 }}>
              {ep.body && (
                <div style={{ padding: "10px 20px", borderRight: `1px solid ${COLORS.border}33` }}>
                  <div style={{ color: COLORS.muted, fontSize: 10, marginBottom: 4, letterSpacing: 1 }}>REQUEST BODY</div>
                  <code style={{ color: COLORS.textDim, fontSize: 11, fontFamily: "monospace" }}>{ep.body}</code>
                </div>
              )}
              <div style={{ padding: "10px 20px" }}>
                <div style={{ color: COLORS.muted, fontSize: 10, marginBottom: 4, letterSpacing: 1 }}>RESPONSE</div>
                <code style={{ color: COLORS.textDim, fontSize: 11, fontFamily: "monospace" }}>{ep.response}</code>
              </div>
            </div>
          </div>
        ))}
      </div>

      <Section title="FastAPI Implementation" accent={COLORS.accent} >
        <CodeBlock code={`# api/routes/scans.py
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from celery_app import celery
from db.models import Scan, ScanStatus
from auth.deps import get_current_user
import uuid, datetime

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

class ScanRequest(BaseModel):
    target_url: HttpUrl
    mode: str = "passive"          # passive | active
    intensity: int = 1             # 1 | 2 | 3
    modules: List[str] = ["xss", "sqli", "csrf"]
    notify_email: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    eta_seconds: int
    created_at: str

@router.post("/", response_model=ScanResponse, status_code=202)
async def create_scan(
    payload: ScanRequest,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    # Input validation
    if payload.mode == "active" and not current_user.is_verified:
        raise HTTPException(403, "Active scanning requires verified account")

    # Rate limiting (checked in middleware, but double-check here)
    recent = await db.count_scans(current_user.id, hours=1)
    if recent >= 10:
        raise HTTPException(429, "Scan rate limit exceeded: 10/hour")

    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id, user_id=current_user.id,
        target_url=str(payload.target_url),
        mode=payload.mode, intensity=payload.intensity,
        modules=payload.modules, status=ScanStatus.QUEUED,
        created_at=datetime.datetime.utcnow()
    )
    await db.save(scan)

    # Dispatch to Celery
    celery.send_task(
        "tasks.run_scan",
        args=[scan_id, payload.dict()],
        queue=f"scans-{payload.mode}"   # separate queues by mode
    )

    eta = {1: 15, 2: 60, 3: 300}[payload.intensity]
    return ScanResponse(
        scan_id=scan_id, status="QUEUED",
        eta_seconds=eta, created_at=scan.created_at.isoformat()
    )

@router.get("/{scan_id}")
async def get_scan(scan_id: str, current_user = Depends(get_current_user), db = Depends(get_db)):
    scan = await db.get_scan(scan_id)
    if not scan or scan.user_id != current_user.id:
        raise HTTPException(404, "Scan not found")
    return scan.to_dict()`} lang="python" />
      </Section>
    </div>
  );
};