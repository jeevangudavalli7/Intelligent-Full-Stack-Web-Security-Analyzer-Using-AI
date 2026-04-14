from fastapi import APIRouter, HTTPException
from .scans import scans_db

router = APIRouter()

@router.get("/{scan_id}")
async def get_report(scan_id: str):
    scan = scans_db.get(scan_id)
    if not scan or scan["status"] != "COMPLETE":
        raise HTTPException(404, "Report not ready")
    # Mock NLP report
    return {
        "scan_id": scan_id,
        "summary": "The scan found 2 critical vulnerabilities and 1 high-severity issue.",
        "findings": scan["findings"],
        "risk_score": 8.5,
        "recommendations": [
            "Use parameterized queries to prevent SQL injection.",
            "Escape all user input in HTML output to prevent XSS.",
        ]
    }