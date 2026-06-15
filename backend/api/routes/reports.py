"""
backend/api/routes/reports.py
"""
from fastapi import APIRouter, HTTPException
from .scans import scans_db

router = APIRouter()

@router.get("/{scan_id}")
async def get_report(scan_id: str):
    scan = scans_db.get(scan_id)
    if not scan:
        from main import _jobs
        job = _jobs.get(scan_id)
        if job and job["status"] == "completed" and job.get("result"):
            scan = {
                "scan_id": scan_id,
                "status": "COMPLETE",
                "findings": job["result"]["findings"],
                "result": job["result"]
            }
            
    if not scan or scan.get("status") not in ["COMPLETE", "completed"]:
        raise HTTPException(404, "Report not ready")

    findings = scan.get("findings", [])
    
    # Calculate counts
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM").upper()
        if sev in counts:
            counts[sev] += 1
            
    # Calculate dynamic score
    result = scan.get("result", {})
    score = result.get("security_score", 100) if result else 100
    
    # Dynamic summary
    summary_parts = []
    if counts["CRITICAL"] > 0:
        summary_parts.append(f"{counts['CRITICAL']} critical-severity vulnerability")
    if counts["HIGH"] > 0:
        summary_parts.append(f"{counts['HIGH']} high-severity vulnerability")
    if counts["MEDIUM"] > 0:
        summary_parts.append(f"{counts['MEDIUM']} medium-severity vulnerability")
    if counts["LOW"] > 0:
        summary_parts.append(f"{counts['LOW']} low-severity vulnerability")
        
    if not summary_parts:
        summary = "The security audit was completed successfully. No security concerns or vulnerabilities were found."
    else:
        summary = f"The security audit identified " + ", ".join(summary_parts) + ". Remediation actions are recommended."

    # Dynamic recommendations
    rems = []
    seen_rems = set()
    for f in findings:
        rem = f.get("remediation")
        if rem and rem not in seen_rems:
            seen_rems.add(rem)
            rems.append(rem)
            
    if not rems:
        rems = ["Maintain current secure coding practices.", "Establish automated pre-commit SAST scanning hooks."]

    return {
        "scan_id": scan_id,
        "summary": summary,
        "findings": findings,
        "risk_score": round((100 - score) / 10, 1),
        "recommendations": rems
    }