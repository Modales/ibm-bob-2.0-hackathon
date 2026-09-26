"""Auditor service — IBM Bob 2.0 hackathon. Owner: Rumman."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from churn import file_churn
from taint_scan import scan_repo as _taint_scan_repo

app = FastAPI(title="Auditor Service")


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    repo_path: str


class ScanResponse(BaseModel):
    risk_score: float
    high_risk_files: list[str]
    findings: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Stub analysis functions — replace with real implementations
# ---------------------------------------------------------------------------

def churn_analysis(repo_path: Path) -> dict[str, Any]:
    """Return commit-churn data for the repo at *repo_path* (last 90 days)."""
    ranked = file_churn(repo_path, days=90)
    return {
        "high_churn_files": [e["file"] for e in ranked],
        "churn_scores": {e["file"]: e["commit_count"] for e in ranked},
    }


def taint_scan(repo_path: Path) -> dict[str, Any]:
    """Scan all Python files under *repo_path* for taint-flow vulnerabilities."""
    findings = _taint_scan_repo(repo_path)
    return {"issues": list(findings)}


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@app.post("/scan-repo", response_model=ScanResponse)
def scan_repo(body: ScanRequest) -> ScanResponse:
    """Scan a locally cloned repository and return a risk assessment."""
    repo_path = Path(body.repo_path)
    if not repo_path.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {repo_path}")

    churn = churn_analysis(repo_path)
    taint = taint_scan(repo_path)

    high_risk_files: list[str] = list(
        set(churn.get("high_churn_files", [])) |
        {issue["file"] for issue in taint.get("issues", [])}
    )

    findings: list[dict[str, Any]] = [
        {"type": "churn", "detail": churn},
        {"type": "taint", "detail": taint},
    ]

    # Placeholder scoring: 0.0 until real analysis is wired up
    risk_score: float = 0.0

    return ScanResponse(
        risk_score=risk_score,
        high_risk_files=high_risk_files,
        findings=findings,
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
