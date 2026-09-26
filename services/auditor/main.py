"""Auditor service — IBM Bob 2.0 hackathon. Owner: Rumman."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from churn import file_churn
from taint_scan import DEFAULT_SKIP_DIRS, scan_repo as _taint_scan_repo

app = FastAPI(title="Auditor Service")

# Directories that are never source code and should be skipped when walking.
# Re-exported from taint_scan so both modules share a single source of truth.
_SKIP_DIRS: frozenset[str] = DEFAULT_SKIP_DIRS

# Scoring weights (must sum to 1.0).
_TAINT_WEIGHT: float = 0.70
_CHURN_WEIGHT: float = 0.30

# How many top files to include in high_risk_files.
_TOP_N: int = 10


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    repo_path: str


class ScanResponse(BaseModel):
    risk_score: float          # repo-level aggregate (0–1)
    high_risk_files: list[str] # top files by per-file risk score
    findings: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _compute_risk_scores(
    taint_issues: list[dict[str, Any]],
    churn_ranked: list[dict[str, Any]],
) -> dict[str, float]:
    """Return a per-file risk score in [0, 1].

    Algorithm
    ---------
    * **Taint score** (70 %): ``min(finding_count / 5, 1.0)`` per file —
      five or more findings saturates the taint component at 1.0.
    * **Churn score** (30 %): normalised rank within the churn list so the
      most-churned file gets 1.0 and the least-churned gets 0.0.  Files not
      seen in churn data score 0.0.
    """
    # --- Taint component ---
    taint_counts: dict[str, int] = {}
    for issue in taint_issues:
        f = issue["file"]
        taint_counts[f] = taint_counts.get(f, 0) + 1

    # --- Churn component ---
    # churn_ranked is already sorted highest-first; assign a normalised rank.
    n_churn = len(churn_ranked)
    churn_score: dict[str, float] = {}
    for rank, entry in enumerate(churn_ranked):
        # rank 0 → score 1.0; rank n_churn-1 → score 0.0 (or 0 if only one)
        churn_score[entry["file"]] = (
            1.0 - rank / (n_churn - 1) if n_churn > 1 else 1.0
        )

    # --- Combine ---
    all_files = set(taint_counts) | set(churn_score)
    scores: dict[str, float] = {}
    for f in all_files:
        t = min(taint_counts.get(f, 0) / 5.0, 1.0)
        c = churn_score.get(f, 0.0)
        scores[f] = round(_TAINT_WEIGHT * t + _CHURN_WEIGHT * c, 4)
    return scores


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@app.post("/scan-repo", response_model=ScanResponse)
def scan_repo(body: ScanRequest) -> ScanResponse:
    """Scan a locally cloned repository and return a risk assessment."""
    repo_path = Path(body.repo_path)
    if not repo_path.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {repo_path}")

    # --- Taint analysis (every .py file, skipping non-source dirs) ---
    taint_issues: list[dict[str, Any]] = cast(
        list[dict[str, Any]], list(_taint_scan_repo(repo_path, skip_dirs=_SKIP_DIRS))
    )

    # --- Churn analysis (git history, last 90 days) ---
    try:
        churn_ranked: list[dict[str, Any]] = cast(
            list[dict[str, Any]], list(file_churn(repo_path, days=90))
        )
    except ValueError:
        # Repo may not have git history (e.g. a fresh export); degrade gracefully.
        churn_ranked = []

    # --- Per-file risk scores ---
    per_file_scores = _compute_risk_scores(taint_issues, churn_ranked)

    # --- high_risk_files: top-N by score, ties broken alphabetically ---
    sorted_files = sorted(
        per_file_scores.items(),
        key=lambda kv: (-kv[1], kv[0]),
    )
    high_risk_files = [f for f, _ in sorted_files[:_TOP_N]]

    # --- Repo-level aggregate score: mean of per-file scores (0 if none) ---
    risk_score = (
        round(sum(per_file_scores.values()) / len(per_file_scores), 4)
        if per_file_scores
        else 0.0
    )

    # --- findings: raw taint output + per-file scores ---
    findings: list[dict[str, Any]] = [
        {
            "type": "taint",
            "issues": taint_issues,
        },
        {
            "type": "churn",
            "ranked_files": churn_ranked,
        },
        {
            "type": "per_file_risk_scores",
            "scores": [
                {"file": f, "score": s}
                for f, s in sorted(per_file_scores.items(), key=lambda kv: -kv[1])
            ],
        },
    ]

    return ScanResponse(
        risk_score=risk_score,
        high_risk_files=high_risk_files,
        findings=findings,
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
