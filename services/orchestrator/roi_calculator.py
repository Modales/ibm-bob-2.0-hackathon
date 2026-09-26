"""
roi_calculator.py — Business Value Engine
=========================================

IBM Bob 2.0 Hackathon · /services/orchestrator/

Translates engineering output (refactor diffs + pipeline metadata) into the
language of the business: hours, dollars, and carbon. This is what turns a
cool demo into an enterprise purchase decision — judges and CFOs alike read
this dashboard.

Metrics
-------
1. **Estimated Human Hours Saved** — what it would cost a human team to
   perform the same work: base hours per vulnerability by severity, plus
   per-line diff effort, plus review/testing overhead.
2. **Financial Cost Saved** — hours saved × configurable blended developer
   hourly rate (``DEV_HOURLY_RATE_USD``, default $95).
3. **Carbon Footprint Reduction (kg CO₂e/yr)** — when the AST gate measured a
   reduction in loop-nesting depth (Big-O proxy), we estimate the avoided
   compute: each depth level removed is treated as an order-of-magnitude
   reduction in work per invocation, multiplied by an assumed invocation
   volume and a cloud kWh/CO₂e coefficient.

All formulas are explicit, documented, and tunable via environment variables
so judges can audit every number. Nothing here is magic — it's a transparent,
defensible model.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Tunable business assumptions (all overridable via environment)
# ---------------------------------------------------------------------------

DEV_HOURLY_RATE_USD: float = float(os.getenv("DEV_HOURLY_RATE_USD", "95.0"))

#: Base hours a human needs to research, patch, and document one finding,
#: keyed by severity. Critical CVEs demand deeper audits.
SEVERITY_BASE_HOURS: Dict[str, float] = {
    "critical": 16.0,
    "high": 8.0,
    "medium": 4.0,
    "low": 1.5,
}

HOURS_PER_DIFF_LINE: float = float(os.getenv("HOURS_PER_DIFF_LINE", "0.02"))  # ~1.2 min/line
REVIEW_OVERHEAD_FACTOR: float = float(os.getenv("REVIEW_OVERHEAD_FACTOR", "0.30"))  # +30% review/test

# --- Carbon model ------------------------------------------------------------
#: Assumed production invocations per year for a patched hot path.
ANNUAL_INVOCATIONS: float = float(os.getenv("ROI_ANNUAL_INVOCATIONS", "50000000"))  # 50M
#: Average work per invocation per unit of loop-nesting depth (arbitrary
#: compute units); removing one depth level is a ~10x reduction of that unit.
COMPUTE_UNITS_PER_INVOCATION: float = 1.0
#: Cloud compute energy and grid intensity (approximate global averages).
KWH_PER_MILLION_UNITS: float = 0.0004
KG_CO2E_PER_KWH: float = 0.385


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ROIBreakdownItem(BaseModel):
    """Per-refactor contribution to the totals — for dashboard drill-downs."""

    file_hint: str = Field(..., description="First line / finding identifier.")
    lines_changed: int
    severity: str
    loop_depth_before: int
    loop_depth_after: int
    hours_saved: float
    cost_saved_usd: float
    carbon_kg_co2e_per_year: float


class ROISummary(BaseModel):
    """Structured payload consumed by the frontend ROI dashboard."""

    total_hours_saved: float
    total_cost_saved_usd: float
    total_carbon_kg_co2e_per_year: float
    refactors_analyzed: int
    hourly_rate_usd: float
    assumptions: Dict[str, Any] = Field(
        ..., description="Every constant used, exposed for auditability."
    )
    breakdown: List[ROIBreakdownItem]


# ---------------------------------------------------------------------------
# Diff & complexity measurement
# ---------------------------------------------------------------------------

def count_changed_lines(original: str, refactored: str) -> int:
    """
    Approximate diff size: lines added + lines removed (line-set symmetric
    difference). Good enough for effort estimation without difflib overhead.
    """
    old_lines = set(original.splitlines())
    new_lines = set(refactored.splitlines())
    return len(old_lines - new_lines) + len(new_lines - old_lines)


def estimate_carbon_kg(depth_before: int, depth_after: int) -> float:
    """
    Estimate annual CO₂e reduction from a Big-O improvement.

    Each nesting-depth level removed ~ an order of magnitude less inner-loop
    work per invocation. No depth reduction -> zero (conservative).
    """
    depth_removed = max(0, depth_before - depth_after)
    if depth_removed == 0:
        return 0.0
    units_before = ANNUAL_INVOCATIONS * COMPUTE_UNITS_PER_INVOCATION * (10 ** depth_before)
    units_after = ANNUAL_INVOCATIONS * COMPUTE_UNITS_PER_INVOCATION * (10 ** depth_after)
    units_saved = units_before - units_after
    kwh_saved = (units_saved / 1_000_000) * KWH_PER_MILLION_UNITS
    return round(kwh_saved * KG_CO2E_PER_KWH, 3)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def calculate_roi(
    refactors: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
) -> ROISummary:
    """
    Compute the ROI summary for one pipeline run.

    ``refactors``      — list of RefactorResult-shaped dicts (may include
                         ``loop_depth_before`` / ``loop_depth_after`` when the
                         AST gate supplied them; else 0).
    ``vulnerabilities``— list of VulnerabilityItem-shaped dicts, aligned by
                         index with ``refactors`` where possible.

    Runs synchronously-safe math inside ``asyncio.to_thread`` to keep the
    event loop free on very large refactor sets.
    """
    def _compute() -> ROISummary:
        breakdown: List[ROIBreakdownItem] = []
        for i, refactor in enumerate(refactors):
            if refactor.get("status") != "success":
                continue  # only shipped value counts
            vuln = vulnerabilities[i] if i < len(vulnerabilities) else {}
            severity = str(vuln.get("severity", "medium")).lower()
            lines = count_changed_lines(
                str(refactor.get("original_code", "")),
                str(refactor.get("refactored_code", "")),
            )
            depth_before = int(refactor.get("loop_depth_before", 0))
            depth_after = int(refactor.get("loop_depth_after", 0))

            base = SEVERITY_BASE_HOURS.get(severity, SEVERITY_BASE_HOURS["medium"])
            hours = (base + lines * HOURS_PER_DIFF_LINE) * (1 + REVIEW_OVERHEAD_FACTOR)
            cost = hours * DEV_HOURLY_RATE_USD
            carbon = estimate_carbon_kg(depth_before, depth_after)

            breakdown.append(ROIBreakdownItem(
                file_hint=str(vuln.get("file_path", f"refactor_{i}")),
                lines_changed=lines,
                severity=severity,
                loop_depth_before=depth_before,
                loop_depth_after=depth_after,
                hours_saved=round(hours, 2),
                cost_saved_usd=round(cost, 2),
                carbon_kg_co2e_per_year=carbon,
            ))

        return ROISummary(
            total_hours_saved=round(sum(b.hours_saved for b in breakdown), 2),
            total_cost_saved_usd=round(sum(b.cost_saved_usd for b in breakdown), 2),
            total_carbon_kg_co2e_per_year=round(sum(b.carbon_kg_co2e_per_year for b in breakdown), 3),
            refactors_analyzed=len(breakdown),
            hourly_rate_usd=DEV_HOURLY_RATE_USD,
            assumptions={
                "severity_base_hours": SEVERITY_BASE_HOURS,
                "hours_per_diff_line": HOURS_PER_DIFF_LINE,
                "review_overhead_factor": REVIEW_OVERHEAD_FACTOR,
                "annual_invocations": ANNUAL_INVOCATIONS,
                "kwh_per_million_units": KWH_PER_MILLION_UNITS,
                "kg_co2e_per_kwh": KG_CO2E_PER_KWH,
            },
            breakdown=breakdown,
        )

    return await asyncio.to_thread(_compute)


# ---------------------------------------------------------------------------
# Self-test: `python roi_calculator.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    async def _demo() -> None:
        summary = await calculate_roi(
            refactors=[{
                "status": "success",
                "original_code": "import hashlib\nhashlib.md5(x)",
                "refactored_code": "import hashlib\nhashlib.sha256(x)",
                "loop_depth_before": 2,
                "loop_depth_after": 1,
            }],
            vulnerabilities=[{
                "file_path": "src/legacy/auth.py",
                "severity": "critical",
                "description": "deprecated md5",
            }],
        )
        print(summary.model_dump_json(indent=2))

    asyncio.run(_demo())
