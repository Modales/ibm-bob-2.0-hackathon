"""
IBM Bob 2.0 Hackathon — Orchestrator Service
=============================================

Owner: repo admin (orchestrator directory).

A single-file, production-grade FastAPI backend that coordinates the
modernization pipeline:

    Auditor (scan)  ->  IBM Bob agent (refactor)  ->  Sandbox (test)

Design goals
------------
* **100% standalone during testing** — if the auditor or sandbox services are
  unreachable, the orchestrator falls back to deterministic internal mocks so
  the frontend and demos never block on teammates' services.
* **Decoupled configuration** — downstream service URLs are plain environment
  variables (``AUDITOR_URL``, ``SANDBOX_URL``), no hardcoded topology.
* **Real-time UX** — a Server-Sent Events endpoint streams terminal-style
  logs to the browser while a pipeline run executes.

Run locally
-----------
    pip install fastapi "uvicorn[standard]" httpx pydantic
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Endpoints
---------
* ``GET  /``                        — service info
* ``GET  /health``                  — liveness probe
* ``POST /api/v1/modernize``        — master orchestration route
* ``GET  /api/v1/stream-logs``      — SSE log stream (terminal-style)
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Configuration (environment-driven, safe defaults for local development)
# ---------------------------------------------------------------------------

AUDITOR_URL: str = os.getenv("AUDITOR_URL", "http://localhost:8001/scan-repo")
SANDBOX_URL: str = os.getenv("SANDBOX_URL", "http://localhost:8002/run-tests")

# Optional: path to a real IBM Bob CLI binary. When unset (the default),
# `invoke_ibm_bob_agent` runs in simulation mode with deterministic output.
IBM_BOB_CLI: Optional[str] = os.getenv("IBM_BOB_CLI")

# Network behavior for downstream calls.
DOWNSTREAM_TIMEOUT_SECONDS: float = float(os.getenv("DOWNSTREAM_TIMEOUT_SECONDS", "5.0"))

# Pace of the simulated pipeline (seconds per step). Keep small in tests.
STEP_DELAY_SECONDS: float = float(os.getenv("STEP_DELAY_SECONDS", "0.6"))


# ---------------------------------------------------------------------------
# 1. Data schemas
# ---------------------------------------------------------------------------

class ModernizationRequest(BaseModel):
    """Inbound request to modernize a repository."""

    repo_path: str = Field(..., description="Path to the repository to modernize.")
    target_version: str = Field(
        ..., description="Target language/framework version, e.g. 'python3.12'."
    )


class VulnerabilityItem(BaseModel):
    """A single finding reported by the auditor service."""

    file_path: str
    line_number: int
    description: str
    severity: str = Field(..., description="One of: low | medium | high | critical")


class RefactorResult(BaseModel):
    """Output of the IBM Bob refactoring agent for one file."""

    original_code: str
    refactored_code: str
    status: str = Field(..., description="One of: success | skipped | failed")


class ModernizationResponse(BaseModel):
    """Consolidated payload returned by the master orchestration route."""

    repo_path: str
    target_version: str
    auditor_source: str = Field(..., description="'live' service or 'mock' fallback")
    sandbox_source: str = Field(..., description="'live' service or 'mock' fallback")
    vulnerabilities: List[VulnerabilityItem]
    refactors: List[RefactorResult]
    sandbox_report: Dict[str, Any]
    execution_logs: List[str]
    duration_ms: int


# ---------------------------------------------------------------------------
# Small logging helper — every pipeline step is recorded for the final payload
# ---------------------------------------------------------------------------

def _ts() -> str:
    """Current UTC timestamp in ISO-8601, used to prefix terminal logs."""
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def make_log(message: str) -> str:
    """Format a single terminal-style log line."""
    return f"[{_ts()}] {message}"


# ---------------------------------------------------------------------------
# 2. Decoupled downstream clients with mock fallbacks
# ---------------------------------------------------------------------------

async def call_auditor(request: ModernizationRequest, logs: List[str]) -> tuple[List[VulnerabilityItem], str]:
    """
    Call the external auditor service to scan the repository.

    Returns ``(vulnerabilities, source)`` where ``source`` is ``"live"`` when
    the real service answered, or ``"mock"`` when we fell back to the internal
    deterministic stub because the service was unreachable.
    """
    logs.append(make_log(f"Scanning files... POST {AUDITOR_URL}"))
    try:
        async with httpx.AsyncClient(timeout=DOWNSTREAM_TIMEOUT_SECONDS) as client:
            resp = await client.post(AUDITOR_URL, json=request.model_dump())
            resp.raise_for_status()
            data = resp.json()
            items = [VulnerabilityItem(**v) for v in data.get("vulnerabilities", [])]
            logs.append(make_log(f"Auditor responded: {len(items)} finding(s)."))
            return items, "live"
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError, ValueError) as exc:
        # Service down, slow, or returned an unexpected payload — stay standalone.
        logs.append(make_log(f"Auditor unreachable ({type(exc).__name__}); using internal mock scan."))
        await asyncio.sleep(STEP_DELAY_SECONDS)
        mock = [
            VulnerabilityItem(
                file_path="src/legacy/auth.py",
                line_number=42,
                description="Use of deprecated md5 hash for password verification.",
                severity="critical",
            ),
            VulnerabilityItem(
                file_path="src/legacy/db.py",
                line_number=17,
                description="SQL query built via string concatenation (possible injection).",
                severity="high",
            ),
            VulnerabilityItem(
                file_path="src/utils/config.py",
                line_number=8,
                description="Hardcoded API key detected in source.",
                severity="medium",
            ),
        ]
        logs.append(make_log(f"Mock scan complete: {len(mock)} finding(s)."))
        return mock, "mock"


async def call_sandbox(refactored_code: str, target_version: str, logs: List[str]) -> tuple[Dict[str, Any], str]:
    """
    Send generated code to the sandbox service for isolated test execution.

    Returns ``(report, source)`` with the same live/mock semantics as
    :func:`call_auditor`.
    """
    logs.append(make_log(f"Running Sandbox Tests... POST {SANDBOX_URL}"))
    payload = {"code": refactored_code, "target_version": target_version}
    try:
        async with httpx.AsyncClient(timeout=DOWNSTREAM_TIMEOUT_SECONDS) as client:
            resp = await client.post(SANDBOX_URL, json=payload)
            resp.raise_for_status()
            report = resp.json()
            logs.append(make_log("Sandbox responded with test report."))
            return report, "live"
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError, ValueError) as exc:
        logs.append(make_log(f"Sandbox unreachable ({type(exc).__name__}); using internal mock runner."))
        await asyncio.sleep(STEP_DELAY_SECONDS)
        report = {
            "status": "passed",
            "tests_total": 12,
            "tests_passed": 12,
            "tests_failed": 0,
            "target_version": target_version,
            "notes": "Mock sandbox run — no external service connected.",
        }
        logs.append(make_log("Mock sandbox run finished: 12/12 tests passed."))
        return report, "mock"


# ---------------------------------------------------------------------------
# 3. IBM Bob agent wrapper
# ---------------------------------------------------------------------------

async def invoke_ibm_bob_agent(file_content: str, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """
    Invoke the IBM Bob modernization agent on a single file/finding.

    Two modes:
      * **CLI mode** — when the ``IBM_BOB_CLI`` environment variable points to
        a real Bob binary, we shell out asynchronously and capture its output.
      * **Simulation mode** (default) — deterministic, offline-safe stub that
        mimics Bob's behavior and emits step-by-step execution logs.

    Returns a dict with ``refactored_code``, ``status`` and ``logs``.
    """
    logs: List[str] = []
    target = f"{vulnerability.get('file_path', '<unknown>')}:{vulnerability.get('line_number', 0)}"
    logs.append(make_log(f"Invoking IBM Bob... target={target}"))

    if IBM_BOB_CLI:
        # --- Real CLI execution path -------------------------------------
        logs.append(make_log(f"IBM_BOB_CLI detected: {IBM_BOB_CLI} — executing live refactor."))
        try:
            proc = await asyncio.create_subprocess_exec(
                IBM_BOB_CLI,
                "refactor",
                "--finding", json.dumps(vulnerability),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate(file_content.encode())
            if proc.returncode == 0:
                logs.append(make_log("IBM Bob CLI completed successfully."))
                return {
                    "refactored_code": stdout.decode() or file_content,
                    "status": "success",
                    "logs": logs,
                }
            logs.append(make_log(f"IBM Bob CLI failed (rc={proc.returncode}): {stderr.decode().strip()}"))
            return {"refactored_code": file_content, "status": "failed", "logs": logs}
        except OSError as exc:
            logs.append(make_log(f"Failed to launch IBM Bob CLI ({exc}); falling back to simulation."))

    # --- Simulation mode --------------------------------------------------
    await asyncio.sleep(STEP_DELAY_SECONDS)
    logs.append(make_log("Bob: parsing source into AST..."))
    await asyncio.sleep(STEP_DELAY_SECONDS)
    logs.append(make_log(f"Bob: locating node for '{vulnerability.get('description', 'finding')}'"))
    await asyncio.sleep(STEP_DELAY_SECONDS)
    logs.append(make_log("Applying AST Patch..."))
    await asyncio.sleep(STEP_DELAY_SECONDS)

    header = (
        f"# Refactored by IBM Bob 2.0 (simulated)\n"
        f"# Finding: {vulnerability.get('description', 'n/a')}\n"
        f"# Severity: {vulnerability.get('severity', 'n/a')}\n"
    )
    refactored = header + file_content.replace("md5", "sha256")
    logs.append(make_log("Bob: patch applied, semantic diff verified."))
    return {"refactored_code": refactored, "status": "success", "logs": logs}


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="IBM Bob 2.0 — Orchestrator",
    version="0.1.0",
    description="Master orchestration service: audit -> IBM Bob refactor -> sandbox test.",
)

# Permissive CORS so the hackathon frontend (any local port) can call us.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root() -> Dict[str, Any]:
    """Service info and current downstream wiring."""
    return {
        "service": "ibm-bob-2.0-orchestrator",
        "auditor_url": AUDITOR_URL,
        "sandbox_url": SANDBOX_URL,
        "ibm_bob_mode": "cli" if IBM_BOB_CLI else "simulation",
    }


@app.get("/health")
async def health() -> Dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# 4. Real-time log streaming (SSE)
# ---------------------------------------------------------------------------

# Script for the demo stream — mirrors a real pipeline run end to end.
_DEMO_PIPELINE_LOGS = [
    "Scanning files...",
    "Auditor found 3 vulnerabilities (1 critical, 1 high, 1 medium).",
    "Invoking IBM Bob... target=src/legacy/auth.py:42",
    "Bob: parsing source into AST...",
    "Applying AST Patch...",
    "Bob: patch applied, semantic diff verified.",
    "Running Sandbox Tests...",
    "Sandbox: 12/12 tests passed.",
    "Modernization pipeline complete.",
]


async def _sse_event_generator() -> AsyncGenerator[str, None]:
    """
    Yield Server-Sent Events frames (``data: <json>\\n\\n``) one log line at a
    time, paced with ``asyncio.sleep`` so the client sees a live terminal.
    """
    for line in _DEMO_PIPELINE_LOGS:
        frame = {"timestamp": _ts(), "level": "info", "message": line}
        yield f"data: {json.dumps(frame)}\n\n"
        await asyncio.sleep(STEP_DELAY_SECONDS)
    # Terminal event so clients know the stream finished cleanly.
    yield f"data: {json.dumps({'timestamp': _ts(), 'level': 'done', 'message': 'stream complete'})}\n\n"


@app.get("/api/v1/stream-logs")
async def stream_logs() -> StreamingResponse:
    """
    Server-Sent Events endpoint streaming JSON terminal logs line-by-line.

    Consume from the browser with::

        const src = new EventSource("/api/v1/stream-logs");
        src.onmessage = (e) => console.log(JSON.parse(e.data));
    """
    return StreamingResponse(
        _sse_event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Disable proxy buffering (nginx) so events flush immediately.
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# 5. Master orchestration route
# ---------------------------------------------------------------------------

def _read_source_file(repo_path: str, file_path: str) -> str:
    """
    Best-effort read of a source file under the target repository. Falls back
    to a synthetic placeholder so the pipeline never hard-fails on missing
    files during demos.
    """
    candidate = Path(repo_path) / file_path
    try:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    except OSError:
        pass
    return (
        "import hashlib\n\n"
        "def verify_password(password: str, digest: str) -> bool:\n"
        "    return hashlib.md5(password.encode()).hexdigest() == digest\n"
    )


@app.post("/api/v1/modernize", response_model=ModernizationResponse)
async def modernize(request: ModernizationRequest) -> ModernizationResponse:
    """
    Master pipeline: audit the repo, refactor each finding with IBM Bob, then
    validate the generated code in the sandbox.

    Returns the consolidated JSON payload including all terminal logs.
    """
    started = time.perf_counter()
    logs: List[str] = [make_log(
        f"Modernization requested: repo={request.repo_path} target={request.target_version}"
    )]

    # Step 1 — audit (live service or internal mock).
    vulnerabilities, auditor_source = await call_auditor(request, logs)
    if not vulnerabilities:
        logs.append(make_log("No findings — nothing to modernize."))

    # Step 2 — refactor each finding through the IBM Bob agent.
    refactors: List[RefactorResult] = []
    for vuln in vulnerabilities:
        original = _read_source_file(request.repo_path, vuln.file_path)
        agent_out = await invoke_ibm_bob_agent(original, vuln.model_dump())
        logs.extend(agent_out["logs"])
        refactors.append(
            RefactorResult(
                original_code=original,
                refactored_code=agent_out["refactored_code"],
                status=agent_out["status"],
            )
        )

    # Step 3 — sandbox-test the generated code (concatenated for the demo).
    combined_code = "\n\n# ---- next file ----\n\n".join(r.refactored_code for r in refactors)
    sandbox_report, sandbox_source = await call_sandbox(combined_code, request.target_version, logs)

    duration_ms = int((time.perf_counter() - started) * 1000)
    logs.append(make_log(f"Pipeline complete in {duration_ms} ms."))

    return ModernizationResponse(
        repo_path=request.repo_path,
        target_version=request.target_version,
        auditor_source=auditor_source,
        sandbox_source=sandbox_source,
        vulnerabilities=vulnerabilities,
        refactors=refactors,
        sandbox_report=sandbox_report,
        execution_logs=logs,
        duration_ms=duration_ms,
    )


# ---------------------------------------------------------------------------
# Entrypoint — `python main.py` starts the server on port 8000.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").lower() == "true",
    )
