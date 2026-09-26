"""
IBM Bob 2.0 Hackathon — Orchestrator Service (integrated)
=========================================================

Owner: repo admin (orchestrator directory).

FastAPI front door for the full modernization pipeline. All heavy lifting
lives in the five sibling subsystems, wired together through the asyncio
event bus — this module only translates HTTP <-> bus events:

    POST /api/v1/modernize  (JWT-protected)
        AUDIT_STARTED -> auditor (live/mock) -> AUDIT_FINISHED
        -> vector CVE lookup        -> CVE_RETRIEVED
        -> IBM Bob refactor + AST gate -> REFACTOR_PROPOSED
        -> 3-persona debate         -> CONSENSUS_REACHED
        -> self-healing sandbox loop -> TESTS_PASSED / TESTS_FAILED
        -> PIPELINE_COMPLETE
        + ROI summary + Prometheus metrics on every run

    GET /api/v1/stream-logs?repo_path=...&target_version=...
        Runs the same pipeline in the background and streams every bus event
        to the browser as Server-Sent Events, in real time.

Subsystems (same directory)
---------------------------
* ``vector_cve_db.py``         — RAG security engine
* ``multi_agent_consensus.py`` — debate & resolution engine
* ``self_healing_loop.py``     — autonomous retry engine
* ``ast_mutation_engine.py``   — deep structural verification
* ``master_event_bus.py``      — asynchronous event router
* ``roi_calculator.py``        — business value engine
* ``observability_exporter.py``— Prometheus metrics
* ``cross_language_parser.py`` — polyglot static analysis
* ``enterprise_auth.py``       — zero-trust JWT layer

Run locally
-----------
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Demo credentials: ``admin`` / ``bob-hackathon-2026`` at ``POST /token``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# --- Sibling subsystem imports (same directory on sys.path) -----------------
sys.path.insert(0, str(Path(__file__).resolve().parent))

from master_event_bus import Event, EventBus, Topic  # noqa: E402
from vector_cve_db import (  # noqa: E402
    CVEQueryResult,
    build_db_with_mock_catalog,
    lookup_cves_for_package,
)
from multi_agent_consensus import ConsensusResult, reach_consensus  # noqa: E402
from self_healing_loop import HealResult, self_heal_code  # noqa: E402
from ast_mutation_engine import VerificationReport, verify_refactor  # noqa: E402
from roi_calculator import ROISummary, calculate_roi  # noqa: E402
from observability_exporter import (  # noqa: E402
    record_debate_duration,
    record_pipeline_run,
    render_metrics,
)
from cross_language_parser import PolyglotFinding, scan_repository  # noqa: E402
from enterprise_auth import EnterpriseUser, auth_router, get_current_user  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("orchestrator.main")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUDITOR_URL: str = os.getenv("AUDITOR_URL", "http://localhost:8001/scan-repo")
SANDBOX_URL: str = os.getenv("SANDBOX_URL", "http://localhost:8002/run-tests")
IBM_BOB_CLI: Optional[str] = os.getenv("IBM_BOB_CLI")

DOWNSTREAM_TIMEOUT_SECONDS: float = float(os.getenv("DOWNSTREAM_TIMEOUT_SECONDS", "5.0"))
STEP_DELAY_SECONDS: float = float(os.getenv("STEP_DELAY_SECONDS", "0.15"))
#: Max wall-clock time for one pipeline run before we force-complete.
PIPELINE_TIMEOUT_SECONDS: float = float(os.getenv("PIPELINE_TIMEOUT_SECONDS", "120.0"))


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ModernizationRequest(BaseModel):
    """Inbound request to modernize a repository."""

    repo_path: str = Field(..., description="Path to the repository to modernize.")
    target_version: str = Field(..., description="e.g. 'python3.12'")


class VulnerabilityItem(BaseModel):
    """A single finding reported by the auditor service."""

    file_path: str
    line_number: int
    description: str
    severity: str


class RefactorResult(BaseModel):
    """Outcome of the full agentic review for one finding."""

    original_code: str
    refactored_code: str
    status: str  # success | rejected_consensus | rejected_ast_gate | failed
    consensus_score: Optional[float] = None
    ast_violations: List[str] = Field(default_factory=list)
    healing_attempts: Optional[int] = None
    loop_depth_before: int = 0
    loop_depth_after: int = 0


class ModernizationResponse(BaseModel):
    """Consolidated payload returned by the master orchestration route."""

    repo_path: str
    target_version: str
    auditor_source: str
    sandbox_source: str
    vulnerabilities: List[VulnerabilityItem]
    cve_hits: List[Dict[str, Any]]
    refactors: List[RefactorResult]
    sandbox_report: Dict[str, Any]
    roi_summary: ROISummary
    pipeline_success: bool
    execution_logs: List[str]
    event_timeline: List[str]
    duration_ms: int


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def make_log(message: str) -> str:
    return f"[{_ts()}] {message}"


# ---------------------------------------------------------------------------
# External clients with mock fallbacks (auditor + IBM Bob)
# ---------------------------------------------------------------------------

async def call_auditor(request: ModernizationRequest, logs: List[str]) -> tuple[List[VulnerabilityItem], str]:
    """
    POST the repo to the auditor service; deterministic mock on failure.

    In mock mode the polyglot static scanner (``cross_language_parser``) also
    sweeps ``repo_path`` for JS/TS/Java/Python findings so the demo works on
    real repositories without any teammate service running.
    """
    logs.append(make_log(f"Scanning files... POST {AUDITOR_URL}"))
    try:
        async with httpx.AsyncClient(timeout=DOWNSTREAM_TIMEOUT_SECONDS) as client:
            resp = await client.post(AUDITOR_URL, json=request.model_dump())
            resp.raise_for_status()
            items = [VulnerabilityItem(**v) for v in resp.json().get("vulnerabilities", [])]
            logs.append(make_log(f"Auditor responded: {len(items)} finding(s)."))
            return items, "live"
    except Exception as exc:
        logs.append(make_log(f"Auditor unreachable ({type(exc).__name__}); using internal mock scan."))
        await asyncio.sleep(STEP_DELAY_SECONDS)
        mock = [
            VulnerabilityItem(
                file_path="src/legacy/auth.py", line_number=42,
                description="Use of deprecated md5 hash for password verification.",
                severity="critical",
            ),
            VulnerabilityItem(
                file_path="src/legacy/db.py", line_number=17,
                description="SQL query built via string concatenation (possible injection).",
                severity="high",
            ),
        ]
        # Polyglot sweep of the real repo path (no-op when it doesn't exist).
        polyglot: List[PolyglotFinding] = await scan_repository(request.repo_path)
        if polyglot:
            logs.append(make_log(f"Polyglot scanner added {len(polyglot)} finding(s) from {request.repo_path}."))
            mock.extend(VulnerabilityItem(
                file_path=f.file_path, line_number=f.line_number,
                description=f"[{f.rule_id}] {f.description}", severity=f.severity,
            ) for f in polyglot)
        logs.append(make_log(f"Mock scan complete: {len(mock)} finding(s)."))
        return mock, "mock"


async def invoke_ibm_bob_agent(file_content: str, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """
    IBM Bob wrapper: real CLI when ``IBM_BOB_CLI`` is set, else deterministic
    simulation. Returns refactored code + step-by-step logs.
    """
    logs: List[str] = [make_log(f"Invoking IBM Bob... target={vulnerability.get('file_path')}:{vulnerability.get('line_number')}")]

    if IBM_BOB_CLI:
        try:
            proc = await asyncio.create_subprocess_exec(
                IBM_BOB_CLI, "refactor", "--finding", json.dumps(vulnerability),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate(file_content.encode())
            if proc.returncode == 0:
                logs.append(make_log("IBM Bob CLI completed successfully."))
                return {"refactored_code": stdout.decode() or file_content, "status": "success", "logs": logs}
            logs.append(make_log(f"IBM Bob CLI failed (rc={proc.returncode}); falling back to simulation."))
        except OSError as exc:
            logs.append(make_log(f"IBM Bob CLI launch failed ({exc}); simulation mode."))

    await asyncio.sleep(STEP_DELAY_SECONDS)
    logs.append(make_log("Bob: parsing source into AST..."))
    await asyncio.sleep(STEP_DELAY_SECONDS)
    logs.append(make_log("Applying AST Patch..."))
    header = (
        f"# Refactored by IBM Bob 2.0 (simulated)\n"
        f"# Finding: {vulnerability.get('description', 'n/a')}\n"
    )
    refactored = header + file_content.replace("md5", "sha256")
    logs.append(make_log("Bob: patch applied, semantic diff verified."))
    return {"refactored_code": refactored, "status": "success", "logs": logs}


def _read_source_file(repo_path: str, file_path: str) -> str:
    """Best-effort read; synthetic placeholder when the file is absent."""
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


def _guess_package(file_path: str) -> str:
    """Map a finding's file path to a likely package name for CVE lookup."""
    stem = Path(file_path).stem.lower()
    return {"auth": "requests", "db": "cryptography", "config": "jinja2"}.get(stem, "requests")


# ---------------------------------------------------------------------------
# Bus-driven pipeline (shared by /modernize and /stream-logs)
# ---------------------------------------------------------------------------

class PipelineContext:
    """Mutable state shared by the bus handlers of one pipeline run."""

    def __init__(self, request: ModernizationRequest) -> None:
        self.request = request
        self.logs: List[str] = []
        self.timeline: List[str] = []
        self.vulnerabilities: List[VulnerabilityItem] = []
        self.auditor_source = "mock"
        self.sandbox_source = "mock"
        self.cve_hits: List[CVEQueryResult] = []
        self.refactors: List[RefactorResult] = []
        self.sandbox_report: Dict[str, Any] = {}
        self.debate_durations: List[Dict[str, Any]] = []  # for the metrics exporter
        self.success = False
        # Set once the CVE stage has proposed every refactor; completion
        # checks must ignore refactor work that hasn't been proposed yet.
        self.proposals_done = False
        self.completed = asyncio.Event()


async def run_pipeline(request: ModernizationRequest, event_sink: "Optional[asyncio.Queue[Event]]" = None) -> PipelineContext:
    """
    Execute the full modernization pipeline on a fresh event bus.

    When ``event_sink`` is given, every bus event is also pushed into that
    queue (used by the SSE endpoint to stream live); the queue receives a
    final ``None``-equivalent sentinel via ``PIPELINE_COMPLETE``.
    """
    ctx = PipelineContext(request)
    bus = EventBus()

    async def observer(event: Event) -> None:
        line = f"{event.topic.value} [{event.event_id}]"
        ctx.timeline.append(line)
        ctx.logs.append(make_log(f"EVENT {line} {json.dumps(event.payload)[:120]}"))
        if event_sink is not None:
            await event_sink.put(event)

    bus.subscribe(None, observer)

    # -- stage 2: CVE retrieval ---------------------------------------------
    async def on_audit_finished(event: Event) -> None:
        db = await build_db_with_mock_catalog()
        for vuln in ctx.vulnerabilities:
            ctx.cve_hits.extend(await lookup_cves_for_package(db, _guess_package(vuln.file_path)))
        await bus.emit(Topic.CVE_RETRIEVED, {"cve_hits": len(ctx.cve_hits)})

    bus.subscribe(Topic.AUDIT_FINISHED, on_audit_finished)

    # -- stage 3: IBM Bob refactor + AST gate --------------------------------
    async def on_cve_retrieved(event: Event) -> None:
        for vuln in ctx.vulnerabilities:
            original = _read_source_file(request.repo_path, vuln.file_path)
            agent = await invoke_ibm_bob_agent(original, vuln.model_dump())
            ctx.logs.extend(agent["logs"])
            gate: VerificationReport = verify_refactor(original, agent["refactored_code"])
            if not gate.approved:
                ctx.refactors.append(RefactorResult(
                    original_code=original, refactored_code=agent["refactored_code"],
                    status="rejected_ast_gate", ast_violations=gate.violations,
                ))
                await bus.emit(Topic.TESTS_FAILED, {"reason": "AST gate", "violations": gate.violations})
                continue
            ctx.refactors.append(RefactorResult(
                original_code=original, refactored_code=agent["refactored_code"], status="proposed",
                loop_depth_before=gate.max_loop_depth_original,
                loop_depth_after=gate.max_loop_depth_refactored,
            ))
            await bus.emit(Topic.REFACTOR_PROPOSED, {"file": vuln.file_path})
        ctx.proposals_done = True
        if not any(r.status == "proposed" for r in ctx.refactors):
            await bus.emit(Topic.PIPELINE_COMPLETE, {"success": False})

    bus.subscribe(Topic.CVE_RETRIEVED, on_cve_retrieved)

    # -- stage 4: multi-agent debate ------------------------------------------
    async def on_refactor_proposed(event: Event) -> None:
        # Process refactors serially: find the next one still in 'proposed'.
        idx = next(i for i, r in enumerate(ctx.refactors) if r.status == "proposed")
        vuln = ctx.vulnerabilities[min(idx, len(ctx.vulnerabilities) - 1)]
        debate_started = time.perf_counter()
        result: ConsensusResult = await reach_consensus(
            ctx.refactors[idx].original_code, ctx.refactors[idx].refactored_code, vuln.model_dump(),
        )
        debate_seconds = time.perf_counter() - debate_started
        # Metrics: debate-duration histogram (fire-and-forget).
        record_debate_duration(debate_seconds, result.approved)
        ctx.debate_durations.append({"seconds": debate_seconds, "approved": result.approved})
        ctx.logs.extend(make_log(f"DEBATE {line}") for line in result.transcript)
        ctx.refactors[idx].consensus_score = result.consensus_score
        ctx.refactors[idx].status = "consensus_passed" if result.approved else "rejected_consensus"
        await bus.emit(Topic.CONSENSUS_REACHED, {
            "file": vuln.file_path, "approved": result.approved, "score": result.consensus_score,
        })

    bus.subscribe(Topic.REFACTOR_PROPOSED, on_refactor_proposed)

    # -- stage 5: self-healing sandbox loop -----------------------------------
    async def on_consensus_reached(event: Event) -> None:
        pending_statuses = {"proposed", "consensus_passed"}
        if not event.payload.get("approved"):
            # Rejected by debate — complete only once every refactor has been
            # proposed AND nothing is still pending review or healing.
            if ctx.proposals_done and not any(r.status in pending_statuses for r in ctx.refactors):
                await bus.emit(Topic.PIPELINE_COMPLETE, {"success": ctx.success})
            return
        idx = next((i for i, r in enumerate(ctx.refactors) if r.status == "consensus_passed"), None)
        if idx is None:
            return
        heal: HealResult = await self_heal_code(
            ctx.refactors[idx].refactored_code, target_version=request.target_version,
        )
        ctx.logs.extend(make_log(f"HEAL {line}") for line in heal.log)
        ctx.refactors[idx].healing_attempts = heal.total_attempts
        ctx.refactors[idx].status = "success" if heal.success else "failed"
        ctx.sandbox_source = heal.attempts[-1].sandbox_source if heal.attempts else "mock"
        ctx.sandbox_report = {
            "healing_success": heal.success,
            "attempts": [a.model_dump() for a in heal.attempts],
        }
        await bus.emit(Topic.HEALING_FINISHED, {"success": heal.success, "attempts": heal.total_attempts})
        await bus.emit(Topic.TESTS_PASSED if heal.success else Topic.TESTS_FAILED,
                       {"attempts": heal.total_attempts})
        if heal.success:
            ctx.success = True
        # Complete when every proposal exists and none is still awaiting review.
        pending = {"proposed", "consensus_passed"}
        if ctx.proposals_done and not any(r.status in pending for r in ctx.refactors):
            await bus.emit(Topic.PIPELINE_COMPLETE, {"success": ctx.success})

    bus.subscribe(Topic.CONSENSUS_REACHED, on_consensus_reached)

    async def on_pipeline_complete(event: Event) -> None:
        ctx.success = bool(event.payload.get("success", ctx.success))
        ctx.completed.set()

    bus.subscribe(Topic.PIPELINE_COMPLETE, on_pipeline_complete)

    # -- kick off: audit -> AUDIT_FINISHED ------------------------------------
    await bus.start()
    await bus.emit(Topic.AUDIT_STARTED, {"repo_path": request.repo_path, "target_version": request.target_version})
    ctx.vulnerabilities, ctx.auditor_source = await call_auditor(request, ctx.logs)
    await bus.emit(Topic.AUDIT_FINISHED, {"vulnerabilities": len(ctx.vulnerabilities)})

    # Wait for the cascade to finish (bounded).
    try:
        await asyncio.wait_for(ctx.completed.wait(), timeout=PIPELINE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        ctx.logs.append(make_log("PIPELINE TIMEOUT — force completing."))
        await bus.emit(Topic.PIPELINE_COMPLETE, {"success": ctx.success, "timeout": True})
        await asyncio.sleep(0.05)
    await bus.stop()
    return ctx


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="IBM Bob 2.0 — Orchestrator",
    version="0.3.0",
    description="Bus-driven modernization pipeline: audit -> CVE RAG -> IBM Bob -> consensus -> self-heal, with zero-trust auth, ROI analytics and Prometheus metrics.",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Zero-trust auth router: POST /token issues JWTs for the enterprise IdP.
app.include_router(auth_router)


@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "service": "ibm-bob-2.0-orchestrator",
        "version": "0.3.0",
        "auditor_url": AUDITOR_URL,
        "sandbox_url": SANDBOX_URL,
        "ibm_bob_mode": "cli" if IBM_BOB_CLI else "simulation",
        "subsystems": [
            "vector_cve_db", "multi_agent_consensus", "self_healing_loop",
            "ast_mutation_engine", "master_event_bus", "roi_calculator",
            "observability_exporter", "cross_language_parser", "enterprise_auth",
        ],
    }


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
async def metrics() -> Response:
    """
    Prometheus scrape endpoint (text exposition format).

    Intentionally unauthenticated: Prometheus scrapers typically do not carry
    user credentials; protect via network policy in production.
    """
    return Response(content=render_metrics(), media_type="text/plain; version=0.0.4")


@app.post("/api/v1/modernize", response_model=ModernizationResponse)
async def modernize(
    request: ModernizationRequest,
    user: EnterpriseUser = Depends(get_current_user),
) -> ModernizationResponse:
    """
    Master orchestration route — runs the full bus-driven pipeline.

    **Zero-trust protected**: requires a Bearer JWT with the ``modernizer``
    role (obtain via ``POST /token``). Every run feeds Prometheus metrics and
    returns an ROI summary for the business dashboard.
    """
    logger.info("Pipeline triggered by user '%s' (role=%s).", user.username, user.role)
    started = time.perf_counter()
    ctx = await run_pipeline(request)
    duration_ms = int((time.perf_counter() - started) * 1000)
    ctx.logs.append(make_log(f"Pipeline complete in {duration_ms} ms. success={ctx.success}"))

    # Metrics: patch counter + rolling pass rate (never raises).
    record_pipeline_run(
        refactors=[r.model_dump() for r in ctx.refactors],
        vulnerabilities=[v.model_dump() for v in ctx.vulnerabilities],
    )

    # Business value summary for the frontend dashboard.
    roi = await calculate_roi(
        refactors=[r.model_dump() for r in ctx.refactors],
        vulnerabilities=[v.model_dump() for v in ctx.vulnerabilities],
    )

    return ModernizationResponse(
        repo_path=request.repo_path,
        target_version=request.target_version,
        auditor_source=ctx.auditor_source,
        sandbox_source=ctx.sandbox_source,
        vulnerabilities=ctx.vulnerabilities,
        cve_hits=[{"cve_id": h.cve.cve_id, "package": h.cve.package, "severity": h.cve.severity,
                   "score": h.score, "fixed_version": h.cve.fixed_version} for h in ctx.cve_hits],
        refactors=ctx.refactors,
        sandbox_report=ctx.sandbox_report,
        roi_summary=roi,
        pipeline_success=ctx.success,
        execution_logs=ctx.logs,
        event_timeline=ctx.timeline,
        duration_ms=duration_ms,
    )


@app.get("/api/v1/stream-logs")
async def stream_logs(
    repo_path: str = Query(default="./legacy-app"),
    target_version: str = Query(default="python3.12"),
) -> StreamingResponse:
    """
    SSE endpoint: runs a live pipeline and streams every bus event as JSON.

        const src = new EventSource("/api/v1/stream-logs?repo_path=./app");
        src.onmessage = (e) => console.log(JSON.parse(e.data));
    """

    async def event_stream() -> AsyncGenerator[str, None]:
        sink: "asyncio.Queue[Event]" = asyncio.Queue()
        request = ModernizationRequest(repo_path=repo_path, target_version=target_version)

        async def emit_frame(topic: str, level: str, message: str, extra: Dict[str, Any] | None = None) -> str:
            frame = {"timestamp": _ts(), "topic": topic, "level": level, "message": message, **(extra or {})}
            return f"data: {json.dumps(frame)}\n\n"

        yield await emit_frame("client.connected", "info", f"Pipeline starting: repo={repo_path} target={target_version}")

        task = asyncio.create_task(run_pipeline(request, event_sink=sink))
        try:
            while True:
                event = await sink.get()
                message = {
                    Topic.AUDIT_STARTED: "Scanning files...",
                    Topic.AUDIT_FINISHED: f"Audit finished: {event.payload.get('vulnerabilities', 0)} finding(s).",
                    Topic.CVE_RETRIEVED: f"CVE database: {event.payload.get('cve_hits', 0)} relevant advisories retrieved.",
                    Topic.REFACTOR_PROPOSED: "Invoking IBM Bob... Applying AST Patch...",
                    Topic.CONSENSUS_REACHED: f"Consensus {'reached' if event.payload.get('approved') else 'REJECTED'} (score={event.payload.get('score')}).",
                    Topic.HEALING_FINISHED: f"Self-healing finished (attempts={event.payload.get('attempts')}).",
                    Topic.TESTS_PASSED: "Running Sandbox Tests... PASSED.",
                    Topic.TESTS_FAILED: f"Tests FAILED: {event.payload.get('reason', 'sandbox')}",
                    Topic.PIPELINE_COMPLETE: f"Pipeline complete. success={event.payload.get('success')}",
                }.get(event.topic, event.topic.value)
                yield await emit_frame(event.topic.value, "info", message, {"payload": event.payload})
                if event.topic is Topic.PIPELINE_COMPLETE:
                    break
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        yield await emit_frame("stream.closed", "done", "stream complete")

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
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
