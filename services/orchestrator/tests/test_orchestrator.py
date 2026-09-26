"""
test_orchestrator.py — Orchestrator test suite
==============================================

IBM Bob 2.0 Hackathon · /services/orchestrator/tests/

Regression tests for the orchestrator's nine subsystems and the HTTP API
surface. Everything runs offline against the built-in mock fallbacks — no
auditor, sandbox, LLM, or IBM Bob CLI required.

Run:  python -m pytest tests/ -q      (from services/orchestrator/)
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Make the orchestrator modules importable regardless of pytest's cwd.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402
from ast_mutation_engine import verify_refactor  # noqa: E402
from cross_language_parser import detect_language, scan_file  # noqa: E402
from enterprise_auth import create_access_token, decode_access_token  # noqa: E402
from master_event_bus import run_full_pipeline  # noqa: E402
from multi_agent_consensus import reach_consensus  # noqa: E402
from roi_calculator import calculate_roi  # noqa: E402
from self_healing_loop import parse_traceback, self_heal_code  # noqa: E402
from vector_cve_db import build_db_with_mock_catalog, lookup_cves_for_package  # noqa: E402

client = TestClient(main.app)

MD5_ORIGINAL = "import hashlib\ndef check(p, d): return hashlib.md5(p.encode()).hexdigest() == d\n"
MD5_PATCHED = MD5_ORIGINAL.replace("md5", "sha256")
FINDING = {"description": "deprecated md5 usage", "severity": "critical"}


def _token(role: str = "modernizer") -> str:
    return create_access_token("test-user", role)


# ---------------------------------------------------------------------------
# enterprise_auth
# ---------------------------------------------------------------------------

class TestAuth:
    def test_token_roundtrip(self) -> None:
        claims = decode_access_token(_token())
        assert claims["sub"] == "test-user" and claims["role"] == "modernizer"

    def test_tampered_token_rejected(self) -> None:
        with pytest.raises(ValueError):
            decode_access_token(_token()[:-2] + "xx")

    def test_login_and_call(self) -> None:
        resp = client.post("/token", data={"username": "admin", "password": "bob-hackathon-2026"})
        assert resp.status_code == 200
        assert resp.json()["token_type"] == "bearer"

    def test_bad_credentials_401(self) -> None:
        assert client.post("/token", data={"username": "admin", "password": "wrong"}).status_code == 401

    def test_modernize_requires_token(self) -> None:
        resp = client.post("/api/v1/modernize", json={"repo_path": "./x", "target_version": "python3.12"})
        assert resp.status_code == 401

    def test_modernize_requires_role(self) -> None:
        resp = client.post(
            "/api/v1/modernize",
            json={"repo_path": "./x", "target_version": "python3.12"},
            headers={"Authorization": f"Bearer {_token(role='viewer')}"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# ast_mutation_engine
# ---------------------------------------------------------------------------

class TestAstGate:
    def test_clean_patch_approved(self) -> None:
        assert verify_refactor(MD5_ORIGINAL, MD5_PATCHED).approved

    def test_eval_injection_blocked(self) -> None:
        assert not verify_refactor(MD5_ORIGINAL, MD5_PATCHED + "\neval(x)\n").safe

    def test_complexity_regression_blocked(self) -> None:
        slow = "for a in xs:\n    for b in ys:\n        for c in zs:\n            work(a,b,c)\n"
        assert not verify_refactor("work()\n", slow).complexity_ok

    def test_unparseable_refactor_rejected(self) -> None:
        assert not verify_refactor(MD5_ORIGINAL, "def broken(:\n").syntax_valid


# ---------------------------------------------------------------------------
# multi_agent_consensus
# ---------------------------------------------------------------------------

class TestConsensus:
    def test_good_patch_approved(self) -> None:
        result = asyncio.run(reach_consensus(MD5_ORIGINAL, MD5_PATCHED, FINDING))
        assert result.approved and result.consensus_score >= 0.7

    def test_evil_patch_vetoed(self) -> None:
        evil = MD5_ORIGINAL + "\nimport os\nos.system(user_input)\n"
        result = asyncio.run(reach_consensus(MD5_ORIGINAL, evil, FINDING))
        assert not result.approved  # security score collapses -> veto


# ---------------------------------------------------------------------------
# self_healing_loop
# ---------------------------------------------------------------------------

class TestSelfHealing:
    def test_traceback_parsing(self) -> None:
        tb = 'Traceback (most recent call last):\n  File "a.py", line 7, in f\nValueError: bad\n'
        info = parse_traceback(tb)
        assert info.exception_type == "ValueError" and info.line_number == 7

    def test_converges_on_mock_sandbox(self) -> None:
        result = asyncio.run(self_heal_code(MD5_ORIGINAL))
        assert result.success and result.total_attempts <= 5


# ---------------------------------------------------------------------------
# vector_cve_db
# ---------------------------------------------------------------------------

class TestCveDb:
    def test_lookup_requests(self) -> None:
        async def go() -> int:
            db = await build_db_with_mock_catalog()
            return len(await lookup_cves_for_package(db, "requests", "2.28.0"))
        assert asyncio.run(go()) >= 1


# ---------------------------------------------------------------------------
# roi_calculator
# ---------------------------------------------------------------------------

class TestRoi:
    def test_roi_math(self) -> None:
        summary = asyncio.run(calculate_roi(
            refactors=[{"status": "success", "original_code": MD5_ORIGINAL,
                        "refactored_code": MD5_PATCHED, "loop_depth_before": 2, "loop_depth_after": 1}],
            vulnerabilities=[{"file_path": "a.py", "severity": "critical"}],
        ))
        assert summary.total_hours_saved > 16  # critical base + diff + overhead
        assert summary.total_cost_saved_usd == pytest.approx(summary.total_hours_saved * 95, rel=0.01)
        assert summary.total_carbon_kg_co2e_per_year > 0  # depth 2 -> 1 counts

    def test_rejected_refactors_count_nothing(self) -> None:
        summary = asyncio.run(calculate_roi(
            refactors=[{"status": "rejected_consensus", "original_code": "a", "refactored_code": "b"}],
            vulnerabilities=[],
        ))
        assert summary.total_hours_saved == 0 and summary.refactors_analyzed == 0


# ---------------------------------------------------------------------------
# cross_language_parser
# ---------------------------------------------------------------------------

class TestPolyglot:
    def test_language_detection(self) -> None:
        assert detect_language("a.tsx").value == "typescript"
        assert detect_language("a.java").value == "java"
        assert detect_language("a.py").value == "python"

    def test_js_findings(self) -> None:
        findings = asyncio.run(scan_file("Login.tsx", 'eval(userInput)\n<div dangerouslySetInnerHTML={{__html: x}} />'))
        rule_ids = {f.rule_id for f in findings}
        assert "JS001" in rule_ids and "JS002" in rule_ids


# ---------------------------------------------------------------------------
# auditor contract adapter
# ---------------------------------------------------------------------------

class TestAuditorAdapter:
    def test_native_shape(self) -> None:
        data = {"vulnerabilities": [{"file_path": "a.py", "line_number": 1, "description": "d", "severity": "low"}]}
        items = main._adapt_auditor_payload(data)
        assert len(items) == 1 and items[0].severity == "low"

    def test_muhammed_auditor_shape(self) -> None:
        data = {
            "risk_score": 0.14, "high_risk_files": ["b.py"],
            "findings": [
                {"type": "taint", "issues": [{"file": "b.py", "line": 6, "variable": "query",
                                              "source": "request.args.get()", "sink": "obj.execute()"}]},
                {"type": "churn", "ranked_files": []},
            ],
        }
        items = main._adapt_auditor_payload(data)
        assert len(items) == 1
        assert items[0].file_path == "b.py" and items[0].severity == "high"


# ---------------------------------------------------------------------------
# master_event_bus end-to-end
# ---------------------------------------------------------------------------

class TestEventBusPipeline:
    def test_full_pipeline_completes(self) -> None:
        summary = asyncio.run(run_full_pipeline(repo_path="./x", target_version="python3.12"))
        topics = {line.split(":")[0] for line in summary.timeline}
        assert "pipeline.complete" in topics
        assert "consensus.reached" in topics


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------

class TestApi:
    def test_health(self) -> None:
        assert client.get("/health").json() == {"status": "ok"}

    def test_metrics_endpoint(self) -> None:
        resp = client.get("/metrics")
        assert resp.status_code == 200 and "modernizer_" in resp.text

    def test_modernize_happy_path(self) -> None:
        resp = client.post(
            "/api/v1/modernize",
            json={"repo_path": "./nonexistent", "target_version": "python3.12"},
            headers={"Authorization": f"Bearer {_token()}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["auditor_source"] == "mock"
        assert len(body["vulnerabilities"]) >= 1
        assert "roi_summary" in body and body["roi_summary"]["total_cost_saved_usd"] >= 0
        assert body["event_timeline"]  # bus events recorded

    def test_stream_logs_sse(self) -> None:
        with client.stream("GET", "/api/v1/stream-logs") as resp:
            assert resp.status_code == 200
            text = "".join(resp.iter_text())
        assert "data:" in text and "pipeline.complete" in text
