"""
multi_agent_consensus.py — Debate & Resolution Engine
=====================================================

IBM Bob 2.0 Hackathon · /services/orchestrator/

A multi-agent review loop: after the IBM Bob API proposes a refactor, three
specialist personas debate the patch concurrently and a weighted consensus
score decides whether the patch is approved.

Personas
--------
* **Security Expert**   — does the patch actually close the CVE? Any new
  attack surface? (weight 0.5 — security vetoes everything)
* **Performance Guru**  — does the patch introduce regressions, allocations,
  blocking calls? (weight 0.25)
* **Legacy Maintainer** — is the change minimal, readable, and backwards
  compatible with the surrounding codebase? (weight 0.25)

LLM strategy
------------
If ``CONSENSUS_LLM_URL`` points at a live model endpoint, each persona prompt
is POSTed there concurrently and the JSON critiques are parsed from the
responses. Otherwise (the default), each persona runs a deterministic
heuristic review of the diff — fully offline, demo-safe, and reproducible.

Consensus math
--------------
Every persona returns per-dimension scores in [0, 1]. The consensus score is
the persona-weighted mean; a patch is approved only if
``score >= APPROVAL_THRESHOLD`` **and** the Security Expert's score is above
``SECURITY_VETO_THRESHOLD`` (security is never overruled by the average).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("orchestrator.multi_agent_consensus")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONSENSUS_LLM_URL: Optional[str] = os.getenv("CONSENSUS_LLM_URL")  # e.g. http://localhost:9000/chat
LLM_TIMEOUT_SECONDS: float = float(os.getenv("LLM_TIMEOUT_SECONDS", "20.0"))
DEBATE_ROUNDS: int = int(os.getenv("DEBATE_ROUNDS", "1"))

APPROVAL_THRESHOLD: float = float(os.getenv("APPROVAL_THRESHOLD", "0.70"))
SECURITY_VETO_THRESHOLD: float = float(os.getenv("SECURITY_VETO_THRESHOLD", "0.60"))

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover - offline fallback
    httpx = None  # type: ignore


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PersonaName(str, Enum):
    SECURITY_EXPERT = "security_expert"
    PERFORMANCE_GURU = "performance_guru"
    LEGACY_MAINTAINER = "legacy_maintainer"


class Critique(BaseModel):
    """Structured JSON critique produced by one persona for one round."""

    persona: PersonaName
    round: int = Field(..., ge=1)
    score: float = Field(..., ge=0.0, le=1.0, description="Overall approval in [0,1].")
    verdict: str = Field(..., description="approve | revise | reject")
    concerns: List[str] = Field(default_factory=list)
    suggestions: List[str] = Field(default_factory=list)

    @field_validator("verdict")
    @classmethod
    def _verdict_allowed(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"approve", "revise", "reject"}:
            raise ValueError(f"invalid verdict: {v}")
        return v


class ConsensusResult(BaseModel):
    """Final aggregated outcome of the debate."""

    approved: bool
    consensus_score: float = Field(..., ge=0.0, le=1.0)
    security_score: float = Field(..., ge=0.0, le=1.0)
    security_vetoed: bool
    critiques: List[Critique]
    transcript: List[str]
    rounds: int


@dataclass(frozen=True)
class Persona:
    """A debate participant: prompt style, weight, and heuristic reviewer."""

    name: PersonaName
    weight: float
    system_prompt: str


# ---------------------------------------------------------------------------
# Persona definitions
# ---------------------------------------------------------------------------

PERSONAS: Tuple[Persona, ...] = (
    Persona(
        name=PersonaName.SECURITY_EXPERT,
        weight=0.50,
        system_prompt=(
            "You are a staff application-security engineer. Review the proposed "
            "patch strictly for security: does it remediate the cited "
            "vulnerability, does it introduce eval/exec/injection/hardcoded "
            "secrets, does it weaken crypto? Reply with STRICT JSON: "
            '{"score": float 0..1, "verdict": "approve|revise|reject", '
            '"concerns": [...], "suggestions": [...]}'
        ),
    ),
    Persona(
        name=PersonaName.PERFORMANCE_GURU,
        weight=0.25,
        system_prompt=(
            "You are a performance engineer. Review the patch for algorithmic "
            "regressions, redundant work in hot paths, blocking I/O, and memory "
            "blowups. Reply with STRICT JSON: {\"score\": float 0..1, "
            "\"verdict\": \"approve|revise|reject\", \"concerns\": [...], "
            "\"suggestions\": [...]}"
        ),
    ),
    Persona(
        name=PersonaName.LEGACY_MAINTAINER,
        weight=0.25,
        system_prompt=(
            "You are the long-time maintainer of this legacy codebase. Review "
            "the patch for minimality, readability, style consistency, and "
            "backwards compatibility. Reply with STRICT JSON: {\"score\": float "
            "0..1, \"verdict\": \"approve|revise|reject\", \"concerns\": [...], "
            "\"suggestions\": [...]}"
        ),
    ),
)


# ---------------------------------------------------------------------------
# Offline heuristic reviewers (mock fallback — deterministic, no LLM needed)
# ---------------------------------------------------------------------------

_DANGEROUS_RE = re.compile(r"\b(eval|exec|__import__|os\.system|subprocess\.call|pickle\.loads)\b")
_CRYPTO_DOWNGRADE_RE = re.compile(r"\b(md5|sha1)\b", re.IGNORECASE)
_NESTED_LOOP_RE = re.compile(r"^\s*(for|while)\b", re.MULTILINE)
_BLOCKING_RE = re.compile(r"\b(time\.sleep|requests\.get|requests\.post|input\()\b")


def _heuristic_review(persona: PersonaName, original: str, refactored: str, vulnerability: Dict[str, Any]) -> Critique:
    """
    Deterministic stand-in for an LLM persona. Scores are derived from
    measurable properties of the diff so offline runs are reproducible.
    """
    concerns: List[str] = []
    suggestions: List[str] = []
    score = 0.85  # optimistic base; evidence subtracts

    new_dangerous = set(_DANGEROUS_RE.findall(refactored)) - set(_DANGEROUS_RE.findall(original))
    crypto_left = _CRYPTO_DOWNGRADE_RE.findall(refactored)
    loops_before = len(_NESTED_LOOP_RE.findall(original))
    loops_after = len(_NESTED_LOOP_RE.findall(refactored))
    blocking_new = set(_BLOCKING_RE.findall(refactored)) - set(_BLOCKING_RE.findall(original))
    diff_size = abs(len(refactored) - len(original))

    if persona is PersonaName.SECURITY_EXPERT:
        if new_dangerous:
            concerns.append(f"Patch introduces dangerous builtins: {sorted(new_dangerous)}")
            score -= 0.5
        if crypto_left and "md5" in vulnerability.get("description", "").lower():
            concerns.append("Weak hash (md5/sha1) still present — finding not remediated.")
            score -= 0.4
        elif not crypto_left:
            suggestions.append("Weak cryptography removed; consider adding a constant-time compare.")
    elif persona is PersonaName.PERFORMANCE_GURU:
        if loops_after > loops_before:
            concerns.append(f"Loop count increased {loops_before} -> {loops_after}; check hot paths.")
            score -= 0.25
        if blocking_new:
            concerns.append(f"New blocking calls introduced: {sorted(blocking_new)}")
            score -= 0.2
        if not concerns:
            suggestions.append("No measurable performance regression in the diff.")
    else:  # LEGACY_MAINTAINER
        if diff_size > 4000:
            concerns.append("Patch is large; prefer a minimal, surgical change for legacy code.")
            score -= 0.2
        if "TODO" in refactored or "FIXME" in refactored:
            concerns.append("Patch leaves TODO/FIXME markers behind.")
            score -= 0.1
        if not concerns:
            suggestions.append("Change is minimal and stylistically consistent.")

    score = max(0.0, min(1.0, score))
    verdict = "approve" if score >= 0.7 else ("revise" if score >= 0.4 else "reject")
    return Critique(
        persona=persona, round=1, score=round(score, 3),
        verdict=verdict, concerns=concerns, suggestions=suggestions,
    )


# ---------------------------------------------------------------------------
# Live LLM call (optional) with strict JSON parsing
# ---------------------------------------------------------------------------

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def parse_critique_json(raw: str, persona: PersonaName, round_no: int) -> Critique:
    """
    Extract the first JSON object from an LLM response and validate it.
    Raises ``ValueError`` if the payload is unusable — callers fall back to
    the heuristic reviewer rather than crashing the debate.
    """
    match = _JSON_BLOCK_RE.search(raw)
    if not match:
        raise ValueError("no JSON object found in LLM response")
    data = json.loads(match.group(0))
    return Critique(
        persona=persona,
        round=round_no,
        score=float(data["score"]),
        verdict=str(data["verdict"]),
        concerns=[str(c) for c in data.get("concerns", [])],
        suggestions=[str(s) for s in data.get("suggestions", [])],
    )


async def _query_persona_llm(persona: Persona, original: str, refactored: str, vulnerability: Dict[str, Any], round_no: int) -> Critique:
    """Call the configured LLM endpoint for one persona; heuristic fallback."""
    if not CONSENSUS_LLM_URL or httpx is None:
        return _heuristic_review(persona.name, original, refactored, vulnerability)

    prompt = (
        f"{persona.system_prompt}\n\n"
        f"VULNERABILITY: {json.dumps(vulnerability)}\n\n"
        f"ORIGINAL CODE:\n{original}\n\nPROPOSED PATCH:\n{refactored}\n"
    )
    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT_SECONDS) as client:
            resp = await client.post(CONSENSUS_LLM_URL, json={"prompt": prompt})
            resp.raise_for_status()
            return parse_critique_json(resp.json().get("response", ""), persona.name, round_no)
    except Exception as exc:
        logger.warning("LLM call failed for %s (%s); using heuristic review.", persona.name.value, exc)
        return _heuristic_review(persona.name, original, refactored, vulnerability)


# ---------------------------------------------------------------------------
# Debate orchestration
# ---------------------------------------------------------------------------

async def run_debate_round(
    original: str,
    refactored: str,
    vulnerability: Dict[str, Any],
    round_no: int,
    transcript: List[str],
) -> List[Critique]:
    """Run one round where all personas review the patch concurrently."""
    transcript.append(f"--- Debate round {round_no}: {len(PERSONAS)} personas reviewing patch ---")
    critiques = await asyncio.gather(
        *(_query_persona_llm(p, original, refactored, vulnerability, round_no) for p in PERSONAS)
    )
    for c in critiques:
        transcript.append(
            f"[{c.persona.value}] score={c.score:.2f} verdict={c.verdict} "
            f"concerns={len(c.concerns)} suggestions={len(c.suggestions)}"
        )
    return list(critiques)


def calculate_consensus(critiques: List[Critique]) -> Tuple[float, float, bool]:
    """
    Weighted-mean consensus score.

    Returns ``(consensus_score, security_score, security_vetoed)``.
    """
    weight_of = {p.name: p.weight for p in PERSONAS}
    total_weight = sum(weight_of[c.persona] for c in critiques) or 1.0
    consensus = sum(c.score * weight_of[c.persona] for c in critiques) / total_weight
    security = next((c.score for c in critiques if c.persona is PersonaName.SECURITY_EXPERT), 0.0)
    return round(consensus, 4), security, security < SECURITY_VETO_THRESHOLD


async def reach_consensus(
    original_code: str,
    refactored_code: str,
    vulnerability: Dict[str, Any],
) -> ConsensusResult:
    """
    Full debate loop: up to ``DEBATE_ROUNDS`` rounds of concurrent persona
    review, then a mathematical approval decision.

    Later rounds re-review the same patch informed by prior concerns (in live
    LLM mode the prompt would carry the running transcript; in heuristic mode
    rounds are idempotent by design).
    """
    transcript: List[str] = [f"Debate opened for finding: {vulnerability.get('description', 'n/a')}"]
    all_critiques: List[Critique] = []

    for round_no in range(1, DEBATE_ROUNDS + 1):
        all_critiques = await run_debate_round(original_code, refactored_code, vulnerability, round_no, transcript)
        score, security, _ = calculate_consensus(all_critiques)
        transcript.append(f"Round {round_no} consensus={score:.3f} security={security:.3f}")
        if score >= APPROVAL_THRESHOLD and security >= SECURITY_VETO_THRESHOLD:
            break  # early exit — patch already clears the bar

    consensus_score, security_score, vetoed = calculate_consensus(all_critiques)
    approved = consensus_score >= APPROVAL_THRESHOLD and not vetoed
    transcript.append(
        f"Decision: {'APPROVED' if approved else 'REJECTED'} "
        f"(consensus={consensus_score:.3f}, threshold={APPROVAL_THRESHOLD}, "
        f"security={security_score:.3f}, veto_threshold={SECURITY_VETO_THRESHOLD})"
    )
    return ConsensusResult(
        approved=approved,
        consensus_score=consensus_score,
        security_score=round(security_score, 4),
        security_vetoed=vetoed,
        critiques=all_critiques,
        transcript=transcript,
        rounds=len({c.round for c in all_critiques}) or 1,
    )


# ---------------------------------------------------------------------------
# Self-test: `python multi_agent_consensus.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    async def _demo() -> None:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
        original = "import hashlib\ndef check(p, d): return hashlib.md5(p.encode()).hexdigest() == d\n"
        patched = original.replace("md5", "sha256")
        result = await reach_consensus(original, patched, {"description": "deprecated md5 usage", "severity": "critical"})
        print("\n".join(result.transcript))
        print(f"\nApproved: {result.approved} (score={result.consensus_score})")

    asyncio.run(_demo())
