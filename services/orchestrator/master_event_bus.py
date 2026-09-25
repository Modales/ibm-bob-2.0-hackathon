"""
master_event_bus.py — Asynchronous Event Router
===============================================

IBM Bob 2.0 Hackathon · /services/orchestrator/

The nervous system of the orchestrator: an ``asyncio.Queue``-based pub/sub
event bus that decouples every subsystem. Producers publish typed events to
topics; consumers subscribe with async handlers and process events
concurrently — no module imports another module's internals, they only speak
through the bus.

Topics (pipeline lifecycle)
---------------------------
``AUDIT_STARTED`` -> ``AUDIT_FINISHED`` -> ``CVE_RETRIEVED`` ->
``REFACTOR_PROPOSED`` -> ``CONSENSUS_REACHED`` -> ``TESTS_PASSED`` /
``TESTS_FAILED`` -> ``HEALING_FINISHED`` -> ``PIPELINE_COMPLETE``

Architecture
------------
* ``EventBus`` owns one ``asyncio.Queue`` per subscriber (fan-out), plus a
  wildcard subscription for observers (SSE log streaming, metrics).
* ``publish`` is non-blocking; backpressure is bounded by per-subscriber
  queue size — a slow consumer drops to dead-letter logging rather than
  stalling the pipeline.
* Handlers run as supervised tasks; a crashing handler is logged and
  isolated, never taking down the bus.
* ``run_full_pipeline`` wires the four subsystems (vector CVE DB, multi-agent
  consensus, self-healing loop, AST gate) into a single end-to-end demo flow.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("orchestrator.master_event_bus")

# ---------------------------------------------------------------------------
# Topics & event model
# ---------------------------------------------------------------------------

class Topic(str, Enum):
    AUDIT_STARTED = "audit.started"
    AUDIT_FINISHED = "audit.finished"
    CVE_RETRIEVED = "cve.retrieved"
    REFACTOR_PROPOSED = "refactor.proposed"
    CONSENSUS_REACHED = "consensus.reached"
    TESTS_PASSED = "tests.passed"
    TESTS_FAILED = "tests.failed"
    HEALING_FINISHED = "healing.finished"
    PIPELINE_COMPLETE = "pipeline.complete"


@dataclass(frozen=True)
class Event:
    """An immutable message on the bus."""

    topic: Topic
    payload: Dict[str, Any]
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)
    correlation_id: str = ""  # ties all events of one pipeline run together


#: Async handler signature: receives the event, returns nothing.
EventHandler = Callable[[Event], Awaitable[None]]

#: Per-subscriber queue bound; overflow events go to dead-letter logging.
SUBSCRIBER_QUEUE_SIZE: int = int(os.getenv("EVENT_QUEUE_SIZE", "256"))


# ---------------------------------------------------------------------------
# Event bus
# ---------------------------------------------------------------------------

class EventBus:
    """
    Fan-out pub/sub over asyncio queues.

    Each subscription gets its own queue + dispatcher task, so a slow or
    failing consumer never blocks publishers or sibling consumers.
    """

    def __init__(self) -> None:
        self._subscriptions: Dict[Optional[Topic], List[Dict[str, Any]]] = {}
        self._tasks: List[asyncio.Task[None]] = []
        self._running = False
        self._processed = 0
        self._dropped = 0
        # Handlers currently executing — events published from inside a handler
        # must keep drain() waiting even if their target queue was momentarily
        # empty when drain began (fixes a queue.join() race).
        self._in_flight = 0

    # -- subscription management ------------------------------------------

    def subscribe(self, topic: Optional[Topic], handler: EventHandler) -> None:
        """
        Register ``handler`` for ``topic``. Pass ``topic=None`` for the
        wildcard subscription (receives every event — used by SSE streaming
        and audit logging).
        """
        self._subscriptions.setdefault(topic, []).append(
            {"handler": handler, "queue": asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_SIZE)}
        )

    async def _dispatch(self, handler: EventHandler, queue: "asyncio.Queue[Event]", label: str) -> None:
        """Long-running consumer loop for one subscription."""
        while True:
            event = await queue.get()
            self._in_flight += 1
            try:
                await handler(event)
                self._processed += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # isolate handler crashes
                logger.error("Handler '%s' crashed on %s: %s", label, event.topic.value, exc)
            finally:
                self._in_flight -= 1
                queue.task_done()

    async def start(self) -> None:
        """Spawn dispatcher tasks for all registered subscriptions."""
        if self._running:
            return
        self._running = True
        for topic, subs in self._subscriptions.items():
            label = topic.value if topic else "*"
            for sub in subs:
                self._tasks.append(asyncio.create_task(
                    self._dispatch(sub["handler"], sub["queue"], label),
                    name=f"eventbus:{label}",
                ))
        logger.info("EventBus started with %d dispatcher task(s).", len(self._tasks))

    async def publish(self, event: Event) -> None:
        """Non-blocking fan-out to the topic's subscribers + wildcard."""
        targets: List["asyncio.Queue[Event]"] = []
        for topic in (event.topic, None):  # exact topic, then wildcard
            for sub in self._subscriptions.get(topic, []):
                targets.append(sub["queue"])
        for queue in targets:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                self._dropped += 1
                logger.error("Dead-letter: subscriber queue full, dropped %s event %s", event.topic.value, event.event_id)

    async def emit(self, topic: Topic, payload: Dict[str, Any], correlation_id: str = "") -> Event:
        """Convenience: build + publish an event, returning it for logging."""
        event = Event(topic=topic, payload=payload, correlation_id=correlation_id)
        await self.publish(event)
        return event

    @property
    def stats(self) -> Dict[str, int]:
        return {"processed": self._processed, "dropped": self._dropped, "dispatchers": len(self._tasks)}

    async def drain(self, timeout: float = 10.0) -> None:
        """
        Wait until every subscriber queue is empty AND no handler is in flight.

        Plain ``queue.join()`` races with cascade-published events (a handler
        that publishes to a queue whose ``join()`` already resolved when the
        queue was momentarily empty). Polling ``qsize`` + ``_in_flight`` is
        race-free for this single-loop use case.
        """
        queues = [s["queue"] for subs in self._subscriptions.values() for s in subs]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pending = sum(q.qsize() for q in queues)
            if pending == 0 and self._in_flight == 0:
                return
            await asyncio.sleep(0.01)
        logger.warning(
            "EventBus drain timed out: %d queued, %d handler(s) in flight.",
            sum(q.qsize() for q in queues), self._in_flight,
        )

    async def stop(self) -> None:
        """Drain and cancel all dispatchers."""
        await self.drain()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._running = False
        logger.info("EventBus stopped. stats=%s", self.stats)


# ---------------------------------------------------------------------------
# Pipeline wiring — connects all four subsystems through the bus
# ---------------------------------------------------------------------------

class PipelineSummary(BaseModel):
    """Aggregated result of a full pipeline run, built purely from events."""

    correlation_id: str
    vulnerabilities_found: int = 0
    cves_retrieved: int = 0
    consensus_approved: bool = False
    consensus_score: float = 0.0
    healing_success: bool = False
    healing_attempts: int = 0
    events_seen: int = 0
    timeline: List[str] = Field(default_factory=list)


async def run_full_pipeline(repo_path: str, target_version: str, packages: Optional[List[str]] = None) -> PipelineSummary:
    """
    End-to-end demonstration of bus-driven orchestration:

    1. publish AUDIT_STARTED -> mock audit -> AUDIT_FINISHED
    2. handler: look up CVEs in the vector DB -> CVE_RETRIEVED
    3. handler: IBM Bob proposes a patch -> REFACTOR_PROPOSED
    4. handler: multi-agent debate -> CONSENSUS_REACHED
    5. handler: AST gate + self-healing loop -> TESTS_PASSED / TESTS_FAILED
    6. publish PIPELINE_COMPLETE with the summary
    """
    # Local imports keep module boundaries clean; each subsystem stays
    # independently testable and the bus is the only integration point.
    from vector_cve_db import build_db_with_mock_catalog, lookup_cves_for_package
    from multi_agent_consensus import reach_consensus
    from self_healing_loop import self_heal_code
    from ast_mutation_engine import verify_refactor

    bus = EventBus()
    cid = uuid.uuid4().hex[:8]
    summary = PipelineSummary(correlation_id=cid)
    state: Dict[str, Any] = {"packages": packages or ["requests"]}

    # -- observers ---------------------------------------------------------

    async def timeline_recorder(event: Event) -> None:
        summary.events_seen += 1
        summary.timeline.append(f"{event.topic.value}: {event.event_id}")

    bus.subscribe(None, timeline_recorder)  # wildcard observer

    # -- stage 2: CVE retrieval ---------------------------------------------

    async def on_audit_finished(event: Event) -> None:
        db = await build_db_with_mock_catalog()
        hits = []
        for pkg in state["packages"]:
            hits.extend(await lookup_cves_for_package(db, pkg))
        summary.cves_retrieved = len(hits)
        state["cve_hits"] = hits
        await bus.emit(Topic.CVE_RETRIEVED, {"count": len(hits), "packages": state["packages"]}, cid)

    bus.subscribe(Topic.AUDIT_FINISHED, on_audit_finished)

    # -- stage 3: Bob proposes a refactor ------------------------------------

    async def on_cve_retrieved(event: Event) -> None:
        original = (
            "import hashlib\n\n"
            "def verify_password(password: str, digest: str) -> bool:\n"
            "    return hashlib.md5(password.encode()).hexdigest() == digest\n"
        )
        refactored = original.replace("md5", "sha256")  # simulated IBM Bob output
        state["original"] = original
        state["refactored"] = refactored
        await bus.emit(Topic.REFACTOR_PROPOSED, {"bytes": len(refactored)}, cid)

    bus.subscribe(Topic.CVE_RETRIEVED, on_cve_retrieved)

    # -- stage 4: multi-agent consensus --------------------------------------

    async def on_refactor_proposed(event: Event) -> None:
        result = await reach_consensus(
            state["original"], state["refactored"],
            {"description": "deprecated md5 usage", "severity": "critical"},
        )
        summary.consensus_approved = result.approved
        summary.consensus_score = result.consensus_score
        await bus.emit(Topic.CONSENSUS_REACHED, {
            "approved": result.approved, "score": result.consensus_score,
        }, cid)

    bus.subscribe(Topic.REFACTOR_PROPOSED, on_refactor_proposed)

    # -- stage 5: AST gate + self-healing -------------------------------------

    async def on_consensus_reached(event: Event) -> None:
        if not event.payload.get("approved"):
            await bus.emit(Topic.TESTS_FAILED, {"reason": "consensus rejected patch"}, cid)
            await bus.emit(Topic.PIPELINE_COMPLETE, {"success": False}, cid)
            return
        gate = verify_refactor(state["original"], state["refactored"])
        if not gate.approved:
            await bus.emit(Topic.TESTS_FAILED, {"reason": "AST gate", "violations": gate.violations}, cid)
            await bus.emit(Topic.PIPELINE_COMPLETE, {"success": False}, cid)
            return
        heal = await self_heal_code(state["refactored"], target_version=target_version)
        summary.healing_success = heal.success
        summary.healing_attempts = heal.total_attempts
        await bus.emit(Topic.HEALING_FINISHED, {"success": heal.success, "attempts": heal.total_attempts}, cid)
        if heal.success:
            await bus.emit(Topic.TESTS_PASSED, {"attempts": heal.total_attempts}, cid)
        else:
            await bus.emit(Topic.TESTS_FAILED, {"reason": "healing exhausted"}, cid)
        await bus.emit(Topic.PIPELINE_COMPLETE, {"success": heal.success}, cid)

    bus.subscribe(Topic.CONSENSUS_REACHED, on_consensus_reached)

    # -- kick off --------------------------------------------------------------

    await bus.start()
    await bus.emit(Topic.AUDIT_STARTED, {"repo_path": repo_path, "target_version": target_version}, cid)
    # Mock audit completes; in production this payload comes from call_auditor().
    summary.vulnerabilities_found = 1
    await bus.emit(Topic.AUDIT_FINISHED, {"vulnerabilities": 1}, cid)

    await bus.stop()  # drains all queues before shutdown
    return summary


# ---------------------------------------------------------------------------
# Self-test: `python master_event_bus.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    async def _demo() -> None:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
        result = await run_full_pipeline(repo_path="./legacy-app", target_version="python3.12")
        print("\n=== Pipeline timeline ===")
        for line in result.timeline:
            print(f"  {line}")
        print(f"\nConsensus: {result.consensus_approved} (score={result.consensus_score})")
        print(f"Healing:   {result.healing_success} in {result.healing_attempts} attempt(s)")
        print(f"Events:    {result.events_seen}")

    asyncio.run(_demo())
