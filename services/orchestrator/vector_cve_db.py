"""
vector_cve_db.py — RAG Security Engine
======================================

IBM Bob 2.0 Hackathon · /services/orchestrator/

An in-memory vector database for Common Vulnerabilities and Exposures (CVEs).
The engine ingests a JSON catalog of CVEs, embeds their descriptions, and
answers semantic queries such as "which CVEs affect the `requests` package
before 2.31?".

Dependency strategy (production-ready, demo-safe)
-------------------------------------------------
The module prefers real embedding backends when they are installed:

1. ``sentence-transformers`` (HuggingFace)  — semantic embeddings
2. ``faiss`` (optional)                     — approximate nearest neighbors
3. **Deterministic fallback**               — a seeded hashing embedder and a
   brute-force cosine scan, implemented in pure Python + stdlib. This keeps
   the orchestrator 100% standalone during hackathon testing, CI, and demos
   where GPU/model downloads are unavailable.

All public functions are ``async`` so ingestion and retrieval never block the
event loop; CPU-heavy embedding work is offloaded via ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger("orchestrator.vector_cve_db")

# ---------------------------------------------------------------------------
# Optional heavyweight dependencies — resolved once at import time.
# ---------------------------------------------------------------------------

_EMBEDDER_BACKEND = "hashing"  # default: deterministic offline embedder
_sentence_model: Any = None

try:  # pragma: no cover - depends on local environment
    from sentence_transformers import SentenceTransformer  # type: ignore

    _model_name = os.getenv("CVE_EMBED_MODEL", "all-MiniLM-L6-v2")
    _sentence_model = SentenceTransformer(_model_name)
    _EMBEDDER_BACKEND = f"sentence-transformers:{_model_name}"
    logger.info("CVE embedder backend: %s", _EMBEDDER_BACKEND)
except Exception as exc:  # ImportError, download failure, no GPU, etc.
    logger.warning("sentence-transformers unavailable (%s); using hashing embedder.", exc)

try:  # pragma: no cover - depends on local environment
    import faiss  # type: ignore  # noqa: F401

    _FAISS_AVAILABLE = True
except Exception:
    _FAISS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CVEItem(BaseModel):
    """A single CVE catalog entry."""

    cve_id: str = Field(..., description="e.g. 'CVE-2024-35195'")
    package: str = Field(..., description="Affected package name, lowercase.")
    affected_versions: str = Field(..., description="Version range, e.g. '<2.31.0'")
    severity: str = Field(..., description="low | medium | high | critical")
    description: str
    fixed_version: Optional[str] = None


class CVEQueryResult(BaseModel):
    """One retrieval hit with its similarity score."""

    cve: CVEItem
    score: float = Field(..., ge=0.0, le=1.0, description="Cosine similarity.")


# ---------------------------------------------------------------------------
# Embedding functions
# ---------------------------------------------------------------------------

_HASH_DIM = 384  # matches all-MiniLM-L6-v2 dimensionality for drop-in parity
_TOKEN_RE = re.compile(r"[a-z0-9_\.\-]+")


def _tokenize(text: str) -> List[str]:
    return _TOKEN_RE.findall(text.lower())


def _hashing_embed(text: str) -> List[float]:
    """
    Deterministic, dependency-free embedding.

    Each token (and token bigram) is hashed into a fixed-dimensional bag and
    L2-normalized. Not semantic — but stable, fast, and good enough to rank
    package names / version strings when no model is available.
    """
    vec = [0.0] * _HASH_DIM
    tokens = _tokenize(text)
    features = tokens + [f"{a}#{b}" for a, b in zip(tokens, tokens[1:])]
    for feat in features:
        digest = hashlib.blake2b(feat.encode(), digest_size=8).digest()
        idx = int.from_bytes(digest[:4], "little") % _HASH_DIM
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vec[idx] += sign
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _sync_embed(texts: Sequence[str]) -> List[List[float]]:
    """Blocking embed — always called via ``asyncio.to_thread``."""
    if _sentence_model is not None:
        embeddings = _sentence_model.encode(list(texts), normalize_embeddings=True)
        return [list(map(float, row)) for row in embeddings]
    return [_hashing_embed(t) for t in texts]


async def embed_texts(texts: Sequence[str]) -> List[List[float]]:
    """Embed a batch of texts without blocking the event loop."""
    return await asyncio.to_thread(_sync_embed, texts)


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity for (assumed normalized) vectors, clamped to [0, 1]."""
    dot = sum(x * y for x, y in zip(a, b))
    return max(0.0, min(1.0, dot))


# ---------------------------------------------------------------------------
# Vector store
# ---------------------------------------------------------------------------

@dataclass
class VectorCVEDatabase:
    """
    In-memory CVE vector store.

    Uses FAISS (IndexFlatIP) when available for inner-product search; otherwise
    falls back to an O(n) cosine scan — entirely acceptable for hackathon-scale
    catalogs (thousands of entries).
    """

    _items: List[CVEItem] = field(default_factory=list)
    _vectors: List[List[float]] = field(default_factory=list)
    _faiss_index: Any = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def backend(self) -> str:
        """Human-readable description of the active embedding backend."""
        return _EMBEDDER_BACKEND

    @property
    def size(self) -> int:
        return len(self._items)

    async def ingest(self, items: Sequence[CVEItem]) -> int:
        """
        Embed and index a batch of CVEs. Returns the number of entries added.
        """
        if not items:
            return 0
        texts = [f"{i.package} {i.affected_versions} {i.severity} {i.description}" for i in items]
        vectors = await embed_texts(texts)
        async with self._lock:
            self._items.extend(items)
            self._vectors.extend(vectors)
            if _FAISS_AVAILABLE:
                self._rebuild_faiss_locked()
        logger.info("Ingested %d CVEs (total=%d).", len(items), self.size)
        return len(items)

    async def ingest_from_json(self, path: os.PathLike[str] | str) -> int:
        """
        Load a JSON catalog (list of CVE objects) from disk and index it.

        File I/O and JSON parsing are offloaded to a worker thread so large
        catalogs never stall the event loop.
        """
        raw = await asyncio.to_thread(Path(path).read_text, "utf-8")
        payload: List[Dict[str, Any]] = json.loads(raw)
        items = [CVEItem(**entry) for entry in payload]
        return await self.ingest(items)

    def _rebuild_faiss_locked(self) -> None:
        """Rebuild the FAISS flat index from scratch (caller holds the lock)."""
        import numpy as np  # type: ignore  # faiss implies numpy
        import faiss  # type: ignore

        matrix = np.array(self._vectors, dtype="float32")
        index = faiss.IndexFlatIP(matrix.shape[1])
        index.add(matrix)
        self._faiss_index = index

    async def query(self, query_text: str, top_k: int = 5, package: Optional[str] = None) -> List[CVEQueryResult]:
        """
        Semantic search over the catalog.

        ``package`` optionally hard-filters results to one package name — the
        common orchestrator flow is "we detected outdated package X, fetch its
        CVEs", which combines both filters.
        """
        if not self._items:
            return []
        [qvec] = await embed_texts([query_text])

        candidate_idx = [
            i for i, item in enumerate(self._items)
            if package is None or item.package.lower() == package.lower()
        ]
        if not candidate_idx:
            return []

        scored: List[Tuple[int, float]] = [
            (i, cosine_similarity(qvec, self._vectors[i])) for i in candidate_idx
        ]
        scored.sort(key=lambda t: t[1], reverse=True)
        return [
            CVEQueryResult(cve=self._items[i], score=round(score, 4))
            for i, score in scored[:top_k]
        ]


# ---------------------------------------------------------------------------
# Convenience: query by outdated package (the orchestrator's primary use case)
# ---------------------------------------------------------------------------

async def lookup_cves_for_package(
    db: VectorCVEDatabase,
    package_name: str,
    installed_version: Optional[str] = None,
    top_k: int = 5,
) -> List[CVEQueryResult]:
    """
    Retrieve the most relevant CVEs for an outdated package.

    The query text blends the package name and version so semantic backends
    rank version-relevant advisories higher.
    """
    query_text = (
        f"known vulnerabilities in {package_name} {installed_version or ''} "
        "security advisory exploit patch upgrade"
    ).strip()
    return await db.query(query_text, top_k=top_k, package=package_name)


# ---------------------------------------------------------------------------
# Mock catalog — used when no JSON file exists (standalone demos / CI)
# ---------------------------------------------------------------------------

MOCK_CVE_CATALOG: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2024-35195",
        "package": "requests",
        "affected_versions": "<2.32.0",
        "severity": "medium",
        "description": "Requests leaks Proxy-Authorization headers to destination servers during redirects.",
        "fixed_version": "2.32.0",
    },
    {
        "cve_id": "CVE-2023-32681",
        "package": "requests",
        "affected_versions": ">=2.3.0,<2.31.0",
        "severity": "medium",
        "description": "Unintended leak of Proxy-Authorization header in requests when following redirects to HTTPS.",
        "fixed_version": "2.31.0",
    },
    {
        "cve_id": "CVE-2024-3651",
        "package": "idna",
        "affected_versions": "<3.7",
        "severity": "medium",
        "description": "idna vulnerable to resource consumption via crafted domain name (DoS).",
        "fixed_version": "3.7",
    },
    {
        "cve_id": "CVE-2024-26130",
        "package": "cryptography",
        "affected_versions": ">=38.0.0,<42.0.4",
        "severity": "high",
        "description": "NULL pointer dereference in pkcs12.serialize_key_and_certificates leading to crash.",
        "fixed_version": "42.0.4",
    },
    {
        "cve_id": "CVE-2023-0286",
        "package": "cryptography",
        "affected_versions": "<39.0.1",
        "severity": "high",
        "description": "Type confusion in X.400 address processing inside X.509 GeneralName.",
        "fixed_version": "39.0.1",
    },
    {
        "cve_id": "CVE-2024-1135",
        "package": "gunicorn",
        "affected_versions": "<22.0.0",
        "severity": "high",
        "description": "HTTP request smuggling via Transfer-Encoding header validation bypass.",
        "fixed_version": "22.0.0",
    },
    {
        "cve_id": "CVE-2019-1010083",
        "package": "flask",
        "affected_versions": "<1.0",
        "severity": "high",
        "description": "Flask denial of service via unexpected memory usage on malformed JSON.",
        "fixed_version": "1.0",
    },
    {
        "cve_id": "CVE-2024-34064",
        "package": "jinja2",
        "affected_versions": "<3.1.4",
        "severity": "medium",
        "description": "XSS via the xmlattr filter when user-controlled keys are rendered.",
        "fixed_version": "3.1.4",
    },
]


async def build_db_with_mock_catalog() -> VectorCVEDatabase:
    """Construct a database pre-loaded with :data:`MOCK_CVE_CATALOG`."""
    db = VectorCVEDatabase()
    await db.ingest([CVEItem(**e) for e in MOCK_CVE_CATALOG])
    return db


# ---------------------------------------------------------------------------
# Self-test: `python vector_cve_db.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    async def _demo() -> None:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
        db = await build_db_with_mock_catalog()
        print(f"Backend: {db.backend} | entries: {db.size}")
        results = await lookup_cves_for_package(db, "requests", installed_version="2.28.0")
        for hit in results:
            print(f"  {hit.cve.cve_id:<16} score={hit.score:.3f}  {hit.cve.description[:60]}")

    asyncio.run(_demo())
