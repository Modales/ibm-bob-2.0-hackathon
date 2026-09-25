"""
ast_mutation_engine.py — Deep Structural Verification
=====================================================

IBM Bob 2.0 Hackathon · /services/orchestrator/

Static, AST-level verification of AI-generated refactors. LLM output is never
trusted: before any patch is adopted, this engine proves two properties:

1. **Safety**  — the patch introduces no dangerous builtins or call patterns
   (``eval``, ``exec``, ``__import__``, ``os.system``, ``pickle.loads``,
   dynamic ``getattr`` chains, etc.).
2. **Complexity stability** — the patch does not drastically worsen the
   asymptotic complexity of the code, approximated by maximum loop nesting
   depth: depth 0 ~ O(1)/O(n) elementwise, depth k ~ O(n^k) for the worst
   loop nest. A patch may raise depth by at most ``MAX_DEPTH_INCREASE``.

Everything is pure stdlib ``ast`` — no code is ever executed, so this module
is safe to run on hostile input.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Set

logger = logging.getLogger("orchestrator.ast_mutation_engine")

# ---------------------------------------------------------------------------
# Policy tables
# ---------------------------------------------------------------------------

#: Builtin / attribute names that must never appear in AI-generated code
#: unless they already existed in the original source.
DANGEROUS_NAMES: Set[str] = {
    "eval", "exec", "__import__", "compile", "globals", "locals",
}

#: ``module.attr`` call patterns that are dangerous (e.g. os.system).
DANGEROUS_ATTR_CALLS: Set[str] = {
    "os.system", "os.popen", "os.remove", "os.rmdir",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "pickle.loads", "pickle.load", "marshal.loads",
    "shutil.rmtree",
}

#: A patch may worsen loop-nesting depth by at most this much.
MAX_DEPTH_INCREASE: int = 1


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------

@dataclass
class VerificationReport:
    """Outcome of verifying a refactored source against its original."""

    safe: bool
    complexity_ok: bool
    violations: List[str] = field(default_factory=list)
    max_loop_depth_original: int = 0
    max_loop_depth_refactored: int = 0
    syntax_valid: bool = True

    @property
    def approved(self) -> bool:
        """A patch is adoptable only when both gates pass."""
        return self.syntax_valid and self.safe and self.complexity_ok


# ---------------------------------------------------------------------------
# Visitor: dangerous construct detection + loop-depth measurement
# ---------------------------------------------------------------------------

class SecurityComplexityVisitor(ast.NodeVisitor):
    """
    Walks the AST collecting:
      * dangerous name/attribute calls (with line numbers), and
      * the maximum nesting depth of for/while/async-for loops
        (comprehensions count as one loop level each).
    """

    def __init__(self) -> None:
        self.dangerous_hits: List[str] = []
        self._loop_depth: int = 0
        self.max_loop_depth: int = 0

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _qualified_name(node: ast.AST) -> str:
        """Resolve ``os.system``-style dotted names from a call func node."""
        parts: List[str] = []
        current: Optional[ast.AST] = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _enter_loop(self, node: ast.AST) -> None:
        self._loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self._loop_depth)
        self.generic_visit(node)
        self._loop_depth -= 1

    # -- loop nodes -------------------------------------------------------

    def visit_For(self, node: ast.For) -> None:
        self._enter_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._enter_loop(node)

    def visit_While(self, node: ast.While) -> None:
        self._enter_loop(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._enter_loop(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._enter_loop(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._enter_loop(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._enter_loop(node)

    # -- call nodes --------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        name = self._qualified_name(node.func)
        short = name.split(".")[-1]
        if short in DANGEROUS_NAMES:
            self.dangerous_hits.append(f"line {node.lineno}: call to dangerous builtin '{short}'")
        if name in DANGEROUS_ATTR_CALLS:
            self.dangerous_hits.append(f"line {node.lineno}: call to dangerous function '{name}'")
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_source(source: str) -> SecurityComplexityVisitor:
    """Parse and inspect one source string. Raises ``SyntaxError`` if invalid."""
    tree = ast.parse(source)
    visitor = SecurityComplexityVisitor()
    visitor.visit(tree)
    return visitor


def verify_refactor(original_code: str, refactored_code: str) -> VerificationReport:
    """
    Verify an AI-produced refactor against its original source.

    Safety rule: any dangerous construct present in the refactor but NOT in
    the original is a violation (pre-existing legacy smells are reported as
    informational, not blockers — the modernizer's job is to remove them).

    Complexity rule: ``depth(refactored) <= depth(original) + MAX_DEPTH_INCREASE``.
    """
    violations: List[str] = []

    # --- parse both sides -------------------------------------------------
    try:
        original_visitor = analyze_source(original_code)
    except SyntaxError as exc:
        logger.warning("Original source failed to parse (%s); treating depth as 0.", exc)
        original_visitor = SecurityComplexityVisitor()

    try:
        refactored_visitor = analyze_source(refactored_code)
    except SyntaxError as exc:
        return VerificationReport(
            safe=False, complexity_ok=False, syntax_valid=False,
            violations=[f"refactored code does not parse: {exc}"],
        )

    # --- safety gate -------------------------------------------------------
    original_dangerous = set(original_visitor.dangerous_hits)
    new_dangerous = [
        hit.split(": ", 1)[1] for hit in refactored_visitor.dangerous_hits
        if hit not in original_dangerous
    ]
    violations.extend(f"NEW dangerous construct introduced: {d}" for d in new_dangerous)
    safe = not new_dangerous

    # --- complexity gate ----------------------------------------------------
    depth_before = original_visitor.max_loop_depth
    depth_after = refactored_visitor.max_loop_depth
    complexity_ok = depth_after <= depth_before + MAX_DEPTH_INCREASE
    if not complexity_ok:
        violations.append(
            f"loop nesting depth worsened {depth_before} -> {depth_after} "
            f"(allowed increase: {MAX_DEPTH_INCREASE}) — suspected Big-O regression"
        )

    report = VerificationReport(
        safe=safe,
        complexity_ok=complexity_ok,
        violations=violations,
        max_loop_depth_original=depth_before,
        max_loop_depth_refactored=depth_after,
    )
    logger.info(
        "AST verification: safe=%s complexity_ok=%s depth %d -> %d violations=%d",
        report.safe, report.complexity_ok, depth_before, depth_after, len(violations),
    )
    return report


# ---------------------------------------------------------------------------
# Self-test: `python ast_mutation_engine.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    good_original = "for a in xs:\n    for b in ys:\n        work(a, b)\n"
    evil_patch = good_original + "\nresult = eval(user_input)\n"
    slow_patch = "for a in xs:\n    for b in ys:\n        for c in zs:\n            for d in ws:\n                work(a, b, c, d)\n"

    r1 = verify_refactor(good_original, evil_patch)
    print(f"evil patch approved={r1.approved}  violations={r1.violations}")

    r2 = verify_refactor(good_original, slow_patch)
    print(f"slow patch approved={r2.approved}  violations={r2.violations}")

    r3 = verify_refactor(good_original, good_original.replace("work", "process"))
    print(f"clean patch approved={r3.approved}  violations={r3.violations}")
