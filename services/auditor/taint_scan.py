"""Taint-flow analysis for Python source files using the ``ast`` module.

Tracks user-controlled data from *source* call-sites to potentially dangerous
*sink* call-sites within a single file, reporting cases where no sanitizer
intervenes.

Supported sources
-----------------
* ``request.args.get(...)``
* ``request.form.get(...)``
* ``input(...)``
* ``sys.argv``  (subscript or direct reference)

Supported sinks
---------------
* Any ``.execute(...)`` call whose first argument is built with an f-string,
  ``%`` operator, or ``.format()`` — i.e. the query string is constructed at
  runtime rather than using a parameterized placeholder.

Sanitizers (clear taint on a variable)
---------------------------------------
* Assignment through ``sanitize(...)`` or ``escape(...)``
* Parameterized queries: ``.execute(sql, params)`` where *sql* is a plain
  string literal (contains ``?`` or ``%s``) — these do NOT generate a finding.

Usage::

    from taint_scan import scan_file, scan_repo
    findings = scan_file("app.py")
    all_findings = scan_repo("/path/to/project")
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import TypedDict


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

class Finding(TypedDict):
    file: str
    line: int
    variable: str
    source: str
    sink: str


# ---------------------------------------------------------------------------
# Helpers — source / sink / sanitizer detection
# ---------------------------------------------------------------------------

# Dotted attribute chains we recognise as taint sources.
_SOURCE_CHAINS: set[tuple[str, ...]] = {
    ("request", "args", "get"),
    ("request", "form", "get"),
}

# Bare function names that are taint sources.
_SOURCE_FUNCS: set[str] = {"input"}

# Function names whose single argument is sanitized on return.
_SANITIZER_FUNCS: set[str] = {"sanitize", "escape"}


def _attr_chain(node: ast.expr) -> tuple[str, ...]:
    """Return the dotted attribute chain for an AST expression, or ()."""
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        parent = _attr_chain(node.value)
        if parent:
            return parent + (node.attr,)
    return ()


def _is_source_call(node: ast.expr) -> str | None:
    """Return a human-readable source label if *node* is a taint source, else None."""
    if not isinstance(node, ast.Call):
        return None
    chain = _attr_chain(node.func)
    if chain in _SOURCE_CHAINS:
        return ".".join(chain) + "()"
    if len(chain) == 1 and chain[0] in _SOURCE_FUNCS:
        return chain[0] + "()"
    return None


def _is_sys_argv(node: ast.expr) -> bool:
    """Return True if *node* is ``sys.argv`` or ``sys.argv[n]``."""
    if isinstance(node, ast.Subscript):
        node = node.value
    chain = _attr_chain(node)
    return chain == ("sys", "argv")


def _is_sanitizer_call(node: ast.expr) -> bool:
    """Return True if *node* is a call to a known sanitizer function."""
    if not isinstance(node, ast.Call):
        return False
    chain = _attr_chain(node.func)
    return len(chain) == 1 and chain[0] in _SANITIZER_FUNCS


# ---------------------------------------------------------------------------
# Sink — detect unsafe .execute() calls
# ---------------------------------------------------------------------------

def _is_formatted_string(node: ast.expr) -> bool:
    """Return True if *node* produces a dynamically assembled string.

    Covers:
    * f-strings  (``ast.JoinedStr``)
    * ``%`` operator  (``BinOp`` with ``Mod``)
    * ``.format()`` call  (``Call`` whose func is ``Attribute`` named ``format``)
    * Concatenation (``BinOp`` with ``Add``) where at least one side is tainted
      — we conservatively flag any ``+`` on strings.
    """
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return False


def _execute_sink_label(call_node: ast.Call) -> str | None:
    """Return a sink label if *call_node* is an unsafe ``.execute()`` call.

    Returns None when:
    * the method name is not ``execute``
    * the first argument is a plain string literal (parameterized query)
    * the first argument is a ``Name`` node — we handle the tainted-variable
      path separately in the caller.
    """
    if not isinstance(call_node.func, ast.Attribute):
        return None
    if call_node.func.attr != "execute":
        return None
    if not call_node.args:
        return None
    first_arg = call_node.args[0]
    # Parameterized query: literal string → safe, no finding.
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        return None
    if _is_formatted_string(first_arg):
        chain = _attr_chain(call_node.func.value)
        obj = ".".join(chain) if chain else "obj"
        return f"{obj}.execute()"
    return None


# ---------------------------------------------------------------------------
# Single-file analyser
# ---------------------------------------------------------------------------

class _TaintVisitor(ast.NodeVisitor):
    """Walk an AST and collect taint-flow findings."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        # Maps variable name → source label (e.g. "request.args.get()")
        self._tainted: dict[str, str] = {}
        self.findings: list[Finding] = []

    # ------------------------------------------------------------------
    # Assignment — propagate / clear taint
    # ------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        source_label = self._taint_label_of(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if source_label:
                    self._tainted[target.id] = source_label
                elif target.id in self._tainted:
                    # Re-assigned to something that is not tainted → clear.
                    del self._tainted[target.id]
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # ``x += tainted_expr`` propagates taint into x.
        if isinstance(node.target, ast.Name):
            if self._taint_label_of(node.value):
                existing = self._tainted.get(node.target.id, "")
                self._tainted[node.target.id] = existing or self._taint_label_of(node.value) or ""
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value and isinstance(node.target, ast.Name):
            source_label = self._taint_label_of(node.value)
            if source_label:
                self._tainted[node.target.id] = source_label
            elif node.target.id in self._tainted:
                del self._tainted[node.target.id]
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Function scope — isolate taint per function
    # ------------------------------------------------------------------

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit a function with a fresh, isolated taint scope.

        Saves the current ``_tainted`` dict, resets it to empty (so outer
        taint does not leak in), visits the function body, then restores
        the saved dict (so the function's locals do not leak out).
        Function parameters are never pre-tainted — they start clean.
        """
        saved = self._tainted
        self._tainted = {}
        self.generic_visit(node)
        self._tainted = saved

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    # ------------------------------------------------------------------
    # Call expressions — detect sinks
    # ------------------------------------------------------------------

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            self._check_call(node.value)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _taint_label_of(self, node: ast.expr) -> str | None:
        """Return the source label if *node* is tainted, else None."""
        # Direct source call
        label = _is_source_call(node)
        if label:
            return label
        # sys.argv reference
        if _is_sys_argv(node):
            return "sys.argv"
        # Sanitizer call clears taint
        if _is_sanitizer_call(node):
            return None
        # Previously tainted variable
        if isinstance(node, ast.Name) and node.id in self._tainted:
            return self._tainted[node.id]
        # Subscript of a tainted variable (e.g. tainted[0])
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            if node.value.id in self._tainted:
                return self._tainted[node.value.id]
        # f-string / BinOp / .format() that contains a tainted sub-expression
        if _is_formatted_string(node):
            return self._any_tainted_child(node)
        return None

    def _any_tainted_child(self, node: ast.expr) -> str | None:
        """Return source label if any child expression of *node* is tainted."""
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, ast.Name) and child.id in self._tainted:
                return self._tainted[child.id]
        return None

    def _check_call(self, call: ast.Call) -> None:
        """Check whether *call* is an unsafe sink and emit a finding."""
        # --- Path 1: .execute(formatted_string) ---
        sink_label = _execute_sink_label(call)
        if sink_label:
            # The formatted string itself may embed a tainted variable.
            first_arg = call.args[0]
            source = self._any_tainted_child(first_arg) or "<formatted>"
            # Best-effort variable name: look for a Name inside the format expr.
            var_name = self._first_tainted_name_in(first_arg) or "<expr>"
            self.findings.append(
                Finding(
                    file=self.filepath,
                    line=call.lineno,
                    variable=var_name,
                    source=source,
                    sink=sink_label,
                )
            )
            return

        # --- Path 2: .execute(tainted_variable) ---
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "execute"
            and call.args
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id in self._tainted
        ):
            var = call.args[0].id
            chain = _attr_chain(call.func.value)
            obj = ".".join(chain) if chain else "obj"
            self.findings.append(
                Finding(
                    file=self.filepath,
                    line=call.lineno,
                    variable=var,
                    source=self._tainted[var],
                    sink=f"{obj}.execute()",
                )
            )

    def _first_tainted_name_in(self, node: ast.expr) -> str | None:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self._tainted:
                return child.id
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_file(filepath: str | Path) -> list[Finding]:
    """Parse *filepath* and return taint-flow findings.

    Parameters
    ----------
    filepath:
        Path to a Python source file.

    Returns
    -------
    List of :class:`Finding` dicts, one per detected taint flow.
    """
    filepath = Path(filepath)
    source = filepath.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return []

    visitor = _TaintVisitor(str(filepath))
    visitor.visit(tree)
    return visitor.findings


#: Default set of directory names that are never Python source and should be
#: skipped when walking a repository tree.
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules",
    "venv", ".venv", "env", ".env",
    "__pycache__", ".mypy_cache", ".pytest_cache",
    "dist", "build", ".tox",
    "site-packages",
})


def scan_repo(
    repo_path: str | Path,
    skip_dirs: frozenset[str] | set[str] | None = None,
) -> list[Finding]:
    """Walk *repo_path* recursively, scanning every ``*.py`` file.

    Parameters
    ----------
    repo_path:
        Root directory of a locally cloned repository.
    skip_dirs:
        Directory names to skip entirely when walking the tree.  Any path
        component that matches a name in this set causes the whole subtree to
        be skipped.  Defaults to :data:`DEFAULT_SKIP_DIRS`.  Directory names
        that start with ``.`` are *always* skipped regardless of this set.

    Returns
    -------
    Combined list of :class:`Finding` dicts from all Python files,
    sorted by (file, line).
    """
    root = Path(repo_path).resolve()
    _skip = DEFAULT_SKIP_DIRS if skip_dirs is None else frozenset(skip_dirs)

    all_findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skipped directories in-place so os.walk won't descend into them.
        dirnames[:] = [
            d for d in dirnames
            if not d.startswith(".") and d not in _skip
        ]
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            py_file = Path(dirpath) / name
            rel_posix = py_file.relative_to(root).as_posix()
            for finding in scan_file(py_file):
                finding["file"] = rel_posix
                all_findings.append(finding)

    return sorted(all_findings, key=lambda f: (f["file"], f["line"]))
