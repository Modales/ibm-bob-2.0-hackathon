"""Churn analysis — count per-file commit frequency over a rolling window.

Usage::

    from churn import file_churn
    results = file_churn("/path/to/repo", days=90)
    # [{"file": "src/foo.py", "commit_count": 42}, ...]
"""

from __future__ import annotations

import datetime
from collections import defaultdict
from pathlib import Path
from typing import TypedDict

from git import Repo
from git.exc import InvalidGitRepositoryError, NoSuchPathError


class ChurnEntry(TypedDict):
    file: str
    commit_count: int


def file_churn(repo_path: str | Path, days: int = 90) -> list[ChurnEntry]:
    """Return files ranked by commit frequency over the last *days* days.

    Parameters
    ----------
    repo_path:
        Local filesystem path to a git repository (already cloned).
    days:
        Rolling window in days.  Commits whose author date is older than
        this many days before *now* (UTC) are excluded.

    Returns
    -------
    list of ``{"file": str, "commit_count": int}`` dicts, sorted by
    ``commit_count`` descending.

    Raises
    ------
    ValueError
        If *repo_path* is not a valid git repository or does not exist.
    """
    if days < 1:
        raise ValueError(f"days must be >= 1, got {days}")

    try:
        repo = Repo(str(repo_path), search_parent_directories=False)
    except NoSuchPathError:
        raise ValueError(f"Path does not exist: {repo_path}")
    except InvalidGitRepositoryError:
        raise ValueError(f"Not a git repository: {repo_path}")

    cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=days)

    counts: dict[str, int] = defaultdict(int)

    for commit in repo.iter_commits():
        # authored_datetime is timezone-aware
        if commit.authored_datetime < cutoff:
            break  # iter_commits walks newest-first; stop once past the window

        # stats.files maps filename -> {insertions, deletions, lines}
        for filepath in commit.stats.files:
            counts[filepath] += 1

    return sorted(
        [{"file": f, "commit_count": c} for f, c in counts.items()],
        key=lambda e: e["commit_count"],
        reverse=True,
    )
