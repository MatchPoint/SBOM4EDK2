"""Minimal git helpers for SBOM version discovery."""

from __future__ import annotations

import subprocess
from typing import List, Optional


def run_git(args: List[str], cwd: Optional[str] = None) -> str:
    """Run ``git <args>`` and return stripped stdout."""
    return (
        subprocess.check_output(
            ["git", *args],
            cwd=cwd,
            stderr=subprocess.STDOUT,
        )
        .decode("utf-8", errors="replace")
        .strip()
    )


def run_git_optional(args: List[str], cwd: Optional[str] = None) -> Optional[str]:
    """Like :func:`run_git` but returns ``None`` on failure."""
    try:
        return run_git(args, cwd=cwd)
    except subprocess.CalledProcessError:
        return None


def git_exit_code(args: List[str], cwd: Optional[str] = None) -> int:
    """Return the exit code for ``git <args>`` (0 = success)."""
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        check=False,
    ).returncode


def resolve_tag_commit(cwd: str, tag: str) -> Optional[str]:
    """Resolve an annotated/lightweight *tag* to a commit SHA."""
    if not tag or not cwd:
        return None
    for ref in (f"{tag}^{{commit}}", tag):
        sha = run_git_optional(["rev-parse", ref], cwd=cwd)
        if sha:
            return sha
    return None


def has_git_remote(cwd: str, remote_name: str) -> bool:
    out = run_git_optional(["remote"], cwd=cwd)
    if not out:
        return False
    return remote_name in out.split()


def commit_contained_in_ref(cwd: str, commit_sha: str, ref: str) -> bool:
    """True when *commit_sha* is an ancestor of *ref* (reachable from ref)."""
    if not (cwd and commit_sha and ref):
        return False
    return git_exit_code(["merge-base", "--is-ancestor", commit_sha, ref], cwd=cwd) == 0
