"""Git-describe version normalization for OSS submodules."""

from __future__ import annotations

import os
import re
from typing import NamedTuple, Optional, Tuple

from sbom4edk2.git_vcs import resolve_tag_commit, run_git_optional

_GIT_DESCRIBE_SUFFIX_RE = re.compile(r"-(\d+)-g([0-9a-f]+)$")
_PROJECT_SUFFIX_RE = re.compile(r"[+][a-zA-Z0-9_-]+$")
_BARE_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


class SubmoduleVcs(NamedTuple):
    """Resolved VCS metadata for one submodule directory."""

    clean: str
    raw: str
    base_tag: Optional[str]
    commit_sha: Optional[str]
    patch_count: int
    base_tag_commit: Optional[str]
    display_version: str


def normalize_submodule_version(
    raw: str,
) -> Tuple[str, int, Optional[str], Optional[str]]:
    """Return ``(clean_version, patch_count, commit_sha, base_tag)``."""
    raw = (raw or "").strip()
    if _BARE_COMMIT_RE.match(raw):
        return "0.0.0", 0, raw, None

    patch_count = 0
    commit_sha: Optional[str] = None
    m = _GIT_DESCRIBE_SUFFIX_RE.search(raw)
    if m:
        patch_count = int(m.group(1))
        commit_sha = m.group(2)
        raw = raw[: m.start()]

    raw = _PROJECT_SUFFIX_RE.sub("", raw)
    base_tag: Optional[str] = raw or None

    vm = re.search(r"(\d[\d.]*)", raw)
    if not vm:
        return "0.0.0", patch_count, commit_sha, base_tag

    clean_version = vm.group(1).rstrip(".")
    return clean_version, patch_count, commit_sha, base_tag


def format_display_version(
    clean: str,
    patch_count: int,
    *,
    commit_sha: Optional[str] = None,
) -> str:
    """Human/purl version: ``1.1.5`` or ``1.1.5+23`` (optional ``.g{sha}``)."""
    if patch_count <= 0:
        return clean
    suffix = f"+{patch_count}"
    if commit_sha:
        suffix += f".g{commit_sha[:7]}"
    return f"{clean}{suffix}"


def resolve_submodule_vcs(submodule_dir: str) -> SubmoduleVcs:
    """Return resolved VCS metadata for *submodule_dir*."""
    empty = SubmoduleVcs(
        "NOASSERTION", "", None, None, 0, None, "NOASSERTION"
    )
    if not submodule_dir or not os.path.isdir(submodule_dir):
        return empty

    raw_version = run_git_optional(["describe", "--tags", "--always"], cwd=submodule_dir)
    if not raw_version:
        raw_version = run_git_optional(["rev-parse", "HEAD"], cwd=submodule_dir)
        if raw_version:
            raw_version = raw_version[:12]
    if not raw_version:
        return empty

    clean, patch_count, commit_sha, base_tag = normalize_submodule_version(raw_version)
    base_tag_commit = (
        resolve_tag_commit(submodule_dir, base_tag) if base_tag else None
    )
    display = format_display_version(
        clean, patch_count, commit_sha=commit_sha
    )
    return SubmoduleVcs(
        clean=clean,
        raw=raw_version,
        base_tag=base_tag,
        commit_sha=commit_sha,
        patch_count=patch_count,
        base_tag_commit=base_tag_commit,
        display_version=display,
    )
