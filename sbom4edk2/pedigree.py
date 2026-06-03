"""Post-tag git commits as CycloneDX ``pedigree.patches[]`` entries."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from sbom4edk2.git_vcs import (
    commit_contained_in_ref,
    has_git_remote,
    run_git_optional,
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
_COMMIT_SEP = "---SBOM4EDK2_COMMIT_END---"
_UPSTREAM_REFS = ("upstream/master", "upstream/stable-1.1", "upstream/main")


def _cyclonedx_issue_type(has_cve: bool, cherry_pick: bool) -> str:
    if has_cve:
        return "security"
    if cherry_pick:
        return "defect"
    return "enhancement"


def _describe_patch_provenance(cwd: str, commit_sha: str) -> str:
    """``upstream`` when *commit_sha* is already on upstream remote; else ``vendor``."""
    if not has_git_remote(cwd, "upstream"):
        return "vendor"
    for ref in _UPSTREAM_REFS:
        if commit_contained_in_ref(cwd, commit_sha, ref):
            return "upstream"
    return "vendor"


def patch_dict_for_commit(
    *,
    subject: str,
    body_lines: List[str],
    commit_sha: str,
    vcs_url: str,
    provenance: str = "vendor",
) -> Dict[str, Any]:
    full_text = subject + " " + " ".join(body_lines)
    cves = sorted(set(_CVE_RE.findall(full_text)))
    has_cve = bool(cves)
    cherry_pick = not has_cve

    desc = (subject or "").strip()
    if len(desc) > 500:
        desc = desc[:497] + "..."
    prefix = (
        "[upstream] " if provenance == "upstream" else "[vendor pin] "
    )
    desc = f"{prefix}{desc}" if desc else prefix.strip()

    commit_url = (
        f"{vcs_url.rstrip('/')}/commit/{commit_sha}" if vcs_url.startswith("http") else None
    )

    patch: Dict[str, Any] = {
        "type": "cherry-pick" if cherry_pick else "security",
    }
    if commit_url:
        patch["diff"] = {"url": commit_url}

    issue: Dict[str, Any] = {
        "type": _cyclonedx_issue_type(has_cve, cherry_pick),
    }
    if desc:
        issue["description"] = desc
    if cves:
        issue["references"] = cves
    patch["resolves"] = [issue]
    return patch


def patches_for_commits_since_ref(
    cwd: str,
    base_ref: str,
    vcs_url: str,
) -> List[Dict[str, Any]]:
    """One CycloneDX patch dict per commit in ``base_ref..HEAD``."""
    log = run_git_optional(
        [
            "log",
            f"{base_ref}..HEAD",
            "--no-merges",
            "--reverse",
            f"--format=%H%x09%s%n%b%n{_COMMIT_SEP}",
        ],
        cwd=cwd,
    )
    if not log:
        return []

    patches: List[Dict[str, Any]] = []
    current_sha = ""
    current_subject = ""
    current_body: List[str] = []

    def _flush() -> None:
        nonlocal current_sha, current_subject, current_body
        if not current_sha:
            return
        prov = _describe_patch_provenance(cwd, current_sha)
        patches.append(
            patch_dict_for_commit(
                subject=current_subject,
                body_lines=current_body,
                commit_sha=current_sha,
                vcs_url=vcs_url,
                provenance=prov,
            )
        )
        current_sha = ""
        current_subject = ""
        current_body = []

    for line in log.splitlines():
        if line == _COMMIT_SEP:
            _flush()
            continue
        if "\t" in line and not current_sha:
            parts = line.split("\t", 1)
            current_sha = parts[0]
            current_subject = parts[1] if len(parts) > 1 else ""
        else:
            current_body.append(line)
    _flush()
    return patches


def patches_for_commits_since_tag(
    cwd: str,
    base_tag: str,
    vcs_url: str,
) -> List[Dict[str, Any]]:
    """Backward-compatible wrapper using *base_tag* as the git revision."""
    return patches_for_commits_since_ref(cwd, base_tag, vcs_url)


def pedigree_for_submodule_dir(
    submodule_dir: str,
    *,
    patch_count: int,
    base_tag: Optional[str],
    base_tag_commit: Optional[str],
    commit_sha: Optional[str],
    vcs_url: str,
) -> Optional[Dict[str, Any]]:
    """Build a ``pedigree`` object or ``None`` when there is nothing to record."""
    base_ref = base_tag_commit or base_tag
    if patch_count > 0 and base_ref:
        patch_list = patches_for_commits_since_ref(
            submodule_dir, base_ref, vcs_url
        )
        if patch_list:
            return {"patches": patch_list}
    if commit_sha and base_tag is None:
        return {
            "patches": [
                {
                    "type": "cherry-pick",
                    "resolves": [
                        {
                            "type": "defect",
                            "description": (
                                f"[vendor pin] No release tag found; "
                                f"pinned at commit {commit_sha}"
                            ),
                        }
                    ],
                }
            ]
        }
    return None
