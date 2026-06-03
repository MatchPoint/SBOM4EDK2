"""EDK II tag parsing for primary component versioning."""

from __future__ import annotations

import re
from typing import Tuple

from sbom4edk2.git_vcs import run_git_optional

EDK2_TAG_PATTERN = re.compile(
    r"^(?P<tag>edk2-stable\d+)(?:-(?P<dist>\d+)-g(?P<sha>[0-9a-f]+))?$"
)


def describe_edk2_version(edk2_dir: str) -> Tuple[str, str, str]:
    """Return ``(version_label, purl_version, cpe_version)`` for *edk2_dir*."""
    describe = run_git_optional(["describe", "--tags", "--always"], cwd=edk2_dir)
    if not describe:
        return "unknown", "unknown", "unknown"

    m = EDK2_TAG_PATTERN.match(describe)
    if m and m.group("dist"):
        tag = m.group("tag")
        dist = m.group("dist")
        sha = m.group("sha")
        version_label = f"{tag}+{dist}.g{sha}"
        m2 = re.search(r"(\d+)$", tag)
        short = m2.group(1) if m2 else tag
        return version_label, short, short
    if m:
        tag = m.group("tag")
        m2 = re.search(r"(\d+)$", tag)
        short = m2.group(1) if m2 else tag
        return tag, short, short
    return describe, describe, describe
