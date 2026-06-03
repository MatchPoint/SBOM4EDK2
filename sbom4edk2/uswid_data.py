"""Ensure hughsie/uswid-data templates are available (auto-clone)."""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional

from sbom4edk2.git_utils import clone_or_update

logger = logging.getLogger(__name__)

USWID_DATA_REPO = "https://github.com/hughsie/uswid-data.git"
USWID_DATA_DIR = "uswid-data"


def package_root() -> str:
    """SBOM4EDK2 repository root (parent of ``sbom4edk2/``)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _is_uswid_data_dir(path: str) -> bool:
    return os.path.isfile(os.path.join(path, "edk2.cdx.json"))


def ensure_uswid_data(explicit_path: Optional[str] = None) -> str:
    """Return a directory with uswid-data templates, cloning if needed.

    Resolution order:

    1. *explicit_path* when provided (``--uswid-data``).
    2. ``$USWID_DATA`` environment variable.
    3. ``<SBOM4EDK2-repo>/uswid-data``.
    4. ``./uswid-data`` in the current working directory.
    5. Shallow clone into ``<SBOM4EDK2-repo>/uswid-data``.
    """
    if explicit_path:
        resolved = os.path.abspath(explicit_path)
        if _is_uswid_data_dir(resolved):
            logger.info("Using uswid-data at %s", resolved)
            return resolved
        logger.error("uswid-data not found or invalid at %s (missing edk2.cdx.json)", resolved)
        sys.exit(1)

    env = (os.environ.get("USWID_DATA") or "").strip()
    if env:
        resolved = os.path.abspath(env)
        if _is_uswid_data_dir(resolved):
            logger.info("Using uswid-data from USWID_DATA=%s", resolved)
            return resolved
        logger.warning("USWID_DATA=%s is invalid; continuing with auto-detect", env)

    for candidate in (
        os.path.join(package_root(), USWID_DATA_DIR),
        os.path.join(os.getcwd(), USWID_DATA_DIR),
    ):
        if _is_uswid_data_dir(candidate):
            logger.info("Using uswid-data at %s", candidate)
            return candidate

    dest = os.path.join(package_root(), USWID_DATA_DIR)
    logger.info(
        "uswid-data not found; cloning %s -> %s (one-time, shallow)",
        USWID_DATA_REPO,
        dest,
    )
    _clone_uswid_data_shallow(USWID_DATA_REPO, dest)
    if not _is_uswid_data_dir(dest):
        logger.error("Clone completed but edk2.cdx.json missing under %s", dest)
        sys.exit(1)
    return dest


def _clone_uswid_data_shallow(repo_url: str, dest: str) -> None:
    """Clone or update *dest* with a shallow tree (templates only)."""
    if os.path.isdir(os.path.join(dest, ".git")):
        logger.info("Updating uswid-data in %s...", dest)
        clone_or_update(repo_url, dest)
        return
    import subprocess

    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, dest],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        logger.error("Failed to clone uswid-data: %s", stderr)
        sys.exit(1)
