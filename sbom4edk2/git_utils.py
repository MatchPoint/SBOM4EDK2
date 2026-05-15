"""Git repository clone and update helpers."""

from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)


def clone_or_update(repo_url: str, dest: str, *, init_submodules: bool = False) -> None:
    """Clone *repo_url* into *dest*, or pull if it already exists.

    Raises ``SystemExit`` on failure.
    """
    import os, sys

    if os.path.exists(dest):
        logger.info("Pulling latest changes in %s …", dest)
        _git(["git", "pull"], cwd=dest)
        if init_submodules:
            logger.info("Updating submodules in %s …", dest)
            _git(["git", "submodule", "update", "--init", "--recursive"], cwd=dest)
    else:
        logger.info("Cloning %s → %s …", repo_url, dest)
        _git(["git", "clone", repo_url, dest])
        if init_submodules:
            logger.info("Initialising submodules in %s …", dest)
            _git(["git", "submodule", "update", "--init", "--recursive"], cwd=dest)


def _git(cmd: list[str], cwd: str | None = None) -> None:
    import sys

    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else "(no output)"
        logger.error("Git command failed: %s\n%s", " ".join(cmd), stderr)
        sys.exit(1)
