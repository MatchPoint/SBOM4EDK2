"""CycloneDX source SBOM generation and parsing helpers."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import List, Optional

from sbom4edk2.cdx_merge import write_source_sbom

logger = logging.getLogger(__name__)


def generate_sbom_from_checkout(
    location: str,
    output_name: str,
    *,
    uswid_data: Optional[str] = None,
    sbom_type: str = "source",
    **legacy_kwargs,
) -> Optional[str]:
    """Build a **source** CycloneDX SBOM for an EDK II checkout.

    Emits ``metadata.component`` for EDK II plus one component per OSS git
    submodule (from ``.gitmodules`` and uswid-data templates). Does **not**
    scan ``.inf`` build modules.

    Returns the absolute path to ``<output_name>.cdx.json`` on success.
    """
    if legacy_kwargs:
        logger.debug(
            "Ignoring legacy kwargs: %s",
            sorted(legacy_kwargs.keys()),
        )

    if not os.path.isdir(location):
        logger.error("EDK II checkout not found: %s", location)
        return None

    output_path = os.path.abspath(os.path.join(os.getcwd(), f"{output_name}.cdx.json"))
    rc = write_source_sbom(
        os.path.abspath(location),
        output_path,
        uswid_data_dir=uswid_data,
        sbom_type=sbom_type,
    )
    if rc != 0:
        return None
    return output_path


def parse_sbom(path: str) -> list[dict]:
    """Parse a CycloneDX JSON file and return its component list."""
    logger.info("Parsing SBOM file: %s", path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("SBOM file not found: %s", path)
        return []
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", path, exc)
        return []

    components = _extract_components(data)
    logger.info("Parsed %d components from %s", len(components), path)
    return components


def _extract_components(data: dict) -> list[dict]:
    if not isinstance(data, dict):
        return []
    if "components" in data:
        comps = data["components"]
    elif "metadata" in data:
        meta = data.get("metadata", {}).get("component", {})
        comps = meta.get("components", []) if isinstance(meta, dict) else []
    else:
        return []
    return comps if isinstance(comps, list) else []


def sanitize_cdx_file(cdx_path: str) -> bool:
    """Fix ``None`` source-dir values in a CDX file."""
    try:
        with open(cdx_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read %s: %s", cdx_path, exc)
        return False

    modified = False
    for component in data.get("components", []):
        if isinstance(component, dict) and component.get("source-dir") is None:
            component["source-dir"] = ""
            modified = True

    if modified:
        try:
            with open(cdx_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except OSError as exc:
            logger.error("Failed to write %s: %s", cdx_path, exc)
            return False
    return True


def run_command(cmd: list[str]) -> int:
    logger.info("Running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.stdout:
            logger.debug("stdout: %s", proc.stdout.strip())
        if proc.stderr:
            logger.warning("stderr: %s", proc.stderr.strip())
        return proc.returncode
    except Exception as exc:
        logger.error("Command failed: %s", exc)
        return 1
