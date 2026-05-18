"""SBOM4EDK2 SBOM helpers.

Thin orchestration over the ``uswid`` CLI from ``python-uswid-sbom``.

The end-to-end SBOM generation pipeline (``.inf`` parsing, ``.gitmodules``
walk, ``git describe`` version normalisation, ``@VCS_*@`` placeholder
substitution against each submodule's actual directory, orphan-template
filtering, and CycloneDX ``dependencies[]`` tree wiring) now lives entirely
in ``python-uswid-sbom`` (>= 0.2.0). See:

* :mod:`uswid.cli` — implements ``--primary-dir`` (Phase 2b)
* :mod:`uswid.submodule` — generic submodule mechanics, OSS data tables
* :mod:`uswid.edk2` — EDK II-specific seam (tag parser, light/full mode
  package lists)

What stays in this module:

* :func:`generate_sbom_from_checkout` — orchestration entry point that
  invokes ``uswid`` as a subprocess and returns the resulting CDX path
* :func:`parse_sbom`, :func:`_extract_components` — small CDX reader
  helpers used by the downstream CVE analysis code and the test suite
* :func:`sanitize_cdx_file` — defensive ``source-dir == null`` cleanup
  (kept as a safety net for older uswid output)
* :func:`list_cdx_files`, :func:`find_inf_files`, :func:`run_command` —
  small utility helpers retained for back-compat with existing scripts
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Generation: thin wrapper over the uswid CLI
# ---------------------------------------------------------------------------


def generate_sbom_from_checkout(
    location: str,
    output_name: str,
    *,
    uswid_data: Optional[str] = None,
    sbom_type: str = "source",
    **legacy_kwargs,
) -> Optional[str]:
    """Generate a merged CycloneDX SBOM by invoking ``uswid --primary-dir``.

    *location* is the EDK II source-tree root, *output_name* is the basename
    (without extension) for the resulting ``<output_name>.cdx.json`` (written
    in the current working directory), *uswid_data* (optional) points at a
    directory of curated submodule CDX templates with ``@VCS_*@`` placeholders.

    All other kwargs (``parent_yaml``, ``max_workers``) are kept for
    back-compat but silently ignored; the per-INF thread pool and CDX
    file-by-file merge are no longer needed because ``uswid --find`` walks
    the whole tree in one pass.

    Returns the absolute path to the generated SBOM on success, ``None`` on
    failure. Failures are logged with the captured CLI stderr.
    """
    if legacy_kwargs:
        logger.debug(
            "generate_sbom_from_checkout: ignoring legacy kwargs %s",
            sorted(legacy_kwargs.keys()),
        )

    if not os.path.isdir(location):
        logger.error("EDK II checkout not found: %s", location)
        return None

    output_path = os.path.abspath(os.path.join(os.getcwd(), f"{output_name}.cdx.json"))

    # Compute the expected post-substitution primary bom-ref so we can mark
    # the EDK II firmware component explicitly. uswid's `.git`-discovery
    # fallback replaces @VCS_TAG@ in the loaded edk2.cdx.json template with
    # uSwidVcs.get_tag(), which extracts the longest digit run from the
    # current `git describe` output (e.g. `edk2-stable202411` -> `"202411"`).
    primary_bomref = _compute_edk2_primary_bomref(location)

    cmd = [
        "uswid",
        "--find", location,
        "--primary-dir", location,
        "--fixup",
        "--save", output_path,
        "--format", "cyclonedx",
        "--sbom-type", sbom_type,
    ]
    if uswid_data and os.path.isdir(uswid_data):
        cmd += ["--fallback-path", uswid_data]
    if primary_bomref:
        cmd += ["--primary", primary_bomref]

    logger.info("Invoking uswid: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        logger.error(
            "uswid CLI failed (rc=%d):\nstdout: %s\nstderr: %s",
            proc.returncode,
            proc.stdout[-2000:] if proc.stdout else "",
            proc.stderr[-2000:] if proc.stderr else "",
        )
        return None

    if not os.path.isfile(output_path):
        logger.error("uswid succeeded but did not write %s", output_path)
        return None

    logger.info("SBOM generated: %s", output_path)
    return output_path


def _compute_edk2_primary_bomref(location: str) -> Optional[str]:
    """Predict the post-substitution bom-ref of the loaded EDK II template.

    Mirrors ``uswid.vcs.uSwidVcs.get_tag``: runs
    ``git describe --tags --abbrev=0`` in *location* and extracts the
    longest digit run from the dash-separated tag parts. For the EDK II
    standard tag scheme (``edk2-stable<YYYYMM>``) this yields the bare
    six-digit form (e.g. ``"202411"``).

    Returns ``None`` if git is unavailable or the directory has no tags;
    in that case the caller omits ``--primary`` and lets ``uswid``'s
    auto-pick-first-firmware-component fallback do its job.
    """
    try:
        from uswid.vcs import uSwidVcs
    except ImportError:
        logger.debug("uswid not importable; skipping --primary computation")
        return None
    try:
        vcs = uSwidVcs(filepath=location, dirpath=location)
        tag = vcs.get_tag()
    except Exception as exc:
        logger.debug("uSwidVcs.get_tag() failed: %s", exc)
        return None
    if not tag or tag == "NOASSERTION":
        return None
    return f"pkg:github/tianocore/edk2@{tag}"


# ---------------------------------------------------------------------------
# CDX parsing (used by the CVE-analysis pipeline and the test suite)
# ---------------------------------------------------------------------------


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
        comps = (
            data.get("metadata", {})
            .get("component", {})
            .get("components", [])
        )
    else:
        return []
    return comps if isinstance(comps, list) else []


# ---------------------------------------------------------------------------
# Small utility helpers (kept for back-compat with existing scripts and tests)
# ---------------------------------------------------------------------------


def list_cdx_files(folder: str) -> list[str]:
    """Return sorted list of ``*.cdx.json`` paths in *folder*."""
    try:
        paths = sorted(
            os.path.join(folder, f)
            for f in os.listdir(folder)
            if f.lower().endswith(".cdx.json")
        )
    except OSError as exc:
        logger.error("Error listing CDX files in %s: %s", folder, exc)
        return []
    logger.info("Found %d CDX files in %s", len(paths), folder)
    return paths


def find_inf_files(root: str) -> list[str]:
    """Recursively find all ``.inf`` files under *root*."""
    results: list[str] = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().endswith(".inf"):
                results.append(os.path.join(dirpath, fn))
    logger.info("Found %d .inf files under %s", len(results), root)
    return results


def sanitize_cdx_file(cdx_path: str) -> bool:
    """Replace ``"source-dir": null`` with ``""`` in-place.

    Historically this worked around a uswid bug that crashed on null
    source-dir values during ``--fixup``. The bug is fixed upstream, so
    this is now purely a safety net — kept for back-compat with the test
    suite and any third-party SBOMs that still contain such nulls.

    Returns ``True`` when the file was readable and writeable (whether or
    not modifications were necessary); ``False`` if the file is missing
    or unreadable.
    """
    try:
        with open(cdx_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read %s for sanitisation: %s", cdx_path, exc)
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
            logger.warning("Cannot write sanitised %s: %s", cdx_path, exc)
            return False
    return True


def run_command(cmd: list[str]) -> int:
    """Run *cmd* and return its exit code. Stdout/stderr are logged."""
    logger.info("Running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.stdout:
            logger.debug("stdout: %s", proc.stdout.strip())
        if proc.stderr:
            logger.warning("stderr: %s", proc.stderr.strip())
        if proc.returncode != 0:
            logger.warning("Command exited with code %d", proc.returncode)
        return proc.returncode
    except OSError as exc:
        logger.error("Command failed: %s", exc)
        return 1
