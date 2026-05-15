"""CycloneDX SBOM parsing and CDX file utilities."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


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


def sanitize_cdx_file(cdx_path: str) -> bool:
    """Fix ``None`` source-dir values that crash ``uswid --fixup``."""
    try:
        with open(cdx_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
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
        except Exception as exc:
            logger.error("Failed to write sanitised %s: %s", cdx_path, exc)
            return False

    return True


def merge_cdx_files(
    cdx_files: list[str],
    output_path: str,
    *,
    parent_yaml: Optional[str] = None,
    fallback_path: Optional[str] = None,
    sbom_type: str = "source",
    chunk_size: int = 100,
) -> int:
    """Hierarchically merge CDX files via ``uswid``.

    *sbom_type* is passed as ``--sbom-type`` to every uswid merge invocation
    so the CycloneDX ``metadata.lifecycles[].phase`` field is set correctly per
    UEFI SBOM Guidelines §3.1.1.3 (``source``→``pre-build``,
    ``build``→``build``, ``binary``→``post-build``).

    Returns 0 on success, non-zero on failure.
    """
    if not cdx_files:
        logger.error("No CDX files to merge")
        return 1

    logger.info("Merging %d CDX files -> %s", len(cdx_files), output_path)

    for path in cdx_files:
        sanitize_cdx_file(path)

    current = list(cdx_files)
    intermediates: list[str] = []
    parent_loaded = False
    pass_num = 0

    while len(current) > 1:
        pass_num += 1
        next_round: list[str] = []

        for i in range(0, len(current), chunk_size):
            chunk = current[i : i + chunk_size]
            chunk_num = i // chunk_size + 1
            out = os.path.join(
                os.path.dirname(output_path),
                f"_intermediate_p{pass_num}_c{chunk_num}.cdx.json",
            )

            cmd = ["uswid"]
            if parent_yaml and not parent_loaded and pass_num == 1 and i == 0:
                cmd += ["--load", parent_yaml]
                parent_loaded = True
            for f in chunk:
                cmd += ["--load", f]
            cmd.append("--fixup")
            if fallback_path:
                cmd += ["--fallback-path", fallback_path]
            cmd += ["--sbom-type", sbom_type]
            cmd += ["--save", out]

            rc = run_command(cmd)
            if rc != 0:
                logger.error("Merge pass %d chunk %d failed (rc=%d)", pass_num, chunk_num, rc)
                return rc

            sanitize_cdx_file(out)
            next_round.append(out)
            intermediates.append(out)

        current = next_round

    final = current[0]
    if final != output_path:
        shutil.move(final, output_path)
        intermediates = [f for f in intermediates if f != final]

    for f in intermediates:
        try:
            os.remove(f)
        except OSError:
            pass

    logger.info("Merge complete: %s", output_path)
    return 0


def process_inf_file(
    inf_path: str,
    output_folder: str,
    *,
    uswid_data: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """Run ``uswid --load`` on one ``.inf`` file and save a per-component CDX."""
    if not os.path.isfile(inf_path):
        return False, f"File not found: {inf_path}"

    base = os.path.splitext(os.path.basename(inf_path))[0]
    out = os.path.join(output_folder, f"{base}.cdx.json")

    cmd = ["uswid", "--load", inf_path, "--fixup"]
    if uswid_data:
        cmd += ["--fallback-path", uswid_data]
    cmd += ["--save", out]

    rc = run_command(cmd)
    if rc != 0:
        return False, f"uswid exited with code {rc} for {inf_path}"
    return True, None


def _get_edk2_version(location: str) -> str:
    """Extract the EDK2 release version string from the git checkout at *location*.

    Returns a string like ``"202602"`` (YYYYMM from the ``edk2-stable<YYYYMM>`` tag)
    or ``"unknown"`` when the tag cannot be determined.
    """
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--match", "edk2-stable*", "--abbrev=0"],
            cwd=location,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            tag = result.stdout.strip()          # e.g. "edk2-stable202602"
            return tag.replace("edk2-stable", "")
    except Exception:
        pass
    return "unknown"


def _merge_inf_cdx_direct(
    inf_cdx_files: list[str],
    output_path: str,
    *,
    location: str = "",
    fallback_path: Optional[str] = None,
    sbom_type: str = "source",
) -> int:
    """Build a merged CycloneDX SBOM from per-.inf CDX files + uswid-data.

    The ``uswid --load`` merge approach silently overwrites each loaded
    ``metadata.component`` with the next, leaving only the last component in
    the output.  This function works around the limitation by doing a direct
    JSON merge:

    1.  The EDK2 primary component is taken from
        ``<fallback_path>/edk2.cdx.json`` ``components[0]`` (if present).
    2.  OSS submodule components are collected from all other
        ``<fallback_path>/*.cdx.json`` files.
    3.  Each per-``.inf`` component is extracted from its CDX
        ``metadata.component``.
    4.  All components are placed in the ``components[]`` array.
    5.  ``@VCS_*`` placeholders in the primary component are resolved via
        git in *location*.
    """
    import uuid
    import re
    from datetime import datetime, timezone

    phase_map = {"source": "pre-build", "build": "build", "binary": "post-build"}
    phase = phase_map.get(sbom_type, "pre-build")

    # --- primary component (EDK2) from uswid-data/edk2.cdx.json ---
    primary: dict = {
        "type": "firmware",
        "bom-ref": "tianocore:edk2",
        "name": "EDK II",
        "version": "unknown",
        "supplier": {"name": "TianoCore"},
        "licenses": [{"license": {"id": "BSD-2-Clause"}}],
    }
    if fallback_path:
        edk2_cdx = os.path.join(fallback_path, "edk2.cdx.json")
        if os.path.isfile(edk2_cdx):
            try:
                fd = json.load(open(edk2_cdx, encoding="utf-8"))
                candidates = fd.get("components", []) or [fd.get("metadata", {}).get("component", {})]
                if candidates and candidates[0]:
                    primary = dict(candidates[0])
                    logger.info("EDK2 primary component loaded from %s", edk2_cdx)
            except Exception as exc:
                logger.warning("Could not load EDK2 primary from %s: %s", edk2_cdx, exc)

    # Resolve @VCS_* placeholders
    edk2_ver = _get_edk2_version(location) if location else "unknown"
    logger.info("EDK2 version: %s", edk2_ver)

    def _subst(val: str) -> str:
        val = re.sub(r"@VCS_VERSION@", edk2_ver, val)
        val = re.sub(r"@VCS_TAG@", f"edk2-stable{edk2_ver}", val)
        val = re.sub(r"@VCS_AUTHORS@", "TianoCore contributors", val)
        return val

    def _subst_recursive(obj):
        if isinstance(obj, str):
            return _subst(obj)
        if isinstance(obj, list):
            return [_subst_recursive(i) for i in obj]
        if isinstance(obj, dict):
            return {k: _subst_recursive(v) for k, v in obj.items()}
        return obj

    primary = _subst_recursive(primary)

    # --- OSS submodule components from other uswid-data CDX files ---
    submodule_components: list[dict] = []
    if fallback_path and os.path.isdir(fallback_path):
        for cdx_file in sorted(os.listdir(fallback_path)):
            if not cdx_file.endswith(".cdx.json") or cdx_file == "edk2.cdx.json":
                continue
            fp = os.path.join(fallback_path, cdx_file)
            try:
                fd = json.load(open(fp, encoding="utf-8"))
                for comp in fd.get("components", []):
                    if comp:
                        submodule_components.append(comp)
                mc = fd.get("metadata", {}).get("component", {})
                if mc and mc.get("name"):
                    submodule_components.append(mc)
            except Exception as exc:
                logger.warning("Could not load fallback CDX %s: %s", fp, exc)
        logger.info("Loaded %d submodule components from uswid-data", len(submodule_components))

    # --- per-.inf components ---
    inf_components: list[dict] = []
    for cdx_file in inf_cdx_files:
        try:
            fd = json.load(open(cdx_file, encoding="utf-8"))
            mc = fd.get("metadata", {}).get("component", {})
            if mc and mc.get("name"):
                inf_components.append(mc)
        except Exception as exc:
            logger.warning("Could not load INF CDX %s: %s", cdx_file, exc)
    logger.info("Loaded %d INF components", len(inf_components))

    # Deduplicate by bom-ref (submodule data takes precedence over INF data)
    seen_refs: set[str] = set()
    all_components: list[dict] = []
    for comp in submodule_components + inf_components:
        key = comp.get("bom-ref") or comp.get("name", "")
        if key and key not in seen_refs:
            seen_refs.add(key)
            all_components.append(comp)

    # Build the final CDX
    output_cdx: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "SBOM4EDK2",
                    "name": "SBOM4EDK2",
                    "version": "0.0.0+unknown",
                }
            ],
            "lifecycles": [{"phase": phase}],
            "component": primary,
        },
        "components": all_components,
    }

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(output_cdx, fh, indent=2)
        logger.info(
            "Direct JSON merge: %d components -> %s",
            len(all_components),
            output_path,
        )
        return 0
    except Exception as exc:
        logger.error("Failed to write merged CDX %s: %s", output_path, exc)
        return 1


def generate_sbom_from_checkout(
    location: str,
    output_name: str,
    *,
    uswid_data: Optional[str] = None,
    parent_yaml: Optional[str] = None,
    sbom_type: str = "source",
    max_workers: int = 12,
) -> Optional[str]:
    """Generate a merged CycloneDX SBOM from an EDK2 source tree.

    Scans *location* for ``.inf`` files, processes each with
    ``uswid --load --fixup``, then merges all per-component CDX files into a
    single ``<output_name>.cdx.json`` in the current working directory.

    Returns the path to the merged CDX file on success, ``None`` on failure.
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed

    inf_files = find_inf_files(location)
    if not inf_files:
        logger.warning("No .inf files found in %s", location)
        return None

    cdx_output = os.path.join(os.getcwd(), "cdx_json_output")
    os.makedirs(cdx_output, exist_ok=True)

    logger.info("Processing %d .inf files with %d workers...", len(inf_files), max_workers)
    failed: list[str] = []
    done = [0]
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(process_inf_file, inf, cdx_output, uswid_data=uswid_data): inf
            for inf in inf_files
        }
        for future in as_completed(futures):
            inf = futures[future]
            success, err = future.result()
            with lock:
                done[0] += 1
                if not success:
                    failed.append(inf)
                if done[0] % 100 == 0:
                    logger.info("Progress: %d/%d .inf files processed", done[0], len(inf_files))

    logger.info(
        "INF processing complete: %d succeeded, %d failed",
        len(inf_files) - len(failed),
        len(failed),
    )

    cdx_files = list_cdx_files(cdx_output)
    if not cdx_files:
        logger.error("No CDX files generated from .inf processing")
        return None

    output_path = os.path.join(os.getcwd(), f"{output_name}.cdx.json")
    rc = _merge_inf_cdx_direct(
        cdx_files,
        output_path,
        location=location,
        fallback_path=uswid_data,
        sbom_type=sbom_type,
    )
    if rc != 0:
        logger.error("CDX merge failed (rc=%d)", rc)
        return None

    return output_path


def find_inf_files(root: str) -> list[str]:
    """Recursively find all ``.inf`` files under *root*."""
    results: list[str] = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().endswith(".inf"):
                results.append(os.path.join(dirpath, fn))
    logger.info("Found %d .inf files under %s", len(results), root)
    return results


def run_command(cmd: list[str]) -> int:
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
    except Exception as exc:
        logger.error("Command failed: %s", exc)
        return 1
