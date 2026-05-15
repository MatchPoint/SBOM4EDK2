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
    rc = merge_cdx_files(
        cdx_files,
        output_path,
        parent_yaml=parent_yaml,
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
