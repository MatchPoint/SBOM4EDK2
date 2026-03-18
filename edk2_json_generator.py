#!/usr/bin/env python3
"""Scenario 2 — Process a local EDK2 checkout: generate SBOM and CVE list."""

import argparse
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv

from sbom4edk2.cve_analyzer import generate_cve_report
from sbom4edk2.sbom import (
    find_inf_files,
    list_cdx_files,
    merge_cdx_files,
    run_command,
    sanitize_cdx_file,
)

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(f"edk2_json_generator_{time.strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def process_inf_file(
    inf_path: str, output_folder: str, *, uswid_data: str | None = None
) -> tuple[bool, str | None]:
    """Run ``uswid`` on a single ``.inf`` file and return ``(success, error)``."""
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
        return False, f"uswid exited with code {rc}"
    return True, None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Process a local EDK2 checkout: generate SBOM and CVE list.",
    )
    parser.add_argument("-l", "--location", required=True, help="EDK2 source tree to scan")
    parser.add_argument(
        "-n", "--jsonname", required=True,
        help="Output CDX filename (without extension)",
    )
    parser.add_argument(
        "-k", "--apikey", default=None,
        help="NVD API key (overrides NVD_API_KEY from .env)",
    )
    parser.add_argument("--uswid-data", default=None, help="Path to uswid-data for fallback metadata")
    parser.add_argument("--parent-yaml", default=None, help="Parent component YAML to include in merge")
    parser.add_argument("--max-workers", type=int, default=12, help="Threads for .inf processing (default: 12)")
    args = parser.parse_args()

    api_key = args.apikey or os.environ.get("NVD_API_KEY")
    if not api_key:
        logger.error("NVD API key required. Use -k or set NVD_API_KEY in .env")
        sys.exit(1)

    location = os.path.abspath(args.location)
    logger.info("Scanning: %s", location)

    cdx_output = os.path.join(os.getcwd(), "cdx_json_output")
    os.makedirs(cdx_output, exist_ok=True)

    # Check uswid is available
    if run_command(["uswid", "--version"]) != 0:
        logger.error("uswid not found. Install with: pip install -r requirements.txt")
        sys.exit(1)

    inf_files = find_inf_files(location)
    if not inf_files:
        logger.warning("No .inf files found in %s", location)
        sys.exit(0)

    # Process .inf files concurrently
    failed: list[str] = []
    done = [0]
    lock = threading.Lock()

    logger.info("Processing %d .inf files with %d workers …", len(inf_files), args.max_workers)
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        futures = {
            pool.submit(process_inf_file, inf, cdx_output, uswid_data=args.uswid_data): inf
            for inf in inf_files
        }
        for future in as_completed(futures):
            inf = futures[future]
            try:
                ok, err = future.result()
                if not ok:
                    failed.append(inf)
                    logger.warning("Failed: %s — %s", inf, err)
            except Exception as exc:
                failed.append(inf)
                logger.error("Exception for %s: %s", inf, exc, exc_info=True)
            with lock:
                done[0] += 1
                if done[0] % 20 == 0:
                    logger.info("Progress: %d/%d .inf files", done[0], len(inf_files))

    logger.info("Processed %d .inf files (%d failed)", len(inf_files), len(failed))
    if failed:
        logger.error("Failed files:\n  %s", "\n  ".join(failed))

    # Merge CDX files
    final_cdx = os.path.join(cdx_output, f"{args.jsonname}.cdx.json")
    cdx_files = list_cdx_files(cdx_output)
    if not cdx_files:
        logger.error("No CDX files to merge")
        sys.exit(2)

    rc = merge_cdx_files(
        cdx_files, final_cdx,
        parent_yaml=args.parent_yaml,
        fallback_path=args.uswid_data,
    )
    if rc != 0:
        logger.error("CDX merge failed (exit code %d)", rc)
        sys.exit(2)

    # Generate CVE report
    generate_cve_report(final_cdx, api_key)
    logger.info("Done.")


if __name__ == "__main__":
    main()
