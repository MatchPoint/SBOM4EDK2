#!/usr/bin/env python3
"""Scenario 1 — Clone an EDK2 repo, generate SBOM, and create CVE list."""

import argparse
import logging
import os
import subprocess
import sys
import time

from dotenv import load_dotenv

from sbom4edk2.cve_analyzer import generate_cve_report
from sbom4edk2.git_utils import clone_or_update

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(f"sbom4edk2_{time.strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

USWID_DATA_REPO = "https://github.com/hughsie/uswid-data.git"
USWID_DATA_DIR = "uswid-data"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Clone an EDK2 repo, generate SBOM, and create CVE list.",
    )
    parser.add_argument("-r", "--repo", required=True, help="EDK2 git repository URL")
    parser.add_argument(
        "-o", "--output", required=True,
        help="Output name (used as clone directory and CDX filename, without extension)",
    )
    parser.add_argument(
        "-k", "--apikey", default=None,
        help="NVD API key (overrides NVD_API_KEY from .env)",
    )
    args = parser.parse_args()

    api_key = args.apikey or os.environ.get("NVD_API_KEY")
    if not api_key:
        logger.error("NVD API key required. Use -k or set NVD_API_KEY in .env")
        sys.exit(1)

    clone_or_update(USWID_DATA_REPO, USWID_DATA_DIR)
    clone_or_update(args.repo, args.output, init_submodules=True)

    cdx_file = f"{args.output}.cdx.json"
    logger.info("Running uswid to generate SBOM …")
    result = subprocess.run(
        ["uswid", "--verbose", "--find", args.output,
         "--fallback-path", USWID_DATA_DIR, "--save", cdx_file],
        check=False,
    )
    if result.returncode != 0 or not os.path.exists(cdx_file):
        logger.error("uswid failed to generate %s", cdx_file)
        sys.exit(1)
    logger.info("SBOM generated: %s", cdx_file)

    generate_cve_report(cdx_file, api_key)
    logger.info("Done.")


if __name__ == "__main__":
    main()
