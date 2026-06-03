#!/usr/bin/env python3
"""Scenario 1 — Clone an EDK2 repo and generate a source SBOM."""

import argparse
import logging
import os
import sys
import time

from dotenv import load_dotenv

from sbom4edk2.git_utils import clone_or_update
from sbom4edk2.sbom import generate_sbom_from_checkout
from sbom4edk2.uswid_data import ensure_uswid_data

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
USWID_DATA_DIR = "uswid-data"  # default clone dir under SBOM4EDK2 repo root


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Clone an EDK2 repo and generate a source CycloneDX SBOM.",
    )
    parser.add_argument("-r", "--repo", required=True, help="EDK2 git repository URL")
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output name (clone directory and CDX filename, without extension)",
    )
    parser.add_argument(
        "--sbom-type",
        default="source",
        choices=["source", "build", "binary"],
        help="SBOM lifecycle type per UEFI SBOM Guidelines §3.1.1.3 (default: source)",
    )
    args = parser.parse_args()

    uswid_dir = ensure_uswid_data()
    clone_or_update(args.repo, args.output, init_submodules=True)

    logger.info("Generating source SBOM from EDK2 checkout...")
    cdx_file = generate_sbom_from_checkout(
        location=args.output,
        output_name=args.output,
        uswid_data=uswid_dir,
        sbom_type=args.sbom_type,
    )
    if not cdx_file:
        logger.error("SBOM generation failed")
        sys.exit(1)
    logger.info("SBOM generated: %s", cdx_file)
    logger.info(
        "CVE scan: use VEX4EDK2 — python scripts/get_cve_response.py %s",
        cdx_file,
    )


if __name__ == "__main__":
    main()
