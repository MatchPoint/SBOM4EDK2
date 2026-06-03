#!/usr/bin/env python3
"""Scenario 2 — Process a local EDK2 checkout and generate a source SBOM."""

import argparse
import logging
import os
import sys
import time

from dotenv import load_dotenv

from sbom4edk2.sbom import generate_sbom_from_checkout
from sbom4edk2.uswid_data import ensure_uswid_data

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(
            f"edk2_json_generator_{time.strftime('%Y%m%d_%H%M%S')}.log"
        ),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Process a local EDK2 checkout and generate a source SBOM.",
    )
    parser.add_argument(
        "-l", "--location", required=True, help="EDK2 source tree to scan"
    )
    parser.add_argument(
        "-n",
        "--jsonname",
        required=True,
        help="Output CDX filename (without extension)",
    )
    parser.add_argument(
        "--uswid-data",
        default=None,
        help="Path to uswid-data templates (optional; auto-cloned under SBOM4EDK2 if missing)",
    )
    parser.add_argument(
        "--sbom-type",
        default="source",
        choices=["source", "build", "binary"],
        help="SBOM lifecycle type (default: source)",
    )
    args = parser.parse_args()

    location = os.path.abspath(args.location)
    uswid_dir = ensure_uswid_data(args.uswid_data)
    final_cdx = generate_sbom_from_checkout(
        location,
        args.jsonname,
        uswid_data=uswid_dir,
        sbom_type=args.sbom_type,
    )
    if not final_cdx:
        logger.error("SBOM generation failed")
        sys.exit(2)

    logger.info("SBOM written: %s", final_cdx)
    logger.info(
        "CVE scan: use VEX4EDK2 — python scripts/get_cve_response.py %s",
        final_cdx,
    )


if __name__ == "__main__":
    main()
