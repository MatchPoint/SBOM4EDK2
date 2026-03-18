#!/usr/bin/env python3
"""Scenario 3 — Generate CVE list from an existing SBOM (.cdx.json) file."""

import argparse
import logging
import os
import sys

from dotenv import load_dotenv

from sbom4edk2.cve_analyzer import generate_cve_report

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("get_cve_response.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate CVE list from an existing SBOM (.cdx.json) file.",
    )
    parser.add_argument("cdx_file", help="Path to CycloneDX SBOM (.cdx.json)")
    parser.add_argument(
        "-k", "--apikey", default=None,
        help="NVD API key (overrides NVD_API_KEY from .env)",
    )
    args = parser.parse_args()

    api_key = args.apikey or os.environ.get("NVD_API_KEY")
    if not api_key:
        logger.error("NVD API key required. Use -k or set NVD_API_KEY in .env")
        sys.exit(1)

    generate_cve_report(args.cdx_file, api_key)
    logger.info("Done.")


if __name__ == "__main__":
    main()
