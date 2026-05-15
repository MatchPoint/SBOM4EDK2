#!/usr/bin/env python3
"""Scenario 1 — Clone an EDK2 repo, generate SBOM, and create CVE list."""

import argparse
import logging
import os
import sys
import time

from dotenv import load_dotenv

from sbom4edk2.cve_analyzer import generate_cve_report
from sbom4edk2.ghsa import scan_sbom_with_ghsa
from sbom4edk2.git_utils import clone_or_update
from sbom4edk2.grype import is_grype_available, scan_sbom_with_grype
from sbom4edk2.sbom import generate_sbom_from_checkout

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
    parser.add_argument(
        "--sbom-type", default="source", choices=["source", "build", "binary"],
        help="SBOM lifecycle type per UEFI SBOM Guidelines §3.1.1.3 (default: source)",
    )
    parser.add_argument(
        "--scanner", default="auto", choices=["auto", "nvd", "grype", "both"],
        help=(
            "Vulnerability scanner back-end (default: auto). "
            "'auto' uses NVD when NVD_API_KEY is set, otherwise grype. "
            "See README for trade-off details."
        ),
    )
    parser.add_argument(
        "--no-ghsa", dest="ghsa", action="store_false", default=True,
        help="Skip the TianoCore GHSA advisory check (included by default).",
    )
    args = parser.parse_args()

    api_key = args.apikey or os.environ.get("NVD_API_KEY")

    if args.scanner == "auto":
        use_nvd = bool(api_key)
        use_grype = not bool(api_key)
        logger.info("Scanner auto-detect: %s", "NVD" if use_nvd else "grype (no NVD_API_KEY)")
    else:
        use_nvd = args.scanner in ("nvd", "both")
        use_grype = args.scanner in ("grype", "both")

    if use_nvd and not api_key:
        logger.error(
            "NVD API key required for --scanner %s. "
            "Use -k/--apikey or set NVD_API_KEY in .env",
            args.scanner,
        )
        sys.exit(1)

    clone_or_update(USWID_DATA_REPO, USWID_DATA_DIR)
    clone_or_update(args.repo, args.output, init_submodules=True)

    logger.info("Generating SBOM from EDK2 .inf files...")
    cdx_file = generate_sbom_from_checkout(
        location=args.output,
        output_name=args.output,
        uswid_data=USWID_DATA_DIR if os.path.isdir(USWID_DATA_DIR) else None,
        sbom_type=args.sbom_type,
    )
    if not cdx_file:
        logger.error("SBOM generation failed")
        sys.exit(1)
    logger.info("SBOM generated: %s", cdx_file)

    base = os.path.splitext(os.path.basename(cdx_file))[0]

    if use_nvd:
        generate_cve_report(cdx_file, api_key)

    if use_grype:
        if is_grype_available():
            scan_sbom_with_grype(cdx_file, output_xlsx=f"CVE_List_grype_{base}.xlsx")
        else:
            logger.warning(
                "grype binary not found — skipping grype scan.  "
                "Install: curl -sSfL "
                "https://raw.githubusercontent.com/anchore/grype/main/install.sh"
                " | sh -s -- -b ~/.local/bin"
            )

    if args.ghsa:
        scan_sbom_with_ghsa(cdx_file, output_xlsx=f"CVE_List_ghsa_{base}.xlsx")

    logger.info("Done.")


if __name__ == "__main__":
    main()
