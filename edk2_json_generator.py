#!/usr/bin/env python3
"""Scenario 2 — Process a local EDK2 checkout: generate SBOM and CVE list.

Thin orchestration around :func:`sbom4edk2.sbom.generate_sbom_from_checkout`
(which is itself a thin wrapper over the ``uswid --primary-dir`` CLI from
``python-uswid-sbom``). All SBOM-creation work happens inside ``uswid``;
this script handles command-line parsing, scanner selection, and the CVE
reporting step.
"""

import argparse
import logging
import os
import sys
import time

from dotenv import load_dotenv

from sbom4edk2.cve_analyzer import generate_cve_report
from sbom4edk2.ghsa import scan_sbom_with_ghsa
from sbom4edk2.grype import is_grype_available, scan_sbom_with_grype
from sbom4edk2.sbom import generate_sbom_from_checkout, run_command

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
        description="Process a local EDK2 checkout: generate SBOM and CVE list.",
    )
    parser.add_argument(
        "-l", "--location", required=True, help="EDK2 source tree to scan"
    )
    parser.add_argument(
        "-n", "--jsonname", required=True,
        help="Output CDX filename (without extension)",
    )
    parser.add_argument(
        "-k", "--apikey", default=None,
        help="NVD API key (overrides NVD_API_KEY from .env)",
    )
    parser.add_argument(
        "--uswid-data", default=None,
        help="Path to uswid-data for fallback metadata templates",
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
    # Kept for back-compat with prior invocations; ignored by the uswid CLI
    # which discovers and processes all .inf files in a single pass.
    parser.add_argument(
        "--max-workers", type=int, default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--parent-yaml", default=None,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    api_key = args.apikey or os.environ.get("NVD_API_KEY")

    if args.scanner == "auto":
        use_nvd = bool(api_key)
        use_grype = not bool(api_key)
        logger.info(
            "Scanner auto-detect: %s", "NVD" if use_nvd else "grype (no NVD_API_KEY)"
        )
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

    location = os.path.abspath(args.location)
    logger.info("Scanning: %s", location)

    if run_command(["uswid", "--version"]) != 0:
        logger.error("uswid not found. Install with: pip install -r requirements.txt")
        sys.exit(1)

    final_cdx = generate_sbom_from_checkout(
        location=location,
        output_name=args.jsonname,
        uswid_data=args.uswid_data,
        sbom_type=args.sbom_type,
    )
    if not final_cdx:
        logger.error("SBOM generation failed")
        sys.exit(2)
    logger.info("SBOM generated: %s", final_cdx)

    base = os.path.splitext(os.path.basename(final_cdx))[0]

    if use_nvd:
        generate_cve_report(final_cdx, api_key)

    if use_grype:
        if is_grype_available():
            scan_sbom_with_grype(final_cdx, output_xlsx=f"CVE_List_grype_{base}.xlsx")
        else:
            logger.warning(
                "grype binary not found — skipping grype scan.  "
                "Install: curl -sSfL "
                "https://raw.githubusercontent.com/anchore/grype/main/install.sh"
                " | sh -s -- -b ~/.local/bin"
            )

    if args.ghsa:
        scan_sbom_with_ghsa(final_cdx, output_xlsx=f"CVE_List_ghsa_{base}.xlsx")

    logger.info("Done.")


if __name__ == "__main__":
    main()
