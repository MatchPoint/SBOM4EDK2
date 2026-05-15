#!/usr/bin/env python3
"""Scenario 3 — Generate CVE list from an existing SBOM (.cdx.json) file.

Scanner back-ends (``--scanner``):

* ``auto``  — **Default.** Uses NVD if ``NVD_API_KEY`` is set, otherwise falls
              back to grype.  Recommended for most users.
* ``nvd``   — Query the NVD REST API directly. Requires ``NVD_API_KEY``.
              No local DB download; authoritative but rate-limited (~30 min for
              a full EDK2 SBOM).
* ``grype`` — Run the Anchore grype binary. No API key required; downloads a
              local vulnerability DB (~600 MB, cached with daily delta updates).
              Scans complete in seconds.
* ``both``  — Run both NVD and grype; writes two separate Excel reports.

In addition to the selected back-end, TianoCore GitHub Security Advisories are
**always** checked (``CVE_List_ghsa.xlsx``).  These advisories are published
directly by the EDK2 maintainers before NVD processes them, making them the
most timely source of EDK2-specific CVEs.
"""

import argparse
import logging
import os
import sys

from dotenv import load_dotenv

from sbom4edk2.cve_analyzer import generate_cve_report
from sbom4edk2.ghsa import scan_sbom_with_ghsa
from sbom4edk2.grype import is_grype_available, scan_sbom_with_grype

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


def _resolve_scanner(requested: str, api_key: str | None) -> tuple[bool, bool]:
    """Return (use_nvd, use_grype) based on requested scanner and key availability."""
    if requested == "auto":
        if api_key:
            logger.info("NVD_API_KEY found — using NVD scanner.")
            return True, False
        logger.info("No NVD_API_KEY — falling back to grype scanner.")
        return False, True
    return requested in ("nvd", "both"), requested in ("grype", "both")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate CVE list from an existing SBOM (.cdx.json) file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("cdx_file", help="Path to CycloneDX SBOM (.cdx.json)")
    parser.add_argument(
        "-k", "--apikey", default=None,
        help="NVD API key (overrides NVD_API_KEY from .env); required for --scanner nvd/both",
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
    use_nvd, use_grype = _resolve_scanner(args.scanner, api_key)

    if use_nvd and not api_key:
        logger.error(
            "NVD API key required for --scanner %s. "
            "Use -k/--apikey or set NVD_API_KEY in .env",
            args.scanner,
        )
        sys.exit(1)

    if use_grype and not is_grype_available():
        logger.error(
            "grype binary not found.  Install it with:\n"
            "  Linux/WSL: curl -sSfL "
            "https://raw.githubusercontent.com/anchore/grype/main/install.sh"
            " | sh -s -- -b ~/.local/bin\n"
            "  Windows:   winget install Anchore.Grype"
        )
        if args.scanner == "grype":
            sys.exit(1)
        logger.warning("Grype unavailable; no CVE scan will run. Use --scanner nvd with an API key.")
        use_grype = False

    base = os.path.splitext(os.path.basename(args.cdx_file))[0]

    if use_nvd:
        generate_cve_report(args.cdx_file, api_key)

    if use_grype:
        scan_sbom_with_grype(args.cdx_file, output_xlsx=f"CVE_List_grype_{base}.xlsx")

    if args.ghsa:
        scan_sbom_with_ghsa(args.cdx_file, output_xlsx=f"CVE_List_ghsa_{base}.xlsx")

    logger.info("Done.")


if __name__ == "__main__":
    main()
