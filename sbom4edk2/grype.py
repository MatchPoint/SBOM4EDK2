"""Grype-based vulnerability scanning for CycloneDX SBOMs.

Grype (https://github.com/anchore/grype) is an open-source vulnerability
scanner that accepts a CycloneDX SBOM as direct input and matches components
against multiple databases (NVD, GitHub Advisory, OSV, etc.).  It is a
preferred alternative to manual NVD API queries because:

* It resolves CPE matches using an offline database (no API key required).
* It handles PURL-based matching in addition to CPE, catching more hits.
* It reports EPSS scores alongside CVSS so you can prioritise by exploitability.
* It deduplicates across vulnerability databases automatically.

Installation
-----------
Linux / WSL::

    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \\
        | sh -s -- -b ~/.local/bin

Windows (winget)::

    winget install Anchore.Grype

The module auto-discovers the binary in these locations (in order):

1. ``grype`` on the system PATH
2. ``~/.local/bin/grype`` (Linux/WSL per-user install)
3. ``%LOCALAPPDATA%\\Microsoft\\WinGet\\Packages\\*grype*\\grype.exe`` (Windows winget)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------

_EXTRA_SEARCH_PATHS = [
    Path.home() / ".local" / "bin" / "grype",
    # Common winget install locations (Windows)
    Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links" / "grype.exe",
]


def _find_grype() -> Optional[str]:
    """Return the path to the grype binary, or *None* if not found."""
    # 1. On PATH
    found = shutil.which("grype")
    if found:
        return found
    # 2. Well-known per-user / package-manager locations
    for candidate in _EXTRA_SEARCH_PATHS:
        if candidate.is_file():
            return str(candidate)
    return None


def is_grype_available() -> bool:
    """Return *True* if a grype binary can be located."""
    return _find_grype() is not None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def scan_sbom_with_grype(
    cdx_path: str,
    *,
    output_xlsx: str = "CVE_List_grype.xlsx",
    add_epss: bool = True,
) -> Optional[pd.DataFrame]:
    """Run grype against *cdx_path* and write a CVE Excel report.

    Parameters
    ----------
    cdx_path:
        Path to a CycloneDX JSON SBOM file.
    output_xlsx:
        Destination Excel file for the CVE report.
    add_epss:
        Include EPSS score / percentile columns when *True* (default).

    Returns
    -------
    pd.DataFrame
        A DataFrame of findings (may be empty), or *None* if grype could not
        be run or failed.
    """
    grype_bin = _find_grype()
    if not grype_bin:
        logger.error(
            "grype binary not found.  Install it with:\n"
            "  Linux/WSL: "
            "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh"
            " | sh -s -- -b ~/.local/bin\n"
            "  Windows:   winget install Anchore.Grype"
        )
        return None

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        cmd = [grype_bin, f"sbom:{cdx_path}", "--output", "json", "--file", tmp_path]
        logger.info("grype command: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode not in (0, 1):
            # grype exits 1 when vulnerabilities ARE found (not an error)
            logger.error("grype failed (rc=%d): %s", result.returncode, result.stderr.strip())
            return None

        with open(tmp_path, encoding="utf-8") as f:
            data = json.load(f)

        matches: list[dict] = data.get("matches", [])
        if not matches:
            logger.info("grype: no vulnerabilities found in %s", cdx_path)
            return pd.DataFrame()

        rows = []
        for m in matches:
            vuln = m.get("vulnerability", {})
            artifact = m.get("artifact", {})

            # Pick the best CVSS score: prefer v3.1 primary, fall back to v2.0
            cvss_score: Optional[float] = None
            cvss_vector: Optional[str] = None
            for entry in vuln.get("cvss", []):
                metrics = entry.get("metrics", {})
                score = metrics.get("baseScore")
                if score is None:
                    continue
                version = entry.get("version", "")
                if version.startswith("3") or cvss_score is None:
                    cvss_score = score
                    cvss_vector = entry.get("vector")

            # EPSS (Exploit Prediction Scoring System) — first entry if present
            epss_score: Optional[float] = None
            epss_percentile: Optional[float] = None
            epss_entries = vuln.get("epss", [])
            if epss_entries:
                epss_score = epss_entries[0].get("epss")
                epss_percentile = epss_entries[0].get("percentile")

            # Fix information
            fix_info = vuln.get("fix", {})
            fix_versions = ", ".join(fix_info.get("versions", [])) or "no fix"
            fix_state = fix_info.get("state", "")

            # First CPE reported by grype for this artifact
            artifact_cpe = next(iter(artifact.get("cpes", [])), "")

            row: dict = {
                "id": vuln.get("id"),
                "name": artifact.get("name"),
                "version": artifact.get("version"),
                "severity": vuln.get("severity"),
                "score": cvss_score,
                "CVSSString": cvss_vector,
                "fix_versions": fix_versions,
                "fix_state": fix_state,
                "published": vuln.get("publishedDate", ""),
                "descriptions": (vuln.get("description") or "")[:300],
                "cpe": artifact_cpe,
                "purl": artifact.get("purl", ""),
                "namespace": vuln.get("namespace", ""),
            }
            if add_epss:
                row["epss_score"] = epss_score
                row["epss_percentile"] = epss_percentile

            rows.append(row)

        df = pd.DataFrame(rows).sort_values(
            ["score", "id"], ascending=[False, True], na_position="last"
        ).drop_duplicates(subset="id", keep="first").reset_index(drop=True)

        logger.info(
            "grype found %d unique vulnerabilities (%d total matches) in %s",
            len(df),
            len(matches),
            cdx_path,
        )

        df.to_excel(output_xlsx, index=False)
        logger.info("Grype CVE report written to %s", output_xlsx)
        return df

    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
