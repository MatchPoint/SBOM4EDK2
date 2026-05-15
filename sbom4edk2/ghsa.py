"""TianoCore EDK2 GitHub Security Advisory (GHSA) scanner.

This module queries the TianoCore EDK2 GitHub security advisories directly,
bypassing NVD's publication lag (typically 6–12 months for firmware CVEs).
Advisories are published at:

  https://github.com/tianocore/edk2/security/advisories?state=published

No API key is required for public repositories.  An optional GitHub personal
access token can be provided via the ``GITHUB_TOKEN`` environment variable to
raise the rate limit from 60 to 5,000 requests per hour.

Version matching
----------------
TianoCore advisory version constraints use 6-digit YYYYMM integers (e.g.
``<=202508``).  The SBOM's EDK2 version is extracted as the same 6-digit form
from strings like ``edk2-stable202602+444.gb03a21a63e`` or the CPE version
field ``202602``.

Compound semver-style constraints are supported (e.g. ``>=202311, <202402``).

Output
------
An Excel workbook ``CVE_List_ghsa.xlsx`` is written alongside the other scanner
reports.  The module also returns a :class:`pandas.DataFrame` for programmatic
merging into a combined report.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

_ADVISORIES_API = (
    "https://api.github.com/repos/tianocore/edk2/security-advisories"
    "?state=published&per_page=100"
)

# Extract 6-digit YYYYMM from any EDK2 version string.
_VERSION_RE = re.compile(r"(\d{6})")

# Parse a single version constraint token: operator + 6-digit version.
_CONSTRAINT_RE = re.compile(r"([<>]=?)\s*(\d{6})")


def _extract_edk2_version(version_str: str) -> Optional[int]:
    """Return the 6-digit YYYYMM integer from an EDK2 version string, or None."""
    m = _VERSION_RE.search(version_str or "")
    return int(m.group(1)) if m else None


def _version_in_range(version: int, range_str: str) -> bool:
    """Return True if *version* (YYYYMM int) satisfies the constraint string.

    Supports single constraints (``<=202508``) and compound AND constraints
    separated by commas or semicolons (``>=202311, <202402``).
    If *range_str* is empty or None every version is considered affected.
    """
    if not range_str:
        return True  # no constraint → all versions affected
    constraints = _CONSTRAINT_RE.findall(range_str)
    if not constraints:
        return True  # unparseable → conservatively report as affected
    for op, ver_str in constraints:
        ver = int(ver_str)
        if op == "<=" and not (version <= ver):
            return False
        if op == "<" and not (version < ver):
            return False
        if op == ">=" and not (version >= ver):
            return False
        if op == ">" and not (version > ver):
            return False
    return True


def _fetch_advisories(github_token: Optional[str] = None) -> list[dict]:
    """Fetch all published EDK2 advisories from the GitHub API."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    req = urllib.request.Request(_ADVISORIES_API, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except Exception as exc:
        logger.error("Failed to fetch GHSA advisories: %s", exc)
        return []


def scan_sbom_with_ghsa(
    cdx_path: str,
    *,
    output_xlsx: str = "CVE_List_ghsa.xlsx",
    github_token: Optional[str] = None,
) -> Optional[pd.DataFrame]:
    """Query the TianoCore GHSA feed and report advisories that affect the SBOM.

    Parameters
    ----------
    cdx_path:
        Path to a CycloneDX JSON SBOM file.
    output_xlsx:
        Destination Excel file for the GHSA CVE report.
    github_token:
        Optional GitHub PAT to avoid API rate limits (60 req/hr unauthenticated
        vs 5,000 req/hr authenticated).  Falls back to the ``GITHUB_TOKEN``
        environment variable if not supplied.

    Returns
    -------
    pd.DataFrame
        A DataFrame of matching advisories (may be empty), or *None* on error.
    """
    token = github_token or os.environ.get("GITHUB_TOKEN")

    # --- Determine the EDK2 version from the SBOM metadata ---
    try:
        with open(cdx_path, encoding="utf-8") as f:
            sbom = json.load(f)
    except Exception as exc:
        logger.error("Cannot read SBOM %s: %s", cdx_path, exc)
        return None

    meta_comp = sbom.get("metadata", {}).get("component", {})
    # Prefer the CPE version field (6-digit YYYYMM) over the full version string.
    edk2_version_raw = (
        meta_comp.get("cpe", "")
        or meta_comp.get("version", "")
    )
    edk2_ver = _extract_edk2_version(edk2_version_raw)
    if not edk2_ver:
        logger.warning(
            "Cannot determine EDK2 version from SBOM (got %r); "
            "reporting ALL advisories as potentially applicable.",
            edk2_version_raw,
        )

    logger.info(
        "GHSA scan: EDK2 SBOM version = %s, querying TianoCore advisories …",
        edk2_ver or "UNKNOWN",
    )

    advisories = _fetch_advisories(github_token=token)
    if not advisories:
        logger.warning("No advisories returned from GitHub API")
        return pd.DataFrame()

    rows = []
    for adv in advisories:
        # Skip test entries (TianoCore has one GHSA-5xcf-j538-p769 marked ***IGNORE***)
        if "***IGNORE***" in (adv.get("summary") or ""):
            continue

        cve_id = adv.get("cve_id") or next(
            (i["value"] for i in adv.get("identifiers", []) if i.get("type") == "CVE"),
            adv["ghsa_id"],
        )
        severity = adv.get("severity", "unknown")
        summary = adv.get("summary", "")
        published = (adv.get("published_at") or "")[:10]
        ghsa_url = adv.get("html_url", "")

        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None
        cvss_block = adv.get("cvss_severities", {}).get("cvss_v3") or adv.get("cvss") or {}
        cvss_score = cvss_block.get("score")
        cvss_vector = cvss_block.get("vector_string")

        # Evaluate each vulnerability entry against the SBOM version.
        vulns = adv.get("vulnerabilities") or []
        if not vulns:
            # Advisory has no version constraints → applicable to all versions.
            vulns = [{"package": {}, "vulnerable_version_range": None, "patched_versions": None}]

        applicable = False
        affected_packages: list[str] = []
        patched_in: list[str] = []
        for vuln in vulns:
            pkg = vuln.get("package", {}) or {}
            vrange = vuln.get("vulnerable_version_range") or ""
            patched = vuln.get("patched_versions") or ""
            pkg_name = pkg.get("name", "")

            if edk2_ver is None or _version_in_range(edk2_ver, vrange):
                applicable = True
                if pkg_name:
                    affected_packages.append(pkg_name)
                if patched:
                    patched_in.append(patched)

        if applicable:
            rows.append({
                "id": cve_id,
                "ghsa_id": adv["ghsa_id"],
                "name": "EDK II",
                "version": meta_comp.get("version", ""),
                "severity": severity,
                "score": cvss_score,
                "CVSSString": cvss_vector,
                "affected_packages": ", ".join(affected_packages) or "EDK II",
                "fix_versions": ", ".join(patched_in) or "no fix",
                "published": published,
                "descriptions": summary[:300],
                "source": "TianoCore GHSA",
                "url": ghsa_url,
            })

    df = pd.DataFrame(rows)
    if df.empty:
        logger.info(
            "GHSA: no advisories apply to EDK2 version %s (checked %d advisories)",
            edk2_ver,
            len(advisories),
        )
        return df

    df = df.sort_values(["score", "id"], ascending=[False, True], na_position="last").reset_index(drop=True)
    logger.info(
        "GHSA: %d applicable advisories for EDK2 version %s (out of %d total)",
        len(df),
        edk2_ver,
        len(advisories),
    )
    df.to_excel(output_xlsx, index=False)
    logger.info("GHSA report written to %s", output_xlsx)
    return df
