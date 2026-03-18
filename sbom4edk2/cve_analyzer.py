"""Concurrent CVE analysis: process SBOM components and generate reports."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd

from .cpe import build_cpe_pattern, extract_cve_details, is_valid_component
from .nvd import NvdClient
from .sbom import parse_sbom

logger = logging.getLogger(__name__)


def generate_cve_report(
    cdx_path: str,
    api_key: str,
    *,
    output_xlsx: str = "CVE_List.xlsx",
    max_workers: int = 6,
) -> pd.DataFrame | None:
    """Analyse a CycloneDX SBOM and write a CVE Excel report.

    Returns the CVE DataFrame, or ``None`` if no CVEs were found.
    """
    components = parse_sbom(cdx_path)
    if not components:
        logger.warning("No components in %s — nothing to analyse", cdx_path)
        return None

    client = NvdClient(api_key)
    total = len(components)
    logger.info("Analysing %d components with %d workers", total, max_workers)

    results: list[dict] = []
    invalid_patterns: list[dict] = []
    lock = threading.Lock()
    done = [0]

    def _process(idx: int, comp: dict) -> None:
        details, invalids = _analyse_component(client, comp, idx, total)
        with lock:
            results.extend(details)
            invalid_patterns.extend(invalids)
            done[0] += 1
            if done[0] % 10 == 0 or done[0] == total:
                logger.info("Progress: %d/%d components", done[0], total)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_process, i, c) for i, c in enumerate(components)]
        for future in as_completed(futures):
            exc = future.exception()
            if exc:
                logger.error("Component processing error: %s", exc, exc_info=True)

    if invalid_patterns:
        logger.info("Invalid CPE patterns: %d", len(invalid_patterns))

    if not results:
        logger.warning("No CVE data found")
        return None

    df = pd.DataFrame(results).drop_duplicates(subset="id", keep="first")
    logger.info(
        "CVEs collected: %d total, %d unique",
        len(results),
        len(df),
    )

    df.to_excel(output_xlsx, index=False)
    logger.info("Report written to %s", output_xlsx)
    return df


def _analyse_component(
    client: NvdClient, component: dict, idx: int, total: int
) -> tuple[list[dict], list[dict]]:
    if not is_valid_component(component):
        return [], []

    cpe = build_cpe_pattern(component)
    if not cpe:
        return [], []

    logger.info("[%d/%d] CPE: %s", idx + 1, total, cpe)
    cve_df, status, invalid_info = client.search_cves_for_cpe(cpe)

    details: list[dict] = []
    if not cve_df.empty:
        for _, row in cve_df.iterrows():
            details.append(extract_cve_details(component, cpe, row))

    invalids: list[dict] = []
    if invalid_info:
        invalids.append(invalid_info)

    return details, invalids
