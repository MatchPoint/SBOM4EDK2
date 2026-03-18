"""NVD API client for CPE lookups and CVE retrieval."""

from __future__ import annotations

import logging
import threading
from typing import Optional

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_NVD_BASE = "https://services.nvd.nist.gov/rest/json"
_REQUEST_TIMEOUT = 30


class NvdClient:
    """Thread-safe NVD API client with retry logic and per-CPE caching."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._session = self._build_session()
        self._cache: dict[str, tuple] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _build_session() -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def search_cves_for_cpe(
        self, cpe_pattern: str
    ) -> tuple[pd.DataFrame, str, Optional[dict]]:
        """Look up CVEs for a CPE 2.3 pattern.

        Returns ``(dataframe, status_message, invalid_pattern_info)``.
        Results are cached per *cpe_pattern* for the lifetime of this client.
        """
        with self._lock:
            if cpe_pattern in self._cache:
                logger.debug("Cache hit for CPE pattern: %s", cpe_pattern)
                return self._cache[cpe_pattern]

        result = self._query(cpe_pattern)

        with self._lock:
            self._cache[cpe_pattern] = result
        return result

    def _query(
        self, cpe_pattern: str
    ) -> tuple[pd.DataFrame, str, Optional[dict]]:
        headers = {"apiKey": self._api_key}
        empty = pd.DataFrame()

        cpe_url = f"{_NVD_BASE}/cpes/2.0?cpeMatchString={cpe_pattern}"
        try:
            res = self._session.get(cpe_url, headers=headers, timeout=_REQUEST_TIMEOUT)
            logger.info("CPE API %d for %s", res.status_code, cpe_pattern)
        except Exception as exc:
            logger.error("CPE API call failed for %s: %s", cpe_pattern, exc)
            return empty, "CPE API call failed", {"cpe_pattern": cpe_pattern}

        if res.status_code == 403:
            return empty, "Permission denied", {"cpe_pattern": cpe_pattern}
        if res.status_code != 200:
            return empty, "Invalid CPE pattern", {"cpe_pattern": cpe_pattern}

        try:
            data = res.json()
        except Exception:
            return empty, "Invalid JSON response", {"cpe_pattern": cpe_pattern}

        if data.get("totalResults", 0) == 0:
            return empty, "No CPE results — manual check needed", None

        resolved_cpe = self._first_active_cpe(data)
        if not resolved_cpe:
            return empty, "All CPEs deprecated", {"cpe_pattern": cpe_pattern}

        cve_url = f"{_NVD_BASE}/cves/2.0?cpeName={resolved_cpe}"
        try:
            res = self._session.get(cve_url, headers=headers, timeout=_REQUEST_TIMEOUT)
            logger.info("CVE API %d for %s", res.status_code, resolved_cpe)
        except Exception as exc:
            logger.error("CVE API call failed for %s: %s", resolved_cpe, exc)
            return empty, "CVE API call failed", {"cpe_pattern": cpe_pattern}

        if res.status_code == 403:
            return empty, "Permission denied", {"cpe_pattern": cpe_pattern}
        if res.status_code != 200:
            return empty, "Invalid CVE request", {"cpe_pattern": cpe_pattern}

        try:
            data = res.json()
        except Exception:
            return empty, "Invalid JSON response", {"cpe_pattern": cpe_pattern}

        if data.get("totalResults", 0) == 0:
            logger.info("No CVEs for %s", resolved_cpe)
            return empty, "No vulnerabilities detected", None

        cve_records = [item["cve"] for item in data.get("vulnerabilities", [])]
        df = pd.DataFrame(cve_records).drop_duplicates(subset="id", keep="first")
        logger.info("Found %d CVEs for %s", len(df), resolved_cpe)
        return df, f"{len(df)} CVEs found", None

    @staticmethod
    def _first_active_cpe(data: dict) -> Optional[str]:
        for product in data.get("products", []):
            cpe = product.get("cpe", {})
            if not cpe.get("deprecated", False):
                return cpe.get("cpeName")
        return None
