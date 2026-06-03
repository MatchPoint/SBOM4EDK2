"""NVD CPE dictionary validation for CycloneDX ``cpe`` fields.

Only emit ``cpe:2.3:a:…`` when the exact name exists as a non-deprecated
entry in the NVD CPE API (``/cpes/2.0``). See ``SUBMODULE_CPE_MAP`` in
``submodule_data`` for GitHub slug → vendor/product hints.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
_REQUEST_TIMEOUT = 30
_MIN_INTERVAL_NO_KEY = 6.0

# When the map uses vendor ``*``, try these NVD vendors (first match wins).
PRODUCT_VENDOR_CANDIDATES: Dict[str, Tuple[str, ...]] = {
    "mbed_tls": ("arm", "mbed"),
    "jansson": ("jansson_project",),
    "oniguruma": ("oniguruma_project",),
}

INVALID_CPE_VERSIONS = frozenset({"", "0.0.0", "NOASSERTION"})

_session: Optional[requests.Session] = None
_last_request_at: float = 0.0
_memory_cache: Dict[str, bool] = {}
_allowlist: Optional[frozenset[str]] = None
_omissions: List["CpeOmissionEntry"] = []


@dataclass(frozen=True)
class CpeOmissionEntry:
    """One component that was emitted without a ``cpe`` field."""

    component: str
    bom_ref: str
    vcs_url: str
    clean_version: str
    github_slug: str
    reason: str
    candidates: Tuple[str, ...] = field(default_factory=tuple)
    template_cpe: str = ""


def version_unsuitable_for_cpe(clean_version: str) -> bool:
    return clean_version in INVALID_CPE_VERSIONS


def clear_cpe_omission_log() -> None:
    _omissions.clear()


def cpe_omissions() -> Tuple[CpeOmissionEntry, ...]:
    return tuple(_omissions)


def record_cpe_omission(
    *,
    component: str,
    bom_ref: str = "",
    vcs_url: str = "",
    clean_version: str = "",
    github_slug: str = "",
    reason: str,
    candidates: Optional[Sequence[str]] = None,
    template_cpe: str = "",
) -> None:
    _omissions.append(
        CpeOmissionEntry(
            component=component,
            bom_ref=bom_ref,
            vcs_url=vcs_url,
            clean_version=clean_version,
            github_slug=github_slug,
            reason=reason,
            candidates=tuple(candidates or ()),
            template_cpe=template_cpe,
        )
    )


def cpe_omission_log_path(sbom_output_path: str) -> str:
    """Derive ``<sbom-stem>.cpe-omissions.log`` next to the CycloneDX JSON file."""
    path = Path(sbom_output_path)
    name = path.name
    if name.endswith(".cdx.json"):
        stem = name[: -len(".cdx.json")]
    elif path.suffix == ".json":
        stem = path.stem
    else:
        stem = path.name or "sbom"
    return str(path.parent / f"{stem}.cpe-omissions.log")


def write_cpe_omission_log(sbom_output_path: str) -> Optional[str]:
    """Write accumulated omission reasons; returns path when the file was written."""
    if not _omissions:
        return None
    out_path = cpe_omission_log_path(sbom_output_path)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# SBOM4EDK2 — components emitted without a cpe field",
        f"# SBOM: {sbom_output_path}",
        f"# Generated: {generated}",
        f"# Count: {len(_omissions)}",
        "",
    ]
    for entry in _omissions:
        parts = [
            f"component={entry.component}",
            f"reason={entry.reason}",
        ]
        if entry.bom_ref:
            parts.append(f"bom-ref={entry.bom_ref}")
        if entry.vcs_url:
            parts.append(f"vcs_url={entry.vcs_url}")
        if entry.github_slug:
            parts.append(f"github_slug={entry.github_slug}")
        if entry.clean_version:
            parts.append(f"version={entry.clean_version}")
        if entry.template_cpe:
            parts.append(f"template_cpe={entry.template_cpe}")
        if entry.candidates:
            parts.append(f"candidates={'; '.join(entry.candidates)}")
        lines.append(" ".join(parts))
    lines.append("")
    try:
        Path(out_path).write_text("\n".join(lines), encoding="utf-8")
    except OSError as exc:
        logger.error("Failed to write CPE omission log %s: %s", out_path, exc)
        return None
    logger.info("CPE omissions (%d) logged to %s", len(_omissions), out_path)
    return out_path


def package_data_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data"


def _allowlist_path() -> Path:
    return package_data_dir() / "nvd_cpe_allowlist.json"


def load_allowlist() -> frozenset[str]:
    global _allowlist
    if _allowlist is not None:
        return _allowlist
    path = _allowlist_path()
    if not path.is_file():
        _allowlist = frozenset()
        return _allowlist
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            _allowlist = frozenset(str(x) for x in data)
        else:
            _allowlist = frozenset()
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not load NVD CPE allowlist %s: %s", path, exc)
        _allowlist = frozenset()
    return _allowlist


def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _session_get() -> requests.Session:
    global _session
    if _session is None:
        _session = _build_session()
    return _session


def _api_key() -> str:
    return os.environ.get("NVD_API_KEY", "").strip()


def _throttle() -> None:
    global _last_request_at
    if _api_key():
        return
    elapsed = time.monotonic() - _last_request_at
    if elapsed < _MIN_INTERVAL_NO_KEY:
        time.sleep(_MIN_INTERVAL_NO_KEY - elapsed)


def form_application_cpe(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def expand_vendor_product(vendor: str, product: str) -> List[Tuple[str, str]]:
    if vendor != "*":
        return [(vendor, product)]
    candidates = PRODUCT_VENDOR_CANDIDATES.get(product)
    if not candidates:
        return []
    return [(v, product) for v in candidates]


def candidate_cpes(
    vendor: str,
    product: str,
    clean_version: str,
    *,
    extra: Optional[Sequence[str]] = None,
) -> List[str]:
    if version_unsuitable_for_cpe(clean_version):
        return []
    formed = [
        form_application_cpe(v, p, clean_version)
        for v, p in expand_vendor_product(vendor, product)
    ]
    if extra:
        for cpe in extra:
            if cpe and cpe not in formed:
                formed.insert(0, cpe)
    return formed


def cpe_in_nvd_dictionary(
    cpe_name: str,
    *,
    skip_network: bool = False,
) -> bool:
    """True when *cpe_name* is an exact, non-deprecated NVD CPE dictionary entry."""
    if not cpe_name or not cpe_name.startswith("cpe:2.3:"):
        return False
    if cpe_name in _memory_cache:
        return _memory_cache[cpe_name]
    if cpe_name in load_allowlist():
        _memory_cache[cpe_name] = True
        return True
    if skip_network or skip_nvd_cpe_validation():
        _memory_cache[cpe_name] = False
        return False

    global _last_request_at
    _throttle()
    headers = {}
    key = _api_key()
    if key:
        headers["apiKey"] = key
    params = {"cpeMatchString": cpe_name}
    try:
        res = _session_get().get(
            _NVD_CPE_URL,
            params=params,
            headers=headers,
            timeout=_REQUEST_TIMEOUT,
        )
        _last_request_at = time.monotonic()
    except requests.RequestException as exc:
        logger.warning("NVD CPE lookup failed for %s: %s", cpe_name, exc)
        _memory_cache[cpe_name] = False
        return False

    if res.status_code != 200:
        logger.info("NVD CPE API %s for %s", res.status_code, cpe_name)
        _memory_cache[cpe_name] = False
        return False

    try:
        data = res.json()
    except json.JSONDecodeError:
        _memory_cache[cpe_name] = False
        return False

    ok = False
    for product in data.get("products", []):
        cpe = product.get("cpe", {})
        if cpe.get("cpeName") == cpe_name and not cpe.get("deprecated", False):
            ok = True
            break

    _memory_cache[cpe_name] = ok
    if not ok:
        logger.debug("CPE not in NVD dictionary (exact match): %s", cpe_name)
    return ok


def first_valid_cpe(
    candidates: Iterable[str],
    *,
    skip_network: bool = False,
) -> Optional[str]:
    for cpe in candidates:
        if cpe_in_nvd_dictionary(cpe, skip_network=skip_network):
            return cpe
    return None


def reset_validation_cache() -> None:
    """Clear in-memory validation cache and omission log (for tests)."""
    global _allowlist, _memory_cache, _last_request_at
    _memory_cache = {}
    _allowlist = None
    _last_request_at = 0.0
    clear_cpe_omission_log()


def skip_nvd_cpe_validation() -> bool:
    return bool(os.environ.get("SBOM4EDK2_SKIP_NVD_CPE_VALIDATE", "").strip())
