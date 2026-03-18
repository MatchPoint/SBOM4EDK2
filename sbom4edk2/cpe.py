"""CPE pattern construction and component-name normalisation for NVD lookups."""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

_INVALID_NAME_CHARS = re.compile(r"[,()\/]")
_INVALID_NAME_WORDS = {"Proprietary", "Not provided", "release"}

_NAME_ALIASES: dict[str, str] = {
    "mbed": "arm",
    "mbedtls": "arm",
}

MAX_NAME_LENGTH = 60


def is_valid_component(component: dict) -> bool:
    """Return True if the component has enough data for a CPE lookup."""
    name = component.get("name")
    version = component.get("version")
    if not name or not version:
        return False
    if len(name) > MAX_NAME_LENGTH:
        return False
    if _has_invalid_name(name) or _has_invalid_version(version):
        return False
    if not _has_open_source_license(component):
        return False
    return True


def build_cpe_pattern(component: dict) -> Optional[str]:
    """Build a CPE 2.3 pattern string from a SBOM component, or None if invalid."""
    name = component["name"]
    version = component["version"]

    name = _normalise_name(name)
    version = _normalise_version(version)

    if not name or not version:
        return None
    if isinstance(version, str) and version.lower() == "n/a":
        return None
    if "edk2" in name and isinstance(version, str) and "-" not in version:
        return None

    pattern = f"cpe:2.3:a:*:{name}:{version}:*:*:*:*:*:*:*"
    pattern = pattern.replace("+", "").replace(" ", "")
    return pattern


def extract_cve_details(component: dict, cpe_pattern: str, cve_row: dict) -> dict:
    """Build a flat CVE detail record for the output report."""
    payload: dict = {
        "name": component["name"],
        "version": component["version"],
        "cpe_pattern": cpe_pattern,
        "id": cve_row["id"],
        "published": cve_row["published"],
    }

    descriptions = cve_row.get("descriptions", [])
    if descriptions:
        payload["descriptions"] = descriptions[0].get("value", "")

    metrics = cve_row.get("metrics")
    if metrics:
        for metric_key, metric_list in metrics.items():
            if metric_list:
                cvss = metric_list[0].get("cvssData", {})
                payload["cvss_ver"] = cvss.get("version")
                payload["score"] = cvss.get("baseScore")
                payload["CVSSString"] = cvss.get("vectorString")
            break

    return payload


def _normalise_name(name: str) -> str:
    if "dtc" in name:
        return "dtc_project"

    name = name.strip().lower()
    name = _NAME_ALIASES.get(name, name)

    if "." in name:
        name = name.split(".")[0]
    if "-" in name:
        name = name.split("-")[0]
    return name


def _normalise_version(version) -> str:
    if not isinstance(version, str):
        return str(version)
    if "-" in version:
        version = version.split("-", 1)[1]
    version = version.replace("stable", "")
    return version


def _has_invalid_name(name: str) -> bool:
    if _INVALID_NAME_CHARS.search(name):
        return True
    return any(word in name for word in _INVALID_NAME_WORDS)


def _has_invalid_version(version) -> bool:
    return isinstance(version, str) and "Not provided" in version


def _has_open_source_license(component: dict) -> bool:
    """Return True unless the component explicitly lacks an open-source license id."""
    licenses = component.get("licenses")
    if not licenses:
        return True
    first = licenses[0]
    if "license" not in first:
        return True
    if component["name"] == "zlib":
        return True
    return "id" in first["license"]
