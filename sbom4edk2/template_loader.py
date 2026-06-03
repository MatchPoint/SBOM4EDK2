"""Load CycloneDX JSON templates from uswid-data."""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def subst_placeholders(obj: Any, replacements: Dict[str, str]) -> Any:
    if isinstance(obj, str):
        out = obj
        for key, val in replacements.items():
            out = out.replace(key, val)
        return out
    if isinstance(obj, list):
        return [subst_placeholders(i, replacements) for i in obj]
    if isinstance(obj, dict):
        return {k: subst_placeholders(v, replacements) for k, v in obj.items()}
    return obj


def load_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not load %s: %s", path, exc)
        return None


def load_edk2_primary_template(
    uswid_data_dir: str,
    replacements: Dict[str, str],
) -> dict:
    """Load ``edk2.cdx.json`` primary component with *replacements* applied."""
    primary: dict = {
        "type": "firmware",
        "bom-ref": "tianocore:edk2",
        "name": "EDK II",
        "version": replacements.get("@VCS_VERSION@", "unknown"),
        "supplier": {
            "name": "TianoCore",
            "url": ["https://www.tianocore.org/"],
        },
        "licenses": [{"license": {"id": "BSD-2-Clause"}}],
    }
    if not uswid_data_dir:
        return subst_placeholders(primary, replacements)

    edk2_cdx = os.path.join(uswid_data_dir, "edk2.cdx.json")
    if not os.path.isfile(edk2_cdx):
        return subst_placeholders(primary, replacements)

    fd = load_json(edk2_cdx)
    if not fd:
        return subst_placeholders(primary, replacements)

    candidates = fd.get("components", []) or [
        fd.get("metadata", {}).get("component", {})
    ]
    if candidates and candidates[0]:
        primary = dict(candidates[0])
        primary["supplier"] = {
            "name": "TianoCore",
            "url": ["https://www.tianocore.org/"],
        }
        logger.info("EDK2 primary component loaded from %s", edk2_cdx)

    return subst_placeholders(primary, replacements)


def iter_fallback_components(uswid_data_dir: str) -> List[tuple[str, List[dict]]]:
    """Yield ``(filepath, components)`` for each OSS template CDX file."""
    if not uswid_data_dir or not os.path.isdir(uswid_data_dir):
        return []

    out: List[tuple[str, List[dict]]] = []
    for name in sorted(os.listdir(uswid_data_dir)):
        if not name.endswith(".cdx.json") or name == "edk2.cdx.json":
            continue
        fp = os.path.join(uswid_data_dir, name)
        fd = load_json(fp)
        if not fd:
            continue
        comps = list(fd.get("components", []) or [])
        mc = fd.get("metadata", {}).get("component", {})
        if mc and mc.get("name"):
            comps.append(mc)
        out.append((fp, [c for c in comps if c]))
    return out


def vcs_url_of(comp: dict) -> str:
    for ref in comp.get("externalReferences", []) or []:
        if isinstance(ref, dict) and ref.get("type") == "vcs" and ref.get("url"):
            return canonicalize_vcs_url_from_comp(ref["url"])
    return ""


def canonicalize_vcs_url_from_comp(url: str) -> str:
    from sbom4edk2.submodule_data import canonicalize_vcs_url

    return canonicalize_vcs_url(url)
