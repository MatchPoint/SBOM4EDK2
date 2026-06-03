"""OSS submodule reference data and .gitmodules walk.

Derived from MatchPoint/python-uswid-sbom ``uswid.submodule`` (HP Development
Company, BSD-2-Clause-Patent). See NOTICE.
"""

from __future__ import annotations

import os
import re
from typing import Dict, Optional, Tuple

# GitHub org renames and well-known repo mirrors (canonical lowercase URLs).
SUBMODULE_URL_ALIASES: Dict[str, str] = {
    "https://github.com/mbed-tls/mbedtls": "https://github.com/armmbed/mbedtls",
    "https://github.com/dgibson/dtc": "https://github.com/devicetree-org/pylibfdt",
}

# NVD CPE vendor/product by GitHub owner/repo (Jun 2026 dictionary).
# Vendor ``*`` → ``PRODUCT_VENDOR_CANDIDATES`` in ``nvd_cpe`` (exact dictionary match required).
SUBMODULE_CPE_MAP: Dict[str, Tuple[str, str]] = {
    "openssl/openssl": ("openssl", "openssl"),
    "ARMmbed/mbedtls": ("*", "mbed_tls"),
    "akheron/jansson": ("*", "jansson"),
    "kkos/oniguruma": ("*", "oniguruma"),
    "google/brotli": ("google", "brotli"),
    "DMTF/libspdm": ("dmtf", "libspdm"),
    # OSS submodules that lacked CPE without a map entry (validated via NVD before emit).
    "google/boringssl": ("google", "boringssl"),
    "tianocore/edk2-cmocka": ("cmocka", "cmocka"),
    "mbed-tls/mbedtls-framework": ("arm", "mbed_tls"),
    "tlsfuzzer/python-ecdsa": ("python-ecdsa_project", "python-ecdsa"),
    "tlsfuzzer/tlslite-ng": ("tlslite-ng_project", "tlslite-ng"),
}

_GITMODULES_NAME_RE = re.compile(r'^\s*\[submodule\s+"([^"]+)"\]\s*$')
_GITMODULES_KV_RE = re.compile(r"^\s*(\w+)\s*=\s*(\S+.*?)\s*$")


def canonicalize_vcs_url(url: str) -> str:
    if not url:
        return ""
    out = url.strip().rstrip("/")
    if out.lower().endswith(".git"):
        out = out[:-4]
    return out.lower()


def resolve_with_aliases(
    url: str,
    url_to_path: Dict[str, str],
    aliases: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    if not url:
        return None
    canon = canonicalize_vcs_url(url)
    if canon in url_to_path:
        return url_to_path[canon]
    if aliases is None:
        aliases = SUBMODULE_URL_ALIASES
    aliased = aliases.get(canon)
    if aliased:
        return url_to_path.get(canonicalize_vcs_url(aliased))
    return None


def parse_gitmodules_file(path: str) -> Dict[str, Dict[str, str]]:
    result: Dict[str, Dict[str, str]] = {}
    current: Optional[str] = None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _GITMODULES_NAME_RE.match(line)
                if m:
                    current = m.group(1)
                    result[current] = {}
                    continue
                if not current:
                    continue
                m = _GITMODULES_KV_RE.match(line)
                if m:
                    result[current][m.group(1).strip()] = m.group(2).strip()
    except OSError:
        return {}
    return result


def walk_gitmodules(primary_dir: str, *, recursive: bool = True) -> Dict[str, str]:
    """Return ``{canonical_vcs_url: absolute_submodule_path}`` (first-write-wins)."""
    result: Dict[str, str] = {}
    if not primary_dir or not os.path.isdir(primary_dir):
        return result

    def _emit(parent_dir: str, fields: Dict[str, str]) -> None:
        path = fields.get("path")
        url = fields.get("url")
        if not (path and url):
            return
        key = canonicalize_vcs_url(url)
        if not key:
            return
        abs_path = os.path.normpath(os.path.join(parent_dir, path))
        if key not in result:
            result[key] = abs_path

    def _ingest_one(gm_path: str) -> None:
        parent_dir = os.path.dirname(gm_path)
        for fields in parse_gitmodules_file(gm_path).values():
            _emit(parent_dir, fields)

    top_gm = os.path.join(primary_dir, ".gitmodules")
    if os.path.isfile(top_gm):
        _ingest_one(top_gm)

    if not recursive:
        return result

    for root, dirs, files in os.walk(primary_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        if root == primary_dir:
            continue
        if ".gitmodules" in files:
            _ingest_one(os.path.join(root, ".gitmodules"))

    return result
