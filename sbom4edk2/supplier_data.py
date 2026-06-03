"""Globally recognized supplier names for OSS components.

uswid-data templates often use ``<project> developers``; when the GitHub
organization (or a curated slug map) identifies a well-known supplier, prefer
that over the template ``supplier.name``.
"""

from __future__ import annotations

import re
from typing import Dict, Optional

_GITHUB_OWNER_REPO_RE = re.compile(
    r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)"
)

# Full ``owner/repo`` → display name (wins over template supplier).
GITHUB_SLUG_SUPPLIER: Dict[str, str] = {
    "google/brotli": "Google",
    "google/boringssl": "Google",
    "google/googletest": "Google",
    "cloudflare/quiche": "Cloudflare",
    "ARMmbed/mbedtls": "Arm",
    "mbed-tls/mbedtls-framework": "Arm",
    "Mbed-TLS/mbedtls": "Arm",
    "DMTF/libspdm": "DMTF",
    "devicetree-org/pylibfdt": "Device Tree",
    "MIPI-Alliance/public-mipi-sys-t": "MIPI Alliance",
    "ucb-bar/berkeley-softfloat-3": "University of California, Berkeley",
    "kkos/oniguruma": "Oniguruma",
    "akheron/jansson": "Jansson",
    "tianocore/edk2-cmocka": "cmocka",
    "tianocore/edk2-subhook": "TianoCore",
    "tlsfuzzer/python-ecdsa": "Python ECDSA",
    "tlsfuzzer/tlslite-ng": "tlsfuzzer",
    "openssl/fuzz-corpora": "OpenSSL",
    "google/wuffs": "Google",
    "google/wycheproof": "Google",
    "ARM-software/arm-trusted-firmware": "Arm",
    "raspberrypi/opensbi": "RISC-V International",
    "open-quantum-safe/oqs-provider": "Open Quantum Safe",
    "open-iscsi/krb5": "Massachusetts Institute of Technology",
    "pyca/cryptography": "Python Cryptographic Authority",
    "randombit/gost-engine": "GOST Engine",
    "zeha/pkcs11-provider": "OpenSSL",
    "libtom/libtomcrypt": "LibTom",
    "coreboot/libgfxinit": "coreboot",
    "coreboot/libhwbase": "coreboot",
    "pugixml/pugixml": "pugixml",
    "hostap/hostap": "Jouni Malinen",
}

# GitHub org only (used when slug map has no entry and template is generic).
GITHUB_OWNER_SUPPLIER: Dict[str, str] = {
    "google": "Google",
    "openssl": "OpenSSL",
    "cloudflare": "Cloudflare",
    "ARMmbed": "Arm",
    "Mbed-TLS": "Arm",
    "mbed-tls": "Arm",
    "DMTF": "DMTF",
    "devicetree-org": "Device Tree",
    "MIPI-Alliance": "MIPI Alliance",
    "ucb-bar": "University of California, Berkeley",
    "tianocore": "TianoCore",
    "Intel": "Intel",
    "Galileo-dev": "Intel",
}

# Non-generic template supplier names worth keeping when no slug map applies.
TEMPLATE_SUPPLIER_KEEP: frozenset[str] = frozenset(
    {
        "The OpenSSL Project",
        "Cloudflare, Inc",
        "Arm",
        "Google",
        "Massachusetts Institute of Technology",
        "RISC-V Foundation",
        "RISC-V International",
        "The OQS core team",
        "Open Quantum Safe",
        "GOST Engine Team",
        "Project Wycheproof Team",
        "TianoCore",
    }
)


def github_slug_from_url(url: str) -> Optional[str]:
    m = _GITHUB_OWNER_REPO_RE.search(url or "")
    if not m:
        return None
    return f"{m.group('owner')}/{m.group('repo')}"


def _is_generic_supplier(name: str) -> bool:
    n = (name or "").strip()
    if not n or n == "NOASSERTION":
        return True
    if n.endswith(" developers"):
        return True
    if n.endswith(" developers."):
        return True
    return False


def recognized_supplier_name(vcs_url: str) -> Optional[str]:
    slug = github_slug_from_url(vcs_url)
    if not slug:
        return None
    if slug in GITHUB_SLUG_SUPPLIER:
        return GITHUB_SLUG_SUPPLIER[slug]
    lower = slug.lower()
    for key, val in GITHUB_SLUG_SUPPLIER.items():
        if key.lower() == lower:
            return val
    owner = slug.split("/")[0]
    if owner in GITHUB_OWNER_SUPPLIER:
        return GITHUB_OWNER_SUPPLIER[owner]
    for key, val in GITHUB_OWNER_SUPPLIER.items():
        if key.lower() == owner.lower():
            return val
    return None


def apply_recognized_supplier(comp: dict, vcs_url: str) -> None:
    """Set ``supplier.name`` when a recognized org/project name is available."""
    recognized = recognized_supplier_name(vcs_url)
    if not recognized:
        return

    current = ""
    supplier = comp.get("supplier")
    if isinstance(supplier, dict):
        current = (supplier.get("name") or "").strip()

    if current == recognized:
        return

    slug = github_slug_from_url(vcs_url)
    slug_mapped = False
    if slug:
        if slug in GITHUB_SLUG_SUPPLIER:
            slug_mapped = True
        else:
            slug_mapped = any(k.lower() == slug.lower() for k in GITHUB_SLUG_SUPPLIER)

    if slug_mapped or _is_generic_supplier(current) or current not in TEMPLATE_SUPPLIER_KEEP:
        comp["supplier"] = {"name": recognized}
