"""Build a source CycloneDX SBOM (EDK2 primary + OSS submodules only)."""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sbom4edk2.cdx_emit import emit_cdx_json
from sbom4edk2.edk2_version import describe_edk2_version
from sbom4edk2.pedigree import pedigree_for_submodule_dir
from sbom4edk2.nvd_cpe import (
    candidate_cpes,
    clear_cpe_omission_log,
    cpe_omission_log_path,
    first_valid_cpe,
    record_cpe_omission,
    skip_nvd_cpe_validation,
    version_unsuitable_for_cpe,
    write_cpe_omission_log,
)
from sbom4edk2.submodule_data import (
    SUBMODULE_CPE_MAP,
    SUBMODULE_URL_ALIASES,
    resolve_with_aliases,
    walk_gitmodules,
)
from sbom4edk2.supplier_data import apply_recognized_supplier, github_slug_from_url
from sbom4edk2.template_loader import (
    iter_fallback_components,
    load_edk2_primary_template,
    subst_placeholders,
    vcs_url_of,
)
from sbom4edk2.version_normalize import resolve_submodule_vcs

logger = logging.getLogger(__name__)

_PHASE_MAP = {"source": "pre-build", "build": "build", "binary": "post-build"}


def _github_slug_from_url(url: str) -> Optional[str]:
    return github_slug_from_url(url)


def _cpe_map_entry(slug: str) -> Optional[Tuple[str, str]]:
    """Look up NVD CPE vendor/product; keys are case-sensitive upstream names."""
    if slug in SUBMODULE_CPE_MAP:
        return SUBMODULE_CPE_MAP[slug]
    lower = slug.lower()
    for key, val in SUBMODULE_CPE_MAP.items():
        if key.lower() == lower:
            return val
    return None


def _component_label(comp: dict, vcs_url: str) -> str:
    return (
        comp.get("name")
        or comp.get("bom-ref")
        or vcs_url
        or "unknown"
    )


def _apply_nvd_cpe(comp: dict, clean_version: str, vcs_url: str) -> None:
    """Set ``cpe`` only when an exact name exists in the NVD CPE dictionary."""
    label = _component_label(comp, vcs_url)
    bom_ref = comp.get("bom-ref") or ""
    template_cpe = comp.get("cpe") or ""
    slug = _github_slug_from_url(vcs_url) or ""

    def _omit(reason: str, candidates: Optional[List[str]] = None) -> None:
        record_cpe_omission(
            component=label,
            bom_ref=bom_ref,
            vcs_url=vcs_url,
            clean_version=clean_version,
            github_slug=slug,
            reason=reason,
            candidates=candidates,
            template_cpe=template_cpe,
        )
        comp.pop("cpe", None)

    if version_unsuitable_for_cpe(clean_version):
        _omit("version_not_suitable_for_cpe")
        return

    entry = _cpe_map_entry(slug) if slug else None
    extra = [template_cpe] if template_cpe else None
    if entry:
        vendor, product = entry
        candidates = candidate_cpes(
            vendor, product, clean_version, extra=extra
        )
    elif extra:
        candidates = list(extra)
    else:
        if not slug:
            _omit("no_github_slug_and_no_template_cpe")
        else:
            _omit("no_cpe_map_entry_and_no_template_cpe")
        return

    if not candidates:
        _omit("no_cpe_candidates_generated")
        return

    validated = first_valid_cpe(candidates)
    if validated:
        comp["cpe"] = validated
        return

    if skip_nvd_cpe_validation():
        reason = "nvd_validation_disabled_not_in_allowlist"
    else:
        reason = "not_in_nvd_dictionary"
    _omit(reason, candidates=candidates)


def _synthesize_component(
    rel_path: str,
    vcs_url: str,
    submodule_dir: str,
) -> dict:
    vcs = resolve_submodule_vcs(submodule_dir)
    slug = _github_slug_from_url(vcs_url)
    name = os.path.basename(rel_path.rstrip("/\\")) or "submodule"
    bom_ref = (
        f"pkg:github/{slug}@{vcs.display_version}"
        if slug
        else f"pkg:submodule/{rel_path}@{vcs.display_version}"
    )
    comp: dict = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": name,
        "version": vcs.display_version,
        "supplier": {"name": "NOASSERTION"},
        "externalReferences": [{"type": "vcs", "url": vcs_url}],
    }
    apply_recognized_supplier(comp, vcs_url)
    if comp["supplier"]["name"] == "NOASSERTION" and slug:
        comp["supplier"]["name"] = slug.split("/")[0]
    _apply_nvd_cpe(comp, vcs.clean, vcs_url)
    ped = pedigree_for_submodule_dir(
        submodule_dir,
        patch_count=vcs.patch_count,
        base_tag=vcs.base_tag,
        base_tag_commit=vcs.base_tag_commit,
        commit_sha=vcs.commit_sha,
        vcs_url=vcs_url if vcs_url.startswith("http") else "",
    )
    if ped:
        comp["pedigree"] = ped
    return comp


def _resolve_template_component(
    comp: dict,
    submodule_dir: str,
    vcs_url: str,
) -> Optional[dict]:
    vcs = resolve_submodule_vcs(submodule_dir)
    if not vcs.clean or vcs.clean == "NOASSERTION":
        return None

    resolved = subst_placeholders(
        dict(comp),
        {
            "@VCS_VERSION@": vcs.display_version,
            "@VCS_TAG@": vcs.display_version,
            "@VCS_AUTHORS@": "NOASSERTION",
        },
    )
    if "@VCS_" in json.dumps(resolved):
        return None

    resolved["version"] = vcs.display_version
    apply_recognized_supplier(resolved, vcs_url)
    _apply_nvd_cpe(resolved, vcs.clean, vcs_url)
    ped = pedigree_for_submodule_dir(
        submodule_dir,
        patch_count=vcs.patch_count,
        base_tag=vcs.base_tag,
        base_tag_commit=vcs.base_tag_commit,
        commit_sha=vcs.commit_sha,
        vcs_url=vcs_url if vcs_url.startswith("http") else "",
    )
    if ped:
        resolved["pedigree"] = ped
    return resolved


def _build_dependencies(
    primary_ref: str,
    resolved_paths: List[Tuple[str, str]],
) -> List[dict]:
    if not primary_ref or not resolved_paths:
        return []

    all_paths = [p for p, _ in resolved_paths]
    path_to_ref = {p: r for p, r in resolved_paths}
    deps_map: Dict[str, List[str]] = {}

    for path, ref in resolved_paths:
        ancestors = [
            p for p in all_paths if p != path and path.startswith(p + os.sep)
        ]
        if ancestors:
            parent_path = max(ancestors, key=len)
            parent_ref = path_to_ref[parent_path]
        else:
            parent_ref = primary_ref
        if parent_ref == ref:
            continue
        deps_map.setdefault(parent_ref, []).append(ref)

    dependencies: List[dict] = []
    for parent_ref, children in sorted(deps_map.items()):
        depends_on = sorted(set(children))
        depends_on = [c for c in depends_on if c != parent_ref]
        if depends_on:
            dependencies.append({"ref": parent_ref, "dependsOn": depends_on})
    return dependencies


def build_source_sbom(
    edk2_dir: str,
    *,
    uswid_data_dir: Optional[str] = None,
    sbom_type: str = "source",
) -> dict:
    """Assemble the merged CycloneDX document dict."""
    clear_cpe_omission_log()
    version_label, purl_version, cpe_version = describe_edk2_version(edk2_dir)
    logger.info(
        "EDK2 version: label=%s purl=%s cpe=%s",
        version_label,
        purl_version,
        cpe_version,
    )

    replacements = {
        "@VCS_VERSION@": cpe_version,
        "@VCS_TAG@": version_label,
        "@VCS_AUTHORS@": "TianoCore contributors",
    }
    primary = load_edk2_primary_template(uswid_data_dir or "", replacements)

    url_to_path = walk_gitmodules(edk2_dir) if edk2_dir else {}
    matched_dirs: set[str] = set()
    submodule_components: List[dict] = []
    resolved_paths: List[Tuple[str, str]] = []
    resolved_count = 0
    dropped_orphans = 0

    for _fp, file_comps in iter_fallback_components(uswid_data_dir or ""):
        for comp in file_comps:
            vcs_url = vcs_url_of(comp)
            sub_dir = resolve_with_aliases(
                vcs_url, url_to_path, SUBMODULE_URL_ALIASES
            )
            if sub_dir and os.path.isdir(sub_dir):
                resolved = _resolve_template_component(comp, sub_dir, vcs_url)
                if resolved:
                    submodule_components.append(resolved)
                    resolved_count += 1
                    sub_bom = resolved.get("bom-ref")
                    if sub_bom:
                        resolved_paths.append((os.path.normpath(sub_dir), sub_bom))
                    matched_dirs.add(os.path.normpath(sub_dir))
                continue
            if "@VCS_" in json.dumps(comp):
                dropped_orphans += 1
                continue
            submodule_components.append(comp)

    # Synthesize components for populated submodules without a curated template.
    for canon, sub_dir in url_to_path.items():
        norm_dir = os.path.normpath(sub_dir)
        if norm_dir in matched_dirs or not os.path.isdir(sub_dir):
            continue
        vcs_url = canon
        rel = os.path.relpath(sub_dir, edk2_dir).replace(os.sep, "/")
        synth = _synthesize_component(rel, vcs_url, sub_dir)
        submodule_components.append(synth)
        resolved_count += 1
        sub_bom = synth.get("bom-ref")
        if sub_bom:
            resolved_paths.append((norm_dir, sub_bom))
        matched_dirs.add(norm_dir)

    logger.info(
        "OSS components: %d (resolved from git: %d, dropped orphan templates: %d)",
        len(submodule_components),
        resolved_count,
        dropped_orphans,
    )

    seen_refs: set[str] = set()
    all_components: List[dict] = []
    for comp in submodule_components:
        key = comp.get("bom-ref") or comp.get("name", "")
        if key and key not in seen_refs:
            seen_refs.add(key)
            all_components.append(comp)

    primary_ref = primary.get("bom-ref")
    dependencies = _build_dependencies(primary_ref or "", resolved_paths)

    phase = _PHASE_MAP.get(sbom_type, "pre-build")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "SBOM4EDK2",
                    "name": "SBOM4EDK2",
                    "version": "0.6.1",
                }
            ],
            "lifecycles": [{"phase": phase}],
            "component": primary,
        },
        "components": all_components,
        "dependencies": dependencies,
    }


def write_source_sbom(
    edk2_dir: str,
    output_path: str,
    *,
    uswid_data_dir: Optional[str] = None,
    sbom_type: str = "source",
) -> int:
    """Build and write a source SBOM; returns 0 on success."""
    doc = build_source_sbom(
        edk2_dir,
        uswid_data_dir=uswid_data_dir,
        sbom_type=sbom_type,
    )
    rc = emit_cdx_json(doc, output_path)
    if rc == 0:
        logger.info(
            "Source SBOM: %d OSS components -> %s",
            len(doc.get("components", [])),
            output_path,
        )
        log_path = write_cpe_omission_log(output_path)
        if log_path:
            logger.info("CPE omission log: %s", log_path)
        else:
            logger.debug(
                "No CPE omissions (would write %s if any)",
                cpe_omission_log_path(output_path),
            )
    return rc
