# Source SBOM generation

SBOM4EDK2 produces a **source** CycloneDX 1.6 SBOM (`sbom-type: source`) from an
EDK II git checkout. The document describes **what third-party source trees** are
vendored into the firmware tree, not which `.inf` modules are linked at build time.

## What is in the SBOM

| CycloneDX field | Content |
|-----------------|---------|
| `metadata.component` | EDK II product (TianoCore, `edk2-stableYYYYMM`, CPE/PURL) |
| `components[]` | One row per **OSS git submodule** (openssl, mbedtls, libspdm, …) |
| `dependencies[]` | **Containment only** — EDK2 → submodule → nested submodule |

## What is not in the SBOM

- **Per-`.inf` components** (e.g. `OpensslLib`) — these are build-time modules.
- **INF → submodule wrapper edges** — not needed when OSS is already a component.
- Any dependency on the `uswid` Python package or MatchPoint/python-uswid-sbom.

For build/binary SBOMs (per-module `.inf` parsing), use upstream
[python-uswid](https://github.com/hughsie/python-uswid) (Richard Hughes).

## Prerequisites

1. **Python 3.11+** and `pip install -r requirements.txt`
2. **EDK II checkout** with submodules initialized:

   ```bash
   git clone --recursive https://github.com/tianocore/edk2.git
   # or in an existing clone:
   git submodule update --init --recursive
   ```

3. **Git** on `PATH` (for a one-time shallow clone of [uswid-data](https://github.com/hughsie/uswid-data)
   templates on first run). No manual clone required — SBOM4EDK2 fetches templates into
   `<SBOM4EDK2-repo>/uswid-data` unless you set `--uswid-data` or `USWID_DATA`.

## Scenarios

### Scenario 1 — Clone and full pipeline

```bash
python main.py -o edk2 -r https://github.com/tianocore/edk2.git
```

Clones `edk2` (with submodules), clones `uswid-data` if missing, writes
`edk2.cdx.json` in the current directory. Run CVE scans with VEX4EDK2 (below).

### Scenario 2 — Local checkout (typical for CI)

```bash
python edk2_json_generator.py -l /path/to/edk2 -n edk2
```

Writes `edk2.cdx.json` in the **current working directory** (not under the EDK2 tree).

### Scenario 3 — CVE scan only (VEX4EDK2)

```bash
cd /path/to/VEX4EDK2
pip install -e .
python scripts/get_cve_response.py /path/to/edk2.cdx.json
```

Uses `--scanner auto` by default (NVD when `NVD_API_KEY` is set, otherwise grype).
GHSA is included unless `--no-ghsa` is passed.

## Validation checklist

After generating `edk2.cdx.json`, confirm:

1. **No `@VCS_*@` literals** anywhere in the JSON.
2. **`metadata.component.version`** reflects your checkout (e.g. `edk2-stable202602+…` or `202602` in CPE).
3. **`components[]` count** is on the order of **tens** (OSS submodules), not thousands.
4. **No `OpensslLib`-style names** unless they appear as a curated OSS product name in uswid-data.
5. **`dependencies[].dependsOn`** values are **JSON arrays**, not strings.
6. Mapped OSS families include a **`cpe`** field only when that exact CPE name exists in the
   NVD CPE dictionary (non-deprecated). If the release version is not listed (e.g. a
   BoringSSL snapshot date, `python-ecdsa` 0.19.0, or `tlslite-ng` 0.8.0 without a GA
   dictionary row), the component is emitted **without** `cpe`.
7. When any component lacks `cpe`, review **`<output-stem>.cpe-omissions.log`** in the same
   directory as the CycloneDX JSON for `reason=` and `candidates=` per row.

## How versions and CPEs are resolved

1. Walk all `.gitmodules` files under the EDK2 tree (including nested submodules).
2. For each OSS template in uswid-data, match `externalReferences[type=vcs].url` to a submodule path (with URL alias handling for org renames).
3. Run `git describe --tags --always` in each submodule directory and normalize the tag string for NVD.
4. **Display version** uses release plus patch count (e.g. `1.1.5+23.g1cc9cde` in `version` / `bom-ref`); **CPE** keeps the release only (`1.1.5`).
5. Post-tag commits are recorded under `pedigree.patches[]` using the **tag’s commit SHA** (not only the tag name). Each patch is prefixed `[upstream]` or `[vendor pin]` when a `upstream` remote exists.
6. Substitute `@VCS_VERSION@`, `@VCS_TAG@`, and `@VCS_AUTHORS@` in template JSON.
7. Drop templates that still contain placeholders (submodule not present in this checkout).
8. **Synthesize** minimal components for submodules in `.gitmodules` that have no uswid-data template.
   **Supplier** names use `sbom4edk2.supplier_data` (GitHub org / slug map) instead of
   uswid-data ``<project> developers`` labels when a globally recognized name exists
   (e.g. Brotli → **Google**, Mbed TLS → **Arm**). Curated non-generic template
   suppliers (e.g. **The OpenSSL Project**) are kept unless a slug map applies.
9. Apply `SUBMODULE_CPE_MAP` (GitHub `owner/repo` → NVD vendor/product) and validate each
   candidate `cpe:2.3:a:…` against the NVD CPE API (`sbom4edk2.nvd_cpe`). Template `cpe`
   values from uswid-data are kept only when they pass the same check.
10. Emit `dependencies[]` from directory prefix relationships (longest parent path wins).

When any OSS component is emitted **without** `cpe`, SBOM4EDK2 writes
`<output-stem>.cpe-omissions.log` next to the CycloneDX JSON (e.g. `edk2.cdx.json` →
`edk2.cpe-omissions.log`). The file is omitted when every component that could carry a
`cpe` has one. Each body line is space-separated `key=value` fields:

| Field | Content |
|-------|---------|
| `component` | Component `name` or `bom-ref` |
| `reason` | Why `cpe` was dropped (see table below) |
| `bom-ref` | CycloneDX reference when present |
| `vcs_url` | Matched `externalReferences` VCS URL |
| `github_slug` | `owner/repo` when parsed from GitHub |
| `version` | Clean release version used for CPE |
| `template_cpe` | uswid-data template value before validation |
| `candidates` | Semicolon-separated `cpe:2.3:a:…` names tried |

**Omission reasons**

| `reason` | When |
|----------|------|
| `version_not_suitable_for_cpe` | `0.0.0`, empty, or `NOASSERTION` |
| `no_github_slug_and_no_template_cpe` | Non-GitHub VCS URL, no template `cpe` |
| `no_cpe_map_entry_and_no_template_cpe` | GitHub slug not in `SUBMODULE_CPE_MAP`, no template `cpe` |
| `no_cpe_candidates_generated` | Map present but no candidate strings built |
| `not_in_nvd_dictionary` | Live NVD check: no exact non-deprecated match |
| `nvd_validation_disabled_not_in_allowlist` | `SBOM4EDK2_SKIP_NVD_CPE_VALIDATE=1` and not in `data/nvd_cpe_allowlist.json` |

Example line:

```text
component=boringssl reason=not_in_nvd_dictionary github_slug=google/boringssl version=20210429 candidates=cpe:2.3:a:google:boringssl:20210429:*:*:*:*:*:*:*
```

### GitHub slug → NVD map (Jun 2026)

| GitHub slug | NVD vendor | NVD product | Notes |
|-------------|------------|-------------|-------|
| `openssl/openssl` | `openssl` | `openssl` | |
| `ARMmbed/mbedtls` | `arm` (via `*`) | `mbed_tls` | |
| `akheron/jansson` | `jansson_project` (via `*`) | `jansson` | |
| `kkos/oniguruma` | `oniguruma_project` (via `*`) | `oniguruma` | |
| `google/brotli` | `google` | `brotli` | |
| `DMTF/libspdm` | `dmtf` | `libspdm` | |
| `google/boringssl` | `google` | `boringssl` | Only `2018-06-14` and `-` in dictionary today |
| `tianocore/edk2-cmocka` | `cmocka` | `cmocka` | No cmocka rows in NVD at present — `cpe` omitted |
| `mbed-tls/mbedtls-framework` | `arm` | `mbed_tls` | `4.0.0` has beta/`-` rows only, not GA `4.0.0` |
| `tlsfuzzer/python-ecdsa` | `python-ecdsa_project` | `python-ecdsa` | Dictionary tops out below 0.19.x |
| `tlsfuzzer/tlslite-ng` | `tlslite-ng_project` | `tlslite-ng` | `0.8.0` pre-releases only in dictionary |

`openssl/fuzz-corpora` and `tianocore/edk2-subhook` have no map entry (not in the NVD
dictionary). `0.0.0` versions never receive a `cpe`.

## Post-tag pedigree

When a submodule checkout is **past its last release tag**, commits since the tag’s
**commit** (via `tag^{commit}`) are recorded under `pedigree.patches[]`. Patch
descriptions are prefixed `[upstream]` when the commit is already on `upstream/master`
(GitLab/GitHub upstream remote), otherwise `[vendor pin]`. CVE mentions use security
typing; others default to cherry-pick (defect) per UEFI SBOM practice.

Add `git remote add upstream <url>` in a submodule checkout to enable upstream
detection (optional).

## Environment variables

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | NVD REST API (faster CPE validation during SBOM build; optional but recommended) |
| `SBOM4EDK2_SKIP_NVD_CPE_VALIDATE` | Set to `1` to skip live NVD CPE checks (tests/CI only; uses allowlist only) |
| `GITHUB_TOKEN` | Raises GitHub API rate limit for GHSA fetch (optional) |

See `.env.example` for a starter file.

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Very few `components[]` | Submodules not initialized — run `git submodule update --init --recursive` |
| `@VCS_*@` in output | Submodule path mismatch; check `.gitmodules` URL vs uswid-data template |
| Missing openssl/mbedtls CPE | Submodule directory not a git repo, `git describe` failed, or release version not in NVD dictionary |
| Had `cpe` before, gone now | Version not an exact NVD dictionary row (validation enabled) |
| Need to know why `cpe` is missing | Open `<name>.cpe-omissions.log` beside the SBOM |
| CVE scan finds nothing | Component lacks `cpe` or version; check SBOM and omission log |

## Python API

```python
from sbom4edk2.sbom import generate_sbom_from_checkout

path = generate_sbom_from_checkout(
    "/path/to/edk2",
    "edk2",
    uswid_data="/path/to/uswid-data",
    sbom_type="source",
)
# path -> absolute path to edk2.cdx.json, or None on failure
```

Lower-level assembly: `sbom4edk2.cdx_merge.build_source_sbom(edk2_dir, uswid_data_dir=...)`.
