# Testing

## Unit tests

No EDK II checkout, live NVD API calls, or `uswid` install is required. CPE validation
tests mock the NVD client or use `data/nvd_cpe_allowlist.json` plus
`SBOM4EDK2_SKIP_NVD_CPE_VALIDATE=1` where network must stay off.

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m unittest discover -s tests -p "test_*.py" -v
# or: python -m pytest tests/ -v
```

| File | Coverage |
|------|----------|
| `tests/test_sbom4edk2.py` | SBOM parsing and sanitize helpers |
| `tests/test_source_sbom.py` | Source SBOM pipeline: normalize, gitmodules, merge, emit, pedigree, no-uswid |
| `tests/test_nvd_cpe.py` | NVD CPE map, dictionary validation, omission log path and file write |
| `tests/test_source_sbom.py` (`TestEdk2Stable202602Artifact`) | Gate on `edk2-stable202602.cdx.json` when present (core OSS CPEs, optional omission log) |

## What unit tests assert

- Twelve `git describe` normalization patterns for OSS submodules
- URL canonicalization and Mbed-TLS / libfdt alias resolution
- Nested `.gitmodules` walk (first-write-wins for duplicate URLs)
- CycloneDX `dependencies[].dependsOn` as arrays with nested containment
- Orphan uswid-data templates with `@VCS_*@` are dropped when no submodule matches
- **`SUBMODULE_CPE_MAP`** has eleven GitHub slug entries (six original families plus boringssl, edk2-cmocka, mbedtls-framework, python-ecdsa, tlslite-ng)
- Wildcard NVD vendors (`*` → `arm` / `jansson_project` / `oniguruma_project`) for mbedtls, jansson, oniguruma
- **`cpe`** is set only when the formed name matches the NVD dictionary exactly (mocked or allowlisted in unit tests)
- **`*.cpe-omissions.log`** is written next to the SBOM when any component lacks `cpe`, with documented `reason=` codes
- Display `version` / `bom-ref` may include `+patch` metadata; emitted `cpe` uses the clean release version only
- `requirements.txt` does not reference the `uswid` package

### CPE omission `reason` values (unit-tested)

| Reason | Meaning |
|--------|---------|
| `version_not_suitable_for_cpe` | `0.0.0`, empty, or `NOASSERTION` |
| `no_github_slug_and_no_template_cpe` | Non-GitHub VCS URL and no template `cpe` |
| `no_cpe_map_entry_and_no_template_cpe` | GitHub slug not in map and no template `cpe` |
| `no_cpe_candidates_generated` | Map entry could not build candidates |
| `not_in_nvd_dictionary` | Candidates checked; none match NVD exactly |
| `nvd_validation_disabled_not_in_allowlist` | `SBOM4EDK2_SKIP_NVD_CPE_VALIDATE=1` and name not on allowlist |

## Integration / smoke (optional)

Requires a real EDK II tree with initialized submodules. uswid-data is auto-cloned
unless `--uswid-data` is set. Set **`NVD_API_KEY`** for live CPE dictionary checks
(without it, NVD rate-limits unauthenticated calls to ~one request every six seconds).

```bash
git clone --recursive --depth 1 https://github.com/tianocore/edk2.git /path/to/edk2

python edk2_json_generator.py -l /path/to/edk2 -n edk2-smoke

# Quick checks (PowerShell):
# Select-String -Path edk2-smoke.cdx.json -Pattern '@VCS_'
# (Get-Content edk2-smoke.cdx.json | ConvertFrom-Json).components.Count
# Test-Path edk2-smoke.cpe-omissions.log   # present when some OSS lack cpe
```

Expect tens of OSS components, not thousands. Some OSS rows intentionally have **no**
`cpe` when the release version is absent from the NVD dictionary; read
`edk2-smoke.cpe-omissions.log` for per-component reasons. Do not compare byte-for-byte
to legacy v0.3.0 SBOMs that included per-`.inf` components or unvalidated template CPEs.

## CI

Run `python -m unittest discover -s tests -p "test_*.py"` (or `pytest tests/`) on every
change touching `sbom4edk2/`, `tests/`, or `data/nvd_cpe_allowlist.json`.
