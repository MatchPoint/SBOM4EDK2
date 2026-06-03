# AGENTS.md

## Cursor Cloud specific instructions

### Overview

SBOM4EDK2 is a Python CLI that builds a **source** CycloneDX SBOM from a cloned
[TianoCore EDK II](https://github.com/tianocore/edk2) tree (EDK2 primary +
OSS git submodules). It does **not** run CVE scans — use [VEX4EDK2](https://github.com/MatchPoint/VEX4EDK2)
for NVD, Grype, and GHSA analysis and CSAF VEX output.

No dependency on `python-uswid` or the deprecated MatchPoint/python-uswid-sbom fork.
Per-`.inf` **build** SBOMs remain the domain of
[python-uswid](https://github.com/hughsie/python-uswid) (Richard Hughes).

### Environment setup

- Python 3.11+ with a virtual environment.
- `pip install -r requirements.txt` (no `uswid` package).
- **uswid-data** CDX templates are **auto-cloned** on first run (`sbom4edk2.uswid_data.ensure_uswid_data`);
  optional override via `--uswid-data` or `USWID_DATA`.

### Running the tools

```
python main.py -o <name> -r <repo_url>            # Scenario 1 — clone + SBOM
python edk2_json_generator.py -l <path> -n <name>  # Scenario 2 — local checkout + SBOM
```

CVE scan (Scenario 3) — **VEX4EDK2**:

```
python scripts/get_cve_response.py <path/to>.cdx.json
# or: vex4edk2-cve-scan <path/to>.cdx.json
```

### Source SBOM pipeline (`sbom4edk2/`)

| Module | Role |
|--------|------|
| `cdx_merge.py` | Assemble source SBOM: primary + OSS components + nested `dependencies[]` |
| `cdx_emit.py` | Write CycloneDX JSON to disk |
| `submodule_data.py` | `.gitmodules` walk, URL aliases, `SUBMODULE_CPE_MAP` |
| `nvd_cpe.py` | NVD CPE dictionary validation, `<stem>.cpe-omissions.log` |
| `version_normalize.py` | `git describe` → clean (CPE) + display (`1.1.5+23`) versions |
| `pedigree.py` | Post-tag commits → `pedigree.patches[]`; `[upstream]` / `[vendor pin]` labels |
| `edk2_version.py` | `edk2-stableYYYYMM` parsing for primary `@VCS_*@` |
| `template_loader.py` | Load uswid-data JSON templates |

### Gotchas

- **No `.inf` scan:** OpensslLib-style modules are build-time artifacts, not
  separate source-SBOM components. Output is ~tens of OSS rows, not ~1100 INF rows.
- **Submodules must be initialized:** `git submodule update --init --recursive`
  on the EDK2 checkout before Scenario 2.
- **Tests:** `python -m pytest tests/` — `test_source_sbom.py` + trimmed `test_sbom4edk2.py`.
  CVE scanner tests live in VEX4EDK2 `tests/test_cve_scan.py`.

### Ecosystem

| Repo | Role |
|------|------|
| **SBOM4EDK2** | EDK2 **source** SBOM only (this repo) |
| **VEX4EDK2** | CVE scan (NVD, Grype, GHSA) + quarterly CSAF VEX |
| **uswid-data** | Curated CDX templates (data only) |
| **python-uswid** | Build/binary uSWID SBOM tooling (optional) |
| **StreamingVEX** | Ingest/delivery (separate repo) |
