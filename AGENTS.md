# AGENTS.md

## Cursor Cloud specific instructions

### Overview

SBOM4EDK2 is a Python CLI tool that generates SBOMs from TianoCore EDK2 firmware source code and runs CVE analysis via three complementary sources: the NIST NVD API, Grype (local DB, no key required), and TianoCore GitHub Security Advisories (GHSA, always included). Shared logic lives in the `sbom4edk2/` package; three thin CLI scripts provide the entry points. See `README.md` for usage.

### Environment setup

- Python 3.11+ with a virtual environment at `/workspace/venv`.
- Activate: `source /workspace/venv/bin/activate`
- Dependencies: `pip install -r requirements.txt` (includes `uswid` from a pinned git commit).
- NVD API key (optional): set `NVD_API_KEY` in `.env` or pass `-k` on the CLI. Without it, the default `--scanner auto` mode falls back to grype automatically — NVD queries are not attempted and no error is raised.

### Running the tools

```
python main.py -o <name> -r <repo_url>            # Scenario 1
python edk2_json_generator.py -l <path> -n <name>  # Scenario 2
python get_cve_response.py <cdx_file>               # Scenario 3
```

### Architecture (post-refactor, requires `python-uswid-sbom >= 0.2.0`)

All SBOM **creation** logic now lives in `python-uswid-sbom` (the fork pinned in `requirements.txt`). SBOM4EDK2 only orchestrates: clone EDK2, invoke `uswid`, run CVE scanners on the result.

The single SBOM-generation entry point is `sbom4edk2.sbom.generate_sbom_from_checkout`, a ~95-line wrapper that shells out to:

```
uswid --find <edk2_dir> \
      --primary-dir <edk2_dir> \
      --fallback-path <uswid_data_dir> \
      --primary pkg:github/tianocore/edk2@<tag> \
      --fixup \
      --format cyclonedx \
      --sbom-type {source,build,binary} \
      --save <output>.cdx.json
```

The `--primary-dir` flag (new in `uswid >= 0.2.0`) does the heavy lifting that the old `_merge_inf_cdx_direct` used to: it recursively walks `.gitmodules`, normalises versions, substitutes `@VCS_TAG@` / `@VCS_VERSION@` per component against the matching submodule's git tree, drops orphan templates whose URL doesn't match any submodule, synthesises minimal components for submodules without a curated template, and wires up the CycloneDX `dependencies[]` graph.

### Gotchas

- **Do not reintroduce per-INF processing in this repo.** The old thread-pool / merge pipeline (`process_inf_file` × N → `merge_cdx_files`) is gone; `uswid --find` walks the entire tree in a single pass. If you find yourself reaching for `ThreadPoolExecutor` in this repo to handle `.inf` files, that work belongs in `python-uswid-sbom` instead.
- **Submodule version + alias resolution lives in `uswid.submodule`.** The old `sbom4edk2.sbom._URL_ALIASES`, `_parse_edk2_gitmodules`, `_normalize_submodule_version`, and `_resolve_submodule_vcs` helpers have all been removed; their replacements are `uswid.submodule.SUBMODULE_URL_ALIASES`, `walk_gitmodules`, `normalize_submodule_version`, and `resolve_submodule_vcs`.
- **EDK II-specific logic lives in `uswid.edk2`.** `EDK2_TAG_PATTERN`, `describe_edk2_version`, `EDK2_LIGHT_MODE_PACKAGES`, etc. are EDK II-only and intentionally separated from the generic `uswid.submodule` module so they can later be lifted into a `python-uswid-edk2` plugin.
- **`metadata.component` clobber was a myth.** The previous note claiming `uswid --load` silently overwrites `metadata.component` on each load was empirically disproven during the v0.2.0 work. `--load` preserves all loaded components; the old in-repo JSON merger was unnecessary.
- **Test suite**: `tests/test_sbom4edk2.py` contains 74 unit tests covering `cpe`, `ghsa`, `grype`, `sbom` (including the new `generate_sbom_from_checkout` and `_compute_edk2_primary_bomref` tests), and `cve_analyzer` modules. Run with `python -m pytest tests/`.
- **Full runs are slow**: `main.py` clones the EDK2 repo (several GB with submodules) and makes many NVD API calls.
