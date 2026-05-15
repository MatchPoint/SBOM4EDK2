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

### Gotchas

- **CDX merge**: The SBOM merge step uses a direct Python JSON merge (`sbom4edk2/sbom.py:_merge_inf_cdx_direct`) rather than `uswid --load`, because `uswid --load` silently overwrites `metadata.component` on each file loaded, leaving only the last component in the output. Do not revert to `uswid --load` for the merge step.
- **Submodule version resolution**: `_merge_inf_cdx_direct` also (a) recursively walks every `.gitmodules` under the EDK2 checkout via `_parse_edk2_gitmodules`, (b) runs `git describe` in each submodule clone via `_resolve_submodule_vcs`, (c) normalises the result to an NVD-matchable version, and (d) substitutes `@VCS_TAG@` / `@VCS_VERSION@` per component.  A small `_URL_ALIASES` map handles upstream org renames.  Components whose VCS URL doesn't match any EDK2 submodule are dropped so the output never contains unsubstituted placeholders.
- **Dependency tree**: After version substitution, `_merge_inf_cdx_direct` emits a CycloneDX `dependencies[]` array.  Edges are derived by longest-common-path-prefix matching among resolved submodule directories — e.g. submodules under `CryptoPkg/Library/OpensslLib/openssl/` become children of `openssl`, and top-level submodules become children of the EDK2 primary component.
- **Test suite**: `tests/test_sbom4edk2.py` contains 64 unit tests covering `cpe`, `ghsa`, `grype`, `sbom`, and `cve_analyzer` modules. Run with `python -m pytest tests/`.
- **Full runs are slow**: `main.py` clones the EDK2 repo (several GB with submodules) and makes many NVD API calls.
