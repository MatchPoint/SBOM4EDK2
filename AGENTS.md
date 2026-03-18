# AGENTS.md

## Cursor Cloud specific instructions

### Overview

SBOM4EDK2 is a Python CLI tool that generates Software Bill of Materials (SBOM) from TianoCore EDK2 firmware source code and runs CVE analysis using the NIST NVD API. There are three entry points:

- `main.py` — clones an EDK2 repo, runs `uswid --find` to generate a combined CDX JSON, then queries NVD for CVEs.
- `edk2_json_generator.py` — processes individual `.inf` files with concurrency, merges CDX files hierarchically, then queries NVD for CVEs.
- `get_cve_response.py` — standalone utility to fetch CVE data from a pre-existing `.cdx.json` file. Note: this script has a hardcoded call at module level (`generate_cves('edk.cdx.json')`) and an empty API key, so it requires manual editing before use.

### Environment setup

- Python 3.12+ with a virtual environment at `/workspace/venv`.
- Activate with: `source /workspace/venv/bin/activate`
- All dependencies are in `requirements.txt`. The `uswid` package is installed from a pinned git commit (not PyPI).
- The `uswid` CLI must be on PATH (it is, inside the venv).

### Running the tools

See `README.md` for usage. Key commands (all require the venv activated):

```
python main.py -o <output_name> -k <nvd_api_key> -r <edk2_repo_url>
python edk2_json_generator.py -l <location> -n <json_name> -k <nvd_api_key> [--uswid-data <path>] [--parent-yaml <path>]
```

### Quick validation (hello-world)

To verify the environment works without cloning a full EDK2 repo, use `main.py`'s internal functions against a sample CycloneDX SBOM JSON:

```python
import sys, os
sys.path.insert(0, '/workspace')
from main import parse_sbom_file, generate_cves
components = parse_sbom_file('path/to/sample.cdx.json')
generate_cves('path/to/sample.cdx.json', os.environ['NVD_API_KEY'], max_workers=2)
```

The `NVD_API_KEY` secret is available as an environment variable when configured in Cursor Secrets.

### Gotchas

- **NVD API key required**: CVE generation needs a valid NVD API key (free, request at https://nvd.nist.gov/developers/request-an-api-key). Without it, SBOM/CDX generation still works but NVD queries will fail with 403/404. The key is available as `$NVD_API_KEY` when set in Cursor Secrets.
- **`uswid --fixup` crashes on CDX files without `source_dir`**: The pinned `uswid` version has a bug where `--fixup` fails with `TypeError: object of type 'NoneType' has no len()` on components lacking a `source_dir`. The codebase works around this via `sanitize_cdx_file()` in `edk2_json_generator.py`. When using `uswid` directly, omit `--fixup` for manually-created CDX files, or pre-sanitize them.
- **`edk2_json_generator.py` cannot be imported as a module** because `argparse` runs at module level (outside `if __name__ == '__main__'`).
- **`get_cve_response.py` has a hardcoded empty API key and hardcoded input file** (`edk.cdx.json`). Edit before running.
- **No test suite exists** — there are no unit/integration tests, no pytest configuration, and no linter config in this repo.
- **Full end-to-end run is slow and network-heavy**: `main.py` clones the EDK2 repo (several GB with submodules) and makes many NVD API calls.
- **No lint or formatting tools are configured** in the repo (no flake8, ruff, pylint, mypy, etc.).
