# AGENTS.md

## Cursor Cloud specific instructions

### Overview

SBOM4EDK2 is a Python CLI tool that generates SBOMs from TianoCore EDK2 firmware source code and runs CVE analysis via the NIST NVD API. Shared logic lives in the `sbom4edk2/` package; three thin CLI scripts provide the entry points. See `README.md` for usage.

### Environment setup

- Python 3.12+ with a virtual environment at `/workspace/venv`.
- Activate: `source /workspace/venv/bin/activate`
- Dependencies: `pip install -r requirements.txt` (includes `uswid` from a pinned git commit).
- NVD API key: set `NVD_API_KEY` in `.env` or pass `-k` on the CLI.

### Running the tools

```
python main.py -o <name> -r <repo_url>            # Scenario 1
python edk2_json_generator.py -l <path> -n <name>  # Scenario 2
python get_cve_response.py <cdx_file>               # Scenario 3
```

### Gotchas

- **`uswid --fixup` crash**: The pinned uswid version crashes on `None` `source_dir` values. `sbom4edk2/sbom.py:sanitize_cdx_file()` patches CDX JSON before merge, but uswid's internal sort may still fail. Omit `--fixup` for manually-created CDX files.
- **No test suite**: No unit/integration tests or linter config exist in this repo.
- **Full runs are slow**: `main.py` clones the EDK2 repo (several GB with submodules) and makes many NVD API calls.
