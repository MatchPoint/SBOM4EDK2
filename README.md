# SBOM4EDK2

Generate a Software Bill of Materials (SBOM) from [TianoCore EDK II](https://github.com/tianocore/edk2) source code and run CVE vulnerability analysis using the [NIST NVD](https://nvd.nist.gov/) API.

## Quick Start

```bash
# 1. Set up Python environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure your NVD API key (free: https://nvd.nist.gov/developers/request-an-api-key)
cp .env.example .env
# Edit .env and add your key: NVD_API_KEY=your_key_here

# 4. Run (example — clone EDK2 and generate full report)
python main.py -o edk2 -r https://github.com/tianocore/edk2.git
```

## Project Structure

```
sbom4edk2/              Shared library
  nvd.py                NVD API client (CPE lookup, CVE retrieval, caching)
  cpe.py                CPE pattern construction and name normalisation
  cve_analyzer.py       Concurrent CVE analysis and Excel report generation
  sbom.py               CycloneDX SBOM parsing, CDX merge, uswid helpers
  git_utils.py          Git clone/pull operations

main.py                 Scenario 1 — clone repo + generate SBOM + CVE list
edk2_json_generator.py  Scenario 2 — local checkout + generate SBOM + CVE list
get_cve_response.py     Scenario 3 — existing SBOM + generate CVE list only
```

## Usage

All scripts read `NVD_API_KEY` from `.env` automatically. The `-k` flag overrides it.

### Scenario 1 — Clone EDK2, Generate SBOM, and Create CVE List

```bash
python main.py -o <output_name> -r <edk2_repo_url> [-k <api_key>]
```

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Output name (clone directory and CDX filename, without extension) |
| `-r`, `--repo` | Git URL of the EDK2 repository |
| `-k`, `--apikey` | *(Optional)* NVD API key — overrides `.env` |

**Example:**
```bash
python main.py -o edk2 -r https://github.com/tianocore/edk2.git
```

**Outputs:** `edk2.cdx.json`, `CVE_List.xlsx`, `sbom4edk2_<timestamp>.log`

---

### Scenario 2 — Local EDK2 Checkout: Generate SBOM and CVE List

```bash
python edk2_json_generator.py -l <path> -n <name> [-k <key>] [--uswid-data <path>] [--parent-yaml <file>] [--max-workers N]
```

| Flag | Description |
|------|-------------|
| `-l`, `--location` | Path to local EDK2 source tree |
| `-n`, `--jsonname` | Output CDX filename (without extension) |
| `-k`, `--apikey` | *(Optional)* NVD API key — overrides `.env` |
| `--uswid-data` | *(Optional)* Path to [uswid-data](https://github.com/hughsie/uswid-data.git) clone |
| `--parent-yaml` | *(Optional)* Parent component YAML for merge |
| `--max-workers` | *(Optional)* Thread count for `.inf` processing (default: 12) |

**Example:**
```bash
python edk2_json_generator.py -l /path/to/edk2 -n edk2 --uswid-data /path/to/uswid-data
```

**Outputs:** `cdx_json_output/` (individual CDX files), `cdx_json_output/<name>.cdx.json` (merged), `CVE_List.xlsx`, `edk2_json_generator_<timestamp>.log`

> **Known issue:** The CDX merge step uses `uswid --fixup`, which may crash with
> `TypeError: object of type 'NoneType' has no len()` on components that lack a
> `source_dir` value. If this happens, the individual CDX files in `cdx_json_output/`
> are still valid and can be used with Scenario 3. Manual merge without `--fixup`:
> ```bash
> uswid --load file1.cdx.json --load file2.cdx.json --save merged.cdx.json
> ```

---

### Scenario 3 — Existing SBOM: Generate CVE List Only

```bash
python get_cve_response.py <cdx_file> [-k <api_key>]
```

| Argument / Flag | Description |
|-----------------|-------------|
| `cdx_file` | Path to CycloneDX SBOM (`.cdx.json`) |
| `-k`, `--apikey` | *(Optional)* NVD API key — overrides `.env` |

**Example:**
```bash
python get_cve_response.py edk2.cdx.json
```

**Outputs:** `CVE_List.xlsx`, `get_cve_response.log`

## Notes

- The NVD API has rate limits. The client includes automatic retry with exponential backoff for 429/5xx responses.
- Full EDK2 runs are slow and network-heavy (large git clone + many NVD API calls).
- All scripts produce log files for troubleshooting.

## License

[BSD-2-Clause](LICENSE)
