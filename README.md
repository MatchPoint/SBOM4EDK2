# SBOM4EDK2

Tool to generate a Software Bill of Materials (SBOM) from TianoCore EDK II source code and run CVE vulnerability analysis against the SBOM using the NIST National Vulnerability Database (NVD).

## Prerequisites

1. Install Python 3.12 or later
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv

   # Linux / macOS
   source venv/bin/activate

   # Windows
   venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Request a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key
5. Copy the example environment file and add your API key:
   ```bash
   cp .env.example .env
   ```
   Then edit `.env` and replace the placeholder with your actual key:
   ```
   NVD_API_KEY=your_actual_api_key_here
   ```

   All three scripts read `NVD_API_KEY` from the `.env` file automatically. You can also pass the key via the `-k` flag on the command line, which takes precedence over the `.env` file.

   The API key is required for CVE generation. Without a valid key, SBOM/CDX files are still generated but NVD queries will fail.

## Usage

### Scenario 1 — Clone EDK2, Generate SBOM, and Create CVE List

Use `main.py` when you want to clone (or update) an EDK2 repository, generate the SBOM, and produce a CVE report in a single command.

The script will automatically:
- Clone/update the [uswid-data](https://github.com/hughsie/uswid-data.git) fallback repository
- Clone/update the target EDK2 repository (including submodules)
- Run `uswid --find` to scan the repository and generate a combined CycloneDX SBOM (`.cdx.json`)
- Query the NVD API for CVEs matching each SBOM component

```bash
python main.py -o <output_name> -r <edk2_repo_url>
```

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Output CDX filename (without extension). Also used as the clone directory name. |
| `-r`, `--repo` | Git URL of the EDK2 repository to clone |
| `-k`, `--apikey` | *(Optional)* NVD API key — overrides `NVD_API_KEY` from `.env` |

**Example:**
```bash
# Using API key from .env file
python main.py -o "edk2" -r "https://github.com/tianocore/edk2.git"

# Or passing the API key directly
python main.py -o "edk2" -k "ABC-1234-qwer-5678" -r "https://github.com/tianocore/edk2.git"
```

**Outputs:**
| File | Description |
|------|-------------|
| `edk2.cdx.json` | Combined CycloneDX SBOM for the repository |
| `CVE_List.xlsx` | Excel report of CVEs found for each SBOM component |
| `edk2_json_generator_<timestamp>.log` | Detailed log file |

---

### Scenario 2 — EDK2 Already Cloned Locally: Generate SBOM and Optional CVE List

Use `edk2_json_generator.py` when you already have the EDK2 source code checked out on your local system. This script processes each `.inf` file individually, merges the resulting CDX files, and then runs CVE analysis.

```bash
python edk2_json_generator.py -l <edk2_local_path> -n <output_name> [options]
```

| Flag | Description |
|------|-------------|
| `-l`, `--location` | Path to the local EDK2 source tree to scan |
| `-n`, `--jsonname` | Name of the final CDX JSON file (without extension) |
| `-k`, `--apikey` | *(Optional)* NVD API key — overrides `NVD_API_KEY` from `.env` |
| `--uswid-data` | *(Optional)* Path to a local [uswid-data](https://github.com/hughsie/uswid-data.git) clone for fallback metadata |
| `--parent-yaml` | *(Optional)* Path to a parent component YAML file to include in the merge |
| `--max-workers` | *(Optional)* Number of concurrent threads for `.inf` processing (default: 12) |

**Example:**
```bash
# Using API key from .env file
python edk2_json_generator.py \
  -l "/path/to/edk2" \
  -n "edk2" \
  --uswid-data "/path/to/uswid-data"

# Or passing the API key directly
python edk2_json_generator.py \
  -l "/path/to/edk2" \
  -n "edk2" \
  -k "ABC-1234-qwer-5678" \
  --uswid-data "/path/to/uswid-data"
```

**Outputs:**
| File | Description |
|------|-------------|
| `cdx_json_output/` | Directory containing individual `.cdx.json` files for each `.inf` |
| `cdx_json_output/<output_name>.cdx.json` | Merged CycloneDX SBOM |
| `CVE_List.xlsx` | Excel report of CVEs found for each SBOM component |
| `edk2_json_generator_<timestamp>.log` | Detailed log file |

> **Known issue:** The CDX merge step uses `uswid --fixup`, which may crash with
> `TypeError: object of type 'NoneType' has no len()` on components that lack a
> `source_dir` value. If this happens, the individual `.cdx.json` files in
> `cdx_json_output/` are still valid and can be used with Scenario 3 to generate
> CVE lists. You can also merge them manually without the `--fixup` flag:
> ```bash
> uswid --load cdx_json_output/File1.cdx.json --load cdx_json_output/File2.cdx.json --save merged.cdx.json
> ```

---

### Scenario 3 — SBOM Already Generated: Generate CVE List Only

Use `get_cve_response.py` when you already have an SBOM (`.cdx.json`) from a previous run and only need to generate or refresh the CVE report.

```bash
python get_cve_response.py <cdx_file>
```

| Argument / Flag | Description |
|-----------------|-------------|
| `cdx_file` | Path to the CycloneDX SBOM (`.cdx.json`) file |
| `-k`, `--apikey` | *(Optional)* NVD API key — overrides `NVD_API_KEY` from `.env` |

**Example:**
```bash
# Using API key from .env file
python get_cve_response.py edk2.cdx.json

# Or passing the API key directly
python get_cve_response.py edk2.cdx.json -k "ABC-1234-qwer-5678"
```

**Outputs:**
| File | Description |
|------|-------------|
| `CVE_List.xlsx` | Excel report of CVEs found for each SBOM component |
| `API_Calls_Report.xlsx` | Detailed log of all NVD API requests and responses |
| `get_CVEs_API_response.log` | Log file |

## Notes

- The NVD API has rate limits. The scripts include retry logic and backoff for HTTP 429 (Too Many Requests) responses.
- For large repositories, the full pipeline can take significant time due to the number of `.inf` files and NVD API calls.
- All scripts produce log files for troubleshooting.
