# SBOM4EDK2

Generate a Software Bill of Materials (SBOM) from [TianoCore EDK II](https://github.com/tianocore/edk2) source code and run CVE vulnerability analysis via the [NIST NVD](https://nvd.nist.gov/) API, [Grype](https://github.com/anchore/grype), and TianoCore GitHub Security Advisories (GHSA).

> **SBOM engine:** This project uses [python-uswid-sbom](https://github.com/MatchPoint/python-uswid-sbom),
> a fork of [python-uswid](https://github.com/hughsie/python-uswid) extended with
> UEFI SBOM Guidelines (CISA Level 1) compliance features including accurate CPE
> version strings for OSS submodules, CVE-aware pedigree patches, INF→submodule
> `dependsOn` wiring, and the `--sbom-type` lifecycle flag.

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
  grype.py              Grype-based SBOM scanner (no API key required)
  sbom.py               CycloneDX SBOM parsing, CDX merge, uswid helpers
  git_utils.py          Git clone/pull operations

main.py                 Scenario 1 — clone repo + generate SBOM + CVE list
edk2_json_generator.py  Scenario 2 — local checkout + generate SBOM + CVE list
get_cve_response.py     Scenario 3 — existing SBOM + generate CVE list only
```

## Vulnerability Scanning

SBOM4EDK2 supports three complementary CVE sources, each producing its own
Excel report.  They are combined in a single run for complete coverage.

### Scanner auto-detection

The `--scanner` flag defaults to **`auto`**: if `NVD_API_KEY` is set the NVD
REST API is used; otherwise grype is used.  You never need to set this flag
explicitly unless you want to override the default behaviour.

```bash
# Auto (recommended) — uses NVD if key is present, grype otherwise
python get_cve_response.py edk2.cdx.json

# Force NVD (requires API key)
python get_cve_response.py edk2.cdx.json --scanner nvd -k <your_key>

# Force grype (no key needed)
python get_cve_response.py edk2.cdx.json --scanner grype

# Run both NVD and grype side-by-side
python get_cve_response.py edk2.cdx.json --scanner both -k <your_key>
```

### Trade-offs: NVD vs. grype

| | NVD REST API (`--scanner nvd`) | Grype (`--scanner grype`) |
|---|---|---|
| **API key required** | Yes — free at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) | No |
| **Local DB download** | No — queries NVD cloud per-component | ~600 MB on first run, then daily deltas (~1–5 MB) |
| **Scan time (full EDK2, 1335 components)** | ~30 minutes (rate-limited REST calls) | ~10 seconds (local DB lookup) |
| **Vulnerability coverage** | NVD only | NVD + GitHub Advisory DB + OS distro advisories |
| **Matching method** | CPE only | CPE + PURL |
| **EPSS exploit scores** | No | Yes |
| **Works offline** | No | Yes (after initial DB download) |
| **Best for** | Authoritative NVD output, scheduled CI/CD pipelines | Ad-hoc scans, local development, offline environments |

**Recommendation:** Use `auto` (the default).  For ad-hoc or offline use,
grype is faster and requires no registration.  For production pipelines where
you want authoritative NVD output and already have a key, use `--scanner nvd`.

> **Note on CPE accuracy:** `cpe.py` uses the explicit `cpe` field from the
> SBOM when available (set by `python-uswid-sbom` from NVD-verified data)
> rather than constructing a wildcard pattern, significantly improving match
> rates for submodules like `mbedtls`, `brotli`, and `oniguruma`.

### Installing grype

```bash
# Linux / WSL
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b ~/.local/bin

# Windows (winget)
winget install Anchore.Grype
```

Grype downloads its vulnerability database on first run (~600 MB, cached in
`~/.cache/grype/`).  Subsequent runs fetch only daily deltas (~1–5 MB).

### TianoCore GitHub Security Advisories (GHSA) — always included

In addition to the selected scanner, **all scripts automatically query the
TianoCore EDK2 GitHub security advisories** and produce `CVE_List_ghsa_*.xlsx`.

These advisories are published directly by the EDK2 maintainers — often
**months before NVD processes them** — making them the most timely source of
EDK2-specific CVEs.  No API key is required; set `GITHUB_TOKEN` in `.env` to
raise the GitHub API rate limit from 60 to 5,000 requests/hour.

To skip the GHSA check:

```bash
python get_cve_response.py edk2.cdx.json --no-ghsa
```

### Output files

| File | Source | Notes |
|------|--------|-------|
| `CVE_List.xlsx` | NVD REST API | Produced when `--scanner nvd` or `both` |
| `CVE_List_grype_<name>.xlsx` | Grype local DB | Produced when `--scanner grype`, `both`, or `auto` (no key) |
| `CVE_List_ghsa_<name>.xlsx` | TianoCore GHSA | Always produced (use `--no-ghsa` to skip) |

---

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
| `-k`, `--apikey` | *(Optional)* NVD API key — overrides `.env`; required when `--scanner nvd/both` |
| `--sbom-type` | *(Optional)* `source` \| `build` \| `binary` — SBOM lifecycle type (default: `source`) |
| `--scanner` | *(Optional)* `auto` \| `nvd` \| `grype` \| `both` — scanner back-end (default: `auto`) |
| `--no-ghsa` | *(Optional)* Skip TianoCore GHSA advisory check (included by default) |

**Example (auto — uses NVD if key set, otherwise grype):**
```bash
python main.py -o edk2 -r https://github.com/tianocore/edk2.git
```

**Outputs:** `edk2.cdx.json`, `CVE_List.xlsx` or `CVE_List_grype_edk2.xlsx` (auto-selected), `CVE_List_ghsa_edk2.xlsx`, log

---

### Scenario 2 — Local EDK2 Checkout: Generate SBOM and CVE List

```bash
python edk2_json_generator.py -l <path> -n <name> [-k <key>] [--uswid-data <path>] [--parent-yaml <file>] [--max-workers N]
```

| Flag | Description |
|------|-------------|
| `-l`, `--location` | Path to local EDK2 source tree |
| `-n`, `--jsonname` | Output CDX filename (without extension) |
| `-k`, `--apikey` | *(Optional)* NVD API key — overrides `.env`; required when `--scanner nvd/both` |
| `--uswid-data` | *(Optional)* Path to [uswid-data](https://github.com/hughsie/uswid-data.git) clone |
| `--parent-yaml` | *(Optional)* Parent component YAML for merge |
| `--max-workers` | *(Optional)* Thread count for `.inf` processing (default: 12) |
| `--sbom-type` | *(Optional)* `source` \| `build` \| `binary` — SBOM lifecycle type per UEFI SBOM Guidelines §3.1.1.3 (default: `source`) |
| `--scanner` | *(Optional)* `auto` \| `nvd` \| `grype` \| `both` — scanner back-end (default: `auto`) |
| `--no-ghsa` | *(Optional)* Skip TianoCore GHSA advisory check (included by default) |

**Example (auto — recommended):**
```bash
python edk2_json_generator.py -l /path/to/edk2 -n edk2 --uswid-data /path/to/uswid-data
```

**Outputs:** `cdx_json_output/` (individual CDX files), `cdx_json_output/<name>.cdx.json` (merged), `CVE_List.xlsx`, `edk2_json_generator_<timestamp>.log`

> **Note:** The CDX merge step uses `uswid --fixup`. The `python-uswid-sbom`
> engine defensively sanitises `source-dir` fields before each merge pass to
> avoid the `NoneType` crash seen in earlier versions of the upstream engine.

---

### Scenario 3 — Existing SBOM: Generate CVE List Only

```bash
python get_cve_response.py <cdx_file> [-k <api_key>]
```

| Argument / Flag | Description |
|-----------------|-------------|
| `cdx_file` | Path to CycloneDX SBOM (`.cdx.json`) |
| `-k`, `--apikey` | *(Optional)* NVD API key — overrides `.env`; required when `--scanner nvd/both` |
| `--scanner` | *(Optional)* `auto` \| `nvd` \| `grype` \| `both` — scanner back-end (default: `auto`) |
| `--no-ghsa` | *(Optional)* Skip TianoCore GHSA advisory check (included by default) |

**Example (auto — recommended):**
```bash
python get_cve_response.py edk2.cdx.json
```

**Outputs:**
- `CVE_List.xlsx` (NVD, if key set) or `CVE_List_grype_<name>.xlsx` (auto-selected)
- `CVE_List_ghsa_<name>.xlsx` (TianoCore GHSA, always)
- `get_cve_response.log`

## Notes

- The NVD API has rate limits. The client includes automatic retry with exponential backoff for 429/5xx responses.
- Full EDK2 runs are slow and network-heavy (large git clone + many NVD API calls).
- All scripts produce log files for troubleshooting.

## License

[BSD-2-Clause](LICENSE)
