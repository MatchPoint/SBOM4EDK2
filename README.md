# SBOM4EDK2

Generate a **source** CycloneDX Software Bill of Materials (SBOM) from [TianoCore EDK II](https://github.com/tianocore/edk2) checkouts. CVE analysis (NVD, Grype, GHSA) and CSAF VEX live in [VEX4EDK2](https://github.com/MatchPoint/VEX4EDK2).

> **Source SBOM engine:** SBOM4EDK2 is self-contained (no `uswid` Python package).
> From a cloned EDK II tree it emits `metadata.component` for EDK II plus one
> component per OSS **git submodule** (`.gitmodules` + [uswid-data](https://github.com/hughsie/uswid-data)
> templates), with nested CycloneDX `dependencies[]` for submodule containment.
> It does **not** list per-`.inf` build modules (e.g. OpensslLib). Build/binary
> SBOM tooling lives in upstream [python-uswid](https://github.com/hughsie/python-uswid)
> (Richard Hughes).

## Documentation

| Guide | Description |
|-------|-------------|
| [docs/source-sbom.md](docs/source-sbom.md) | **Source SBOM** scope, prerequisites, validation checklist, troubleshooting |
| [docs/ecosystem.md](docs/ecosystem.md) | How SBOM4EDK2 relates to VEX4EDK2, StreamingVEX, uswid-data, python-uswid |
| [docs/testing.md](docs/testing.md) | Unit tests and optional EDK II smoke validation |
| [AGENTS.md](AGENTS.md) | Notes for AI assistants and contributors |

## Quick Start

```bash
# 1. Set up Python environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run (uswid-data templates are auto-cloned on first use)
python main.py -o edk2 -r https://github.com/tianocore/edk2.git
# Or, existing EDK II tree:
# python edk2_json_generator.py -l /path/to/edk2 -n edk2

# 5. CVE scan (VEX4EDK2) — after pip install -e /path/to/VEX4EDK2:
# python scripts/get_cve_response.py edk2.cdx.json
```

See [docs/source-sbom.md](docs/source-sbom.md) for submodule initialization requirements and output validation.

## Project Structure

```
sbom4edk2/              Shared library
  sbom.py               Source SBOM orchestration
  cdx_merge.py          EDK2 + OSS submodule CycloneDX assembly
  cdx_emit.py           CycloneDX JSON writer
  submodule_data.py     .gitmodules walk, NVD CPE map, URL aliases
  nvd_cpe.py            NVD dictionary validation, CPE omission log
  version_normalize.py  git describe normalization
  pedigree.py           OSS post-tag pedigree patches
  edk2_version.py       edk2-stable tag parsing
  template_loader.py    uswid-data template loading
  uswid_data.py         Auto-fetch uswid-data templates (shallow clone)
  git_utils.py          Git clone/pull operations

main.py                 Scenario 1 — clone repo + generate source SBOM
edk2_json_generator.py  Scenario 2 — local checkout + generate source SBOM
```

## CVE scanning (VEX4EDK2)

SBOM4EDK2 writes `<name>.cdx.json` only. NVD, Grype, GHSA, and quarterly CSAF
batch output live in [VEX4EDK2](https://github.com/MatchPoint/VEX4EDK2):

- `python scripts/get_cve_response.py <cdx.json>` — Scenario 3 (existing SBOM)
- `python -m vex4edk2.batch` — full pipeline (SBOM + NVD + GHSA → CSAF)

See the VEX4EDK2 README for `--scanner`, `NVD_API_KEY`, and grype install notes.

> **CPE at SBOM build time:** `cdx_merge.build_source_sbom` walks `.gitmodules`,
> runs `git describe` per OSS submodule, normalises versions for NVD, applies the
> eleven-entry `SUBMODULE_CPE_MAP`, and keeps `cpe` only when the exact name exists
> in the NVD CPE dictionary. Components without a dictionary match are listed in
> `<name>.cpe-omissions.log` with a `reason=` code (see [docs/source-sbom.md](docs/source-sbom.md)).

## SBOM structure

The generated `<name>.cdx.json` is a CycloneDX 1.6 document with:

- `metadata.component` — the EDK2 firmware itself (supplier `TianoCore`,
  version e.g. `202602`, CPE `cpe:2.3:a:tianocore:edk2:edk2-stable202602:*:...`).
- `components[]` — one entry per matched OSS git submodule from the recursive
  `.gitmodules` walk (plus uswid-data templates).
- `dependencies[]` — captures the nested submodule structure as
  `ref`/`dependsOn` edges.  For example: the EDK2 primary depends on
  `openssl`, `libspdm`, `mbedtls`, …; `openssl` in turn depends on
  `quiche`, `gost-engine`, `oqs-provider`, `pkcs11-provider`, `krb5`, …;
  `gost-engine` depends on `libprov`; `libspdm` depends on `cmocka`.

This containment tree lets SBOM consumers see which dependency chain a
particular CVE applies to (e.g. a `cloudflare/quiche` CVE is reachable
because openssl pulls quiche in).

---

## Usage

### Scenario 1 — Clone EDK2 and generate source SBOM

```bash
python main.py -o <output_name> -r <edk2_repo_url>
```

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Output name (clone directory and CDX filename, without extension) |
| `-r`, `--repo` | Git URL of the EDK2 repository |
| `--sbom-type` | *(Optional)* `source` \| `build` \| `binary` (default: `source`) |

**Example:**
```bash
python main.py -o edk2 -r https://github.com/tianocore/edk2.git
```

**Output:** `edk2.cdx.json` in the current directory (plus clone under `./edk2`). When
some OSS components lack a dictionary `cpe`, `edk2.cpe-omissions.log` is written beside the SBOM.

---

### Scenario 2 — Local EDK2 checkout: generate source SBOM

```bash
python edk2_json_generator.py -l <path> -n <name> [--uswid-data <path>]
```

| Flag | Description |
|------|-------------|
| `-l`, `--location` | Path to local EDK2 source tree (submodules initialized) |
| `-n`, `--jsonname` | Output CDX filename (without extension) |
| `--uswid-data` | *(Optional)* Override path to [uswid-data](https://github.com/hughsie/uswid-data.git); auto-cloned if omitted |
| `--sbom-type` | *(Optional)* `source` \| `build` \| `binary` (default: `source`) |

**Example:**
```bash
python edk2_json_generator.py -l /path/to/edk2 -n edk2
```

**Output:** `<name>.cdx.json` in cwd, optional `<name>.cpe-omissions.log`, and
`edk2_json_generator_<timestamp>.log`

---

### Scenario 3 — CVE scan (VEX4EDK2)

Run in the VEX4EDK2 repo after installing it and setting `PYTHONPATH` to SBOM4EDK2 if needed for batch:

```bash
python scripts/get_cve_response.py edk2.cdx.json
```

## Testing

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -p "test_*.py" -v
```

Details: [docs/testing.md](docs/testing.md).

## Notes

- Full EDK2 checkouts are slow and network-heavy (recursive submodules).
- Source SBOM generation is fast (no per-`.inf` scan); CVE timing is documented in VEX4EDK2.
- Scenario 1–2 scripts produce log files for troubleshooting.

## License

[BSD-2-Clause](LICENSE)
