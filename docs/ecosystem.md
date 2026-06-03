# Ecosystem positioning

SBOM4EDK2 is one layer in the TianoCore / firmware supply-chain toolchain.

```text
EDK II git checkout + uswid-data templates
        │
        ▼
   SBOM4EDK2  ──►  edk2.cdx.json (source SBOM)
        │
        ▼
   VEX4EDK2  ──►  NVD / Grype / GHSA → CSAF VEX (+ optional Excel)
        │
        ▼
   StreamingVEX (ingest / subscribe / deliver)
```

| Project | Role |
|---------|------|
| **SBOM4EDK2** (this repo) | Native **source** SBOM for EDK II |
| **VEX4EDK2** | CVE scanners (NVD, Grype, GHSA) + quarterly CSAF VEX |
| **[uswid-data](https://github.com/hughsie/uswid-data)** | Curated CycloneDX JSON templates (`edk2.cdx.json`, per-OSS `*.cdx.json`) — **data only** |
| **[python-uswid](https://github.com/hughsie/python-uswid)** | Upstream uSWID library for **build/binary** SBOMs (`.inf`, PE, etc.) — **not** required by SBOM4EDK2 |
| **MatchPoint/python-uswid-sbom** | **Deprecated** — logic migrated into SBOM4EDK2; repo scheduled for deletion |
| **StreamingVEX** | Multi-tenant ingest, catalog, subscriptions, webhook delivery |

## Attribution

Submodule normalization, CPE tables, and pedigree behavior were originally developed
during the python-uswid-sbom fork (HP Development Company, BSD-2-Clause-Patent).
See [`NOTICE`](../NOTICE) in this repository.

Richard Hughes maintains **python-uswid** and **uswid-data**; SBOM4EDK2 does not
bundle or require his Python library for source SBOM generation.
