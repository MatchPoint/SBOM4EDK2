"""Unit tests for SBOM4EDK2 modules.

Covers pure-logic functions and I/O-bound functions using mocks/tempfiles so
that no network access, NVD API key, or external binaries are required.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Path setup — SBOM4EDK2 root must be importable.
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ---------------------------------------------------------------------------
# sbom4edk2.cpe
# ---------------------------------------------------------------------------

from sbom4edk2.cpe import (
    _has_invalid_name,
    _has_invalid_version,
    _has_open_source_license,
    _normalise_name,
    _normalise_version,
    build_cpe_pattern,
    extract_cve_details,
    is_valid_component,
)


class TestCpe(unittest.TestCase):
    """Tests for sbom4edk2.cpe — all pure functions, no I/O."""

    # --- build_cpe_pattern --------------------------------------------------

    def test_explicit_cpe_returned_verbatim(self):
        """When the SBOM component already carries a cpe field, use it as-is."""
        comp = {
            "name": "mbed_tls",
            "version": "3.6.6",
            "cpe": "cpe:2.3:a:*:mbed_tls:3.6.6:*:*:*:*:*:*:*",
        }
        self.assertEqual(build_cpe_pattern(comp), "cpe:2.3:a:*:mbed_tls:3.6.6:*:*:*:*:*:*:*")

    def test_explicit_cpe_overrides_name_version(self):
        """Explicit CPE wins even when name/version would construct a different pattern."""
        comp = {
            "name": "SomeLib",
            "version": "1.2.3",
            "cpe": "cpe:2.3:a:vendor:somelib:1.2.3:*:*:*:*:*:*:*",
        }
        self.assertEqual(build_cpe_pattern(comp), "cpe:2.3:a:vendor:somelib:1.2.3:*:*:*:*:*:*:*")

    def test_fallback_constructs_wildcard_pattern(self):
        """Without an explicit cpe, a wildcard vendor pattern is built."""
        comp = {"name": "zlib", "version": "1.3.1"}
        result = build_cpe_pattern(comp)
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("cpe:2.3:a:*:zlib:1.3.1:"))

    def test_fallback_none_when_version_not_available(self):
        """A component with no extractable name/version yields None."""
        comp = {"name": "", "version": "1.0"}
        self.assertIsNone(build_cpe_pattern(comp))

    def test_fallback_edk2_plain_version_yields_none(self):
        """edk2 with a non-hyphenated version is excluded (NVD uses YYYYMM format)."""
        comp = {"name": "edk2", "version": "stable202411"}
        self.assertIsNone(build_cpe_pattern(comp))

    def test_fallback_dtc_normalised(self):
        """'dtc' in name is normalised to 'dtc_project'."""
        comp = {"name": "dtc", "version": "1.6.1"}
        result = build_cpe_pattern(comp)
        self.assertIn("dtc_project", result)

    def test_fallback_mbedtls_alias(self):
        """'mbedtls' is aliased to 'arm' in the fallback path."""
        comp = {"name": "mbedtls", "version": "3.6.0"}
        result = build_cpe_pattern(comp)
        self.assertIn("arm", result)

    # --- is_valid_component -------------------------------------------------

    def test_valid_component_passes(self):
        comp = {"name": "openssl", "version": "3.0.9"}
        self.assertTrue(is_valid_component(comp))

    def test_missing_name_is_invalid(self):
        self.assertFalse(is_valid_component({"name": "", "version": "1.0"}))

    def test_missing_version_is_invalid(self):
        self.assertFalse(is_valid_component({"name": "openssl", "version": ""}))

    def test_name_too_long_is_invalid(self):
        comp = {"name": "x" * 61, "version": "1.0"}
        self.assertFalse(is_valid_component(comp))

    def test_invalid_name_chars(self):
        for bad in ["foo/bar", "foo(bar)", "foo,bar"]:
            with self.subTest(name=bad):
                self.assertFalse(is_valid_component({"name": bad, "version": "1.0"}))

    def test_not_provided_version_is_invalid(self):
        comp = {"name": "openssl", "version": "Not provided"}
        self.assertFalse(is_valid_component(comp))

    def test_proprietary_name_is_invalid(self):
        comp = {"name": "Proprietary UEFI", "version": "1.0"}
        self.assertFalse(is_valid_component(comp))

    def test_component_without_license_id_is_invalid(self):
        """A component whose only license entry has no SPDX id is filtered out."""
        comp = {
            "name": "SomeLib",
            "version": "2.0",
            "licenses": [{"license": {"name": "Custom"}}],
        }
        self.assertFalse(is_valid_component(comp))

    def test_zlib_always_valid_despite_license_name(self):
        """zlib is whitelisted even when only a license name (not id) is present."""
        comp = {
            "name": "zlib",
            "version": "1.3",
            "licenses": [{"license": {"name": "Zlib"}}],
        }
        self.assertTrue(is_valid_component(comp))

    # --- _normalise_name / _normalise_version -------------------------------

    def test_normalise_name_lowercases(self):
        self.assertEqual(_normalise_name("OpenSSL"), "openssl")

    def test_normalise_name_strips_dots(self):
        self.assertEqual(_normalise_name("foo.bar"), "foo")

    def test_normalise_name_strips_hyphens(self):
        self.assertEqual(_normalise_name("foo-bar"), "foo")

    def test_normalise_version_strips_prefix(self):
        """Version strings like 'edk2-stable202411' lose the prefix and 'stable' → '202411'."""
        self.assertEqual(_normalise_version("edk2-stable202411"), "202411")

    def test_normalise_version_strips_stable(self):
        self.assertEqual(_normalise_version("stable202411"), "202411")

    def test_normalise_version_passthrough(self):
        self.assertEqual(_normalise_version("3.5.1"), "3.5.1")

    # --- extract_cve_details ------------------------------------------------

    def test_extract_cve_details_basic(self):
        comp = {"name": "openssl", "version": "3.0.9"}
        cpe = "cpe:2.3:a:openssl:openssl:3.0.9:*:*:*:*:*:*:*"
        cve_row = {
            "id": "CVE-2024-1234",
            "published": "2024-01-15",
            "descriptions": [{"lang": "en", "value": "A serious bug."}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"version": "3.1", "baseScore": 9.8, "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
                ]
            },
        }
        result = extract_cve_details(comp, cpe, cve_row)
        self.assertEqual(result["id"], "CVE-2024-1234")
        self.assertEqual(result["name"], "openssl")
        self.assertEqual(result["version"], "3.0.9")
        self.assertEqual(result["cpe_pattern"], cpe)
        self.assertEqual(result["score"], 9.8)
        self.assertEqual(result["descriptions"], "A serious bug.")

    def test_extract_cve_details_no_metrics(self):
        comp = {"name": "zlib", "version": "1.2.11"}
        cve_row = {"id": "CVE-2023-9999", "published": "2023-05-01"}
        result = extract_cve_details(comp, "cpe:2.3:a:*:zlib:1.2.11:*:*:*:*:*:*:*", cve_row)
        self.assertNotIn("score", result)


# ---------------------------------------------------------------------------
# sbom4edk2.sbom
# ---------------------------------------------------------------------------

from sbom4edk2.sbom import _extract_components, parse_sbom, sanitize_cdx_file


class TestSbomParsing(unittest.TestCase):
    """Tests for sbom4edk2.sbom — uses tempfiles for I/O."""

    def _write_cdx(self, data: dict) -> str:
        """Write *data* as JSON to a temp file and return the path."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cdx.json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(data, f)
            return f.name

    def tearDown(self):
        pass  # temp files cleaned up per-test via os.unlink in tests that care

    # --- parse_sbom ---------------------------------------------------------

    def test_parse_sbom_returns_components(self):
        data = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "openssl", "version": "3.0.9"},
                {"name": "zlib", "version": "1.3.1"},
            ],
        }
        path = self._write_cdx(data)
        try:
            result = parse_sbom(path)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["name"], "openssl")
        finally:
            os.unlink(path)

    def test_parse_sbom_file_not_found(self):
        result = parse_sbom("/nonexistent/path/to/sbom.cdx.json")
        self.assertEqual(result, [])

    def test_parse_sbom_invalid_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cdx.json", delete=False, encoding="utf-8"
        ) as f:
            f.write("{not valid json")
            path = f.name
        try:
            result = parse_sbom(path)
            self.assertEqual(result, [])
        finally:
            os.unlink(path)

    def test_parse_sbom_empty_components(self):
        data = {"bomFormat": "CycloneDX", "components": []}
        path = self._write_cdx(data)
        try:
            result = parse_sbom(path)
            self.assertEqual(result, [])
        finally:
            os.unlink(path)

    # --- _extract_components ------------------------------------------------

    def test_extract_from_top_level_components_key(self):
        data = {"components": [{"name": "a"}, {"name": "b"}]}
        self.assertEqual(len(_extract_components(data)), 2)

    def test_extract_from_metadata_component(self):
        data = {
            "metadata": {
                "component": {
                    "components": [{"name": "x"}]
                }
            }
        }
        self.assertEqual(len(_extract_components(data)), 1)

    def test_extract_non_dict_returns_empty(self):
        self.assertEqual(_extract_components([]), [])

    def test_extract_no_components_key(self):
        self.assertEqual(_extract_components({"bomFormat": "CycloneDX"}), [])

    # --- sanitize_cdx_file --------------------------------------------------

    def test_sanitize_fixes_null_source_dir(self):
        data = {
            "components": [
                {"name": "foo", "source-dir": None},
                {"name": "bar", "source-dir": "/valid/path"},
            ]
        }
        path = self._write_cdx(data)
        try:
            result = sanitize_cdx_file(path)
            self.assertTrue(result)
            with open(path, encoding="utf-8") as f:
                fixed = json.load(f)
            self.assertEqual(fixed["components"][0]["source-dir"], "")
            self.assertEqual(fixed["components"][1]["source-dir"], "/valid/path")
        finally:
            os.unlink(path)

    def test_sanitize_no_change_needed(self):
        data = {"components": [{"name": "foo"}]}
        path = self._write_cdx(data)
        try:
            result = sanitize_cdx_file(path)
            self.assertTrue(result)
        finally:
            os.unlink(path)

    def test_sanitize_missing_file(self):
        result = sanitize_cdx_file("/nonexistent/file.cdx.json")
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# sbom4edk2.ghsa
# ---------------------------------------------------------------------------

from sbom4edk2.ghsa import _extract_edk2_version, _version_in_range, scan_sbom_with_ghsa


class TestGhsa(unittest.TestCase):
    """Tests for sbom4edk2.ghsa — pure logic + mocked network/I/O."""

    # --- _extract_edk2_version ----------------------------------------------

    def test_extract_from_cpe_version(self):
        self.assertEqual(_extract_edk2_version("202602"), 202602)

    def test_extract_from_full_cpe_string(self):
        self.assertEqual(
            _extract_edk2_version("cpe:2.3:a:tianocore:edk2:202602:*:*:*:*:*:*:*"),
            202602,
        )

    def test_extract_from_git_describe(self):
        self.assertEqual(
            _extract_edk2_version("edk2-stable202602+444.gb03a21a63e"),
            202602,
        )

    def test_extract_none_when_not_present(self):
        self.assertIsNone(_extract_edk2_version("v1.2.3"))

    def test_extract_none_from_empty(self):
        self.assertIsNone(_extract_edk2_version(""))

    def test_extract_none_from_none(self):
        self.assertIsNone(_extract_edk2_version(None))

    # --- _version_in_range --------------------------------------------------

    def test_less_than_or_equal_affected(self):
        self.assertTrue(_version_in_range(202411, "<=202412"))

    def test_less_than_or_equal_unaffected(self):
        self.assertFalse(_version_in_range(202602, "<=202508"))

    def test_strict_less_than_boundary(self):
        self.assertFalse(_version_in_range(202602, "<202602"))

    def test_strict_less_than_inside(self):
        self.assertTrue(_version_in_range(202601, "<202602"))

    def test_greater_than_or_equal(self):
        self.assertTrue(_version_in_range(202602, ">=202311"))
        self.assertFalse(_version_in_range(202310, ">=202311"))

    def test_compound_constraint_in_range(self):
        self.assertTrue(_version_in_range(202312, ">=202311, <202402"))

    def test_compound_constraint_out_of_range(self):
        self.assertFalse(_version_in_range(202410, ">=202311, <202402"))

    def test_empty_range_always_true(self):
        self.assertTrue(_version_in_range(202602, ""))
        self.assertTrue(_version_in_range(202602, None))

    def test_unparseable_range_conservatively_true(self):
        self.assertTrue(_version_in_range(202602, "some garbage"))

    # --- scan_sbom_with_ghsa (mocked) ---------------------------------------

    def _make_sbom_file(self, version: str = "202602") -> str:
        data = {
            "metadata": {
                "component": {
                    "name": "EDK II",
                    "version": f"edk2-stable{version}",
                    "cpe": f"cpe:2.3:a:tianocore:edk2:{version}:*:*:*:*:*:*:*",
                }
            },
            "components": [],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cdx.json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(data, f)
            return f.name

    def test_scan_returns_empty_when_no_applicable_advisories(self):
        """No advisories match EDK2 202602 in this mock dataset."""
        advisories = [
            {
                "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
                "cve_id": "CVE-2024-0001",
                "severity": "high",
                "summary": "A test advisory",
                "published_at": "2024-01-15T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-xxxx",
                "cvss_severities": {},
                "identifiers": [],
                "vulnerabilities": [
                    {
                        "package": {"name": "edk2"},
                        "vulnerable_version_range": "<=202508",
                        "patched_versions": "202602",
                    }
                ],
            }
        ]
        path = self._make_sbom_file("202602")
        try:
            with patch("sbom4edk2.ghsa._fetch_advisories", return_value=advisories):
                with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as xf:
                    xlsx_path = xf.name
                try:
                    df = scan_sbom_with_ghsa(path, output_xlsx=xlsx_path)
                    # 202602 > 202508, so <=202508 does NOT match → empty result
                    self.assertIsNotNone(df)
                    self.assertTrue(df.empty)
                finally:
                    os.unlink(xlsx_path)
        finally:
            os.unlink(path)

    def test_scan_returns_rows_when_version_is_affected(self):
        """Advisory with <=202602 DOES match EDK2 202601."""
        advisories = [
            {
                "ghsa_id": "GHSA-yyyy-yyyy-yyyy",
                "cve_id": "CVE-2025-9999",
                "severity": "critical",
                "summary": "Critical RCE in DXE phase",
                "published_at": "2025-01-10T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-yyyy",
                "cvss_severities": {"cvss_v3": {"score": 9.8, "vector_string": "AV:N"}},
                "identifiers": [],
                "vulnerabilities": [
                    {
                        "package": {"name": "edk2"},
                        "vulnerable_version_range": "<=202602",
                        "patched_versions": "",
                    }
                ],
            }
        ]
        path = self._make_sbom_file("202601")
        try:
            with patch("sbom4edk2.ghsa._fetch_advisories", return_value=advisories):
                with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as xf:
                    xlsx_path = xf.name
                try:
                    df = scan_sbom_with_ghsa(path, output_xlsx=xlsx_path)
                    self.assertIsNotNone(df)
                    self.assertEqual(len(df), 1)
                    self.assertEqual(df.iloc[0]["id"], "CVE-2025-9999")
                    self.assertEqual(df.iloc[0]["score"], 9.8)
                finally:
                    os.unlink(xlsx_path)
        finally:
            os.unlink(path)

    def test_scan_skips_ignore_advisories(self):
        """Advisories marked ***IGNORE*** are skipped."""
        advisories = [
            {
                "ghsa_id": "GHSA-5xcf-j538-p769",
                "cve_id": None,
                "severity": "none",
                "summary": "***IGNORE*** test entry",
                "published_at": "2020-01-01T00:00:00Z",
                "html_url": "",
                "cvss_severities": {},
                "identifiers": [],
                "vulnerabilities": [],
            }
        ]
        path = self._make_sbom_file()
        try:
            with patch("sbom4edk2.ghsa._fetch_advisories", return_value=advisories):
                with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as xf:
                    xlsx_path = xf.name
                try:
                    df = scan_sbom_with_ghsa(path, output_xlsx=xlsx_path)
                    self.assertIsNotNone(df)
                    self.assertTrue(df.empty)
                finally:
                    os.unlink(xlsx_path)
        finally:
            os.unlink(path)

    def test_scan_returns_none_on_bad_sbom_path(self):
        df = scan_sbom_with_ghsa("/nonexistent/sbom.cdx.json")
        self.assertIsNone(df)

    def test_scan_returns_empty_df_when_api_returns_nothing(self):
        path = self._make_sbom_file()
        try:
            with patch("sbom4edk2.ghsa._fetch_advisories", return_value=[]):
                with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as xf:
                    xlsx_path = xf.name
                try:
                    df = scan_sbom_with_ghsa(path, output_xlsx=xlsx_path)
                    self.assertIsNotNone(df)
                    self.assertTrue(df.empty)
                finally:
                    os.unlink(xlsx_path)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# sbom4edk2.grype
# ---------------------------------------------------------------------------

from sbom4edk2.grype import _find_grype, is_grype_available, scan_sbom_with_grype


class TestGrype(unittest.TestCase):
    """Tests for sbom4edk2.grype — binary discovery and output parsing."""

    def test_is_grype_available_when_on_path(self):
        with patch("sbom4edk2.grype.shutil.which", return_value="/usr/bin/grype"):
            self.assertTrue(is_grype_available())

    def test_is_grype_available_not_found(self):
        with patch("sbom4edk2.grype.shutil.which", return_value=None):
            with patch("sbom4edk2.grype._EXTRA_SEARCH_PATHS", []):
                self.assertFalse(is_grype_available())

    def test_find_grype_returns_path_binary(self):
        with patch("sbom4edk2.grype.shutil.which", return_value="/usr/local/bin/grype"):
            self.assertEqual(_find_grype(), "/usr/local/bin/grype")

    def test_scan_returns_none_when_grype_missing(self):
        with patch("sbom4edk2.grype._find_grype", return_value=None):
            result = scan_sbom_with_grype("dummy.cdx.json")
            self.assertIsNone(result)

    def test_scan_parses_grype_json_output(self):
        """Verify that the grype JSON match format is correctly mapped to a DataFrame."""
        grype_output = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-5678",
                        "severity": "High",
                        "description": "Buffer overflow in libfoo",
                        "publishedDate": "2024-06-01",
                        "cvss": [
                            {
                                "version": "3.1",
                                "metrics": {"baseScore": 8.8},
                                "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                            }
                        ],
                        "fix": {"versions": ["2.1.0"], "state": "fixed"},
                        "epss": [{"epss": 0.042, "percentile": 0.89}],
                        "namespace": "nvd:cpe",
                    },
                    "artifact": {
                        "name": "libfoo",
                        "version": "2.0.0",
                        "cpes": ["cpe:2.3:a:*:libfoo:2.0.0:*:*:*:*:*:*:*"],
                        "purl": "pkg:generic/libfoo@2.0.0",
                    },
                }
            ]
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cdx.json", delete=False, encoding="utf-8"
        ) as sbom_f:
            json.dump({"components": []}, sbom_f)
            sbom_path = sbom_f.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as out_f:
            json.dump(grype_output, out_f)
            grype_json_path = out_f.name

        try:
            mock_proc = MagicMock()
            mock_proc.returncode = 1  # grype exits 1 when vulns found
            mock_proc.stderr = ""

            def _fake_run(cmd, **kwargs):
                # Copy the pre-written grype JSON to the path grype would have written
                tmp_path = cmd[cmd.index("--file") + 1]
                import shutil
                shutil.copy(grype_json_path, tmp_path)
                return mock_proc

            with patch("sbom4edk2.grype._find_grype", return_value="/usr/bin/grype"):
                with patch("sbom4edk2.grype.subprocess.run", side_effect=_fake_run):
                    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as xf:
                        xlsx_path = xf.name
                    try:
                        df = scan_sbom_with_grype(sbom_path, output_xlsx=xlsx_path)
                        self.assertIsNotNone(df)
                        self.assertEqual(len(df), 1)
                        self.assertEqual(df.iloc[0]["id"], "CVE-2024-5678")
                        self.assertEqual(df.iloc[0]["name"], "libfoo")
                        self.assertAlmostEqual(df.iloc[0]["score"], 8.8)
                        self.assertEqual(df.iloc[0]["fix_versions"], "2.1.0")
                        self.assertAlmostEqual(df.iloc[0]["epss_score"], 0.042)
                    finally:
                        os.unlink(xlsx_path)
        finally:
            os.unlink(sbom_path)
            os.unlink(grype_json_path)

    def test_scan_returns_empty_df_when_no_matches(self):
        grype_output = {"matches": []}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cdx.json", delete=False, encoding="utf-8"
        ) as sbom_f:
            json.dump({"components": []}, sbom_f)
            sbom_path = sbom_f.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as out_f:
            json.dump(grype_output, out_f)
            grype_json_path = out_f.name

        try:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stderr = ""

            def _fake_run(cmd, **kwargs):
                tmp_path = cmd[cmd.index("--file") + 1]
                import shutil
                shutil.copy(grype_json_path, tmp_path)
                return mock_proc

            with patch("sbom4edk2.grype._find_grype", return_value="/usr/bin/grype"):
                with patch("sbom4edk2.grype.subprocess.run", side_effect=_fake_run):
                    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as xf:
                        xlsx_path = xf.name
                    try:
                        df = scan_sbom_with_grype(sbom_path, output_xlsx=xlsx_path)
                        self.assertIsNotNone(df)
                        self.assertTrue(df.empty)
                    finally:
                        os.unlink(xlsx_path)
        finally:
            os.unlink(sbom_path)
            os.unlink(grype_json_path)


# ---------------------------------------------------------------------------
# sbom4edk2.cve_analyzer (pure helpers)
# ---------------------------------------------------------------------------

from sbom4edk2.cve_analyzer import _analyse_component


class TestCveAnalyzer(unittest.TestCase):
    """Tests for sbom4edk2.cve_analyzer helper functions."""

    def _make_mock_client(self, cves: list[dict] | None = None):
        """Return a mock NvdClient that yields *cves* for any CPE."""
        import pandas as pd

        client = MagicMock()
        if cves:
            df = pd.DataFrame(cves)
            client.search_cves_for_cpe.return_value = (df, "ok", None)
        else:
            client.search_cves_for_cpe.return_value = (pd.DataFrame(), "ok", None)
        return client

    def test_invalid_component_skipped(self):
        """is_valid_component=False → no NVD call, empty results."""
        client = self._make_mock_client()
        comp = {"name": "Proprietary UEFI", "version": "1.0"}
        details, invalids = _analyse_component(client, comp, 0, 1)
        client.search_cves_for_cpe.assert_not_called()
        self.assertEqual(details, [])

    def test_valid_component_no_cves(self):
        client = self._make_mock_client(cves=None)
        comp = {"name": "openssl", "version": "3.0.9"}
        details, invalids = _analyse_component(client, comp, 0, 1)
        self.assertEqual(details, [])
        self.assertEqual(invalids, [])

    def test_valid_component_with_cves(self):
        import pandas as pd

        cve_data = [
            {
                "id": "CVE-2024-0001",
                "published": "2024-01-01",
                "descriptions": [{"lang": "en", "value": "Heap overflow."}],
            }
        ]
        client = self._make_mock_client(cves=cve_data)
        comp = {"name": "openssl", "version": "3.0.9"}
        details, invalids = _analyse_component(client, comp, 0, 1)
        self.assertEqual(len(details), 1)
        self.assertEqual(details[0]["id"], "CVE-2024-0001")


if __name__ == "__main__":
    unittest.main()
