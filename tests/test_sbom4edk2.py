"""Unit tests for SBOM4EDK2 SBOM parsing (CVE scanners moved to VEX4EDK2)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sbom4edk2.sbom import _extract_components, parse_sbom, sanitize_cdx_file


class TestSbomParsing(unittest.TestCase):
    """Tests for sbom4edk2.sbom — uses tempfiles for I/O."""

    def _write_cdx(self, data: dict) -> str:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cdx.json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(data, f)
            return f.name

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


if __name__ == "__main__":
    unittest.main()
