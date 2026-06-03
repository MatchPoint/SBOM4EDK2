"""Tests for NVD CPE dictionary validation."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sbom4edk2.nvd_cpe import (
    candidate_cpes,
    clear_cpe_omission_log,
    cpe_omission_log_path,
    cpe_in_nvd_dictionary,
    cpe_omissions,
    expand_vendor_product,
    form_application_cpe,
    first_valid_cpe,
    record_cpe_omission,
    reset_validation_cache,
    write_cpe_omission_log,
)
from sbom4edk2.submodule_data import SUBMODULE_CPE_MAP


class TestNvdCpeHelpers(unittest.TestCase):
    def setUp(self) -> None:
        reset_validation_cache()

    def test_form_application_cpe(self) -> None:
        self.assertEqual(
            form_application_cpe("arm", "mbed_tls", "3.6.5"),
            "cpe:2.3:a:arm:mbed_tls:3.6.5:*:*:*:*:*:*:*",
        )

    def test_expand_wildcard_vendor_mbed_tls(self) -> None:
        pairs = expand_vendor_product("*", "mbed_tls")
        self.assertEqual(pairs[0], ("arm", "mbed_tls"))
        self.assertIn(("mbed", "mbed_tls"), pairs)

    def test_candidate_cpes_skips_invalid_version(self) -> None:
        self.assertEqual(candidate_cpes("google", "brotli", "0.0.0"), [])

    def test_seven_component_slugs_in_map(self) -> None:
        for slug in (
            "google/boringssl",
            "tianocore/edk2-cmocka",
            "mbed-tls/mbedtls-framework",
            "tlsfuzzer/python-ecdsa",
            "tlsfuzzer/tlslite-ng",
        ):
            self.assertIn(slug, SUBMODULE_CPE_MAP)

    def test_cpe_map_entry_count(self) -> None:
        self.assertEqual(len(SUBMODULE_CPE_MAP), 11)

    def test_allowlist_accepts_known_entry(self) -> None:
        cpe = "cpe:2.3:a:arm:mbed_tls:3.6.5:*:*:*:*:*:*:*"
        self.assertTrue(
            cpe_in_nvd_dictionary(cpe, skip_network=True),
        )

    def test_unknown_not_in_allowlist_without_network(self) -> None:
        cpe = "cpe:2.3:a:google:boringssl:20210429:*:*:*:*:*:*:*"
        with patch.dict("os.environ", {"SBOM4EDK2_SKIP_NVD_CPE_VALIDATE": "1"}, clear=False):
            reset_validation_cache()
            self.assertFalse(cpe_in_nvd_dictionary(cpe))

    def test_first_valid_cpe_from_mocked_api(self) -> None:
        good = "cpe:2.3:a:arm:mbed_tls:3.6.5:*:*:*:*:*:*:*"
        bad = "cpe:2.3:a:google:boringssl:20210429:*:*:*:*:*:*:*"

        def fake_validate(cpe_name: str, *, skip_network: bool = False) -> bool:
            return cpe_name == good

        with patch("sbom4edk2.nvd_cpe.cpe_in_nvd_dictionary", side_effect=fake_validate):
            got = first_valid_cpe([bad, good])
        self.assertEqual(got, good)


class TestApplyNvdCpeValidation(unittest.TestCase):
    def setUp(self) -> None:
        reset_validation_cache()

    def test_strips_template_cpe_when_not_in_dictionary(self) -> None:
        from sbom4edk2.cdx_merge import _apply_nvd_cpe

        clear_cpe_omission_log()
        comp = {
            "name": "cmocka",
            "cpe": "cpe:2.3:a:cmocka:cmocka:1.1.7:*:*:*:*:*:*:*",
        }
        with patch.dict("os.environ", {"SBOM4EDK2_SKIP_NVD_CPE_VALIDATE": "1"}, clear=False):
            reset_validation_cache()
            _apply_nvd_cpe(comp, "1.1.7", "https://gitlab.com/cmocka/cmocka.git")
        self.assertNotIn("cpe", comp)
        self.assertEqual(len(cpe_omissions()), 1)
        self.assertEqual(
            cpe_omissions()[0].reason,
            "nvd_validation_disabled_not_in_allowlist",
        )
        self.assertEqual(
            cpe_omissions()[0].template_cpe,
            "cpe:2.3:a:cmocka:cmocka:1.1.7:*:*:*:*:*:*:*",
        )

    def test_keeps_cpe_when_allowlisted(self) -> None:
        from sbom4edk2.cdx_merge import _apply_nvd_cpe

        comp: dict = {}
        with patch(
            "sbom4edk2.cdx_merge.first_valid_cpe",
            return_value="cpe:2.3:a:arm:mbed_tls:3.6.5:*:*:*:*:*:*:*",
        ):
            _apply_nvd_cpe(
                comp,
                "3.6.5",
                "https://github.com/ARMmbed/mbedtls",
            )
        self.assertEqual(
            comp["cpe"],
            "cpe:2.3:a:arm:mbed_tls:3.6.5:*:*:*:*:*:*:*",
        )

    def test_boringssl_map_drops_non_dictionary_snapshot(self) -> None:
        from sbom4edk2.cdx_merge import _apply_nvd_cpe

        clear_cpe_omission_log()
        comp: dict = {"name": "boringssl"}
        with patch("sbom4edk2.cdx_merge.first_valid_cpe", return_value=None):
            _apply_nvd_cpe(
                comp,
                "20210429",
                "https://github.com/google/boringssl",
            )
        self.assertNotIn("cpe", comp)
        omissions = cpe_omissions()
        self.assertEqual(len(omissions), 1)
        self.assertEqual(omissions[0].reason, "not_in_nvd_dictionary")
        self.assertIn("google/boringssl", omissions[0].github_slug)

    def test_invalid_version_records_omission(self) -> None:
        from sbom4edk2.cdx_merge import _apply_nvd_cpe

        clear_cpe_omission_log()
        comp = {"name": "subhook", "cpe": "cpe:2.3:a:example:subhook:0.0.0:*:*:*:*:*:*:*"}
        _apply_nvd_cpe(comp, "0.0.0", "https://github.com/tianocore/edk2-subhook")
        self.assertNotIn("cpe", comp)
        self.assertEqual(cpe_omissions()[0].reason, "version_not_suitable_for_cpe")


class TestCpeOmissionReasons(unittest.TestCase):
    """Each documented omission reason is produced by _apply_nvd_cpe."""

    def setUp(self) -> None:
        reset_validation_cache()

    def test_no_map_no_template_on_github_slug(self) -> None:
        from sbom4edk2.cdx_merge import _apply_nvd_cpe

        clear_cpe_omission_log()
        _apply_nvd_cpe(
            {"name": "fuzz-corpora"},
            "0.0.0",
            "https://github.com/openssl/fuzz-corpora",
        )
        self.assertEqual(cpe_omissions()[0].reason, "version_not_suitable_for_cpe")

    def test_no_map_entry_without_template(self) -> None:
        from sbom4edk2.cdx_merge import _apply_nvd_cpe

        clear_cpe_omission_log()
        with patch("sbom4edk2.cdx_merge.first_valid_cpe", return_value=None):
            _apply_nvd_cpe(
                {"name": "fuzz-corpora"},
                "1.2.3",
                "https://github.com/openssl/fuzz-corpora",
            )
        self.assertEqual(
            cpe_omissions()[0].reason,
            "no_cpe_map_entry_and_no_template_cpe",
        )

    def test_no_github_slug_non_github_vcs(self) -> None:
        from sbom4edk2.cdx_merge import _apply_nvd_cpe

        clear_cpe_omission_log()
        _apply_nvd_cpe(
            {"name": "cmocka"},
            "1.1.7",
            "https://gitlab.com/cmocka/cmocka.git",
        )
        self.assertEqual(
            cpe_omissions()[0].reason,
            "no_github_slug_and_no_template_cpe",
        )


class TestCpeOmissionLogFile(unittest.TestCase):
    def setUp(self) -> None:
        reset_validation_cache()

    def test_log_path_derived_from_sbom_name(self) -> None:
        got = Path(cpe_omission_log_path("/out/edk2-stable202602.cdx.json"))
        self.assertEqual(got.name, "edk2-stable202602.cpe-omissions.log")
        self.assertEqual(got.parent.name, "out")

    def test_write_log_file_on_omissions(self) -> None:
        import tempfile

        clear_cpe_omission_log()
        record_cpe_omission(
            component="cmocka",
            reason="not_in_nvd_dictionary",
            clean_version="1.1.5",
            candidates=["cpe:2.3:a:cmocka:cmocka:1.1.5:*:*:*:*:*:*:*"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            sbom = os.path.join(tmp, "test.cdx.json")
            open(sbom, "w", encoding="utf-8").close()
            log_path = write_cpe_omission_log(sbom)
            self.assertEqual(log_path, os.path.join(tmp, "test.cpe-omissions.log"))
            text = Path(log_path).read_text(encoding="utf-8")
            self.assertIn("reason=not_in_nvd_dictionary", text)
            self.assertIn("component=cmocka", text)

    def test_write_omission_log_returns_none_when_empty(self) -> None:
        clear_cpe_omission_log()
        with tempfile.TemporaryDirectory() as tmp:
            sbom = os.path.join(tmp, "clean.cdx.json")
            Path(sbom).write_text("{}", encoding="utf-8")
            self.assertIsNone(write_cpe_omission_log(sbom))

    def test_build_source_sbom_clears_omission_log(self) -> None:
        from sbom4edk2.cdx_merge import build_source_sbom

        record_cpe_omission(component="stale", reason="not_in_nvd_dictionary")
        with patch(
            "sbom4edk2.cdx_merge.describe_edk2_version",
            return_value=("edk2-stable202602", "202602", "202602"),
        ):
            build_source_sbom(tempfile.mkdtemp())
        self.assertEqual(len(cpe_omissions()), 0)

    def test_write_source_sbom_emits_omission_log(self) -> None:
        import json
        import os
        import tempfile

        from sbom4edk2.cdx_merge import build_source_sbom, write_source_sbom
        from sbom4edk2.version_normalize import SubmoduleVcs

        with tempfile.TemporaryDirectory() as edk2, tempfile.TemporaryDirectory() as data:
            sub = os.path.join(edk2, "boringssl")
            os.makedirs(sub)
            with open(os.path.join(edk2, ".gitmodules"), "w", encoding="utf-8") as fh:
                fh.write(
                    '[submodule "boringssl"]\n'
                    "\tpath = boringssl\n"
                    "\turl = https://github.com/google/boringssl\n"
                )
            with open(os.path.join(data, "edk2.cdx.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "components": [
                            {
                                "type": "firmware",
                                "bom-ref": "cpe:2.3:a:tianocore:edk2:202602:*:*:*:*:*:*:*",
                                "name": "EDK II",
                                "version": "202602",
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(data, "out.cdx.json")
            with patch(
                "sbom4edk2.cdx_merge.describe_edk2_version",
                return_value=("edk2-stable202602", "202602", "202602"),
            ), patch(
                "sbom4edk2.cdx_merge.resolve_submodule_vcs",
                return_value=SubmoduleVcs(
                    "20210429",
                    "20210429",
                    "20210429",
                    None,
                    0,
                    None,
                    "20210429",
                ),
            ), patch("sbom4edk2.cdx_merge.first_valid_cpe", return_value=None):
                self.assertEqual(
                    write_source_sbom(edk2, out, uswid_data_dir=data),
                    0,
                )
            log_path = os.path.join(data, "out.cpe-omissions.log")
            self.assertTrue(os.path.isfile(log_path))
            self.assertIn("boringssl", Path(log_path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
