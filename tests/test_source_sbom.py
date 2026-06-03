"""Tests for native source SBOM modules (no uswid dependency)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sbom4edk2.pedigree import (
    patch_dict_for_commit,
    patches_for_commits_since_ref,
    patches_for_commits_since_tag,
)
from sbom4edk2.submodule_data import (
    SUBMODULE_CPE_MAP,
    canonicalize_vcs_url,
    parse_gitmodules_file,
    resolve_with_aliases,
    walk_gitmodules,
)
from sbom4edk2.version_normalize import (
    SubmoduleVcs,
    format_display_version,
    normalize_submodule_version,
)


class TestNormalizeSubmoduleVersion(unittest.TestCase):
    def test_twelve_patterns(self):
        cases = [
            ("openssl-3.5.1", "3.5.1", 0, False, True),
            ("v3.6.5", "3.6.5", 0, False, True),
            ("v2.13.1", "2.13.1", 0, False, True),
            ("v6.9.10", "6.9.10", 0, False, True),
            ("3.7.0", "3.7.0", 0, False, True),
            ("V184", "184", 0, False, True),
            ("v1.1+edk2", "1.1", 0, False, True),
            ("v1.2.0-1-ge230f47", "1.2.0", 1, True, True),
            ("v1.6.1-3-gcfff805", "1.6.1", 3, True, True),
            ("release-1.11.0-238-g86add134", "1.11.0", 238, True, True),
            ("cmocka-1.1.5-23-g1cc9cde", "1.1.5", 23, True, True),
            ("83d4e1e", "0.0.0", 0, True, False),
        ]
        for raw, exp_ver, exp_patches, exp_sha, exp_tag in cases:
            with self.subTest(raw=raw):
                clean, patches, sha, tag = normalize_submodule_version(raw)
                self.assertEqual(clean, exp_ver)
                self.assertEqual(patches, exp_patches)
                self.assertEqual(sha is not None, exp_sha)
                self.assertEqual(tag is not None, exp_tag)

    def test_format_display_version_with_patches(self):
        self.assertEqual(format_display_version("1.1.5", 23), "1.1.5+23")
        self.assertEqual(
            format_display_version("1.1.5", 23, commit_sha="1cc9cde"),
            "1.1.5+23.g1cc9cde",
        )
        self.assertEqual(format_display_version("3.5.1", 0), "3.5.1")


class TestSupplierData(unittest.TestCase):
    def test_brotli_template_overridden_to_google(self) -> None:
        from sbom4edk2.supplier_data import apply_recognized_supplier

        comp = {"supplier": {"name": "Brotli developers"}}
        apply_recognized_supplier(comp, "https://github.com/google/brotli")
        self.assertEqual(comp["supplier"]["name"], "Google")

    def test_openssl_template_kept(self) -> None:
        from sbom4edk2.supplier_data import apply_recognized_supplier

        comp = {"supplier": {"name": "The OpenSSL Project"}}
        apply_recognized_supplier(comp, "https://github.com/openssl/openssl")
        self.assertEqual(comp["supplier"]["name"], "The OpenSSL Project")

    def test_openssl_generic_developers_becomes_openssl(self) -> None:
        from sbom4edk2.supplier_data import apply_recognized_supplier

        comp = {"supplier": {"name": "openssl developers"}}
        apply_recognized_supplier(comp, "https://github.com/openssl/openssl")
        self.assertEqual(comp["supplier"]["name"], "OpenSSL")

    def test_slug_map_overrides_mbedtls_contributors(self) -> None:
        from sbom4edk2.supplier_data import apply_recognized_supplier

        comp = {"supplier": {"name": "The Mbed TLS Contributors"}}
        apply_recognized_supplier(comp, "https://github.com/ARMmbed/mbedtls")
        self.assertEqual(comp["supplier"]["name"], "Arm")

    def test_berkeley_softfloat_recognized_supplier(self) -> None:
        from sbom4edk2.supplier_data import apply_recognized_supplier

        comp = {"supplier": {"name": "Berkeley SoftFloat developers"}}
        apply_recognized_supplier(
            comp, "https://github.com/ucb-bar/berkeley-softfloat-3"
        )
        self.assertEqual(
            comp["supplier"]["name"],
            "University of California, Berkeley",
        )

class TestSubmoduleData(unittest.TestCase):
    def test_canonicalize_vcs_url(self):
        self.assertEqual(
            canonicalize_vcs_url("https://github.com/Owner/Repo.git/"),
            "https://github.com/owner/repo",
        )

    def test_cpe_map_has_eleven_entries(self):
        self.assertEqual(len(SUBMODULE_CPE_MAP), 11)

    def test_cpe_map_includes_extended_github_slugs(self):
        for slug in (
            "google/boringssl",
            "tianocore/edk2-cmocka",
            "mbed-tls/mbedtls-framework",
            "tlsfuzzer/python-ecdsa",
            "tlsfuzzer/tlslite-ng",
        ):
            with self.subTest(slug=slug):
                self.assertIn(slug, SUBMODULE_CPE_MAP)

    def test_cpe_map_case_insensitive_lookup(self):
        from sbom4edk2.cdx_merge import _cpe_map_entry

        self.assertEqual(_cpe_map_entry("armmbed/mbedtls"), SUBMODULE_CPE_MAP["ARMmbed/mbedtls"])

    def test_parse_gitmodules(self):
        with tempfile.TemporaryDirectory() as tmp:
            gm = os.path.join(tmp, ".gitmodules")
            with open(gm, "w", encoding="utf-8") as fh:
                fh.write(
                    '[submodule "openssl"]\n'
                    "\tpath = CryptoPkg/openssl\n"
                    "\turl = https://github.com/openssl/openssl.git\n"
                )
            parsed = parse_gitmodules_file(gm)
            self.assertIn("openssl", parsed)
            self.assertEqual(parsed["openssl"]["path"], "CryptoPkg/openssl")

    def test_walk_gitmodules_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(walk_gitmodules(tmp), {})

    def test_walk_gitmodules_nested_first_write_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            openssl = os.path.join(tmp, "CryptoPkg", "openssl")
            nested = os.path.join(openssl, "quiche")
            os.makedirs(nested)
            with open(os.path.join(tmp, ".gitmodules"), "w", encoding="utf-8") as fh:
                fh.write(
                    '[submodule "openssl"]\n'
                    "\tpath = CryptoPkg/openssl\n"
                    "\turl = https://github.com/openssl/openssl.git\n"
                )
            with open(os.path.join(openssl, ".gitmodules"), "w", encoding="utf-8") as fh:
                fh.write(
                    '[submodule "quiche"]\n'
                    "\tpath = quiche\n"
                    "\turl = https://github.com/cloudflare/quiche.git\n"
                )
            urls = walk_gitmodules(tmp)
            self.assertIn("https://github.com/openssl/openssl", urls)
            self.assertIn("https://github.com/cloudflare/quiche", urls)
            self.assertTrue(urls["https://github.com/cloudflare/quiche"].endswith("quiche"))

    def test_resolve_with_aliases_mbedtls_rename(self):
        url_to_path = {
            canonicalize_vcs_url("https://github.com/armmbed/mbedtls"): "/edk2/mbedtls",
        }
        found = resolve_with_aliases(
            "https://github.com/Mbed-TLS/mbedtls.git",
            url_to_path,
        )
        self.assertEqual(found, "/edk2/mbedtls")


class TestPedigree(unittest.TestCase):
    def test_patch_dict_security_vs_cherry_pick(self):
        sec = patch_dict_for_commit(
            subject="Fix CVE-2024-9999",
            body_lines=[],
            commit_sha="abc",
            vcs_url="https://github.com/openssl/openssl",
        )
        self.assertEqual(sec["type"], "security")
        resolves = sec["resolves"]
        self.assertIsInstance(resolves, list)
        self.assertEqual(resolves[0]["type"], "security")
        self.assertIn("CVE-2024-9999", resolves[0]["references"])

        cherry = patch_dict_for_commit(
            subject="Minor tweak",
            body_lines=[],
            commit_sha="def",
            vcs_url="https://github.com/openssl/openssl",
            provenance="vendor",
        )
        self.assertEqual(cherry["type"], "cherry-pick")
        self.assertEqual(cherry["resolves"][0]["type"], "defect")
        self.assertIn("[vendor pin]", cherry["resolves"][0]["description"])

        upstream = patch_dict_for_commit(
            subject="Meson build",
            body_lines=[],
            commit_sha="abc",
            vcs_url="https://github.com/tianocore/edk2-cmocka",
            provenance="upstream",
        )
        self.assertIn("[upstream]", upstream["resolves"][0]["description"])

    def test_patches_for_commits_since_tag_mocked(self):
        log = (
            "aaa1111111111111111111111111111111111111111\tFirst after tag\n"
            f"---SBOM4EDK2_COMMIT_END---\n"
            "bbb2222222222222222222222222222222222222222\tFix CVE-2024-1000\n"
            f"---SBOM4EDK2_COMMIT_END---\n"
        )
        with patch("sbom4edk2.pedigree.run_git_optional", return_value=log), patch(
            "sbom4edk2.pedigree.has_git_remote", return_value=False
        ):
            patches = patches_for_commits_since_tag(
                "/fake",
                "v1.0.0",
                "https://github.com/example/repo",
            )
        self.assertEqual(len(patches), 2)
        self.assertEqual(patches[1]["resolves"][0]["type"], "security")

    def test_patches_use_base_commit_and_upstream_labels(self):
        log = (
            "aaa1111111111111111111111111111111111111111\tUpstream fix\n"
            f"---SBOM4EDK2_COMMIT_END---\n"
        )

        def fake_git(args, cwd=None):
            if args and args[0] == "log" and len(args) > 1 and args[1].startswith("f5e2cd77"):
                return log
            return None

        with patch("sbom4edk2.pedigree.run_git_optional", side_effect=fake_git), patch(
            "sbom4edk2.pedigree.commit_contained_in_ref", return_value=True
        ), patch("sbom4edk2.pedigree.has_git_remote", return_value=True):
            patches = patches_for_commits_since_ref(
                "/fake",
                "f5e2cd77c88d9f792562888d2b70c5a396bfbf7a",
                "https://github.com/tianocore/edk2-cmocka",
            )
        self.assertEqual(len(patches), 1)
        self.assertIn("[upstream]", patches[0]["resolves"][0]["description"])


class TestBuildSourceSbom(unittest.TestCase):
    def test_merge_produces_valid_skeleton(self):
        from sbom4edk2.cdx_merge import build_source_sbom

        with tempfile.TemporaryDirectory() as edk2, tempfile.TemporaryDirectory() as data:
            os.makedirs(os.path.join(edk2, ".git"), exist_ok=True)
            with open(os.path.join(edk2, ".gitmodules"), "w", encoding="utf-8") as fh:
                fh.write(
                    '[submodule "oss"]\n'
                    "\tpath = oss\n"
                    "\turl = https://github.com/openssl/openssl\n"
                )
            os.makedirs(os.path.join(edk2, "oss"), exist_ok=True)

            with open(os.path.join(data, "edk2.cdx.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "components": [
                            {
                                "type": "firmware",
                                "bom-ref": "cpe:2.3:a:tianocore:edk2:@VCS_TAG@:*:*:*:*:*:*:*",
                                "name": "EDK II",
                                "version": "@VCS_VERSION@",
                                "cpe": "cpe:2.3:a:tianocore:edk2:@VCS_VERSION@:*:*:*:*:*:*:*",
                            }
                        ]
                    },
                    fh,
                )

            with patch(
                "sbom4edk2.cdx_merge.describe_edk2_version",
                return_value=("edk2-stable202602", "202602", "202602"),
            ), patch(
                "sbom4edk2.cdx_merge.resolve_submodule_vcs",
                return_value=SubmoduleVcs(
                    "3.5.1",
                    "openssl-3.5.1",
                    "openssl-3.5.1",
                    None,
                    0,
                    "f0000001",
                    "3.5.1",
                ),
            ):
                doc = build_source_sbom(edk2, uswid_data_dir=data)

            self.assertEqual(doc["bomFormat"], "CycloneDX")
            primary = doc["metadata"]["component"]
            self.assertEqual(primary["name"], "EDK II")
            self.assertNotIn("@VCS_", json.dumps(doc))
            self.assertGreaterEqual(len(doc["components"]), 1)


class TestEdk2Version(unittest.TestCase):
    def test_describe_edk2_stable_with_distance(self):
        from sbom4edk2.edk2_version import describe_edk2_version

        with patch(
            "sbom4edk2.edk2_version.run_git_optional",
            return_value="edk2-stable202602-196-g0fe6b755f2",
        ):
            label, purl, cpe = describe_edk2_version("/fake/edk2")
        self.assertEqual(label, "edk2-stable202602+196.g0fe6b755f2")
        self.assertEqual(purl, "202602")
        self.assertEqual(cpe, "202602")

    def test_describe_exact_tag(self):
        from sbom4edk2.edk2_version import describe_edk2_version

        with patch(
            "sbom4edk2.edk2_version.run_git_optional",
            return_value="edk2-stable202508",
        ):
            label, purl, cpe = describe_edk2_version("/fake/edk2")
        self.assertEqual(label, "edk2-stable202508")
        self.assertEqual(purl, "202508")


class TestTemplateLoader(unittest.TestCase):
    def test_subst_placeholders_nested(self):
        from sbom4edk2.template_loader import subst_placeholders

        obj = {
            "version": "@VCS_VERSION@",
            "nested": [{"cpe": "cpe:2.3:a:v:@VCS_TAG@:*"}],
        }
        out = subst_placeholders(obj, {"@VCS_VERSION@": "3.5.1", "@VCS_TAG@": "3.5.1"})
        self.assertEqual(out["version"], "3.5.1")
        self.assertIn("3.5.1", out["nested"][0]["cpe"])

    def test_load_edk2_primary_without_data_dir(self):
        from sbom4edk2.template_loader import load_edk2_primary_template

        primary = load_edk2_primary_template(
            "",
            {"@VCS_VERSION@": "202602", "@VCS_TAG@": "edk2-stable202602"},
        )
        self.assertEqual(primary["name"], "EDK II")
        self.assertEqual(primary["version"], "202602")


class TestCdxMergeDetails(unittest.TestCase):
    def test_build_dependencies_nested_containment(self):
        from sbom4edk2.cdx_merge import _build_dependencies

        primary = "cpe:2.3:a:tianocore:edk2:202602:*:*:*:*:*:*:*"
        root = os.path.normpath("/edk2/CryptoPkg/openssl")
        child = os.path.normpath("/edk2/CryptoPkg/openssl/quiche")
        deps = _build_dependencies(
            primary,
            [
                (root, "cpe:2.3:a:openssl:openssl:3.5.1:*:*:*:*:*:*:*"),
                (child, "pkg:github/cloudflare/quiche@1.0.0"),
            ],
        )
        self.assertEqual(len(deps), 2)
        openssl_dep = next(d for d in deps if d["ref"] == primary)
        self.assertIn("cpe:2.3:a:openssl:openssl:3.5.1:*:*:*:*:*:*:*", openssl_dep["dependsOn"])
        quiche_parent = next(
            d for d in deps if d["ref"] == "cpe:2.3:a:openssl:openssl:3.5.1:*:*:*:*:*:*:*"
        )
        self.assertIn("pkg:github/cloudflare/quiche@1.0.0", quiche_parent["dependsOn"])
        for dep in deps:
            self.assertIsInstance(dep["dependsOn"], list)

    def test_orphan_template_with_placeholders_dropped(self):
        from sbom4edk2.cdx_merge import build_source_sbom

        with tempfile.TemporaryDirectory() as edk2, tempfile.TemporaryDirectory() as data:
            with open(os.path.join(edk2, ".gitmodules"), "w", encoding="utf-8") as fh:
                fh.write("")  # no submodules
            with open(os.path.join(data, "orphan.cdx.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "components": [
                            {
                                "name": "GhostLib",
                                "version": "@VCS_VERSION@",
                                "externalReferences": [
                                    {"type": "vcs", "url": "https://github.com/nobody/nolib"}
                                ],
                            }
                        ]
                    },
                    fh,
                )
            with patch(
                "sbom4edk2.cdx_merge.describe_edk2_version",
                return_value=("edk2-stable202602", "202602", "202602"),
            ):
                doc = build_source_sbom(edk2, uswid_data_dir=data)
            names = [c.get("name") for c in doc["components"]]
            self.assertNotIn("GhostLib", names)

    def test_apply_nvd_cpe_on_resolved_template(self):
        from sbom4edk2.cdx_merge import build_source_sbom

        with tempfile.TemporaryDirectory() as edk2, tempfile.TemporaryDirectory() as data:
            sub = os.path.join(edk2, "mbedtls")
            os.makedirs(sub)
            with open(os.path.join(edk2, ".gitmodules"), "w", encoding="utf-8") as fh:
                fh.write(
                    '[submodule "mbedtls"]\n'
                    "\tpath = mbedtls\n"
                    "\turl = https://github.com/ARMmbed/mbedtls\n"
                )
            with open(os.path.join(data, "mbedtls.cdx.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "components": [
                            {
                                "name": "mbed TLS",
                                "bom-ref": "pkg:github/armmbed/mbedtls@@VCS_TAG@",
                                "version": "@VCS_VERSION@",
                                "externalReferences": [
                                    {
                                        "type": "vcs",
                                        "url": "https://github.com/ARMmbed/mbedtls",
                                    }
                                ],
                            }
                        ]
                    },
                    fh,
                )
            with patch(
                "sbom4edk2.cdx_merge.describe_edk2_version",
                return_value=("edk2-stable202602", "202602", "202602"),
            ), patch(
                "sbom4edk2.cdx_merge.resolve_submodule_vcs",
                return_value=SubmoduleVcs(
                    "3.6.5",
                    "v3.6.5",
                    "v3.6.5",
                    None,
                    0,
                    None,
                    "3.6.5",
                ),
            ), patch(
                "sbom4edk2.cdx_merge.first_valid_cpe",
                return_value="cpe:2.3:a:arm:mbed_tls:3.6.5:*:*:*:*:*:*:*",
            ):
                doc = build_source_sbom(edk2, uswid_data_dir=data)
            mbed = next(c for c in doc["components"] if "mbed" in c.get("name", "").lower())
            self.assertIn("cpe", mbed)
            self.assertIn("arm:mbed_tls", mbed["cpe"])
            self.assertEqual(mbed["version"], "3.6.5")

    def test_display_version_and_cpe_split_for_patched_submodule(self):
        from sbom4edk2.cdx_merge import _synthesize_component

        with patch(
            "sbom4edk2.cdx_merge.resolve_submodule_vcs",
            return_value=SubmoduleVcs(
                "3.6.5",
                "v3.6.5-2-gabc1234",
                "v3.6.5",
                "abc1234",
                2,
                "deadbeef",
                "3.6.5+2.gabc1234",
            ),
        ), patch("sbom4edk2.cdx_merge.pedigree_for_submodule_dir", return_value=None), patch(
            "sbom4edk2.cdx_merge.first_valid_cpe",
            return_value="cpe:2.3:a:arm:mbed_tls:3.6.5:*:*:*:*:*:*:*",
        ):
            comp = _synthesize_component(
                "mbedtls",
                "https://github.com/ARMmbed/mbedtls",
                "/fake/mbedtls",
            )
        self.assertEqual(comp["version"], "3.6.5+2.gabc1234")
        self.assertIn("@3.6.5+2", comp["bom-ref"])
        self.assertIn(":3.6.5:", comp["cpe"])
        self.assertNotIn("+2", comp["cpe"])

    def test_sbom_type_sets_lifecycle_phase(self):
        from sbom4edk2.cdx_merge import build_source_sbom

        with tempfile.TemporaryDirectory() as edk2:
            with patch(
                "sbom4edk2.cdx_merge.describe_edk2_version",
                return_value=("edk2-stable202602", "202602", "202602"),
            ):
                doc = build_source_sbom(edk2, sbom_type="build")
            self.assertEqual(doc["metadata"]["lifecycles"][0]["phase"], "build")


class TestGenerateSbomFromCheckout(unittest.TestCase):
    def test_writes_cdx_file(self):
        from sbom4edk2.sbom import generate_sbom_from_checkout

        with tempfile.TemporaryDirectory() as edk2:
            prev = os.getcwd()
            try:
                os.chdir(edk2)
                with patch(
                    "sbom4edk2.sbom.write_source_sbom",
                    return_value=0,
                ) as mock_write:
                    result = generate_sbom_from_checkout(
                        edk2,
                        "out",
                        uswid_data="/data",
                    )
                self.assertIsNotNone(result)
                self.assertTrue(result.endswith("out.cdx.json"))
                mock_write.assert_called_once()
            finally:
                os.chdir(prev)

    def test_missing_checkout_returns_none(self):
        from sbom4edk2.sbom import generate_sbom_from_checkout

        self.assertIsNone(
            generate_sbom_from_checkout("/nonexistent/edk2/path", "out")
        )


class TestEnsureUswidData(unittest.TestCase):
    def test_uses_explicit_path(self):
        from sbom4edk2.uswid_data import ensure_uswid_data

        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, "edk2.cdx.json"), "w", encoding="utf-8").close()
            got = ensure_uswid_data(tmp)
            self.assertEqual(os.path.abspath(got), os.path.abspath(tmp))

    def test_auto_clone_when_missing(self):
        from sbom4edk2 import uswid_data as ud
        from sbom4edk2.uswid_data import ensure_uswid_data

        with tempfile.TemporaryDirectory() as root:
            with patch.object(ud, "package_root", return_value=root), patch.object(
                os, "getcwd", return_value=root
            ), patch.object(ud, "_clone_uswid_data_shallow") as mock_clone:

                def _fake_clone(_url: str, dest: str) -> None:
                    os.makedirs(dest, exist_ok=True)
                    open(
                        os.path.join(dest, "edk2.cdx.json"), "w", encoding="utf-8"
                    ).close()

                mock_clone.side_effect = _fake_clone
                got = ensure_uswid_data()
            mock_clone.assert_called_once()
            self.assertTrue(os.path.isfile(os.path.join(got, "edk2.cdx.json")))


class TestNoUswidDependency(unittest.TestCase):
    def test_requirements_txt_has_no_uswid_package(self):
        req = (_REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertNotIn("uswid", req.lower())

    def test_sbom_modules_import_without_uswid(self):
        import importlib

        for mod in (
            "sbom4edk2.sbom",
            "sbom4edk2.cdx_merge",
            "sbom4edk2.cdx_emit",
            "sbom4edk2.submodule_data",
            "sbom4edk2.version_normalize",
            "sbom4edk2.pedigree",
            "sbom4edk2.edk2_version",
            "sbom4edk2.template_loader",
            "sbom4edk2.uswid_data",
            "sbom4edk2.nvd_cpe",
            "sbom4edk2.supplier_data",
        ):
            with self.subTest(module=mod):
                importlib.import_module(mod)


class TestEdk2Stable202602Artifact(unittest.TestCase):
    """Validation gate on generated full-tree SBOM (skipped if artifact absent)."""

    _CDX = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "edk2-stable202602.cdx.json",
    )
    _CORE_CPE_FAMILIES = (
        ("openssl", ("openssl",)),
        # arm:mbed_tls after NVD validation; older artifacts may use mbed:mbedtls
        ("mbedtls", ("arm", "mbed_tls", "mbedtls", ":mbed:")),
        ("jansson", ("jansson",)),
        ("oniguruma", ("oniguruma",)),
        ("brotli", ("brotli",)),
        ("libspdm", ("libspdm", "spdm")),
    )
    _OMISSION_LOG = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "edk2-stable202602.cpe-omissions.log",
    )

    @unittest.skipUnless(
        os.path.isfile(_CDX),
        "edk2-stable202602.cdx.json not generated (run edk2_json_generator on full tree)",
    )
    def test_full_tree_source_sbom_gate(self):
        with open(self._CDX, encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotIn("@VCS_", raw)
        doc = json.loads(raw)
        primary = doc["metadata"]["component"]
        self.assertEqual(primary.get("name"), "EDK II")
        self.assertIn("202602", str(primary.get("version", "")))
        components = doc.get("components", [])
        self.assertGreaterEqual(len(components), 20)
        self.assertLess(len(components), 200)
        names = {c.get("name", "") for c in components}
        self.assertFalse(any("OpensslLib" in n for n in names))
        # Core mapped OSS families with dictionary-backed versions must carry cpe.
        hits = {label: False for label, _ in self._CORE_CPE_FAMILIES}
        for comp in components:
            cpe = (comp.get("cpe") or "").lower()
            if not cpe:
                continue
            blob = " ".join(
                (
                    comp.get("name") or "",
                    comp.get("bom-ref") or "",
                    cpe,
                )
            ).lower()
            for label, tokens in self._CORE_CPE_FAMILIES:
                if any(t in blob for t in tokens) and "cpe:2.3:a:" in cpe:
                    hits[label] = True
        missing = [k for k, v in hits.items() if not v]
        self.assertFalse(missing, f"Missing CPE on core mapped OSS: {missing}")
        without_cpe = [c.get("name") or c.get("bom-ref") for c in components if not c.get("cpe")]
        if without_cpe and os.path.isfile(self._OMISSION_LOG):
            log_text = Path(self._OMISSION_LOG).read_text(encoding="utf-8")
            self.assertIn("reason=", log_text)
        for dep in doc.get("dependencies", []):
            self.assertIsInstance(dep.get("dependsOn"), list)
        edk2_ref = primary.get("bom-ref")
        top = next((d for d in doc["dependencies"] if d.get("ref") == edk2_ref), None)
        self.assertIsNotNone(top)
        self.assertGreaterEqual(len(top["dependsOn"]), 5)
