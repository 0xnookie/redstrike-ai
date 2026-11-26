#!/usr/bin/env python3
"""
Unit tests for the VRT (Vulnerability Rating Taxonomy) primitives in scripts/validate.py -- the fix for
the fabricated-VRT incident (a hand-authored submission once shipped a VRT category that does not exist in
the taxonomy; an operator caught it).

Core guarantees:
  * the PINNED taxonomy (skills/bug-bounty/refs/vrt/vulnerability-rating-taxonomy.json) loads, carries
    provenance `_meta`, and still contains the canonical anchor path at its baseline priority;
  * a finding whose vrt.path/id resolves to a REAL node passes (anti-fabrication lets real ones through);
  * a FABRICATED path fails (the real incident);
  * a priority STRONGER than baseline without an argued rationale fails (anti-inflation), while an argued
    elevation WITH a rationale passes;
  * a normal pentest finding (no vrt{} block) is unaffected;
  * scope.yaml program.taxonomy must reference a known/pinned taxonomy.

validate.py's top-level repo scan is guarded behind `if __name__ == "__main__"`, so importing it here only
binds its pure helpers (no interpreter exit). Stdlib only, runnable as `python test_vrt.py` (CI convention).
"""
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import validate as v  # noqa: E402

TAX = json.loads(v.VRT_TAXONOMY_PATH.read_text(encoding="utf-8"))
FLAT = v.flatten_vrt(TAX)

SSI_TI = "server_side_injection > content_spoofing > text_injection"    # baseline P5
SSI_IF = "server_side_injection > content_spoofing > iframe_injection"  # baseline P3


def f(**vrt):
    """Build a minimal finding carrying a vrt{} block."""
    return {"id": "RS-2026-999", "vrt": vrt}


class PinnedTaxonomy(unittest.TestCase):
    def test_file_exists_and_parses(self):
        self.assertTrue(v.VRT_TAXONOMY_PATH.is_file())
        self.assertIsInstance(TAX, dict)
        self.assertIn("content", TAX)

    def test_provenance_meta(self):
        meta = TAX.get("_meta")
        self.assertIsInstance(meta, dict)
        for key in ("upstream_source", "upstream_ref", "upstream_version", "fetched_at", "refresh_policy"):
            self.assertTrue(meta.get(key), f"_meta missing provenance key {key!r}")

    def test_anchor_path_present_at_baseline(self):
        anchor = ("server_side_injection", "content_spoofing", "text_injection")
        self.assertEqual(FLAT["id_paths"].get(anchor), 5)
        self.assertEqual(FLAT["id_paths"].get(("server_side_injection", "content_spoofing", "iframe_injection")), 3)

    def test_flatten_builds_name_paths_too(self):
        self.assertEqual(
            FLAT["name_paths"].get(("server-side injection", "content spoofing", "text injection")), 5)

    def test_some_priorities_present(self):
        self.assertTrue(any(p is not None for p in FLAT["id_paths"].values()))


class FabricationCheck(unittest.TestCase):
    def test_real_id_path_passes(self):
        self.assertEqual(v.vrt_finding_errors(f(path=SSI_TI, priority="P5", priority_basis="baseline"), FLAT), [])

    def test_real_name_path_passes(self):
        finding = f(path="Server-Side Injection > Content Spoofing > Text Injection", priority="P5")
        self.assertEqual(v.vrt_finding_errors(finding, FLAT), [])

    def test_resolution_by_leaf_id(self):
        # path omitted, only the leaf id -> still resolves to the real node.
        errs = v.vrt_finding_errors({"id": "x", "vrt": {"path": "text_injection", "id": "text_injection",
                                                        "priority": "P5"}}, FLAT)
        self.assertEqual(errs, [])

    def test_fabricated_path_fails(self):
        # the exact incident category — does NOT exist in the taxonomy.
        errs = v.vrt_finding_errors(
            f(path="Broken Access Control — Improper Authorization / Server-Side", priority="P3"), FLAT)
        self.assertTrue(errs)
        self.assertIn("fabricated", errs[0].lower())

    def test_fabricated_id_fails(self):
        errs = v.vrt_finding_errors({"id": "x", "vrt": {"path": "not_a_real_node > nope",
                                                        "id": "totally_made_up"}}, FLAT)
        self.assertTrue(errs)


class InflationCheck(unittest.TestCase):
    def test_baseline_priority_passes(self):
        self.assertEqual(v.vrt_finding_errors(f(path=SSI_TI, priority="P5", priority_basis="baseline"), FLAT), [])

    def test_stronger_than_baseline_without_basis_fails(self):
        # P3 on a P5-baseline class, priority_basis=baseline -> inflation.
        errs = v.vrt_finding_errors(f(path=SSI_TI, priority="P3", priority_basis="baseline"), FLAT)
        self.assertTrue(errs)
        self.assertIn("inflation", " ".join(errs).lower())

    def test_stronger_default_basis_fails(self):
        # priority_basis omitted entirely -> treated as baseline -> inflation.
        errs = v.vrt_finding_errors(f(path=SSI_TI, priority="P3"), FLAT)
        self.assertTrue(errs)

    def test_argued_elevation_without_rationale_fails(self):
        errs = v.vrt_finding_errors(f(path=SSI_TI, priority="P3", priority_basis="argued-elevation"), FLAT)
        self.assertTrue(errs)
        self.assertIn("rationale", " ".join(errs).lower())

    def test_argued_elevation_with_rationale_passes(self):
        # the legitimate RS-2026-062 shape: a demonstrated cross-user impact argues the elevation.
        errs = v.vrt_finding_errors(
            f(path=SSI_TI, priority="P3", priority_basis="argued-elevation",
              priority_rationale="demonstrated cross-user nickname spoofing, not plain text injection"), FLAT)
        self.assertEqual(errs, [])

    def test_weaker_reduction_with_rationale_passes(self):
        errs = v.vrt_finding_errors(
            f(path=SSI_IF, priority="P5", priority_basis="argued-reduction",
              priority_rationale="no sensitive action is framed"), FLAT)
        self.assertEqual(errs, [])

    def test_bad_priority_token_fails(self):
        self.assertTrue(v.vrt_finding_errors(f(path=SSI_TI, priority="P9"), FLAT))

    def test_bad_basis_enum_fails(self):
        self.assertTrue(v.vrt_finding_errors(f(path=SSI_TI, priority="P5", priority_basis="whatever"), FLAT))


class Unaffected(unittest.TestCase):
    def test_finding_without_vrt_passes(self):
        self.assertEqual(v.vrt_finding_errors({"id": "RS-2026-001", "severity": "low"}, FLAT), [])

    def test_non_dict_finding_is_safe(self):
        self.assertEqual(v.vrt_finding_errors("not a dict", FLAT), [])

    def test_varies_baseline_skips_inflation(self):
        # a node whose baseline priority is null ('varies') has no numeric baseline to inflate past.
        # pick any id-path whose priority is None.
        none_path = next((p for p, pr in FLAT["id_paths"].items() if pr is None), None)
        self.assertIsNotNone(none_path)
        path = " > ".join(none_path)
        self.assertEqual(v.vrt_finding_errors(f(path=path, priority="P1", priority_basis="baseline"), FLAT), [])


class PriorityParsing(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(v._vrt_priority_int("P3"), 3)
        self.assertEqual(v._vrt_priority_int("3"), 3)
        self.assertEqual(v._vrt_priority_int(3), 3)
        self.assertIsNone(v._vrt_priority_int(None))
        self.assertIsNone(v._vrt_priority_int("varies"))
        self.assertIsNone(v._vrt_priority_int(""))

    def test_rejects_garbage(self):
        for bad in ("P0", "P6", "6", "low", True):
            with self.assertRaises(ValueError):
                v._vrt_priority_int(bad)


class ScopeProgram(unittest.TestCase):
    def test_known_taxonomy_passes(self):
        self.assertEqual(v.scope_program_errors({"platform": "bugcrowd", "taxonomy": "vrt"}), [])
        self.assertEqual(v.scope_program_errors({"platform": "none", "taxonomy": "none"}), [])

    def test_unknown_taxonomy_fails(self):
        self.assertTrue(v.scope_program_errors({"platform": "bugcrowd", "taxonomy": "madeup"}))

    def test_bad_platform_fails(self):
        self.assertTrue(v.scope_program_errors({"platform": "nope", "taxonomy": "none"}))

    def test_absent_program_is_safe(self):
        self.assertEqual(v.scope_program_errors(None), [])
        self.assertEqual(v.scope_program_errors("not a dict"), [])

    def test_template_scope_program_block_parses_and_is_known(self):
        tmpl = v.ROOT / "engagements" / "_template" / "scope.yaml"
        prog = v._parse_simple_block(tmpl.read_text(encoding="utf-8"), "program")
        self.assertIn("taxonomy", prog)
        self.assertIn("platform", prog)
        self.assertEqual(v.scope_program_errors(prog), [])


class EmbeddedSelfTest(unittest.TestCase):
    def test_vrt_selftest_green(self):
        self.assertEqual(v.vrt_selftest(FLAT), [])


if __name__ == "__main__":
    unittest.main()
