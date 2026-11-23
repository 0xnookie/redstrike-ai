import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli.hooks import chain_pressure as cp  # noqa: E402


class _Eng:
    def __enter__(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._td.name) / "eng"
        (self.dir / "runtime").mkdir(parents=True)
        return self.dir

    def __exit__(self, *a):
        self._td.cleanup()


def _accepted(fid, cls, reviewer=None):
    return {"id": fid, "title": f"{cls} finding", "asset": "https://api.acme.com",
            "status": "verified",
            "review": {"verdict": "accepted", "reviewer": reviewer or f"{cls}-verify"},
            "evidence": [{"type": "tool_output", "ref": f"{cls}/e.txt"}],
            "reproduction": ["x"]}


def _write(eng, rel, obj):
    p = eng / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


class TestClassAndAcceptance(unittest.TestCase):
    def test_feeder_class_from_reviewer(self):
        self.assertEqual(cp.finding_class({"review": {"reviewer": "cors-verify"}}), "cors")
        self.assertEqual(cp.finding_class({"review": {"reviewer": "open-redirect-verify"}}), "open-redirect")

    def test_info_disclosure_aliases(self):
        self.assertEqual(cp.finding_class({"review": {"reviewer": "secrets-verify"}}), "info-disclosure")
        self.assertEqual(cp.finding_class({"review": {"reviewer": "exposed-surface-verify"}}),
                         "info-disclosure")

    def test_class_from_source_dir_fallback(self):
        self.assertEqual(cp.finding_class({"id": "RS-1"}, "csrf"), "csrf")

    def test_non_feeder_class_is_none(self):
        self.assertIsNone(cp.finding_class({"review": {"reviewer": "sqli-inband-verify"}}))
        self.assertIsNone(cp.finding_class({"review": {"reviewer": "xss-reflected-verify"}}))

    def test_is_accepted(self):
        self.assertTrue(cp.is_accepted({"review": {"verdict": "accepted"}}))
        self.assertTrue(cp.is_accepted({"review": {"verdict": "blocked"}}))
        self.assertTrue(cp.is_accepted({"status": "verified"}))
        self.assertFalse(cp.is_accepted({"review": {"verdict": "rejected"}}))
        self.assertFalse(cp.is_accepted({"status": "open"}))


class TestFlagFeeders(unittest.TestCase):
    def test_flags_accepted_feeder_without_chain(self):
        fs = [(_accepted("RS-1", "cors"), "cors")]
        flagged = cp.flag_feeders(fs, chained=set(), attempted=set())
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["id"], "RS-1")
        self.assertEqual(flagged[0]["class"], "cors")
        self.assertTrue(flagged[0]["anchors"])  # anchors attached from the table

    def test_non_feeder_not_flagged(self):
        fs = [(_accepted("RS-2", "sqli-inband"), "sqli-inband")]
        self.assertEqual(cp.flag_feeders(fs, set(), set()), [])

    def test_unaccepted_feeder_not_flagged(self):
        f = {"id": "RS-3", "review": {"verdict": "rejected", "reviewer": "cors-verify"}}
        self.assertEqual(cp.flag_feeders([(f, "cors")], set(), set()), [])

    def test_chained_feeder_drops_out(self):
        fs = [(_accepted("RS-4", "open-redirect"), "open-redirect")]
        self.assertEqual(cp.flag_feeders(fs, chained={"RS-4"}, attempted=set()), [])

    def test_attempted_feeder_drops_out(self):
        fs = [(_accepted("RS-5", "csrf"), "csrf")]
        self.assertEqual(cp.flag_feeders(fs, chained=set(), attempted={"RS-5"}), [])

    def test_composite_is_never_a_feeder(self):
        comp = {"id": "chain-x", "composite": True, "review": {"verdict": "accepted",
                "reviewer": "cors-verify"}}
        self.assertEqual(cp.flag_feeders([(comp, None)], set(), set()), [])


class TestCorpusAndDrain(unittest.TestCase):
    def test_build_pending_flags_feeder(self):
        with _Eng() as eng:
            _write(eng, "cors/findings.json", [_accepted("RS-2026-010", "cors")])
            _write(eng, "sqli-inband/findings.json", [_accepted("RS-2026-011", "sqli-inband")])
            doc = cp.build_pending(eng)
            self.assertEqual(doc["count"], 1)
            self.assertEqual(doc["pending"][0]["class"], "cors")

    def test_chained_via_chains_json_drains(self):
        with _Eng() as eng:
            _write(eng, "cors/findings.json", [_accepted("RS-2026-010", "cors")])
            _write(eng, "attack-chain-discovery/chains.json",
                   {"target": "x", "generated_at": "t",
                    "chains": [{"id": "chain-001", "title": "c",
                                "steps": [{"finding_id": "RS-2026-010", "role": "entry"},
                                          {"finding_id": "RS-2026-099", "role": "exfil"}]}]})
            self.assertEqual(cp.build_pending(eng)["count"], 0)

    def test_probed_via_probes_json_drains(self):
        with _Eng() as eng:
            _write(eng, "open-redirect/findings.json", [_accepted("RS-2026-012", "open-redirect")])
            # a dropped hypothesis that names the feeder finding id counts as chaining attempted
            _write(eng, "attack-chain-discovery/probes.json",
                   [{"id": "p1", "chain_hypothesis": "RS-2026-012 open-redirect -> OAuth",
                     "missing_leg": "code delivery", "probe_skill": "oauth", "status": "dropped"}])
            self.assertEqual(cp.build_pending(eng)["count"], 0)

    def test_empty_pending_is_still_written(self):
        with _Eng() as eng:
            doc = cp.build_pending(eng)
            self.assertEqual(doc["count"], 0)
            out = cp.write_pending(eng, doc)
            self.assertIsNotNone(out)
            self.assertTrue((eng / "runtime" / "chain-pending.json").is_file())

    def test_write_and_reread(self):
        with _Eng() as eng:
            _write(eng, "privesc/findings.json", [_accepted("RS-2026-013", "privesc")])
            cp.write_pending(eng, cp.build_pending(eng))
            data = json.loads((eng / "runtime" / "chain-pending.json").read_text())
            self.assertEqual(data["count"], 1)
            self.assertEqual(data["pending"][0]["class"], "privesc")


if __name__ == "__main__":
    unittest.main()
