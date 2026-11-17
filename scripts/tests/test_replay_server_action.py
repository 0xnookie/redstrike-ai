#!/usr/bin/env python3
"""
Unit tests for scripts/replay_server_action.py -- capture->replay of a non-replayable
Next.js / RSC server-action write.

Regression focus: a server-action POST carries a `Next-Action` header + a multipart body whose
first part is the bound `prevState`/closure arg, which CANNOT be synthesized (a hand-built POST
500s). The executors must source such a write from `proxy-context/http_history.json` and replay
it, tampering ONLY an editable field while the bound-state part stays byte-for-byte intact.
These tests pin: server-action detection, exact round-trip, id-swap/payload-inject on editable
fields only, and refusal to touch the bound-state part.

Stdlib only, runnable as `python test_replay_server_action.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import replay_server_action as rsa  # noqa: E402

CRLF = "\r\n"


def sample_history():
    return rsa._sample_history()


class Detection(unittest.TestCase):
    def test_only_next_action_entries_are_server_actions(self):
        acts = rsa.find_server_actions(sample_history())
        self.assertEqual([e["id"] for e in acts], ["h7"])

    def test_header_get_is_case_insensitive(self):
        headers = [["Content-Type", "x"], ["Next-Action", "abc"]]
        self.assertEqual(rsa.header_get(headers, "next-action"), "abc")
        self.assertEqual(rsa.header_get(headers, "NEXT-ACTION"), "abc")
        self.assertIsNone(rsa.header_get(headers, "missing"))

    def test_parse_boundary(self):
        self.assertEqual(
            rsa.parse_boundary("multipart/form-data; boundary=----X"), "----X"
        )
        self.assertEqual(
            rsa.parse_boundary('multipart/form-data; boundary="----Y"'), "----Y"
        )
        self.assertIsNone(rsa.parse_boundary("application/json"))


class TemplateSlots(unittest.TestCase):
    def setUp(self):
        self.ex = rsa.find_server_actions(sample_history())[0]
        self.tpl = rsa.build_replay_template(self.ex)

    def test_action_id_and_boundary(self):
        self.assertEqual(self.tpl.action_id, "7f3c1a9b20")
        self.assertTrue(self.tpl.is_multipart)
        self.assertEqual(self.tpl.boundary, "----WebKitFormBoundaryABC123")

    def test_bound_state_excluded_from_tamperable(self):
        self.assertEqual(self.tpl.tamperable_fields(), ["displayName", "userId"])
        self.assertIn("1_$ACTION_ID_abcdef", self.tpl.bound_state_fields())


class RoundTrip(unittest.TestCase):
    def test_untouched_render_is_byte_exact(self):
        ex = rsa.find_server_actions(sample_history())[0]
        tpl = rsa.build_replay_template(ex)
        self.assertEqual(rsa.render_body(tpl), ex["req"]["body"])


class Tamper(unittest.TestCase):
    def setUp(self):
        self.ex = rsa.find_server_actions(sample_history())[0]
        self.tpl = rsa.build_replay_template(self.ex)

    def test_id_swap_changes_only_that_field(self):
        swapped = rsa.apply_id_swap(self.tpl, "userId", "1002")
        body = rsa.render_body(swapped)
        self.assertIn("$ACTION_REF_0_bound_state_blob", body)  # bound state survives
        self.assertIn('name="userId"' + CRLF + CRLF + "1002" + CRLF, body)
        self.assertNotIn("1001", body.split('name="userId"')[1])
        self.assertIn("Alice", body)  # sibling field untouched

    def test_original_template_is_not_mutated(self):
        rsa.apply_id_swap(self.tpl, "userId", "9999")
        self.assertEqual(rsa.render_body(self.tpl), self.ex["req"]["body"])

    def test_payload_inject_replace(self):
        xss = '"><img src=x onerror=alert(1)>'
        body = rsa.render_body(rsa.apply_payload_inject(self.tpl, "displayName", xss))
        self.assertIn(xss, body)
        self.assertIn("$ACTION_REF_0_bound_state_blob", body)

    def test_payload_inject_append_prepend(self):
        self.assertIn("AliceX", rsa.render_body(
            rsa.apply_payload_inject(self.tpl, "displayName", "X", mode="append")))
        self.assertIn("XAlice", rsa.render_body(
            rsa.apply_payload_inject(self.tpl, "displayName", "X", mode="prepend")))

    def test_tampering_bound_state_is_refused(self):
        with self.assertRaises(ValueError):
            rsa.apply_id_swap(self.tpl, "1_$ACTION_ID_abcdef", "nope")

    def test_unknown_field_is_refused(self):
        with self.assertRaises(KeyError):
            rsa.apply_id_swap(self.tpl, "doesNotExist", "x")


class Selection(unittest.TestCase):
    def test_select_by_id_and_sole(self):
        hist = sample_history()
        self.assertEqual(rsa.select_exchange(hist, "h7")["id"], "h7")
        self.assertEqual(rsa.select_exchange(hist)["id"], "h7")

    def test_select_bad_id_raises(self):
        with self.assertRaises(KeyError):
            rsa.select_exchange(sample_history(), "nope")


class SelfTest(unittest.TestCase):
    def test_module_selftest_passes(self):
        rsa.selftest()  # raises on failure


if __name__ == "__main__":
    unittest.main()
