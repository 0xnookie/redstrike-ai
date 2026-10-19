import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import engagement, yamlio  # noqa: E402

try:
    import yaml  # PyYAML — optional; only the fallback-vs-PyYAML parity check needs it
    HAVE_YAML = True
except ImportError:
    yaml = None
    HAVE_YAML = False

REPO = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "engagements" / "_template" / "scope.yaml"


class TestMiniYaml(unittest.TestCase):
    @unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
    def test_matches_pyyaml_on_template(self):
        text = TEMPLATE.read_text(encoding="utf-8")
        ref = yaml.safe_load(text)
        got = yamlio._mini_load(text)
        for path in (
            ("engagement",),
            ("in_scope", "domains"),
            ("in_scope", "cidrs"),
            ("in_scope", "urls"),
            ("out_of_scope", "domains"),
            ("out_of_scope", "cidrs"),
            ("rules", "no_dos"),
            ("rules", "no_destructive"),
            ("rules", "rate_limit_rps"),
            ("rules", "approval_required_phases"),
        ):
            r, g = ref, got
            for k in path:
                r, g = r[k], g[k]
            self.assertEqual(g, r, f"mismatch at {path}: mini={g!r} pyyaml={r!r}")

    def test_render_roundtrips(self):
        fields = engagement.build_fields(
            client="Acme Corp",
            authorized_by="sec@acme / auth-123",
            domains=["*.acme.com", "api.acme.com"],
            cidrs=["203.0.113.0/24"],
            exclude_domains=["admin.acme.com"],
            oob="oob.example.net",
        )
        text = yamlio.render_scope_yaml(fields)
        got = yamlio._mini_load(text)
        self.assertEqual(got["in_scope"]["domains"], ["*.acme.com", "api.acme.com"])
        self.assertEqual(got["in_scope"]["cidrs"], ["203.0.113.0/24"])
        self.assertEqual(got["in_scope"]["urls"], [])
        self.assertEqual(got["out_of_scope"]["domains"], ["admin.acme.com"])
        self.assertEqual(got["rules"]["approval_required_phases"], ["exploitation", "post-exploitation"])
        self.assertEqual(got["rules"]["rate_limit_rps"], 20)
        # also valid for PyYAML, when it's installed
        if HAVE_YAML:
            y = yaml.safe_load(text)
            self.assertEqual(y["authorized_by"], "sec@acme / auth-123")
            self.assertEqual(y["oob"]["collaborator"], "oob.example.net")


if __name__ == "__main__":
    unittest.main()
