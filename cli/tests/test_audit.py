import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
import unittest.mock as mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import audit, engagement, engines, launch  # noqa: E402


class TestRedaction(unittest.TestCase):
    def test_password_kv_value_redacted(self):
        out = audit.redact_text('{"password": "sup3r-s3cret!", "user": "bob"}')
        self.assertNotIn("sup3r-s3cret!", out)
        self.assertIn("[REDACTED:", out)
        self.assertIn('"user": "bob"', out)  # non-secret untouched
        json.loads(out)  # still valid JSON

    def test_jwt_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.S0meF4keS1gnatur3_val"
        out = audit.redact_text(f"token is {jwt} ok")
        self.assertNotIn(jwt, out)
        self.assertIn("[REDACTED:jwt:", out)

    def test_bearer_token_redacted(self):
        out = audit.redact_text("Authorization: Bearer abcDEF123456ghiJKL")
        self.assertNotIn("abcDEF123456ghiJKL", out)
        self.assertIn("Bearer [REDACTED:", out)

    def test_pwdump_ntlm_hashes_redacted(self):
        line = "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        out = audit.redact_text(line)
        self.assertNotIn("31d6cfe0d16ae931b73c59d7e0c089c0", out)
        self.assertNotIn("aad3b435b51404eeaad3b435b51404ee", out)
        self.assertIn("[REDACTED:ntlm:", out)
        self.assertIn("admin:500:", out)  # structure preserved

    def test_crypt_hash_redacted(self):
        out = audit.redact_text("hash=$6$saltsalt$abcdefghijklmnopqrstuvwxyz0123456789")
        self.assertIn("[REDACTED:hash:", out)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz0123456789", out)

    def test_private_key_block_redacted(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----"
        out = audit.redact_text(pem)
        self.assertEqual(out, "[REDACTED-PRIVATE-KEY]")

    def test_access_key_id_redacted(self):
        out = audit.redact_text("key AKIAIOSFODNN7EXAMPLE here")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertIn("[REDACTED:akid:", out)

    def test_same_secret_same_fingerprint(self):
        a = audit.redact_text('password="hunter2abc"')
        b = audit.redact_text('password="hunter2abc"')
        self.assertEqual(a, b)

    def test_benign_text_untouched(self):
        s = '{"type":"assistant","text":"running nmap on api.acme.com"}'
        self.assertEqual(audit.redact_text(s), s)

    def test_empty(self):
        self.assertEqual(audit.redact_text(""), "")


class TestRunHead(unittest.TestCase):
    def test_head_binds_scope_hash_and_authz(self):
        with tempfile.TemporaryDirectory() as d:
            scope_yaml = pathlib.Path(d) / "scope.yaml"
            scope_yaml.write_text("engagement: x\nauthorized_by: sec@acme\n", encoding="utf-8")
            expected = hashlib.sha256(scope_yaml.read_bytes()).hexdigest()
            head = audit.run_head(
                scope_yaml_path=scope_yaml, authorized_by="sec@acme / auth-123",
                session_id="sess-1", mode="autonomous",
            )
            self.assertTrue(head.startswith("#"))          # console run-boundary marker
            self.assertTrue(head.endswith("\n"))
            self.assertIn(f"scope.yaml#sha256={expected}", head)
            self.assertIn("authorized_by=sec@acme / auth-123", head)
            self.assertIn("session=sess-1", head)

    def test_missing_scope_yaml_marks_unavailable(self):
        head = audit.run_head(scope_yaml_path="/no/such/scope.yaml",
                              authorized_by="x", session_id="s", mode="autonomous")
        self.assertIn("scope.yaml#sha256=unavailable", head)


class TestInteractiveAudit(unittest.TestCase):
    def test_interactive_run_writes_stamped_head_and_footer(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            fields = engagement.build_fields(client="Acme", authorized_by="sec@acme / auth-9",
                                             domains=["*.acme.com"])
            engagement.scaffold(repo, fields, operator="t")
            eng = repo / "engagements" / fields["engagement"]
            prep = launch.prepare_runtime(eng, repo, sys.executable)
            inv = engines.Invocation(argv=["claude", "go"])
            audit_path = eng / "runtime" / "autorun.jsonl"

            eng_obj = engines.ClaudeCodeEngine()
            with mock.patch("redstrike_cli.launch.exec_claude", return_value=0) as ex:
                res = eng_obj.run(prep, eng, inv, mode="interactive", audit=audit_path)
            ex.assert_called_once()
            self.assertEqual(res.rc, 0)

            trail = audit_path.read_text(encoding="utf-8")
            self.assertIn("scope.yaml#sha256=", trail)        # tamper-evident head
            self.assertIn("authorized_by=sec@acme / auth-9", trail)
            self.assertIn("interactive run ended", trail)      # outcome footer
            self.assertIn("exit=0", trail)


if __name__ == "__main__":
    unittest.main()
