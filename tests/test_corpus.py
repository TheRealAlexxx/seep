"""Realistic-shape corpus: secrets in the wild rarely sit in .py strings.

Every fixture is a documented non-live example or a generated dummy in the
right format. Token-shaped values are assembled from parts so no complete
literal ever lives in this repository.
"""
import os
import shutil
import tempfile
import unittest

from seep.scanner import Scanner

GH_TOKEN = "ghp_" + "a1B2c3D4" * 4 + "e5F6"
GITLAB_TOKEN = "glpat-" + "xKq9mZ2vL4pW8nR1tY6u"
STRIPE_LIVE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
AWS_DOC_SECRET = "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY"
SLACK_HOOK = ("https://hooks.slack.com/services/T00000000/B00000000/"
              + "abcd1234" * 3)
GENERIC_KEY = "g9K2xQ7mZ4vL1pW8nR3tY6uI"


class RealisticShapeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))

    def write(self, rel, content):
        full = os.path.join(self.dir, rel)
        with open(full, "wb") as handle:
            handle.write(content if isinstance(content, bytes)
                         else content.encode())

    def rules_found(self):
        return {f.rule_id for f in Scanner().scan_directory(self.dir)}

    def test_yaml_config(self):
        self.write("config.yml", 'github:\n  token: "%s"\n' % GH_TOKEN)
        self.assertIn("github-pat", self.rules_found())

    def test_json_nested(self):
        self.write("settings.json",
                   '{\n  "stripe": {\n    "secret_key": "%s"\n  }\n}\n'
                   % STRIPE_LIVE)
        self.assertIn("stripe-live-secret", self.rules_found())

    def test_url_embedded_credentials(self):
        self.write("app.env",
                   "DATABASE_URL=postgres://app:Sup3rS3cret99x@db:5432/prod\n")
        self.assertIn("database-url", self.rules_found())

    def test_multiline_pem_block(self):
        self.write("id_deploy",
                   "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                   "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n"
                   "-----END OPENSSH PRIVATE KEY-----\n")
        self.assertIn("private-key-block", self.rules_found())

    def test_crlf_line_endings(self):
        self.write("windows.py",
                   ("line one\r\napi_key = \"%s\"\r\n" % GENERIC_KEY).encode())
        findings = Scanner().scan_directory(self.dir)
        self.assertIn("generic-api-key", {f.rule_id for f in findings})
        self.assertEqual(findings[0].line_number, 2)

    def test_minified_single_line_js(self):
        padding = "x" * 3000
        self.write("bundle.js",
                   'const a=1;const HOOK="%s";%s\n' % (SLACK_HOOK, padding))
        self.assertIn("slack-webhook", self.rules_found())

    def test_non_english_utf8_context(self):
        self.write("i18n.env",
                   "# kommentar: schluessel\n"
                   "AWS_SECRET_ACCESS_KEY=%s\n" % AWS_DOC_SECRET)
        self.assertIn("aws-secret-access-key", self.rules_found())

    def test_secret_at_eof_without_newline(self):
        self.write("noeol.py", 'GITLAB_TOKEN = "%s"' % GITLAB_TOKEN)
        self.assertIn("gitlab-pat", self.rules_found())

    def test_long_line_secret_beyond_preview_cut_still_safe(self):
        secret = GH_TOKEN
        line = ("pad = '%s'\n" % ("p" * 500)) + 'tok = "%s"\n' % secret
        self.write("long.py", line)
        for finding in Scanner(include_context=True).scan_directory(self.dir):
            self.assertLessEqual(len(finding.line_preview), 200)
            self.assertNotIn(secret, finding.line_preview)


if __name__ == "__main__":
    unittest.main()
