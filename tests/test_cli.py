import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from seep.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main

DOC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliWorkspaceTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))

    def write(self, rel, content):
        full = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as handle:
            handle.write(content)

    def test_clean_directory_exits_zero(self):
        self.write("app.py", "print('hello')\n")
        code, out, _ = run_cli(["scan", self.dir])
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("no findings", out)

    def test_secret_exits_one_and_redacts(self):
        self.write("app.py", "key = " + DOC_AWS_KEY)
        code, out, _ = run_cli(["scan", self.dir])
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertNotIn(DOC_AWS_KEY, out)
        self.assertIn("aws-access-key-id", out)

    def test_fail_on_high_passes_medium_only(self):
        # A Stripe test key is medium severity.
        # Assembled from parts: no complete token-shaped literal in source.
        self.write("app.py", 'k = "' + "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc" + '"\n')
        code, out, _ = run_cli(["scan", self.dir, "--fail-on", "high"])
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("stripe-restricted-test", out)  # reported, not failing

    def test_json_format(self):
        self.write("app.py", "key = " + DOC_AWS_KEY)
        code, out, _ = run_cli(["scan", self.dir, "--format", "json"])
        self.assertEqual(code, EXIT_FINDINGS)
        payload = json.loads(out)
        self.assertEqual(payload["finding_count"], 1)

    def test_sarif_format(self):
        self.write("app.py", "key = " + DOC_AWS_KEY)
        code, out, _ = run_cli(["scan", self.dir, "--format", "sarif"])
        payload = json.loads(out)
        self.assertEqual(payload["version"], "2.1.0")

    def test_unrecognized_value_on_line_not_in_default_output(self):
        # A credential in a format no rule knows must not leak via context.
        unknown = "sk-proj-" + "Zx7Qw9Lp2Mn4Vb8" * 3
        self.write("app.py", 'key = ' + DOC_AWS_KEY + '; other = "' + unknown + '"')
        code, out, _ = run_cli(["scan", self.dir])
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertNotIn(unknown, out)
        code, out, err = run_cli(["scan", self.dir, "--show-context"])
        self.assertIn("warning", err.lower())

    def test_missing_directory_is_error(self):
        code, _, err = run_cli(["scan", os.path.join(self.dir, "nope")])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not a directory", err)

    def test_baseline_roundtrip_through_cli(self):
        self.write("app.py", "key = " + DOC_AWS_KEY)
        baseline = os.path.join(self.dir, "baseline.json")
        code, _, _ = run_cli(["scan", self.dir, "--write-baseline", baseline])
        self.assertEqual(code, EXIT_FINDINGS)  # first run still reports
        code, out, _ = run_cli(["scan", self.dir, "--baseline", baseline])
        self.assertEqual(code, EXIT_CLEAN, out)

    def test_missing_explicit_config_is_clean_error(self):
        code, _, err = run_cli(
            ["scan", self.dir, "--config", os.path.join(self.dir, "nope.json")])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("config file not found", err)

    def test_config_allowlist_suppresses(self):
        self.write("docs/example.md", "example key " + DOC_AWS_KEY)
        self.write("seep.json", json.dumps({"allowlist": ["docs/"]}))
        code, out, _ = run_cli(["scan", self.dir])
        self.assertEqual(code, EXIT_CLEAN, out)

    def test_exclude_rules_config(self):
        self.write("app.py", "key = " + DOC_AWS_KEY)
        self.write("seep.json", json.dumps({"exclude_rules": ["aws-access-key-id"]}))
        code, out, _ = run_cli(["scan", self.dir])
        self.assertEqual(code, EXIT_CLEAN, out)

    def test_rules_command(self):
        code, out, _ = run_cli(["rules"])
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("aws-access-key-id", out)
        code, out, _ = run_cli(["rules", "--format", "json"])
        self.assertGreaterEqual(len(json.loads(out)), 30)


class CliGitTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        subprocess.run(["git", "init", "-q", "-b", "main", self.dir], check=True)
        subprocess.run(["git", "-C", self.dir, "config", "user.name", "T"], check=True)
        subprocess.run(["git", "-C", self.dir, "config", "user.email", "t@e.c"], check=True)

    def commit(self, rel, content, msg):
        full = os.path.join(self.dir, rel)
        with open(full, "w") as handle:
            handle.write(content)
        subprocess.run(["git", "-C", self.dir, "add", rel], check=True)
        subprocess.run(["git", "-C", self.dir, "commit", "-q", "-m", msg],
                       check=True, capture_output=True)

    def test_history_scan_reports_introducing_commit(self):
        self.commit("app.py", "print('hi')\n", "init")
        self.commit("c.py", "key = " + DOC_AWS_KEY + "\n", "oops")
        code, out, _ = run_cli(["scan", self.dir, "--history"])
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("introduced", out)
        self.assertNotIn(DOC_AWS_KEY, out)

    def test_working_tree_default_ignores_removed_secrets(self):
        self.commit("c.py", "key = " + DOC_AWS_KEY + "\n", "add")
        self.commit("c.py", "key = os.environ['K']\n", "remove")
        code, out, _ = run_cli(["scan", self.dir])
        self.assertEqual(code, EXIT_CLEAN, out)
        code, out, _ = run_cli(["scan", self.dir, "--history"])
        self.assertEqual(code, EXIT_FINDINGS)

    def test_staged_scan_blocks_commit(self):
        self.commit("app.py", "print('hi')\n", "init")
        with open(os.path.join(self.dir, "app.py"), "a") as handle:
            handle.write("key = " + DOC_AWS_KEY + "\n")
        subprocess.run(["git", "-C", self.dir, "add", "app.py"], check=True)
        code, out, _ = run_cli(["scan", self.dir, "--staged"])
        self.assertEqual(code, EXIT_FINDINGS)

    def test_history_outside_repo_is_error(self):
        plain = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(plain, ignore_errors=True))
        code, _, err = run_cli(["scan", plain, "--history"])
        self.assertEqual(code, EXIT_ERROR)


if __name__ == "__main__":
    unittest.main()


class ExcludeRulesValidationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))

    def test_unknown_exclude_rule_id_is_a_clean_error(self):
        with open(os.path.join(self.dir, "seep.json"), "w") as handle:
            json.dump({"exclude_rules": ["not-a-real-rule"]}, handle)
        code, _, err = run_cli(["scan", self.dir])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not-a-real-rule", err)
