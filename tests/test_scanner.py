import os
import subprocess
import tempfile
import unittest

from seep.scanner import Scanner, Finding

DOC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


class ScanTextTest(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner()

    def test_finds_documented_aws_key_with_line_number(self):
        text = "line one\nkey = " + DOC_AWS_KEY + "\nline three\n"
        findings = self.scanner.scan_text(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "aws-access-key-id")
        self.assertEqual(findings[0].line_number, 2)

    def test_full_secret_never_stored(self):
        text = "key = " + DOC_AWS_KEY
        for finding in self.scanner.scan_text(text):
            for value in vars(finding).values():
                self.assertNotIn(DOC_AWS_KEY, str(value))

    def test_inline_ignore_comment_suppresses_line(self):
        text = "key = " + DOC_AWS_KEY + "  # seep:ignore\n"
        self.assertEqual(self.scanner.scan_text(text), [])

    def test_ignore_comment_on_other_line_does_not_suppress(self):
        text = "# seep:ignore everything? no.\nkey = " + DOC_AWS_KEY + "\n"
        self.assertEqual(len(self.scanner.scan_text(text)), 1)

    def test_dedupes_identical_matches(self):
        line = "a = " + DOC_AWS_KEY + "; b = " + DOC_AWS_KEY
        findings = self.scanner.scan_text(line)
        self.assertEqual(len(findings), 1)

    def test_same_secret_different_lines_both_reported(self):
        text = "a = " + DOC_AWS_KEY + "\nb = " + DOC_AWS_KEY + "\n"
        self.assertEqual(len(self.scanner.scan_text(text)), 2)

    def test_allowlist_regex_on_path(self):
        scanner = Scanner(allowlist=[r"docs/.*"])
        self.assertEqual(scanner.scan_text(DOC_AWS_KEY, path="docs/example.md"), [])
        self.assertEqual(len(scanner.scan_text(DOC_AWS_KEY, path="src/app.py")), 1)

    def test_allowlist_regex_on_secret_value(self):
        scanner = Scanner(allowlist=[r"AKIAIOSFODNN7EXAMPLE"])
        self.assertEqual(scanner.scan_text(DOC_AWS_KEY, path="src/app.py"), [])

    def test_finding_uid_stable(self):
        a = self.scanner.scan_text(DOC_AWS_KEY, path="x.py")[0]
        b = self.scanner.scan_text(DOC_AWS_KEY, path="x.py")[0]
        self.assertEqual(a.uid, b.uid)


class ScanDirectoryTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, rel, content):
        full = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(full, mode) as handle:
            handle.write(content)
        return full

    def test_scans_tracked_files_with_relative_paths(self):
        self.write("src/config.py", "key = " + DOC_AWS_KEY)
        findings = Scanner().scan_directory(self.dir)
        self.assertEqual([f.path for f in findings], ["src/config.py"])

    def test_skips_binary_files(self):
        self.write("blob.bin", b"\x00\x01\x02" + DOC_AWS_KEY.encode())
        self.write("src/app.py", "key = " + DOC_AWS_KEY)
        scanner = Scanner()
        findings = scanner.scan_directory(self.dir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(scanner.skipped_binary, 1)

    def test_skips_large_files(self):
        self.write("big.txt", ("pad\n" * 300000) + DOC_AWS_KEY)
        scanner = Scanner(max_file_bytes=1024)
        findings = scanner.scan_directory(self.dir)
        self.assertEqual(findings, [])
        self.assertEqual(scanner.skipped_large, 1)

    def test_skips_dot_git_contents(self):
        self.write(".git/config", "key = " + DOC_AWS_KEY)
        self.assertEqual(Scanner().scan_directory(self.dir), [])

    def test_respects_gitignore_inside_repo(self):
        subprocess.run(["git", "init", "-q", self.dir], check=True)
        self.write(".gitignore", "ignored/\n")
        self.write("ignored/secret.py", "key = " + DOC_AWS_KEY)
        self.write("src/app.py", "key = " + DOC_AWS_KEY)
        findings = Scanner().scan_directory(self.dir)
        self.assertEqual([f.path for f in findings], ["src/app.py"])

    def test_symlinks_not_followed(self):
        target = self.write("real.py", "key = " + DOC_AWS_KEY)
        link = os.path.join(self.dir, "link.py")
        os.symlink(target, link)
        findings = Scanner().scan_directory(self.dir)
        self.assertEqual([f.path for f in findings], ["real.py"])


if __name__ == "__main__":
    unittest.main()


class CoLocatedSecretTest(unittest.TestCase):
    """A finding's preview must never expose a DIFFERENT secret on its line."""

    GH_TOKEN = "ghp_" + "a1B2c3D4" * 4 + "e5F6"

    def test_two_secrets_one_line_both_redacted_in_every_preview(self):
        line = 'aws = "' + DOC_AWS_KEY + '"; gh = "' + self.GH_TOKEN + '"'
        findings = Scanner().scan_text(line, path="x.py")
        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertNotIn(DOC_AWS_KEY, finding.line_preview)
            self.assertNotIn(self.GH_TOKEN, finding.line_preview)

    def test_same_secret_twice_on_line_fully_redacted(self):
        line = "a=" + DOC_AWS_KEY + " b=" + DOC_AWS_KEY
        for finding in Scanner().scan_text(line):
            self.assertNotIn(DOC_AWS_KEY, finding.line_preview)

    def test_secret_substring_of_longer_secret_handled(self):
        url = "postgres://user:Sup3rS3cret!x9@host:5432/db"
        line = 'db = "' + url + '"; backup = "' + url + '"'
        for finding in Scanner().scan_text(line):
            self.assertNotIn(url, finding.line_preview)


class BinarySniffDepthTest(unittest.TestCase):
    def test_nul_beyond_8kb_still_detected_as_binary(self):
        import tempfile, shutil
        d = tempfile.mkdtemp()
        try:
            blob = b"A" * 40000 + b"\x00" + DOC_AWS_KEY.encode()
            path = os.path.join(d, "deep.bin")
            with open(path, "wb") as handle:
                handle.write(blob)
            scanner = Scanner()
            self.assertEqual(scanner.scan_directory(d), [])
            self.assertEqual(scanner.skipped_binary, 1)
        finally:
            shutil.rmtree(d, ignore_errors=True)
