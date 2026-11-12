import os
import shutil
import subprocess
import tempfile
import unittest

from seep import git as seepgit
from seep.scanner import Scanner

DOC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
DOC_AWS_KEY_2 = "ASIAIOSFODNN7EXAMPLE"  # also a documented AWS example prefix form


def git(root, *args):
    subprocess.run(["git", "-C", root] + list(args), check=True,
                   capture_output=True)


class FixtureRepo:
    def __init__(self):
        self.dir = tempfile.mkdtemp()
        git(self.dir, "init", "-q", "-b", "main")
        git(self.dir, "config", "user.name", "Fixture Author")
        git(self.dir, "config", "user.email", "fixture@example.com")

    def commit_file(self, rel, content, message, date=None):
        full = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as handle:
            handle.write(content)
        git(self.dir, "add", rel)
        env = dict(os.environ)
        if date:
            env["GIT_AUTHOR_DATE"] = date
            env["GIT_COMMITTER_DATE"] = date
        subprocess.run(["git", "-C", self.dir, "commit", "-q", "-m", message],
                       check=True, capture_output=True, env=env)

    def head(self):
        out = subprocess.run(["git", "-C", self.dir, "rev-parse", "HEAD"],
                             check=True, capture_output=True)
        return out.stdout.decode().strip()

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class HistoryScanTest(unittest.TestCase):
    def setUp(self):
        self.repo = FixtureRepo()
        self.addCleanup(self.repo.cleanup)

    def test_attributes_secret_to_introducing_commit(self):
        self.repo.commit_file("app.py", "print('hello')\n", "initial")
        self.repo.commit_file("config.py", "key = " + DOC_AWS_KEY + "\n", "add config")
        introducing = self.repo.head()
        self.repo.commit_file("other.py", "x = 1\n", "unrelated")
        findings = seepgit.scan_history(Scanner(), self.repo.dir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "config.py")
        self.assertEqual(findings[0].commit, introducing[:12])
        self.assertEqual(findings[0].author, "Fixture Author")
        self.assertEqual(findings[0].line_number, 1)

    def test_secret_removed_later_still_reported(self):
        self.repo.commit_file("c.py", "key = " + DOC_AWS_KEY + "\n", "add secret")
        self.repo.commit_file("c.py", "key = os.environ['KEY']\n", "remove secret")
        findings = seepgit.scan_history(Scanner(), self.repo.dir)
        self.assertEqual(len(findings), 1)

    def test_same_secret_in_two_files_is_two_findings(self):
        self.repo.commit_file("a.py", "key = " + DOC_AWS_KEY + "\n", "a")
        self.repo.commit_file("b.py", "key = " + DOC_AWS_KEY + "\n", "b")
        findings = seepgit.scan_history(Scanner(), self.repo.dir)
        self.assertEqual({f.path for f in findings}, {"a.py", "b.py"})

    def test_first_only_collapses_repeat_introductions(self):
        self.repo.commit_file("c.py", "key = " + DOC_AWS_KEY + "\n", "add")
        self.repo.commit_file("c.py", "key = os.environ['KEY']\n", "remove")
        self.repo.commit_file("c.py", "key = " + DOC_AWS_KEY + "\n", "re-add")
        findings = seepgit.scan_history(Scanner(), self.repo.dir)
        self.assertEqual(len(findings), 1)
        all_occurrences = seepgit.scan_history(
            Scanner(), self.repo.dir, first_only=False
        )
        self.assertEqual(len(all_occurrences), 2)

    def test_two_distinct_secrets_both_reported(self):
        self.repo.commit_file(
            "c.py",
            "a = " + DOC_AWS_KEY + "\nb = " + DOC_AWS_KEY_2 + "\n",
            "two keys",
        )
        findings = seepgit.scan_history(Scanner(), self.repo.dir)
        self.assertEqual(len(findings), 2)

    def test_since_filter_excludes_old_commits(self):
        self.repo.commit_file("old.py", "key = " + DOC_AWS_KEY + "\n",
                              "old", date="2020-01-01T00:00:00")
        self.repo.commit_file("new.py", "key = " + DOC_AWS_KEY_2 + "\n",
                              "new", date="2030-01-01T00:00:00")
        findings = seepgit.scan_history(Scanner(), self.repo.dir, since="2025-01-01")
        self.assertEqual([f.path for f in findings], ["new.py"])

    def test_clean_repo_reports_nothing(self):
        self.repo.commit_file("app.py", "print('hello')\n", "initial")
        self.assertEqual(seepgit.scan_history(Scanner(), self.repo.dir), [])

    def test_real_line_numbers_preserved(self):
        content = "import os\n\n\nkey = " + DOC_AWS_KEY + "\n"
        self.repo.commit_file("deep.py", content, "nested")
        findings = seepgit.scan_history(Scanner(), self.repo.dir)
        self.assertEqual(findings[0].line_number, 4)


class StagedScanTest(unittest.TestCase):
    def setUp(self):
        self.repo = FixtureRepo()
        self.addCleanup(self.repo.cleanup)

    def test_detects_staged_secret(self):
        self.repo.commit_file("app.py", "print('hi')\n", "initial")
        full = os.path.join(self.repo.dir, "app.py")
        with open(full, "a") as handle:
            handle.write("key = " + DOC_AWS_KEY + "\n")
        git(self.repo.dir, "add", "app.py")
        findings = seepgit.scan_staged(Scanner(), self.repo.dir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "app.py")
        self.assertIsNone(findings[0].commit)

    def test_ignores_unstaged_changes(self):
        self.repo.commit_file("app.py", "print('hi')\n", "initial")
        full = os.path.join(self.repo.dir, "app.py")
        with open(full, "a") as handle:
            handle.write("key = " + DOC_AWS_KEY + "\n")
        self.assertEqual(seepgit.scan_staged(Scanner(), self.repo.dir), [])


class HelpersTest(unittest.TestCase):
    def test_parse_added_lines_tracks_paths_and_numbers(self):
        diff = (
            "diff --git a/x.py b/x.py\n"
            "--- a/x.py\n"
            "+++ b/x.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+one\n"
            "+two\n"
            "diff --git a/y.py b/y.py\n"
            "--- a/y.py\n"
            "+++ b/y.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        rows = list(seepgit.parse_added_lines(diff))
        self.assertEqual(rows, [("x.py", 1, "one"), ("x.py", 2, "two"),
                                ("y.py", 1, "new")])


if __name__ == "__main__":
    unittest.main()


class DiffParserEdgeCaseTest(unittest.TestCase):
    """Regression tests for realistic diff shapes the parser must survive."""

    def test_added_line_starting_with_double_plus_is_scanned(self):
        # Content "++x" appears in a diff as "+++x"; naive startswith("+++")
        # header detection swallows it.
        diff = (
            "diff --git a/x.py b/x.py\n"
            "--- a/x.py\n"
            "+++ b/x.py\n"
            "@@ -0,0 +1 @@\n"
            "+++this content starts with two plus signs\n"
        )
        rows = list(seepgit.parse_added_lines(diff))
        self.assertEqual(rows, [("x.py", 1, "++this content starts with two plus signs")])

    def test_header_lines_still_parse_after_hunk_content(self):
        diff = (
            "diff --git a/a.py b/a.py\n"
            "--- a/a.py\n"
            "+++ b/a.py\n"
            "@@ -0,0 +1 @@\n"
            "+key = value\n"
            "diff --git a/b.py b/b.py\n"
            "--- a/b.py\n"
            "+++ b/b.py\n"
            "@@ -0,0 +1 @@\n"
            "+second = file\n"
        )
        rows = list(seepgit.parse_added_lines(diff))
        self.assertEqual(rows, [("a.py", 1, "key = value"), ("b.py", 1, "second = file")])


class MergeCommitGapTest(unittest.TestCase):
    def setUp(self):
        self.repo = FixtureRepo()
        self.addCleanup(self.repo.cleanup)

    def _git(self, *args):
        subprocess.run(["git", "-C", self.repo.dir] + list(args),
                       check=True, capture_output=True)

    def test_secret_introduced_in_merge_commit_is_found(self):
        # A change made IN a merge commit itself (conflict resolution) is not
        # part of any branch commit; git show without -m prints no diff for
        # merges, so a scanner built on it silently misses these.
        self.repo.commit_file("app.py", "base\n", "base")
        self._git("checkout", "-q", "-b", "feature")
        self.repo.commit_file("app.py", "base\nfeature\n", "feature work")
        self._git("checkout", "-q", "main")
        self.repo.commit_file("app.py", "base\nmain\n", "main work")
        # Merge with conflict resolved manually, adding a secret in the merge.
        subprocess.run(["git", "-C", self.repo.dir, "merge", "feature"],
                       capture_output=True)  # conflicts
        with open(os.path.join(self.repo.dir, "app.py"), "w") as handle:
            handle.write("base\nmain\nfeature\nkey = " + DOC_AWS_KEY + "\n")
        self._git("add", "app.py")
        self._git("commit", "-q", "-m", "merge feature, resolve conflicts")
        findings = seepgit.scan_history(Scanner(), self.repo.dir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "app.py")
        self.assertEqual(findings[0].line_number, 4)  # real line in merged file
