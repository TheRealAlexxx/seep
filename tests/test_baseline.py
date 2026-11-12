import json
import os
import tempfile
import unittest

from seep.baseline import (
    Baseline, filter_new, load_baseline, write_baseline,
)
from seep.scanner import Scanner

DOC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
DOC_AWS_KEY_2 = "ASIAIOSFODNN7EXAMPLE"


class BaselineTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, ".seep-baseline.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def _findings(self, text, path="app.py"):
        return Scanner().scan_text(text, path=path)

    def test_roundtrip_filters_known_findings(self):
        findings = self._findings("a = " + DOC_AWS_KEY)
        write_baseline(self.path, findings)
        baseline = load_baseline(self.path)
        self.assertEqual(filter_new(findings, baseline), [])

    def test_new_findings_pass_through(self):
        old = self._findings("a = " + DOC_AWS_KEY)
        write_baseline(self.path, old)
        both = self._findings("a = " + DOC_AWS_KEY + "\nb = " + DOC_AWS_KEY_2)
        baseline = load_baseline(self.path)
        new = filter_new(both, baseline)
        self.assertEqual(len(new), 1)

    def test_baseline_contains_no_full_secrets(self):
        findings = self._findings("a = " + DOC_AWS_KEY)
        write_baseline(self.path, findings)
        with open(self.path) as handle:
            raw = handle.read()
        self.assertNotIn(DOC_AWS_KEY, raw)

    def test_load_rejects_unknown_version(self):
        with open(self.path, "w") as handle:
            json.dump({"version": 99, "findings": []}, handle)
        with self.assertRaises(ValueError):
            load_baseline(self.path)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_baseline(self.path)


if __name__ == "__main__":
    unittest.main()
