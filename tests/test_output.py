import json
import unittest

from seep.output import (
    SEVERITY_ORDER, meets_threshold, to_json, to_sarif, to_text,
)
from seep.rules import RULES
from seep.scanner import Scanner

DOC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


class OutputTest(unittest.TestCase):
    def setUp(self):
        self.findings = Scanner().scan_text(
            "key = " + DOC_AWS_KEY, path="src/app.py"
        )
        self.rules_by_id = {r.id: r for r in RULES}

    def test_text_groups_by_path_and_never_shows_full_secret(self):
        text = to_text(self.findings)
        self.assertIn("src/app.py", text)
        self.assertIn("aws-access-key-id", text)
        self.assertNotIn(DOC_AWS_KEY, text)
        self.assertIn("1 finding", text)

    def test_text_clean_message(self):
        self.assertEqual(to_text([]), "seep: no findings")

    def test_json_is_parseable_and_redacted(self):
        payload = json.loads(to_json(self.findings))
        self.assertEqual(payload["finding_count"], 1)
        self.assertEqual(payload["findings"][0]["path"], "src/app.py")
        self.assertNotIn(DOC_AWS_KEY, to_json(self.findings))

    def test_sarif_shape_and_redaction(self):
        doc = json.loads(to_sarif(self.findings, self.rules_by_id, "0.1.0"))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "seep")
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "aws-access-key-id")
        self.assertEqual(result["level"], "error")
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["region"]["startLine"], 1
        )
        self.assertNotIn(DOC_AWS_KEY, to_sarif(self.findings, self.rules_by_id, "0.1.0"))

    def test_sarif_maps_severities(self):
        from seep.output import SARIF_LEVEL
        self.assertEqual(SARIF_LEVEL["high"], "error")
        self.assertEqual(SARIF_LEVEL["medium"], "warning")
        self.assertEqual(SARIF_LEVEL["low"], "note")

    def test_threshold_filtering(self):
        from seep.scanner import Finding
        f_high = [f for f in self.findings if f.severity == "high"]
        self.assertTrue(all(meets_threshold(f, "medium") for f in f_high))
        self.assertFalse(any(meets_threshold(f, "high") is False for f in f_high))


if __name__ == "__main__":
    unittest.main()


class EmptyOutputTest(unittest.TestCase):
    def test_sarif_with_zero_findings_is_valid(self):
        rules_by_id = {rule.id: rule for rule in RULES}
        doc = json.loads(to_sarif([], rules_by_id, "0.1.0"))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["results"], [])

    def test_json_with_zero_findings(self):
        payload = json.loads(to_json([]))
        self.assertEqual(payload["finding_count"], 0)
