"""Rule tests use publicly documented non-live example credentials only.

Sources of fixtures include AWS documentation (AKIAIOSFODNN7EXAMPLE and its
documented companion secret), GitHub's own placeholder formats, and random
strings generated for these tests. None of these values are or ever were
valid credentials.
"""
import unittest

from seep.rules import RULES, get_rule


def hits(rule_id, text):
    rule = get_rule(rule_id)
    return [m.group(rule.secret_group) for m in rule.finditer(text)]


class StructuralRuleTest(unittest.TestCase):
    def test_aws_access_key_id_documentation_example(self):
        # AWS's own documentation example key id.
        text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        self.assertEqual(hits("aws-access-key-id", text), ["AKIAIOSFODNN7EXAMPLE"])

    def test_aws_access_key_id_not_flagged_without_prefix(self):
        self.assertEqual(hits("aws-access-key-id", "code = IOSFODNN7EXAMPLE12"), [])

    def test_aws_secret_documentation_example(self):
        # AWS's documented companion secret for the example key id above.
        text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        self.assertEqual(
            hits("aws-secret-access-key", text),
            ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
        )

    def test_github_pat(self):
        token = "ghp_" + "a1B2c3D4" * 4 + "e5F6"
        self.assertEqual(len(token), 40)
        self.assertEqual(hits("github-pat", "token: " + token), [token])

    def test_github_fine_grained_pat(self):
        token = "github_pat_" + "11ABCDEFG0" * 8 + "_z"
        self.assertEqual(hits("github-fine-grained-pat", token), [token])

    def test_github_oauth_prefixes(self):
        for prefix in ("gho_", "ghu_", "ghs_"):
            token = prefix + "x" * 36
            self.assertEqual(hits("github-oauth-token", token), [token])

    def test_gitlab_pat(self):
        # Assembled from parts: no complete token-shaped literal in source.
        token = "glpat-" + "xKq9mZ2vL4pW8nR1tY6u"
        self.assertEqual(hits("gitlab-pat", "GITLAB_TOKEN=" + token), [token])

    def test_stripe_live(self):
        token = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
        self.assertEqual(hits("stripe-live-secret", token), [token])
        self.assertEqual(get_rule("stripe-live-secret").severity, "high")

    def test_stripe_test_key_is_medium(self):
        token = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
        self.assertEqual(hits("stripe-restricted-test", token), [token])
        self.assertEqual(get_rule("stripe-restricted-test").severity, "medium")

    def test_slack_webhook(self):
        url = "https://hooks.slack.com/services/T00000000/B00000000/" + "x" * 24
        self.assertEqual(hits("slack-webhook", url), [url])

    def test_google_api_key(self):
        token = "AIza" + "SyD4kJ8xQ2vN0pW7mZ3rT6uY1iO9aS5dF7g"[:35]
        self.assertEqual(len(token), 39)
        self.assertEqual(hits("google-api-key", token), [token])

    def test_npm_token(self):
        token = "npm_" + "x" * 36
        self.assertEqual(hits("npm-access-token", token), [token])

    def test_jwt(self):
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkV4YW1wbGUifQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        self.assertEqual(hits("jwt", "Authorization: Bearer " + token), [token])

    def test_private_key_block(self):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
        self.assertTrue(hits("private-key-block", text))

    def test_database_url_postgres(self):
        url = "postgres://appuser:Sup3rS3cretPass@db.internal:5432/appdb"
        self.assertEqual(hits("database-url", 'DATABASE_URL="' + url + '"'), [url])

    def test_database_url_mongodb_srv(self):
        url = "mongodb+srv://user:p4ssw0rd!x@cluster0.example.net/db"
        self.assertEqual(hits("database-url", url), [url])

    def test_sendgrid(self):
        token = "SG." + "a" * 22 + "." + "b" * 43
        self.assertEqual(hits("sendgrid-api-key", token), [token])

    def test_telegram_bot(self):
        token = "110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"
        text = "telegram bot token: " + token
        self.assertEqual(hits("telegram-bot-token", text), [token])


class KeywordPrefilterTest(unittest.TestCase):
    def test_prefilter_skips_regex_when_keyword_absent(self):
        # A Slack-shaped webhook on a page that never mentions slack.com
        # should not be scanned by that rule at all.
        url = "https://hooks.example.com/services/T00000000/B00000000/" + "x" * 24
        self.assertEqual(hits("slack-webhook", url), [])

    def test_prefilter_is_case_insensitive(self):
        token = "npm_" + "x" * 36
        self.assertEqual(hits("npm-access-token", "NPM_CONFIG=" + token), [token])


class EntropyGatedRuleTest(unittest.TestCase):
    def test_generic_password_flags_random_value(self):
        text = 'password = "Xk9#mQ2$vL7!pW4nR8"'
        self.assertEqual(hits("generic-password", text), ["Xk9#mQ2$vL7!pW4nR8"])

    def test_generic_password_ignores_obvious_placeholder(self):
        for placeholder in ("password123", "changeme", "letmein123"):
            self.assertEqual(
                hits("generic-password", 'password = "%s"' % placeholder),
                [],
                placeholder,
            )

    def test_generic_api_key_flags_random_value(self):
        text = 'api_key = "g9K2xQ7mZ4vL1pW8nR3tY6uI"'
        self.assertEqual(hits("generic-api-key", text), ["g9K2xQ7mZ4vL1pW8nR3tY6uI"])

    def test_generic_api_key_ignores_placeholder(self):
        self.assertEqual(
            hits("generic-api-key", 'api_key = "your-api-key-here"'), []
        )

    def test_generic_rules_require_assignment_context(self):
        self.assertEqual(hits("generic-password", "the password field"), [])


class EffectiveFloorTest(unittest.TestCase):
    """The entropy gate sets an EFFECTIVE floor above the regex length:
    a value passes only when it is long enough AND mixes enough distinct
    characters. These tests pin that as intentional false-positive
    control, not a bug."""

    def test_short_human_password_intentionally_not_flagged(self):
        # 8 chars, all unique: entropy 3.0 < 3.5 threshold. Real but
        # human-memorable; flagging these floods test/dev code.
        self.assertEqual(hits("generic-password", 'password = "Kx9mQ2vL"'), [])

    def test_14_char_unique_api_key_intentionally_not_flagged(self):
        # 14 unique chars: entropy ~3.81 < 4.0 threshold for API keys.
        self.assertEqual(
            hits("generic-api-key", 'api_key = "Kx9mQ2vLpWnR7t"'), []
        )

    def test_16_char_unique_api_key_flagged(self):
        self.assertEqual(
            hits("generic-api-key", 'api_key = "Kx9mQ2vLpWnR7tY4"'),
            ["Kx9mQ2vLpWnR7tY4"],
        )


class RuleIntegrityTest(unittest.TestCase):
    def test_unique_ids(self):
        ids = [r.id for r in RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_has_description_and_valid_severity(self):
        for rule in RULES:
            self.assertTrue(rule.description, rule.id)
            self.assertIn(rule.severity, ("low", "medium", "high"), rule.id)

    def test_secret_group_within_pattern_groups(self):
        for rule in RULES:
            self.assertLessEqual(
                rule.secret_group, rule.pattern.groups, rule.id
            )

    def test_at_least_thirty_rules(self):
        self.assertGreaterEqual(len(RULES), 30)


if __name__ == "__main__":
    unittest.main()


class RecallGapTest(unittest.TestCase):
    """Independent-review reproductions: values that must be caught."""

    def test_short_high_entropy_password_caught(self):
        # 12-char password with entropy 3.58 was missed: rule regex allowed
        # 8-64 chars but the entropy check hard-floored at 16.
        self.assertEqual(
            hits("generic-password", 'password = "xLd6GncfBAep"'),
            ["xLd6GncfBAep"],
        )

    def test_unquoted_aws_secret_in_env_file_caught(self):
        text = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        self.assertEqual(
            hits("aws-secret-access-key", text),
            ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
        )

    def test_unquoted_generic_api_key_caught(self):
        self.assertEqual(
            hits("generic-api-key", "api_key=g9K2xQ7mZ4vL1pW8nR3tY6uI\n"),
            ["g9K2xQ7mZ4vL1pW8nR3tY6uI"],
        )

    def test_unquoted_placeholder_still_ignored(self):
        self.assertEqual(hits("generic-api-key", "api_key=your-api-key-here\n"), [])
        self.assertEqual(hits("generic-password", "password=changeme\n"), [])

    def test_oversized_value_not_partially_matched(self):
        # 65+ char unquoted values must not match their first 64 chars.
        self.assertEqual(
            hits("generic-api-key", "api_key=" + "aB3" * 25 + "\n"), []
        )

    def test_quoted_still_caught(self):
        self.assertEqual(
            hits("generic-api-key", 'api_key = "g9K2xQ7mZ4vL1pW8nR3tY6uI"'),
            ["g9K2xQ7mZ4vL1pW8nR3tY6uI"],
        )


class PrecisionEvidenceTest(unittest.TestCase):
    """False positives measured on psf/requests history after the first
    unquoted-value change; these shapes must stay quiet."""

    def test_code_expressions_not_passwords(self):
        for line in (
            "        username, password = get_auth_from_url(proxy)",
            "            password = unquote(password)",
            "        password = password.encode('latin1')",
            "        if reduced_uri not in self.passwd:",
        ):
            self.assertEqual(hits("generic-password", line), [], line)

    def test_base64_stream_containing_aws_not_a_secret(self):
        # Cert bundles are 64-char base64 lines; "aws" occurs by chance.
        line = "aWsgQXJhxZ90xLFybWEgS3VydW11IC0gVMOcQsSwVEFLMUgwRgYDVQQLDD9VbHVzYWwgRWxla3Ry"
        self.assertEqual(hits("aws-secret-access-key", line), [])

    def test_dotted_identifier_not_api_key(self):
        self.assertEqual(
            hits("generic-api-key", "api_key = settings.SERVICE_API_KEY\n"), []
        )
        self.assertEqual(
            hits("generic-api-key", "api_key = config.services.api_key_value\n"),
            [],
        )

    def test_rfc_example_token_still_structural_match(self):
        # RFC 6749's documentation example; a deliberate true structural hit.
        line = "Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA"
        self.assertEqual(
            hits("generic-api-key", line), ["2YotnFZFEjr1zCsicMWpAA"]
        )


class AIProviderRuleTest(unittest.TestCase):
    def test_anthropic_key(self):
        token = "sk-ant-api03-" + "Zx9Qw8Lp2Mn4Vb7Kj3Hg6F" + "d5Sa1Rt0Yu"
        self.assertEqual(
            hits("anthropic-api-key", 'ANTHROPIC_API_KEY="' + token + '"'),
            [token],
        )

    def test_openai_project_key(self):
        token = "sk-proj-" + "Zx7Qw9Lp2Mn4Vb8" * 3
        self.assertEqual(
            hits("openai-project-key", "OPENAI_API_KEY=" + token + "\n"),
            [token],
        )

    def test_bare_sk_without_prefix_not_flagged(self):
        self.assertEqual(
            hits("openai-project-key", "key = sk-notaprojkeyhere\n"), []
        )
