import unittest

from seep.entropy import (
    classify_charset,
    is_high_entropy,
    redact,
    shannon_entropy,
)


class ShannonEntropyTest(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_repeated_char_is_zero(self):
        self.assertEqual(shannon_entropy("aaaaaaaaaaaaaaaa"), 0.0)

    def test_two_symbols_equally_likely_is_one_bit(self):
        self.assertAlmostEqual(shannon_entropy("abababab"), 1.0)

    def test_hex_digit_ceiling(self):
        # Uniform over 16 hex digits gives exactly 4 bits/char.
        value = "0123456789abcdef"
        self.assertAlmostEqual(shannon_entropy(value), 4.0)

    def test_english_is_lower_than_random(self):
        english = "the quick brown fox jumps over the lazy dog" * 2
        randomish = "X7kQ9mZ2vL4pW8nR1tY6uI3oP0aS5dF7gH9jK2"
        self.assertLess(shannon_entropy(english), shannon_entropy(randomish))


class ClassifyCharsetTest(unittest.TestCase):
    def test_hex(self):
        self.assertEqual(classify_charset("a1b2c3d4e5f6a7b8"), "hex")

    def test_pure_digits_are_not_hex(self):
        self.assertNotEqual(classify_charset("1234567890123456"), "hex")

    def test_pure_letters_are_not_hex(self):
        self.assertNotEqual(classify_charset("deadbeefcafe"), "hex")

    def test_base64(self):
        self.assertEqual(
            # Assembled at runtime: complete token-shaped literals must never be
            # committed, even as fixtures (GitHub push protection scans history).
            classify_charset("glpat-" + "xKq9mZ2vL4pW8nR1tY6u"), "base64"
        )

    def test_unknown_with_symbols(self):
        self.assertEqual(classify_charset("hello world!"), "unknown")


class IsHighEntropyTest(unittest.TestCase):
    def test_real_stripe_style_key(self):
        self.assertTrue(
            is_high_entropy("4eC39HqLyjWDarjtT1zdp7dc", min_length=20)
        )

    def test_hex_secret(self):
        self.assertTrue(is_high_entropy("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"))

    def test_short_strings_never_flag(self):
        self.assertFalse(is_high_entropy("aX9kQ2mZ"))

    def test_password_words_do_not_flag(self):
        self.assertFalse(is_high_entropy("correcthorsebatterystaple"))

    def test_repeated_padding_does_not_flag(self):
        self.assertFalse(is_high_entropy("abcabcabcabcabcabcabcabc"))

    def test_explicit_threshold_overrides_charset_default(self):
        value = "0123456789abcdef0123"
        self.assertFalse(is_high_entropy(value, threshold=4.1))


class RedactTest(unittest.TestCase):
    def test_long_secret_shows_edges(self):
        self.assertEqual(redact("ghp_abcdefghij0123456789"), "ghp_...6789")

    def test_short_secret_fully_masked(self):
        self.assertEqual(redact("abc123"), "******")

    def test_full_secret_never_appears(self):
        secret = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"  # assembled, see above
        self.assertNotIn(secret, redact(secret))


if __name__ == "__main__":
    unittest.main()
