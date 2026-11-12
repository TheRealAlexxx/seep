"""Shannon-entropy analysis for spotting high-entropy strings.

Secrets are usually random: API keys, tokens and generated passwords have far
more entropy per character than English words or identifiers. Entropy alone
cannot prove a string is a secret, but it is a strong filter on top of
structural rules, which keeps false positives down.
"""

import math
from collections import Counter

HEX_CHARS = frozenset("0123456789abcdefABCDEF")
BASE32_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
BASE64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
)

# Thresholds are in bits per character. Pure hex tops out at 4.0 bits/char,
# base64 at 6.0, so a threshold must sit well below the ceiling of its
# charset but above natural text (~3.5-4.0 for base64-ish identifiers).
DEFAULT_THRESHOLDS = {
    "hex": 3.0,
    "base32": 4.0,
    "base64": 4.3,
    "unknown": 4.0,
}

MIN_LENGTH = 16


def shannon_entropy(data):
    """Return the Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def classify_charset(value):
    """Best-effort charset classification: hex, base32, base64 or unknown."""
    if not value:
        return "unknown"
    chars = set(value)
    if chars <= HEX_CHARS and any(c.isdigit() for c in chars) and any(
        c in "abcdefABCDEF" for c in chars
    ):
        return "hex"
    if chars <= BASE32_CHARS and value.isupper():
        return "base32"
    if chars <= BASE64_CHARS:
        return "base64"
    return "unknown"


def is_high_entropy(value, threshold=None, min_length=MIN_LENGTH):
    """True when a string looks random enough to be a candidate secret.

    Short strings are never flagged: entropy estimates on them are noise.
    The default threshold depends on the detected charset.
    """
    if len(value) < min_length:
        return False
    charset = classify_charset(value)
    if threshold is None:
        threshold = DEFAULT_THRESHOLDS[charset]
    return shannon_entropy(value) >= threshold


def redact(secret, visible=4):
    """Show only the edges of a secret so output is safe to share."""
    if len(secret) <= visible * 2:
        return "*" * len(secret)
    return "{}...{}".format(secret[:visible], secret[-visible:])
