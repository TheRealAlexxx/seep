"""Detection rules: structural patterns plus optional entropy checks.

Each rule pairs a regular expression with a cheap keyword prefilter. The
prefilter keeps scanning fast: a rule only runs its regex against a file
when one of its keywords appears in the file's text. Rules that would match
almost anything (generic password assignments) also require an entropy check
on the captured value so that obvious placeholders stay quiet.

Every fixture used in tests and documentation is a publicly documented
non-live example (for instance AWS's documentation key pair) or a randomly
generated dummy in the right format.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Tuple

from .entropy import is_high_entropy


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern
    severity: str  # "low", "medium", "high"
    keywords: Tuple[str, ...] = field(default=())
    secret_group: int = 0  # capture group holding the secret; 0 = whole match
    entropy_group: Optional[int] = None  # group to entropy-check, if any
    entropy_min: float = 4.3
    entropy_min_length: int = 16  # floor for the entropy check on this rule
    reject: Optional[re.Pattern] = None  # secrets matching this are dropped

    def applies_to(self, text):
        """Cheap prefilter: any keyword must be present (case-insensitive)."""
        if not self.keywords:
            return True
        lowered = text.lower()
        return any(k in lowered for k in self.keywords)

    def finditer(self, text):
        if not self.applies_to(text):
            return
        for match in self.pattern.finditer(text):
            if self.reject is not None and self.reject.match(
                    match.group(self.secret_group)):
                continue
            if self.entropy_group is not None:
                candidate = match.group(self.entropy_group)
                if not is_high_entropy(candidate, threshold=self.entropy_min,
                                       min_length=self.entropy_min_length):
                    continue
            yield match


def _rule(rule_id, description, pattern, severity, keywords=(),
          secret_group=0, entropy_group=None, entropy_min=4.3,
          entropy_min_length=16, reject=None, flags=re.IGNORECASE):
    return Rule(
        id=rule_id,
        description=description,
        pattern=re.compile(pattern, flags),
        severity=severity,
        keywords=tuple(k.lower() for k in keywords),
        secret_group=secret_group,
        entropy_group=entropy_group,
        entropy_min=entropy_min,
        entropy_min_length=entropy_min_length,
        reject=re.compile(reject) if isinstance(reject, str) else reject,
    )


RULES = [
    # --- Cloud providers ---
    _rule(
        "aws-access-key-id",
        "AWS access key ID",
        r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
        "high",
        secret_group=1,
        flags=0,
    ),
    _rule(
        "aws-secret-access-key",
        "AWS secret access key",
        r"(?i)\baws[0-9a-z_\-]{0,40}?\s*[:=]\s*['\"]?([0-9a-zA-Z/+]{40})(?![0-9a-zA-Z/+])['\"]?",
        "high",
        keywords=("aws", "secret"),
        secret_group=1,
        entropy_group=1,
        entropy_min=4.3,
    ),
    _rule(
        "azure-connection-string",
        "Azure connection string with account key",
        r"(?:DefaultEndpointsProtocol|AccountName)=[^;]+;[^\n]*AccountKey=([0-9a-zA-Z+/=]{60,})",
        "high",
        keywords=("accountkey=",),
        secret_group=1,
    ),
    # --- Git hosting ---
    _rule(
        "github-pat",
        "GitHub personal access token",
        r"\b(ghp_[0-9a-zA-Z]{36})\b",
        "high",
        keywords=("ghp_",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "github-fine-grained-pat",
        "GitHub fine-grained personal access token",
        r"\b(github_pat_[0-9a-zA-Z_]{82})\b",
        "high",
        keywords=("github_pat_",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "github-oauth-token",
        "GitHub OAuth or app token",
        r"\b(gh[ousr]_[0-9a-zA-Z]{36})\b",
        "high",
        keywords=("gho_", "ghu_", "ghs_", "ghr_"),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "github-refresh-token",
        "GitHub refresh token (old format)",
        r"\b(ghr_[0-9a-zA-Z]{76})\b",
        "high",
        keywords=("ghr_",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "gitlab-pat",
        "GitLab personal access token",
        r"\b(glpat-[0-9a-zA-Z\-_]{20})\b",
        "high",
        keywords=("glpat-",),
        secret_group=1,
        flags=0,
    ),
    # --- Payments ---
    _rule(
        "stripe-live-secret",
        "Stripe live secret key",
        r"\b([sr]k_live_[0-9a-zA-Z]{16,})\b",
        "high",
        keywords=("sk_live_", "rk_live_"),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "stripe-restricted-test",
        "Stripe test secret key",
        r"\b(sk_test_[0-9a-zA-Z]{16,})\b",
        "medium",
        keywords=("sk_test_",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "square-access-token",
        "Square access token",
        r"\b(sq0atp-[0-9A-Za-z\-_]{22})\b",
        "high",
        keywords=("sq0atp-",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "square-oauth-secret",
        "Square OAuth secret",
        r"\b(sq0csp-[0-9A-Za-z\-_]{43})\b",
        "high",
        keywords=("sq0csp-",),
        secret_group=1,
        flags=0,
    ),
    # --- Communication platforms ---
    _rule(
        "slack-token",
        "Slack token",
        r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[0-9a-zA-Z-]*)\b",
        "high",
        keywords=("xox",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "slack-webhook",
        "Slack incoming webhook URL",
        r"(https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{20,})",
        "high",
        keywords=("hooks.slack.com",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "discord-bot-token",
        "Discord bot token",
        r"\b((?:M|T)[A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,})\b",
        "high",
        keywords=("discord", "bot", "token"),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "telegram-bot-token",
        "Telegram bot token",
        r"\b(\d{8,10}:[0-9A-Za-z_-]{30,46})\b",
        "high",
        keywords=("telegram", "bot", "t.me", "api.telegram"),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "twilio-api-key",
        "Twilio API key",
        r"\bSK[0-9a-f]{32}\b",
        "high",
        keywords=("twilio",),
        flags=0,
    ),
    _rule(
        "sendgrid-api-key",
        "SendGrid API key",
        r"\b(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b",
        "high",
        keywords=("sg.", "sendgrid"),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "mailchimp-api-key",
        "Mailchimp API key",
        r"\b([0-9a-f]{32}-us\d{1,2})\b",
        "high",
        keywords=("mailchimp",),
        secret_group=1,
        flags=0,
    ),
    # --- Google ---
    _rule(
        "google-api-key",
        "Google API key",
        r"\b(AIza[0-9A-Za-z\-_]{35})\b",
        "high",
        keywords=("aiza",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "google-oauth-client-secret",
        "Google OAuth client secret",
        r"\b(GOCSPX-[0-9A-Za-z\-_]{28})\b",
        "high",
        keywords=("gocspx-",),
        secret_group=1,
        flags=0,
    ),
    # --- Package registries / dev platforms ---
    _rule(
        "npm-access-token",
        "npm access token",
        r"\b(npm_[0-9a-zA-Z]{36})\b",
        "high",
        keywords=("npm_",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "pypi-api-token",
        "PyPI API token",
        r"\b(pypi-AgEIcHlwaS5vcmc[0-9A-Za-z\-_]{50,})\b",
        "high",
        keywords=("pypi-",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "digitalocean-pat",
        "DigitalOcean personal access token",
        r"\b(do[op]_v1_[0-9a-f]{64})\b",
        "high",
        keywords=("dop_v1_", "doo_v1_"),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "heroku-api-key",
        "Heroku API key",
        r"(?i)heroku(.{0,20})?['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
        "high",
        keywords=("heroku",),
        secret_group=2,
    ),
    _rule(
        "linear-api-key",
        "Linear API key",
        r"\b(lin_api_[0-9a-zA-Z]{40})\b",
        "high",
        keywords=("lin_api_",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "shopify-access-token",
        "Shopify private app access token",
        r"\b(shpat_[0-9a-fA-F]{32})\b",
        "high",
        keywords=("shpat_",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "supabase-service-key",
        "Supabase service key",
        r"\b(sbp_[0-9a-f]{40})\b",
        "high",
        keywords=("sbp_",),
        secret_group=1,
        flags=0,
    ),
    # --- AI providers ---
    # Prefixes grounded in owning sources: Anthropic's official docs show
    # keys starting sk-ant- (example sk-ant-api03-...); sk-proj- is the
    # current OpenAI project-key prefix per OpenAI's own community forum.
    # Length floors are conservative, not format claims.
    _rule(
        "anthropic-api-key",
        "Anthropic API key",
        r"\b(sk-ant-[0-9A-Za-z\-_]{20,})\b",
        "high",
        keywords=("sk-ant-",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "openai-project-key",
        "OpenAI project API key",
        r"\b(sk-proj-[0-9A-Za-z\-_]{20,})\b",
        "high",
        keywords=("sk-proj-",),
        secret_group=1,
        flags=0,
    ),
    # --- Structured secrets ---
    _rule(
        "jwt",
        "JSON Web Token",
        r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b",
        "medium",
        keywords=("eyj",),
        secret_group=1,
        flags=0,
    ),
    _rule(
        "private-key-block",
        "Private key block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        "high",
        keywords=("-----begin", "private key"),
        flags=0,
    ),
    _rule(
        "database-url",
        "Database connection URL with credentials",
        r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]{1,64}:[^@\s/]{4,}@[^\s'\"]+)",
        "high",
        keywords=("://", "postgres", "mysql", "mongodb", "redis", "amqp", "mariadb"),
        secret_group=1,
        flags=0,
    ),
    # --- Generic assignments (entropy-gated) ---
    _rule(
        "generic-password",
        "Hardcoded password assignment",
        r"(?i)\b(pass(?:word|wd|phrase)|pwd)\b\s*[:=]\s*['\"]([^'\"\s]{8,64})['\"]",
        "medium",
        keywords=("password", "passwd", "pwd", "passphrase"),
        secret_group=2,
        entropy_group=2,
        entropy_min=3.5,
        entropy_min_length=8,
        flags=0,
    ),
    _rule(
        "generic-api-key",
        "Hardcoded API key assignment",
        r"(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]?([0-9a-zA-Z\-_+/=.]{16,64})(?![0-9a-zA-Z\-_+/=.])['\"]?",
        "medium",
        keywords=("api_key", "apikey", "api-key", "access_token", "access-token",
                  "auth_token", "auth-token", "client_secret", "client-secret"),
        secret_group=2,
        entropy_group=2,
        entropy_min=4.0,
        entropy_min_length=12,
        reject=r"(?i)[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+\Z",
        flags=0,
    ),
]

_RULES_BY_ID = {rule.id: rule for rule in RULES}


def get_rule(rule_id):
    return _RULES_BY_ID[rule_id]
