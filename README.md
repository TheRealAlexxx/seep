# seep

Find secrets that seeped into your code and git history. Zero dependencies, pure Python 3.9+ standard library. Clone it, run it, nothing to install.

```
$ python -m seep scan .
src/config.py
  L7 [high] aws-access-key-id
    AKIA...MPLE
seep: 1 finding (1 high)
```

seep scans the working tree, full git history, or just staged changes. It reports where each secret lives, when it entered history and who committed it, with the secret itself always redacted.

**Honest scope:** seep is a heuristic scanner. A clean result does not prove a repository is secret-free, and a finding is a lead to check, not proof of compromise. Established tools in this space (gitleaks, trufflehog, detect-secrets) are more mature; seep's niche is running anywhere Python runs with no install step, no binary downloads and no dependency tree.

## Quickstart

1. Clone the repo: `git clone https://github.com/TheRealAlexxx/seep`
2. Run it against any project: `python -m seep scan /path/to/project`
3. Nothing found? Exit code 0. Findings? Exit code 1 with a redacted report.

To install the `seep` command instead of `python -m seep`: `pip install .` (still no dependencies).

## Usage

```
python -m seep scan .                     # working tree
python -m seep scan . --history           # full git history, with blame
python -m seep scan . --since 2026-01-01  # history since a date
python -m seep scan . --staged            # staged changes only (pre-commit)
python -m seep scan . --format sarif      # text, json or sarif
python -m seep scan . --fail-on high      # only fail on high severity
python -m seep rules                      # list the detection rules
```

### Working tree vs history

A default scan reads files as they are now. `--history` walks every commit oldest-first and scans only the lines each commit added, so a secret that was deleted years ago still shows up, attributed to the commit that introduced it:

```
config.py
  L1 [high] aws-access-key-id (introduced a54ae81f3b2c by Alex)
    AKIA...MPLE
```

Each distinct secret is reported once, at the earliest commit containing it. That is the commit list you need if you decide to rewrite history.

### Baselines: adopt seep in a repo that already leaks

1. Snapshot what exists: `python -m seep scan . --write-baseline .seep-baseline.json`
2. From then on, fail only on new leaks: `python -m seep scan . --baseline .seep-baseline.json`
3. Rotate or remove the old secrets, regenerate the baseline when one is fixed.

A baseline stores rule, path and a truncated SHA-256 fingerprint of each secret. It never contains the secret itself, so it is safe to commit.

### Pre-commit hook

With [pre-commit](https://pre-commit.com), add to `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/TheRealAlexxx/seep
  rev: main
  hooks:
    - id: seep
```

Or without pre-commit, as a git hook (`.git/hooks/pre-commit`):

```sh
#!/bin/sh
python -m seep scan --staged
```

### GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: '3.13'
- run: python -m pip install .
- run: seep scan . --history --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

seep runs exactly this against itself - see `.github/workflows/tests.yml`. Its own test fixtures are exempted through the `seep.json` allowlist in this repo, which doubles as a worked config example.

### Ignoring things

Inline, for one line:

```python
example_key = "AKIAIOSFODNN7EXAMPLE"  # seep:ignore
```

Repo-wide, in `seep.json` (or `.seep.json`) at the root:

```json
{
  "allowlist": ["^tests/", "^docs/"],
  "exclude_rules": ["jwt"],
  "fail_on": "medium",
  "max_file_bytes": 2097152
}
```

Allowlist entries are regexes matched against file paths and matched secret values. `exclude_rules` switches rules off entirely.

## Detection rules

| `aws-access-key-id` | high | AWS access key ID |
| `aws-secret-access-key` | high | AWS secret access key |
| `azure-connection-string` | high | Azure connection string with account key |
| `database-url` | high | Database connection URL with credentials |
| `digitalocean-pat` | high | DigitalOcean personal access token |
| `discord-bot-token` | high | Discord bot token |
| `github-fine-grained-pat` | high | GitHub fine-grained personal access token |
| `github-oauth-token` | high | GitHub OAuth or app token |
| `github-pat` | high | GitHub personal access token |
| `github-refresh-token` | high | GitHub refresh token (old format) |
| `gitlab-pat` | high | GitLab personal access token |
| `google-api-key` | high | Google API key |
| `google-oauth-client-secret` | high | Google OAuth client secret |
| `heroku-api-key` | high | Heroku API key |
| `linear-api-key` | high | Linear API key |
| `mailchimp-api-key` | high | Mailchimp API key |
| `npm-access-token` | high | npm access token |
| `private-key-block` | high | Private key block |
| `pypi-api-token` | high | PyPI API token |
| `sendgrid-api-key` | high | SendGrid API key |
| `shopify-access-token` | high | Shopify private app access token |
| `slack-token` | high | Slack token |
| `slack-webhook` | high | Slack incoming webhook URL |
| `square-access-token` | high | Square access token |
| `square-oauth-secret` | high | Square OAuth secret |
| `stripe-live-secret` | high | Stripe live secret key |
| `supabase-service-key` | high | Supabase service key |
| `telegram-bot-token` | high | Telegram bot token |
| `twilio-api-key` | high | Twilio API key |
| `generic-api-key` | medium | Hardcoded API key assignment |
| `generic-password` | medium | Hardcoded password assignment |
| `jwt` | medium | JSON Web Token |
| `stripe-restricted-test` | medium | Stripe test secret key |

Structural rules match documented token formats (prefixes, lengths, alphabets). Generic password/API-key rules only fire when the assigned value also passes a Shannon-entropy check, which is what keeps `password = "hunter2"` from paging you.

## Design notes

- **Stdlib only, on purpose.** Every import is Python's standard library, so the scanner runs in minimal CI images, on locked-down machines and inside other tools without an install step. The cost is reinventing some wheels (JSON config instead of TOML, `unittest` instead of pytest); the payoff is zero supply-chain surface for a security tool.
- **Keyword prefilter before regex.** Each rule declares substrings that must appear in a file before its regex runs (e.g. `glpat-` for GitLab tokens). Most files trigger most rules' prefilters on nothing, so scanning stays fast without an index.
- **Entropy is a filter, not a detector.** Shannon entropy on its own flags half the identifiers in any codebase. seep uses it only to gate generic assignment rules, with thresholds tuned per charset (hex tops out at 4 bits/char, base64 at 6).
- **Secrets are redacted at the boundary.** The scanner extracts a match, immediately reduces it to a fingerprint plus an edge-redacted display form, and the full value never reaches a Finding object, report, baseline or log line. Output is safe to paste into tickets and CI logs.
- **Oldest-first history walk.** Scanning added lines per commit (instead of every full tree) keeps history scans proportional to total diff size, and reporting first-introduction makes the remediation answer - "what do I rewrite" - direct.

## Limitations

- Regex plus entropy cannot understand context. Obfuscated or split secrets, secrets in binary blobs, and formats with no documented shape will be missed.
- Inline `seep:ignore` and allowlists are honor-system; a determined insider can hide anything from any scanner.
- History scans use `git show` per commit. On very large histories that is thorough rather than fast.

## Development

```
python -m unittest discover -s tests -v
```

108 tests cover the entropy engine, every rule (positive and negative fixtures), the scanner, git attribution, baselines, output formats, config and CLI exit codes. Test fixtures are publicly documented non-live example credentials (e.g. AWS's documentation key pair) or generated dummies in the right format.

## License

MIT
