"""Filesystem scanning: walk files, apply rules, produce findings.

Findings never contain the full matched secret. They carry a fingerprint
(a truncated SHA-256 of the secret, used for baselining and dedupe) and a
redacted display form, so reports are safe to paste into tickets and CI logs.
"""

import hashlib
import os
import re
import subprocess
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .entropy import redact
from .rules import RULES

DEFAULT_MAX_FILE_BYTES = 1024 * 1024  # 1 MiB
IGNORE_COMMENT = "seep:ignore"
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "__pycache__"})


def _fingerprint(secret):
    return hashlib.sha256(secret.encode("utf-8", "surrogateescape")).hexdigest()[:16]


@dataclass
class Finding:
    rule_id: str
    severity: str
    path: str
    line_number: int
    redacted_secret: str
    secret_fingerprint: str
    line_preview: str
    commit: Optional[str] = None
    author: Optional[str] = None
    commit_date: Optional[str] = None

    @property
    def uid(self):
        """Stable identity for baseline matching and dedupe."""
        return "{}:{}:{}".format(self.rule_id, self.path, self.secret_fingerprint)


def _line_offsets(text):
    offsets = [0]
    for match in re.finditer("\n", text):
        offsets.append(match.end())
    return offsets


def _looks_binary(chunk):
    return b"\x00" in chunk


class Scanner:
    def __init__(self, rules=None, allowlist=(), max_file_bytes=DEFAULT_MAX_FILE_BYTES):
        self.rules = list(rules) if rules is not None else list(RULES)
        self.allowlist = [re.compile(p) for p in allowlist]
        self.max_file_bytes = max_file_bytes
        self.skipped_large = 0
        self.skipped_binary = 0

    def _allowlisted(self, path, secret):
        return any(p.search(path) or p.search(secret) for p in self.allowlist)

    def scan_text(self, text, path="<text>"):
        """Scan a string and return findings with full secrets stripped out.

        Two passes: first collect every match, then build findings. A
        finding's line preview must redact EVERY detected secret on the
        line, not just its own - otherwise a finding for one secret would
        leak any co-located secret in the clear.
        """
        offsets = _line_offsets(text)
        lines = text.splitlines()
        collected = []
        for rule in self.rules:
            for match in rule.finditer(text):
                secret = match.group(rule.secret_group)
                if self._allowlisted(path, secret):
                    continue
                line_no = bisect_right(offsets, match.start())
                line_text = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                if IGNORE_COMMENT in line_text:
                    continue
                collected.append((rule, match, secret, line_no))
        secrets_by_line = {}
        for _, _, secret, line_no in collected:
            secrets_by_line.setdefault(line_no, set()).add(secret)
        findings = []
        seen = set()
        for rule, _, secret, line_no in collected:
            fp = _fingerprint(secret)
            key = (rule.id, fp, line_no)
            if key in seen:
                continue
            seen.add(key)
            line_text = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            preview = line_text
            # Longest first so a secret that is a substring of another
            # (e.g. a password inside a database URL) is already gone when
            # the shorter one is replaced.
            for other in sorted(secrets_by_line[line_no], key=len, reverse=True):
                preview = preview.replace(other, redact(other))
            findings.append(Finding(
                rule_id=rule.id,
                severity=rule.severity,
                path=path,
                line_number=line_no,
                redacted_secret=redact(secret),
                secret_fingerprint=fp,
                line_preview=preview.strip()[:200],
            ))
        findings.sort(key=lambda f: (f.path, f.line_number, f.rule_id))
        return findings

    def scan_file(self, path, display_path=None):
        try:
            size = os.path.getsize(path)
        except OSError:
            return []
        if size > self.max_file_bytes:
            self.skipped_large += 1
            return []
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError:
            return []
        if _looks_binary(raw[:65536]):
            self.skipped_binary += 1
            return []
        text = raw.decode("utf-8", "replace")
        return self.scan_text(text, path=display_path or path)

    def _iter_files_git(self, root):
        try:
            out = subprocess.run(
                ["git", "-C", root, "ls-files", "-c", "-o",
                 "--exclude-standard", "-z"],
                capture_output=True, check=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            return None
        return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]

    def _iter_files_walk(self, root):
        paths = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                full = os.path.join(dirpath, name)
                paths.append(os.path.relpath(full, root))
        return sorted(paths)

    def iter_files(self, root):
        """Files to scan. Inside a git repo this respects .gitignore."""
        rel_paths = self._iter_files_git(root)
        if rel_paths is None:
            rel_paths = self._iter_files_walk(root)
        for rel in sorted(rel_paths):
            yield rel, os.path.join(root, rel)

    def scan_directory(self, root):
        findings = []
        for rel, full in self.iter_files(root):
            if not os.path.isfile(full) or os.path.islink(full):
                continue
            findings.extend(self.scan_file(full, display_path=rel))
        findings.sort(key=lambda f: (f.path, f.line_number, f.rule_id))
        return findings
