"""Git history scanning: find when secrets were introduced.

Walks commits oldest-first and scans only lines each commit adds. A finding
is attributed to the first commit where its (rule, path, secret-fingerprint)
combination appears, which answers the question a developer actually asks:
"when did this get in, and what do I need to rewrite?"
"""

import re
import subprocess
from bisect import bisect_right
from dataclasses import replace
from typing import List, Optional, Tuple

from .scanner import Finding, IGNORE_COMMENT, Scanner, _fingerprint, _line_offsets
from .entropy import redact

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_SEP = "\x1f"


class GitError(RuntimeError):
    pass


def _run_git(root, args):
    try:
        result = subprocess.run(
            ["git", "-C", root] + args, capture_output=True, check=True
        )
    except FileNotFoundError:
        raise GitError("git executable not found")
    except subprocess.CalledProcessError as exc:
        raise GitError(exc.stderr.decode("utf-8", "replace").strip() or "git failed")
    return result.stdout.decode("utf-8", "surrogateescape")


def is_git_repo(root):
    try:
        _run_git(root, ["rev-parse", "--git-dir"])
        return True
    except GitError:
        return False


def iter_commits(root, since=None, rev="--all"):
    """Commits oldest-first as (sha, author, iso_date) tuples."""
    args = ["log", "--format=%H%x1f%an%x1f%aI", "--reverse", rev]
    if since:
        args.append("--since=" + since)
    out = _run_git(root, args)
    commits = []
    for line in out.splitlines():
        if not line.strip():
            continue
        sha, author, date = line.split(_SEP)
        commits.append((sha, author, date))
    return commits


def parse_added_lines(diff_text):
    """Yield (path, line_number, added_text) from a zero-context diff.

    File headers (---/+++) are only headers before the first hunk of a file
    section; inside a hunk, content may legitimately start with "++" (or
    anything else), so hunk state is tracked explicitly.
    """
    path = None
    new_line = 0
    in_hunk = False
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
        elif not in_hunk and line.startswith("+++ b/"):
            path = line[len("+++ b/"):]
        elif not in_hunk and line.startswith("+++ "):
            path = line[4:]
        elif line.startswith("@@"):
            match = _HUNK_RE.match(line)
            if match:
                new_line = int(match.group(1))
                in_hunk = True
        elif in_hunk and line.startswith("+"):
            if path is not None and path != "/dev/null":
                yield path, new_line, line[1:]
            new_line += 1
        elif in_hunk and line.startswith("-"):
            continue
        elif in_hunk:
            if not line.startswith("\\"):
                new_line += 1


def _scan_added(scanner, added, commit, author, date):
    """Scan added lines of one commit, attributing findings to it."""
    findings = []
    for path, lines in added.items():
        text = "\n".join(line for _, line in lines)
        for finding in scanner.scan_text(text, path=path):
            # scan_text computes line numbers within the joined text; map them
            # back to real file line numbers.
            real_line = lines[finding.line_number - 1][0]
            findings.append(replace(
                finding,
                line_number=real_line,
                commit=commit,
                author=author,
                commit_date=date,
            ))
    return findings


def scan_history(scanner, root, since=None, rev="--all", first_only=True):
    """Scan git history. Returns findings attributed to introducing commits.

    With first_only=True (default) each unique (rule, path, fingerprint) is
    reported once, at the earliest commit that introduced it.
    """
    commits = iter_commits(root, since=since, rev=rev)
    findings = []
    seen = set()
    for sha, author, date in commits:
        # -m --first-parent: merge commits produce a regular diff against
        # their first parent, so changes made inside merges (conflict
        # resolutions) are scanned with correct paths and line numbers.
        # Without it, merges print a combined diff a line parser cannot
        # handle, or nothing at all.
        diff = _run_git(root, ["show", "--format=", "--unified=0",
                               "-m", "--first-parent", sha])
        added = {}
        for path, line_no, text in parse_added_lines(diff):
            added.setdefault(path, []).append((line_no, text))
        for finding in _scan_added(scanner, added, sha[:12], author, date):
            if first_only:
                if finding.uid in seen:
                    continue
                seen.add(finding.uid)
            findings.append(finding)
    findings.sort(key=lambda f: (f.path, f.line_number, f.rule_id))
    return findings


def scan_staged(scanner, root):
    """Scan staged-but-uncommitted changes (for pre-commit use)."""
    diff = _run_git(root, ["diff", "--cached", "--unified=0"])
    added = {}
    for path, line_no, text in parse_added_lines(diff):
        added.setdefault(path, []).append((line_no, text))
    findings = []
    seen = set()
    for finding in _scan_added(scanner, added, None, None, None):
        if finding.uid in seen:
            continue
        seen.add(finding.uid)
        findings.append(finding)
    findings.sort(key=lambda f: (f.path, f.line_number, f.rule_id))
    return findings
