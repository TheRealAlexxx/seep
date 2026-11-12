"""Git history scanning: find when secrets were introduced.

Walks commits oldest-first and scans only lines each commit adds. A finding
is attributed to the first commit where its (rule, path, secret-fingerprint)
combination appears, which answers the question a developer actually asks:
"when did this get in, and what do I need to rewrite?"
"""

import re
import subprocess
import tempfile
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


_LOG_MARK = "SEEP-COMMIT\x1f"


def scan_history(scanner, root, since=None, rev="--all", first_only=True):
    """Scan git history. Returns findings attributed to introducing commits.

    Streams a single `git log -p` process instead of spawning git per
    commit - the difference between one subprocess and one per commit is
    most of the runtime on real histories. -m makes merge commits diff
    against each parent in regular format, so changes made inside merges
    (conflict resolutions) are scanned. Parent-1 sections arrive first, and
    oldest-first order plus first_only dedupe means anything also present
    in a branch commit is attributed there, not to the merge.

    --first-parent must NOT be passed to git log itself: it restricts
    traversal, silently hiding every commit on a merged branch.

    With first_only=True (default) each unique (rule, path, fingerprint) is
    reported once, at the earliest commit that introduced it.
    """
    args = ["log", "--reverse", "-p", "--unified=0", "-m",
            "--format=" + _LOG_MARK + "%H%x1f%an%x1f%aI", rev]
    if since:
        args.append("--since=" + since)
    findings = []
    seen = set()
    current = None
    diff_lines = []

    def flush():
        if current is None:
            return
        sha, author, date = current
        added = {}
        for path, line_no, text in parse_added_lines("\n".join(diff_lines)):
            added.setdefault(path, []).append((line_no, text))
        for finding in _scan_added(scanner, added, sha[:12], author, date):
            if first_only:
                if finding.uid in seen:
                    continue
                seen.add(finding.uid)
            findings.append(finding)

    err_file = tempfile.TemporaryFile()
    try:
        proc = subprocess.Popen(
            ["git", "-C", root] + args,
            stdout=subprocess.PIPE, stderr=err_file,
            encoding="utf-8", errors="surrogateescape",
        )
    except FileNotFoundError:
        err_file.close()
        raise GitError("git executable not found")
    for line in proc.stdout:
        if line.startswith(_LOG_MARK):
            flush()
            _, sha, author, date = line.rstrip("\n").split("\x1f")
            current = (sha, author, date)
            diff_lines = []
        else:
            diff_lines.append(line.rstrip("\n"))
    flush()
    returncode = proc.wait()
    err_file.seek(0)
    stderr = err_file.read().decode("utf-8", "replace")
    err_file.close()
    if returncode != 0:
        raise GitError(stderr.strip() or "git log failed")
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
