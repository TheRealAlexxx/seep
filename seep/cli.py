"""Command line interface.

Exit codes: 0 = no findings at or above the fail threshold, 1 = findings,
2 = usage or runtime error.
"""

import argparse
import os
import sys

from . import __version__
from .baseline import filter_new, load_baseline, write_baseline
from .config import ConfigError, load_config
from .git import GitError, is_git_repo, scan_history, scan_staged
from .output import meets_threshold, to_json, to_sarif, to_text
from .rules import RULES
from .scanner import Scanner

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_RULES_BY_ID = {r.id: r for r in RULES}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="seep",
        description="Find secrets that seeped into your code and git history. "
                    "Heuristic: a clean result does not prove a repo is secret-free.",
    )
    parser.add_argument("--version", action="version",
                        version="seep " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a directory or git history")
    scan.add_argument("path", nargs="?", default=".",
                      help="directory or repo to scan (default: current)")
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true",
                      help="scan staged changes only (pre-commit use)")
    mode.add_argument("--history", action="store_true",
                      help="scan full git history instead of working tree")
    mode.add_argument("--since", metavar="DATE",
                      help="scan git history since DATE (implies --history)")
    scan.add_argument("--baseline", metavar="FILE",
                      help="only report findings not in FILE")
    scan.add_argument("--write-baseline", metavar="FILE",
                      help="write all findings to FILE as a new baseline")
    scan.add_argument("--format", choices=("text", "json", "sarif"),
                      default="text")
    scan.add_argument("--fail-on", choices=("low", "medium", "high"),
                      help="minimum severity that triggers exit code 1")
    scan.add_argument("--config", metavar="FILE", help="config file path")

    rules_cmd = sub.add_parser("rules", help="list detection rules")
    rules_cmd.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _apply_config(args, root):
    config = load_config(root=root, path=args.config)
    if args.fail_on is None:
        args.fail_on = config["fail_on"]
    return config


def _run_scan(args):
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print("seep: %s is not a directory" % args.path, file=sys.stderr)
        return EXIT_ERROR
    try:
        config = _apply_config(args, root)
    except ConfigError as exc:
        print("seep: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    known_ids = {r.id for r in RULES}
    unknown = set(config["exclude_rules"]) - known_ids
    if unknown:
        print("seep: unknown rules in exclude_rules: %s"
              % ", ".join(sorted(unknown)), file=sys.stderr)
        return EXIT_ERROR
    rules = [r for r in RULES if r.id not in config["exclude_rules"]]
    scanner = Scanner(rules=rules, allowlist=config["allowlist"],
                      max_file_bytes=config["max_file_bytes"])

    try:
        if args.staged:
            if not is_git_repo(root):
                print("seep: --staged needs a git repository", file=sys.stderr)
                return EXIT_ERROR
            findings = scan_staged(scanner, root)
        elif args.history or args.since:
            if not is_git_repo(root):
                print("seep: history scan needs a git repository", file=sys.stderr)
                return EXIT_ERROR
            findings = scan_history(scanner, root, since=args.since)
        else:
            findings = scanner.scan_directory(root)
    except GitError as exc:
        print("seep: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    if args.write_baseline:
        write_baseline(args.write_baseline, findings, root=root)
        print("seep: wrote baseline of %d finding%s to %s" % (
            len(findings), "" if len(findings) == 1 else "s", args.write_baseline))

    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            print("seep: cannot load baseline: %s" % exc, file=sys.stderr)
            return EXIT_ERROR
        findings = filter_new(findings, baseline)

    if args.format == "json":
        print(to_json(findings))
    elif args.format == "sarif":
        print(to_sarif(findings, _RULES_BY_ID, __version__))
    else:
        print(to_text(findings))

    if scanner.skipped_binary or scanner.skipped_large:
        print("seep: skipped %d binary and %d oversized file%s" % (
            scanner.skipped_binary, scanner.skipped_large,
            "s" if scanner.skipped_large != 1 else ""), file=sys.stderr)

    failing = [f for f in findings if meets_threshold(f, args.fail_on)]
    return EXIT_FINDINGS if failing else EXIT_CLEAN


def _run_rules(args):
    if args.format == "json":
        import json
        print(json.dumps([
            {"id": r.id, "description": r.description, "severity": r.severity}
            for r in RULES
        ], indent=2))
    else:
        for rule in RULES:
            print("%-28s %-6s %s" % (rule.id, rule.severity, rule.description))
    return EXIT_CLEAN


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules(args)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
