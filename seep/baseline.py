"""Baseline files: grandfather known findings so only new ones report.

A baseline stores finding uids (rule, path, secret fingerprint - never the
secret itself) plus enough redacted context for a human to audit it. A repo
adopting seep can snapshot its existing leaks, fail CI only on new ones,
and burn the old ones down over time.
"""

import json
import os
from dataclasses import dataclass
from typing import Iterable, List, Set

BASELINE_VERSION = 1


@dataclass
class Baseline:
    uids: Set[str]

    @classmethod
    def empty(cls):
        return cls(uids=set())


def load_baseline(path):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("version") != BASELINE_VERSION:
        raise ValueError("unsupported baseline version: %r" % data.get("version"))
    return Baseline(uids={entry["uid"] for entry in data.get("findings", [])})


def write_baseline(path, findings, root=None):
    entries = [
        {
            "uid": f.uid,
            "rule_id": f.rule_id,
            "severity": f.severity,
            "path": f.path,
            "redacted_secret": f.redacted_secret,
            "commit": f.commit,
        }
        for f in sorted(findings, key=lambda f: f.uid)
    ]
    payload = {"version": BASELINE_VERSION, "findings": entries}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def filter_new(findings, baseline):
    return [f for f in findings if f.uid not in baseline.uids]
