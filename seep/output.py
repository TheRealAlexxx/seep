"""Output formats: human-readable text, JSON, and SARIF for code scanning."""

import json

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error"}


def meets_threshold(finding, threshold):
    return SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[threshold]


def to_text(findings, show_secrets=False):
    """Plain text report. Secrets are redacted regardless; show_secrets is
    reserved and intentionally not implemented - full secrets never print."""
    if not findings:
        return "seep: no findings"
    lines = []
    current_path = None
    for f in sorted(findings, key=lambda f: (f.path, f.line_number)):
        if f.path != current_path:
            current_path = f.path
            lines.append(f.path)
        location = "  L{} [{}] {}".format(f.line_number, f.severity, f.rule_id)
        if f.commit:
            location += " (introduced {} by {})".format(f.commit, f.author)
        lines.append(location)
        lines.append("    " + f.redacted_secret)
        if f.line_preview:
            lines.append("    | " + f.line_preview)
    summary = "seep: {} finding{}".format(len(findings), "" if len(findings) == 1 else "s")
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    detail = ", ".join("{} {}".format(counts[s], s) for s in ("high", "medium", "low") if s in counts)
    if detail:
        summary += " (" + detail + ")"
    lines.append(summary)
    return "\n".join(lines)


def _finding_dict(f):
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "path": f.path,
        "line": f.line_number,
        "redacted_secret": f.redacted_secret,
        "fingerprint": f.secret_fingerprint,
        "commit": f.commit,
        "author": f.author,
        "commit_date": f.commit_date,
    }


def to_json(findings):
    payload = {
        "version": 1,
        "finding_count": len(findings),
        "findings": [_finding_dict(f) for f in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def to_sarif(findings, rules_by_id, tool_version):
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {
                "text": "{} found: {}".format(
                    rules_by_id[f.rule_id].description, f.redacted_secret
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": f.line_number},
                }
            }],
            "partialFingerprints": {"seep/v1": f.secret_fingerprint},
        })
    sarif_rules = [
        {
            "id": rule.id,
            "name": rule.id.replace("-", "_"),
            "shortDescription": {"text": rule.description},
            "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
        }
        for rule in sorted(rules_by_id.values(), key=lambda r: r.id)
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "seep",
                    "version": tool_version,
                    "informationUri": "https://github.com/TheRealAlexxx/seep",
                    "rules": sarif_rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, sort_keys=True)
