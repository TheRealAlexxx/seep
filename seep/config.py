"""JSON configuration (seep.json or .seep.json at the repo root).

JSON keeps seep stdlib-only on every supported Python version; TOML parsing
only exists in the stdlib from 3.11.
"""

import json
import os

CONFIG_NAMES = ("seep.json", ".seep.json")

DEFAULTS = {
    "allowlist": [],
    "max_file_bytes": 1024 * 1024,
    "fail_on": "low",
    "exclude_rules": [],
}


class ConfigError(ValueError):
    pass


def find_config(root):
    for name in CONFIG_NAMES:
        path = os.path.join(root, name)
        if os.path.isfile(path):
            return path
    return None


def load_config(root=None, path=None):
    config = dict(DEFAULTS)
    if path is None and root is not None:
        path = find_config(root)
    if path is None:
        return config
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ConfigError("invalid JSON in %s: %s" % (path, exc))
    if not isinstance(data, dict):
        raise ConfigError("%s must contain a JSON object" % path)
    unknown = set(data) - set(DEFAULTS)
    if unknown:
        raise ConfigError("unknown config keys in %s: %s" % (path, ", ".join(sorted(unknown))))
    config.update(data)
    if config["fail_on"] not in ("low", "medium", "high"):
        raise ConfigError("fail_on must be one of low, medium, high")
    return config
