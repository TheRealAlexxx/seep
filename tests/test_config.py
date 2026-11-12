import json
import os
import tempfile
import unittest

from seep.config import ConfigError, find_config, load_config


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "w") as handle:
            if isinstance(data, str):
                handle.write(data)
            else:
                json.dump(data, handle)
        return path

    def test_defaults_without_config(self):
        config = load_config(root=self.dir)
        self.assertEqual(config["fail_on"], "low")
        self.assertEqual(config["allowlist"], [])

    def test_loads_seep_json(self):
        self.write("seep.json", {"fail_on": "high", "allowlist": ["docs/"]})
        config = load_config(root=self.dir)
        self.assertEqual(config["fail_on"], "high")
        self.assertEqual(config["allowlist"], ["docs/"])

    def test_loads_dotfile_variant(self):
        self.write(".seep.json", {"max_file_bytes": 10})
        self.assertEqual(load_config(root=self.dir)["max_file_bytes"], 10)

    def test_rejects_unknown_keys(self):
        path = self.write("seep.json", {"nonsense": 1})
        with self.assertRaises(ConfigError):
            load_config(path=path)

    def test_rejects_invalid_json(self):
        path = self.write("seep.json", "{not json")
        with self.assertRaises(ConfigError):
            load_config(path=path)

    def test_rejects_bad_fail_on(self):
        path = self.write("seep.json", {"fail_on": "everything"})
        with self.assertRaises(ConfigError):
            load_config(path=path)

    def test_find_config_prefers_plain_name(self):
        self.write("seep.json", {})
        self.write(".seep.json", {})
        self.assertTrue(find_config(self.dir).endswith("seep.json"))


if __name__ == "__main__":
    unittest.main()
