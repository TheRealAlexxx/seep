import unittest

import seep


class VersionTest(unittest.TestCase):
    def test_version_is_set(self):
        self.assertRegex(seep.__version__, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
