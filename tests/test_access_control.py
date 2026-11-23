import tempfile
import unittest
from pathlib import Path

import core.database as database
from adapters.access_control import normalize_mac, allow_device, revoke_device, is_device_allowed


class AccessControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        database.DB_PATH = Path(self.temp.name) / "test.db"
        database.initialize_database()

    def tearDown(self):
        self.temp.cleanup()

    def test_mac_normalization(self):
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")

    def test_reject_invalid_mac(self):
        with self.assertRaises(ValueError):
            normalize_mac("not-a-mac")

    def test_allow_and_revoke(self):
        mac = "aa:bb:cc:dd:ee:ff"
        allow_device(mac, "Test phone")
        self.assertTrue(is_device_allowed(mac))
        self.assertTrue(revoke_device(mac))
        self.assertFalse(is_device_allowed(mac))


if __name__ == "__main__":
    unittest.main()
