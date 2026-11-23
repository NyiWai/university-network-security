import unittest
from adapters.bandwidth import validate_policy, build_preview, get_platform_capabilities

class BandwidthPolicyTests(unittest.TestCase):
    def test_valid_private_lab_policy(self):
        p = validate_policy("192.168.50.20", "eth1", "eth2", 2, "Both")
        self.assertEqual(p["target_ip"], "192.168.50.20")

    def test_reject_public_ip(self):
        with self.assertRaises(ValueError):
            validate_policy("8.8.8.8", "eth1", "eth2", 2, "Both")

    def test_reject_rate_over_lab_cap(self):
        with self.assertRaises(ValueError):
            validate_policy("192.168.50.20", "eth1", "eth2", 100, "Both")

    def test_linux_preview_does_not_execute(self):
        p = validate_policy("192.168.50.20", "eth1", "eth2", 2, "Both")
        preview = build_preview(p, "Linux")
        self.assertIn("PREVIEW ONLY", preview)
        self.assertIn("match ip src", preview)
        self.assertIn("match ip dst", preview)

    def test_windows_limitation_is_explicit(self):
        caps = get_platform_capabilities("Windows")
        self.assertFalse(caps["apply"])
        self.assertIn("host-originated", caps["upload"])

if __name__ == "__main__":
    unittest.main()
