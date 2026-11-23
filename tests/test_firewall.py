import unittest
from adapters.linux.firewall import generate_ruleset, validate_private_network


class FirewallPreviewTests(unittest.TestCase):
    def test_preview_contains_selected_interface(self):
        text = generate_ruleset("test-ap0", "192.168.50.0/24")
        self.assertIn('iifname "test-ap0"', text)
        self.assertIn("192.168.50.0/24", text)

    def test_reject_large_network(self):
        with self.assertRaises(ValueError):
            validate_private_network("10.0.0.0/16")

    def test_reject_public_network(self):
        with self.assertRaises(ValueError):
            validate_private_network("8.8.8.0/24")


if __name__ == "__main__":
    unittest.main()
