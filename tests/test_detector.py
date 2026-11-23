import unittest
from detector.rules import evaluate_rules


class DetectorRuleTests(unittest.TestCase):
    def test_bruteforce_rule(self):
        alerts = evaluate_rules({"failed_logins": 10})
        self.assertTrue(any("brute-force" in a["event_type"].lower() for a in alerts))

    def test_normal_features_no_rule_alert(self):
        alerts = evaluate_rules({"failed_logins": 0, "connection_count": 10,
                                 "bytes_out": 1000, "unique_destinations": 2})
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
