import unittest

from monitoring_proxy.policies.confidential import detect_confidential_leak
from monitoring_proxy.policies.misuse import detect_inappropriate_use
from monitoring_proxy.policies.rate_limit import detect_rate_limit, reset_rate_limit_state


class PolicyModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        reset_rate_limit_state()

    def test_confidential_policy_keeps_medium_signal_for_db_keyword(self) -> None:
        result = detect_confidential_leak("please inspect create table migration")

        self.assertFalse(result.blocked)
        self.assertEqual(result.severity, "medium")
        self.assertIn("database-sensitive keyword", result.reason)

    def test_misuse_policy_keeps_low_warning_for_non_work_request(self) -> None:
        result = detect_inappropriate_use("movie recommendation please")

        self.assertFalse(result.blocked)
        self.assertEqual(result.category, "p2_non_work_related")
        self.assertEqual(result.severity, "low")

    def test_rate_limit_policy_blocks_repeated_query_on_third_attempt(self) -> None:
        first = detect_rate_limit("employee-policy", "same question")
        second = detect_rate_limit("employee-policy", "same question")
        third = detect_rate_limit("employee-policy", "same question")

        self.assertFalse(first.blocked)
        self.assertFalse(second.blocked)
        self.assertTrue(third.blocked)
        self.assertEqual(third.category, "p3_repeated_query")
        self.assertEqual(third.limit_type, "repeated_query")


if __name__ == "__main__":
    unittest.main()
