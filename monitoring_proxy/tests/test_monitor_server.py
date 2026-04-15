import unittest

from monitoring_proxy.monitor_server import (
    MonitorChatRequest,
    process_monitor_request,
    process_monitor_request_with_dependencies,
    reset_rate_limit_state,
)
from monitoring_proxy.schemas import IntentReviewResult


class MonitorServerSmokeTest(unittest.TestCase):
    def setUp(self) -> None:
        reset_rate_limit_state()

    def test_p1_high_confidential_request_is_blocked(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "contact me at secret@company.com"}],
            employee_id="employee-a",
        )

        response = process_monitor_request(payload)

        self.assertTrue(response.blocked)
        self.assertEqual(response.stage, "p1_confidential_scan")
        self.assertEqual(response.severity, "high")
        self.assertIn("email pattern", response.reason)

    def test_p2_low_non_work_request_is_allowed_with_warning_stage(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "주말 계획 추천해줘"}],
            employee_id="employee-b",
        )

        response = process_monitor_request(payload)

        self.assertFalse(response.blocked)
        self.assertEqual(response.stage, "p2_inappropriate_use")
        self.assertEqual(response.severity, "low")
        self.assertIn("non-work-related", response.reason)

    def test_p3_repeated_query_blocks_on_third_attempt(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "same question"}],
            employee_id="employee-c",
        )

        first = process_monitor_request(payload)
        second = process_monitor_request(payload)
        third = process_monitor_request(payload)

        self.assertFalse(first.blocked)
        self.assertFalse(second.blocked)
        self.assertTrue(third.blocked)
        self.assertEqual(third.stage, "p3_rate_limit")
        self.assertEqual(third.limit_type, "repeated_query")
        self.assertIsNotNone(third.retry_after_seconds)

    def test_p1_medium_signal_surfaces_in_common_response_shape(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "Please review this create table draft"}],
            employee_id="employee-d",
        )

        response = process_monitor_request(payload)

        self.assertFalse(response.blocked)
        self.assertEqual(response.stage, "p1_confidential_scan")
        self.assertEqual(response.severity, "medium")
        self.assertIn("database-sensitive keyword", response.reason)
        self.assertIsNone(response.retry_after_seconds)
        self.assertIsNone(response.limit_type)

    def test_p4_violation_blocks_reviewable_request(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "Please review this create table draft"}],
            employee_id="employee-e",
        )

        def fake_intent_reviewer(**_: object) -> IntentReviewResult:
            return IntentReviewResult(
                judgment="violation",
                confidence=0.94,
                reason="request appears intended to obtain restricted internal schema details",
            )

        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=fake_intent_reviewer,
        )

        self.assertTrue(response.blocked)
        self.assertEqual(response.stage, "p4_intent_review")
        self.assertEqual(response.severity, "medium")
        self.assertIn("restricted internal schema", response.reason)

    def test_p4_normal_allows_reviewable_request(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "Please review this create table draft"}],
            employee_id="employee-f",
        )

        def fake_intent_reviewer(**_: object) -> IntentReviewResult:
            return IntentReviewResult(
                judgment="normal",
                confidence=0.87,
                reason="request is consistent with normal engineering review work",
            )

        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=fake_intent_reviewer,
        )

        self.assertFalse(response.blocked)
        self.assertEqual(response.stage, "p1_confidential_scan")
        self.assertEqual(response.severity, "medium")
        self.assertIn("database-sensitive keyword", response.reason)

    def test_p4_ambiguous_allows_request_with_review_note(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "주말 계획 추천해줘"}],
            employee_id="employee-g",
        )

        def fake_intent_reviewer(**_: object) -> IntentReviewResult:
            return IntentReviewResult(
                judgment="ambiguous",
                confidence=0.41,
                reason="request intent is unclear between casual use and low-risk internal usage",
            )

        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=fake_intent_reviewer,
        )

        self.assertFalse(response.blocked)
        self.assertEqual(response.stage, "p2_inappropriate_use")
        self.assertEqual(response.severity, "low")
        self.assertIn("non-work-related request detected", response.reason)
        self.assertIn("p4 review ambiguous", response.reason)

    def test_p1_high_creates_usage_log_and_violation_record(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "email me at secret@company.com"}],
            employee_id="employee-h",
        )
        saved_logs = []
        created_violations = []

        response = process_monitor_request_with_dependencies(
            payload,
            save_usage_log_fn=lambda entry: saved_logs.append(entry) or entry,
            create_violation_record_fn=lambda record: created_violations.append(record) or record,
        )

        self.assertTrue(response.blocked)
        self.assertEqual(len(saved_logs), 1)
        self.assertEqual(saved_logs[0].action_taken, "blocked")
        self.assertEqual(saved_logs[0].policy_violation, "p1_confidential_scan")
        self.assertEqual(len(created_violations), 1)
        self.assertEqual(created_violations[0].violation_type, "p1_confidential_scan")

    def test_p2_low_non_work_request_logs_without_violation(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "주말 계획 추천해줘"}],
            employee_id="employee-i",
        )
        saved_logs = []
        created_violations = []

        response = process_monitor_request_with_dependencies(
            payload,
            save_usage_log_fn=lambda entry: saved_logs.append(entry) or entry,
            create_violation_record_fn=lambda record: created_violations.append(record) or record,
        )

        self.assertFalse(response.blocked)
        self.assertEqual(len(saved_logs), 1)
        self.assertEqual(saved_logs[0].action_taken, "review_needed")
        self.assertEqual(saved_logs[0].policy_violation, "p2_inappropriate_use")
        self.assertEqual(len(created_violations), 0)

    def test_p4_violation_creates_violation_record(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "Please review this create table draft"}],
            employee_id="employee-j",
        )
        saved_logs = []
        created_violations = []

        def fake_intent_reviewer(**_: object) -> IntentReviewResult:
            return IntentReviewResult(
                judgment="violation",
                confidence=0.93,
                reason="request appears intended to obtain restricted internal schema details",
            )

        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=fake_intent_reviewer,
            save_usage_log_fn=lambda entry: saved_logs.append(entry) or entry,
            create_violation_record_fn=lambda record: created_violations.append(record) or record,
        )

        self.assertTrue(response.blocked)
        self.assertEqual(len(saved_logs), 1)
        self.assertEqual(saved_logs[0].policy_violation, "p4_intent_review")
        self.assertEqual(saved_logs[0].action_taken, "blocked")
        self.assertEqual(len(created_violations), 1)
        self.assertEqual(created_violations[0].violation_type, "p4_intent_review")

    def test_p4_ambiguous_logs_review_needed_without_violation(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "Please review this create table draft"}],
            employee_id="employee-k",
        )
        saved_logs = []
        created_violations = []

        def fake_intent_reviewer(**_: object) -> IntentReviewResult:
            return IntentReviewResult(
                judgment="ambiguous",
                confidence=0.40,
                reason="intent is unclear between legitimate review and restricted data probing",
            )

        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=fake_intent_reviewer,
            save_usage_log_fn=lambda entry: saved_logs.append(entry) or entry,
            create_violation_record_fn=lambda record: created_violations.append(record) or record,
        )

        self.assertFalse(response.blocked)
        self.assertEqual(len(saved_logs), 1)
        self.assertEqual(saved_logs[0].action_taken, "review_needed")
        self.assertEqual(saved_logs[0].policy_violation, "p1_confidential_scan")
        self.assertEqual(len(created_violations), 0)


if __name__ == "__main__":
    unittest.main()
