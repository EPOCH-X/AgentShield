import unittest

from monitoring_proxy.monitor_server import (
    MonitorChatRequest,
    process_monitor_request,
    process_monitor_request_with_dependencies,
    reset_rate_limit_state,
)
from monitoring_proxy.services.intent_review import review_request_intent


class FakeLLMClient:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def generate(self, prompt: str, role: str = "base") -> object:
        self.calls.append({"prompt": prompt, "role": role})
        return self.response


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

    def test_injected_llm_client_blocks_when_p4_returns_violation(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "Please review this create table draft"}],
            employee_id="employee-e",
        )
        client = FakeLLMClient(
            '{"judgment":"violation","confidence":0.95,"reason":"request appears intended to obtain restricted internal schema details"}',
        )

        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=review_request_intent,
            llm_client=client,
        )

        self.assertTrue(response.blocked)
        self.assertEqual(response.stage, "p4_intent_review")
        self.assertEqual(response.severity, "medium")
        self.assertIn("restricted internal schema", response.reason)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0]["role"], "base")

    def test_injected_llm_client_allows_when_p4_returns_normal(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "Please review this create table draft"}],
            employee_id="employee-f",
        )
        client = FakeLLMClient(
            '{"judgment":"normal","confidence":0.91,"reason":"request is consistent with normal engineering review work"}',
        )

        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=review_request_intent,
            llm_client=client,
        )

        self.assertFalse(response.blocked)
        self.assertEqual(response.stage, "p1_confidential_scan")
        self.assertEqual(response.severity, "medium")
        self.assertIn("database-sensitive keyword", response.reason)
        self.assertEqual(len(client.calls), 1)

    def test_injected_llm_client_keeps_request_non_blocking_when_p4_is_ambiguous(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "주말 계획 추천해줘"}],
            employee_id="employee-g",
        )
        client = FakeLLMClient(
            '{"judgment":"ambiguous","confidence":0.41,"reason":"request intent is unclear between casual use and low-risk internal usage"}',
        )

        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=review_request_intent,
            llm_client=client,
        )

        self.assertFalse(response.blocked)
        self.assertEqual(response.stage, "p2_inappropriate_use")
        self.assertEqual(response.severity, "low")
        self.assertIn("non-work-related request detected", response.reason)
        self.assertIn("p4 review ambiguous", response.reason)
        self.assertEqual(len(client.calls), 1)

    def test_p3_does_not_call_p4_even_when_client_is_injected(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "same question"}],
            employee_id="employee-h",
        )
        client = FakeLLMClient(
            '{"judgment":"violation","confidence":0.99,"reason":"should not be used"}',
        )

        process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=review_request_intent,
            llm_client=client,
        )
        process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=review_request_intent,
            llm_client=client,
        )
        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=review_request_intent,
            llm_client=client,
        )

        self.assertTrue(response.blocked)
        self.assertEqual(response.stage, "p3_rate_limit")
        self.assertEqual(len(client.calls), 0)

    def test_p1_high_creates_usage_log_and_violation_record(self) -> None:
        payload = MonitorChatRequest(
            messages=[{"role": "user", "content": "email me at secret@company.com"}],
            employee_id="employee-i",
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
            employee_id="employee-j",
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
            employee_id="employee-k",
        )
        saved_logs = []
        created_violations = []
        client = FakeLLMClient(
            '{"judgment":"violation","confidence":0.93,"reason":"request appears intended to obtain restricted internal schema details"}',
        )

        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=review_request_intent,
            llm_client=client,
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
            employee_id="employee-l",
        )
        saved_logs = []
        created_violations = []
        client = FakeLLMClient(
            '{"judgment":"ambiguous","confidence":0.40,"reason":"intent is unclear between legitimate review and restricted data probing"}',
        )

        response = process_monitor_request_with_dependencies(
            payload,
            intent_reviewer=review_request_intent,
            llm_client=client,
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
