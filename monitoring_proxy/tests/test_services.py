import unittest

from monitoring_proxy.services.forwarder import build_forward_request, forward_to_target_ai
from monitoring_proxy.services.logging_service import build_usage_log_entry, save_usage_log
from monitoring_proxy.services.masking import mask_response_content
from monitoring_proxy.services.violation_service import (
    build_violation_record_input,
    create_violation_record,
)


class ServiceContractTest(unittest.TestCase):
    def test_logging_service_returns_usage_log_entry(self) -> None:
        entry = build_usage_log_entry(
            employee_id="employee-log",
            request_content="request text",
            response_content="response text",
            policy_violation="p2_inappropriate_use",
            severity="low",
            action_taken="allowed",
            target_service="https://example.com/chat",
        )

        saved = save_usage_log(entry)

        self.assertEqual(saved.employee_id, "employee-log")
        self.assertEqual(saved.policy_violation, "p2_inappropriate_use")
        self.assertEqual(saved.action_taken, "allowed")

    def test_violation_service_returns_record_input(self) -> None:
        record = build_violation_record_input(
            violation_type="p4_intent_review",
            severity="medium",
            description="policy violation detected",
            evidence="request content",
            reference="https://example.com/chat",
        )

        created = create_violation_record(record)

        self.assertEqual(created.violation_type, "p4_intent_review")
        self.assertEqual(created.severity, "medium")
        self.assertEqual(created.evidence, "request content")

    def test_forwarder_placeholder_returns_safe_noop_response(self) -> None:
        request = build_forward_request(
            target_url="https://example.com/chat",
            messages=[{"role": "user", "content": "hello"}],
            employee_context={"employee_id": "employee-forward"},
        )

        response = forward_to_target_ai(request)

        self.assertFalse(response.forwarded)
        self.assertIsNone(response.content)
        self.assertEqual(response.target_service, "https://example.com/chat")

    def test_masking_placeholder_is_passthrough(self) -> None:
        response_text = "raw response text"

        masked = mask_response_content(response_text)

        self.assertEqual(masked, "raw response text")


if __name__ == "__main__":
    unittest.main()
