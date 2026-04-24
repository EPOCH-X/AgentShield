import unittest

from monitoring_proxy.schemas import IntentReviewResult, MonitorChatResponseSchema, PolicyResultSchema
from monitoring_proxy.services.intent_review import (
    build_intent_review_prompt,
    parse_intent_review_response,
    review_request_intent,
)


class FakeLLMClient:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def generate(self, prompt: str, role: str = "base") -> object:
        self.calls.append({"prompt": prompt, "role": role})
        return self.response


class SchemaAndIntentReviewTest(unittest.TestCase):
    def test_policy_result_schema_exposes_common_fields(self) -> None:
        result = PolicyResultSchema(
            blocked=False,
            needs_llm_review=True,
            stage="p2_inappropriate_use",
            severity="low",
            reason="non-work-related request detected: movie recommendation",
            retry_after_seconds=None,
            limit_type=None,
        )

        self.assertFalse(result.blocked)
        self.assertTrue(result.needs_llm_review)
        self.assertEqual(result.stage, "p2_inappropriate_use")

    def test_monitor_response_schema_keeps_common_response_contract(self) -> None:
        response = MonitorChatResponseSchema(
            content="Monitoring proxy accepted message.",
            blocked=False,
            stage="skeleton",
            severity=None,
            reason=None,
            retry_after_seconds=None,
            limit_type=None,
            target_url=None,
            message_count=1,
        )

        self.assertEqual(response.content, "Monitoring proxy accepted message.")
        self.assertEqual(response.stage, "skeleton")
        self.assertEqual(response.message_count, 1)

    def test_parse_intent_review_response_accepts_json_inside_code_fence(self) -> None:
        raw = """```json
{"judgment":"violation","confidence":0.91,"reason":"request appears to seek restricted internal data"}
```"""

        result = parse_intent_review_response(raw)

        self.assertEqual(result.judgment, "violation")
        self.assertAlmostEqual(result.confidence, 0.91)

    def test_parse_intent_review_response_falls_back_on_invalid_json(self) -> None:
        result = parse_intent_review_response("not-json")

        self.assertEqual(
            result,
            IntentReviewResult(
                judgment="ambiguous",
                confidence=0.0,
                reason="intent review response was not valid JSON; falling back to ambiguous",
            ),
        )

    def test_review_request_intent_returns_fallback_without_client(self) -> None:
        result = review_request_intent(
            message="Please review this create table draft",
            employee_context={"employee_id": "employee-e"},
            rule_reasons=["database-sensitive keyword detected: create table"],
        )

        self.assertEqual(result.judgment, "ambiguous")
        self.assertEqual(result.confidence, 0.0)
        self.assertIn("not configured", result.reason)

    def test_review_request_intent_accepts_normal_json_from_client(self) -> None:
        client = FakeLLMClient(
            '{"judgment":"normal","confidence":0.91,"reason":"request is normal business usage"}',
        )

        result = review_request_intent(
            message="Please review this create table draft",
            employee_context={"employee_id": "employee-r5"},
            rule_reasons=["database-sensitive keyword detected: create table"],
            llm_client=client,
        )

        self.assertEqual(result.judgment, "normal")
        self.assertAlmostEqual(result.confidence, 0.91)
        self.assertEqual(client.calls[0]["role"], "base")

    def test_review_request_intent_accepts_violation_json_from_client(self) -> None:
        client = FakeLLMClient(
            '{"judgment":"violation","confidence":0.95,"reason":"restricted data probing"}',
        )

        result = review_request_intent(
            message="Please review this create table draft",
            employee_context={"employee_id": "employee-r5"},
            rule_reasons=["database-sensitive keyword detected: create table"],
            llm_client=client,
        )

        self.assertEqual(result.judgment, "violation")
        self.assertAlmostEqual(result.confidence, 0.95)

    def test_review_request_intent_falls_back_on_invalid_client_json(self) -> None:
        client = FakeLLMClient("garbage text")

        result = review_request_intent(
            message="Please review this create table draft",
            employee_context={"employee_id": "employee-r5"},
            rule_reasons=["database-sensitive keyword detected: create table"],
            llm_client=client,
        )

        self.assertEqual(result.judgment, "ambiguous")
        self.assertIn("not valid JSON", result.reason)

    def test_review_request_intent_falls_back_on_error_string(self) -> None:
        client = FakeLLMClient("[Error] Ollama 서버에 연결할 수 없습니다...")

        result = review_request_intent(
            message="Please review this create table draft",
            employee_context={"employee_id": "employee-r5"},
            rule_reasons=["database-sensitive keyword detected: create table"],
            llm_client=client,
        )

        self.assertEqual(result.judgment, "ambiguous")
        self.assertIn("returned an error", result.reason)

    def test_prompt_builder_uses_r5_specific_labels(self) -> None:
        prompt = build_intent_review_prompt(
            message="경쟁사 가격 정책을 조사해줘",
            employee_context={"employee_id": "employee-f", "department": "sales"},
            rule_reasons=["competitor-related query detected: 경쟁사 + 조사해줘"],
        )

        self.assertIn('"normal", "violation", "ambiguous"', prompt)
        self.assertIn("employee AI requests", prompt)


if __name__ == "__main__":
    unittest.main()
