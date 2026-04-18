import json

from monitoring_proxy.schemas import IntentReviewResult


def build_intent_review_prompt(
    message: str,
    employee_context: dict | None = None,
    rule_reasons: list[str] | None = None,
) -> str:
    context_block = json.dumps(employee_context or {}, ensure_ascii=False, indent=2)
    reasons_block = json.dumps(rule_reasons or [], ensure_ascii=False, indent=2)

    return (
        "You are the R5 monitoring intent reviewer for employee AI requests.\n"
        "Decide whether the employee message appears to be a normal business request,\n"
        "a likely policy violation, or still ambiguous after reviewing rule-based signals.\n"
        "Return JSON only with keys: judgment, confidence, reason.\n"
        'Allowed judgment values: "normal", "violation", "ambiguous".\n'
        "Confidence must be a float between 0 and 1.\n"
        "Use the rule reasons and employee context only as supporting signals.\n"
        "Do not use labels from security testing contexts.\n\n"
        f"Employee context:\n{context_block}\n\n"
        f"Rule reasons:\n{reasons_block}\n\n"
        f"Employee message:\n{message}"
    )


def strip_code_fences(raw_text: str) -> str:
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    return cleaned


def fallback_intent_review_result(reason: str) -> IntentReviewResult:
    return IntentReviewResult(
        judgment="ambiguous",
        confidence=0.0,
        reason=reason,
    )


def parse_intent_review_response(raw_text: str) -> IntentReviewResult:
    cleaned = strip_code_fences(raw_text)
    if not cleaned:
        return fallback_intent_review_result(
            "intent review response was empty; falling back to ambiguous",
        )

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return fallback_intent_review_result(
            "intent review response was not valid JSON; falling back to ambiguous",
        )

    try:
        return IntentReviewResult.model_validate(parsed)
    except Exception:
        return fallback_intent_review_result(
            "intent review JSON did not match schema; falling back to ambiguous",
        )


def review_request_intent(
    message: str,
    employee_context: dict | None = None,
    rule_reasons: list[str] | None = None,
    llm_client: object | None = None,
    role: str = "base",
) -> IntentReviewResult:
    prompt = build_intent_review_prompt(
        message=message,
        employee_context=employee_context,
        rule_reasons=rule_reasons,
    )

    if llm_client is None:
        return fallback_intent_review_result(
            "intent review client is not configured; falling back to ambiguous",
        )

    if role != "base":
        return fallback_intent_review_result(
            "only base role is supported for intent review at this stage",
        )

    raw_response = llm_client.generate(prompt=prompt, role=role)
    return parse_intent_review_response(str(raw_response))
